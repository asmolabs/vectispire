//! `EndOfLifeService`: platforms whose support has ended — **a whole class of risk that carries no CVE at all**. A
//! runtime out of support will not receive a fix for the next vulnerability, whatever it turns out to be.
//!
//! Two matching paths, because the answer lives in two places in a Syft SBOM: **the distribution**, read from the
//! `distro` block — the base image's own operating system, which no package lookup would find — and **the packages**,
//! matched by purl against endoflife.date's index. The coverage is partly deliberate: the catalog tracks products,
//! not every library; "end of life" is a property of a platform.
//!
//! **Absent on any failure, never empty** (decision 0007): an outage of the catalog read as "no end-of-life platform
//! here" would resolve every end-of-life issue of the target, with its triage. A partial pass is absent too.
//!
//! **Both caches are shared by every scan being ingested**, each behind its own lock, held for a lookup or a store and
//! never across the fetch: two scans may ask for the same product at once and both call out — one redundant request —
//! where serialising every lookup would put a round trip on the path of every other scan.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use futures_util::future::BoxFuture;
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use vectispire_cp_outbound::json::OutboundJson;
use vectispire_cp_outbound::policy::OutboundPolicy;
use vectispire_cp_scanning::ingestion::{EndOfLifeSource, ObservedFinding};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::Clock;
use vectispire_domain::finding_type::FindingType;
use vectispire_domain::sbom;

use crate::life_cycle::{self, Candidate, DEFAULT_WARNING_DAYS, Product, Release};

const API_ROOT: &str = "https://endoflife.date/api/v1";
const SOURCE: &str = "endoflife.date";
const CACHE_TTL: Duration = Duration::hours(24);

/// Why the step did not run: the sentence the log carries.
type Failure = String;

/// Where the catalog is read: endoflife.date through the outbound door, or a stand-in in a test.
pub trait EndOfLifeCatalog: Send + Sync {
    /// The document at `url`: none on a 404 — an answer — and a failure on anything else that is not one.
    fn get<'a>(&'a self, url: &'a str, label: &'a str) -> BoxFuture<'a, Result<Option<Value>, Failure>>;
}

impl EndOfLifeCatalog for OutboundJson {
    fn get<'a>(&'a self, url: &'a str, label: &'a str) -> BoxFuture<'a, Result<Option<Value>, Failure>> {
        Box::pin(async move {
            OutboundJson::get(self, url, OutboundPolicy::PublicOnly, label, &[], None)
                .await
                .map_err(|failure| failure.to_string())
        })
    }
}

/// An answer and when it was fetched; `None` is an answer too — an unknown product.
#[derive(Debug, Clone)]
struct Cached<T> {
    value: T,
    fetched_at: OffsetDateTime,
}

/// `normalized purl → product name`, shared by the scans that read it.
type Index = Arc<HashMap<String, String>>;

/// The service.
#[derive(Clone)]
pub struct EndOfLifeService {
    settings: Settings,
    catalog: Arc<dyn EndOfLifeCatalog>,
    clock: Arc<dyn Clock>,
    purl_index: Arc<Mutex<Option<Cached<Index>>>>,
    products: Arc<Mutex<HashMap<String, Cached<Option<Product>>>>>,
}

impl std::fmt::Debug for EndOfLifeService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("EndOfLifeService").finish_non_exhaustive()
    }
}

impl EndOfLifeService {
    pub fn new(settings: Settings, catalog: Arc<dyn EndOfLifeCatalog>, clock: Arc<dyn Clock>) -> EndOfLifeService {
        EndOfLifeService {
            settings,
            catalog,
            clock,
            purl_index: Arc::new(Mutex::new(None)),
            products: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// `warningWindow`, in days: the setting when it is not negative, 180 otherwise.
    async fn warning_days(&self) -> Result<i64, Failure> {
        let days = self.settings.as_int(Setting::EolWarnDays).await.map_err(|failure| failure.to_string())?;
        Ok(if days >= 0 { i64::from(days) } else { DEFAULT_WARNING_DAYS })
    }

    /// `findings`, failing rather than absent — the caller logs and answers absent.
    async fn detect(&self, document: &Value) -> Result<Vec<ObservedFinding>, Failure> {
        let window = self.warning_days().await?;
        let today = self.clock.now().to_offset(time::UtcOffset::UTC).date();
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for candidate in self.candidates(document).await? {
            let Some(product) = self.product(&candidate.product).await? else {
                continue;
            };
            let Some(release) = life_cycle::match_release(&product, &candidate.version).map_err(|e| e.to_string())?
            else {
                continue;
            };
            // **Deduplicated on the cycle, not on the version**: an image can list the same runtime as a distribution
            // and as a package, as "3.9" and "3.9.1", while the finding is about the cycle in both cases.
            if !seen.insert(format!("{} {}", candidate.product, release.name.as_deref().unwrap_or("null"))) {
                continue;
            }
            if let Some(verdict) = life_cycle::assess(release, today, window) {
                findings.push(finding(&candidate, release, &product, verdict.severity.wire_name()));
            }
        }
        if !findings.is_empty() {
            tracing::info!("End of life: {} cycle(s) reported.", findings.len());
        }
        Ok(findings)
    }

    async fn candidates(&self, document: &Value) -> Result<Vec<Candidate>, Failure> {
        let mut found = Vec::new();
        if let Some(distro) = sbom::distro(Some(document)) {
            // A distribution's identifier already is the product name in most cases (`rhel`, `alpine`, `debian`):
            // asking for it directly costs less than downloading the product list, and a 404 is an answer.
            if self.product(&distro.id).await?.is_some() {
                found.push(Candidate { product: distro.id, version: distro.version, label: distro.label, purl: None });
            }
        }
        let index = self.identifier_index().await?;
        found.extend(life_cycle::package_candidates(&sbom::artifacts(Some(document)), &index));
        Ok(found)
    }

    /// The purl index, a day at a time. **Only an answer is cached, never an outage**: a failure cached as an empty
    /// index blinded the step for a day; it now makes the step absent, and the next scan asks again.
    async fn identifier_index(&self) -> Result<Arc<HashMap<String, String>>, Failure> {
        let now = self.clock.now();
        if let Some(cached) = self.purl_index.lock().map_err(poisoned)?.as_ref().filter(|cached| fresh(cached, now)) {
            return Ok(cached.value.clone());
        }
        let url = format!("{API_ROOT}/identifiers/purl/");
        let index = self
            .catalog
            .get(&url, "end-of-life index")
            .await?
            .map(|payload| life_cycle::parse_identifier_index(&payload))
            .unwrap_or_default();
        tracing::info!("End-of-life index: {} purl match(es).", index.len());
        let index = Arc::new(index);
        *self.purl_index.lock().map_err(poisoned)? =
            Some(Cached { value: index.clone(), fetched_at: self.clock.now() });
        Ok(index)
    }

    /// A product, a day at a time — **its absence cached too**: an unknown product, a 404, must not be asked for again
    /// on every package of every scan. A failure is not cached.
    async fn product(&self, name: &str) -> Result<Option<Product>, Failure> {
        let now = self.clock.now();
        if let Some(cached) = self.products.lock().map_err(poisoned)?.get(name).filter(|cached| fresh(cached, now)) {
            return Ok(cached.value.clone());
        }
        let url = format!("{API_ROOT}/products/{}/", url_encode(name));
        let product = self
            .catalog
            .get(&url, &format!("end-of-life product {name}"))
            .await?
            .and_then(|payload| life_cycle::parse_product(&payload));
        self.products
            .lock()
            .map_err(poisoned)?
            .insert(name.to_owned(), Cached { value: product.clone(), fetched_at: self.clock.now() });
        Ok(product)
    }
}

impl EndOfLifeSource for EndOfLifeService {
    /// Always: the setting is read in [`EndOfLifeSource::findings`], where it can be awaited — switched off, the step
    /// answers absent, as Java's `prepare` answers when `isEnabled` says no.
    fn is_enabled(&self) -> bool {
        true
    }

    fn findings<'a>(&'a self, document: &'a Value) -> BoxFuture<'a, Option<Vec<ObservedFinding>>> {
        Box::pin(async move {
            match self.settings.is_enabled(Setting::EolEnabled).await {
                Ok(true) => {}
                Ok(false) => return None,
                Err(failure) => {
                    // "We could not tell whether to look" is not "nothing is past its support": absent, the backlog
                    // left as it was.
                    tracing::error!("End-of-life detection's setting could not be read — step skipped: {failure}");
                    return None;
                }
            }
            match self.detect(document).await {
                Ok(findings) => Some(findings),
                Err(failed) => {
                    tracing::warn!("End-of-life detection failed — step skipped, backlog left as it was: {failed}");
                    None
                }
            }
        })
    }

    /// The finding's prose, carried through the ingestion's descriptions as a CVE's is.
    fn describe(&self, finding: &ObservedFinding) -> String {
        format!(
            "{} {} belongs to a cycle whose security support has ended or is about to. No fix will be published for \
             this component's next vulnerability, whatever it turns out to be.",
            finding.package_name.as_deref().unwrap_or("null"),
            finding.package_version.as_deref().unwrap_or("null")
        )
    }
}

fn fresh<T>(cached: &Cached<T>, now: OffsetDateTime) -> bool {
    now.checked_sub(CACHE_TTL).is_some_and(|horizon| cached.fetched_at > horizon)
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> Failure {
    "the end-of-life cache's lock was poisoned".to_owned()
}

/// `finding`: **stable from one patch of a cycle to the next** — "python 3.9" reaches end of life, not "python
/// 3.9.18" — since the fingerprint is built on the identifier, so the issue keeps its triage when the patch moves.
fn finding(candidate: &Candidate, release: &Release, product: &Product, severity: &str) -> ObservedFinding {
    let recommended = life_cycle::recommended_version(product);
    ObservedFinding {
        type_: FindingType::Eol.wire_name().to_owned(),
        source: SOURCE.to_owned(),
        identifier: Some(format!("EOL-{}-{}", candidate.product, release.name.as_deref().unwrap_or("null"))),
        severity: Some(severity.to_owned()),
        package_name: Some(candidate.label.clone()),
        package_version: Some(candidate.version.clone()),
        purl: candidate.purl.clone(),
        file_path: None,
        line: None,
        direct_dependency: None,
        owasp_category: None,
        epss_score: None,
        cvss_score: None,
        cvss_vector: None,
        fix_state: Some(if recommended.is_some() { "fixed" } else { "unknown" }.to_owned()),
        fix_versions: recommended,
        link: Some(format!("https://endoflife.date/{}", candidate.product)),
        kev: false,
        description: None,
        tool: None,
        tool_name: None,
        tool_version: None,
    }
}

/// `URLEncoder.encode(name, UTF_8)`: letters, digits and `.-*_` kept, a space as `+`, every other byte `%XX`.
fn url_encode(name: &str) -> String {
    let mut encoded = String::new();
    for byte in name.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => encoded.push(char::from(byte)),
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_encoded_as_a_form_is() {
        assert_eq!(url_encode("amazon-linux"), "amazon-linux");
        assert_eq!(url_encode("red hat/é"), "red+hat%2F%C3%A9");
        assert_eq!(url_encode("a.b*c_d"), "a.b*c_d");
    }

    #[test]
    fn a_cache_holds_for_a_day() {
        let at = OffsetDateTime::UNIX_EPOCH + Duration::days(10);
        let cached = Cached { value: (), fetched_at: at };
        assert!(fresh(&cached, at + Duration::hours(23)));
        assert!(!fresh(&cached, at + Duration::hours(24)));
    }
}
