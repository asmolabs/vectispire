//! `EnrichmentService`: a scan's vulnerabilities enriched from the stored EPSS scores and the stored CISA KEV
//! catalogue.
//!
//! **A scan asks nobody.** The scores were once asked of `api.first.org` for every scan — a third party learned which
//! vulnerabilities each repository carried the day it was scanned. Both feeds are synchronised whole by the control
//! plane, and a scan reads what was stored.
//!
//! **Before a feed's first synchronisation it knows nothing**, and says so at warning level: no score is set and
//! nothing is marked exploited, which the ingestion leaves as unknown — never as a measured zero. **Nothing is written
//! here**: the ingestion writes these values onto its own findings, in its transaction, a score only where one is
//! known.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use futures_util::future::BoxFuture;
use vectispire_cp_db::Db;
use vectispire_cp_scanning::ingestion::{Enricher, Enrichment};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::java;

use crate::feeds::{FeedError, ThreatIntel};
use crate::persistence::repository::{IntelRepository, SyncRepository};
use crate::persistence::{self, SINGLETON_ID};

/// Kept well under every engine's bind-parameter ceiling, for a scan of a large image.
const KEV_QUERY_BATCH: usize = 500;

/// The service.
#[derive(Debug, Clone)]
pub struct EnrichmentService {
    db: Db,
    settings: Settings,
    feeds: ThreatIntel,
}

impl EnrichmentService {
    pub fn new(db: Db, settings: Settings, feeds: ThreatIntel) -> EnrichmentService {
        EnrichmentService { db, settings, feeds }
    }

    /// `enrich`, failing rather than absent.
    async fn lookup(&self, identifiers: &[String]) -> Result<Option<Enrichment>, FeedError> {
        if !self.settings.is_enabled(Setting::EnrichmentEnabled).await.map_err(|e| FeedError(Box::new(e)))?
            || identifiers.is_empty()
        {
            return Ok(None);
        }
        // `groupingBy(trim, upper-case)`: each canonical identifier with every spelling the scan used for it.
        let mut spellings: HashMap<String, Vec<String>> = HashMap::new();
        for identifier in identifiers {
            spellings.entry(java::to_upper_root(java::trim(identifier))).or_default().push(identifier.clone());
        }
        let epss_scores = self.epss_scores(&spellings).await?;
        let exploited = self.exploited(&spellings).await?;
        tracing::info!(
            "Enrichment: {}/{} CVE with an EPSS score, {} in the KEV catalogue.",
            epss_scores.len(),
            identifiers.len(),
            exploited.len()
        );
        Ok(Some(Enrichment { epss_scores, exploited }))
    }

    /// The stored scores, keyed as the scan spelled each identifier — the ingestion matches on its own spelling, and
    /// the file is stored upper-case.
    async fn epss_scores(&self, spellings: &HashMap<String, Vec<String>>) -> Result<BTreeMap<String, f64>, FeedError> {
        if !self.feeds.epss_synchronised().await? {
            tracing::warn!(
                "EPSS scores never synchronised: no finding of this scan gets a score, and none reads as zero."
            );
            return Ok(BTreeMap::new());
        }
        let mut scores = BTreeMap::new();
        for known in self.feeds.scores_of(spellings.keys().map(String::as_str)).await?.into_values() {
            for spelling in spellings.get(&known.cve_id).into_iter().flatten() {
                scores.insert(spelling.clone(), known.score);
            }
        }
        Ok(scores)
    }

    /// The identifiers the stored catalogue lists, spelled as the scan spelled them. A refresh never un-flags an issue a
    /// scan does not find exploited, so the gap before the first synchronisation costs new issues their flag until it
    /// runs, and it re-evaluates them.
    async fn exploited(&self, spellings: &HashMap<String, Vec<String>>) -> Result<BTreeSet<String>, FeedError> {
        let mut tx = persistence::read(&self.db).await?;
        let synced =
            SyncRepository::find(&mut tx, SINGLETON_ID).await?.is_some_and(|sync| sync.last_synced_at.is_some());
        if !synced {
            persistence::commit(tx).await?;
            tracing::warn!(
                "KEV catalogue never synchronised: no finding of this scan can be marked as actively exploited."
            );
            return Ok(BTreeSet::new());
        }
        let lower_case: Vec<String> = spellings.keys().map(|id| java::to_lower_root(id)).collect();
        let mut exploited = BTreeSet::new();
        for batch in lower_case.chunks(KEV_QUERY_BATCH) {
            for stored in IntelRepository::exploited_among(&mut tx, batch).await? {
                exploited.extend(spellings.get(&java::to_upper_root(&stored)).into_iter().flatten().cloned());
            }
        }
        persistence::commit(tx).await?;
        Ok(exploited)
    }
}

impl Enricher for EnrichmentService {
    fn enrich<'a>(&'a self, identifiers: &'a [String]) -> BoxFuture<'a, Option<Enrichment>> {
        Box::pin(async move {
            match self.lookup(identifiers).await {
                Ok(found) => found,
                Err(failure) => {
                    // Java's lookups would fail the ingestion; here the port answers absent — no score and nothing
                    // exploited, which the ingestion keeps as unknown and the next KEV synchronisation re-evaluates.
                    tracing::error!("Enrichment failed — the scan's findings keep their defaults: {failure}");
                    None
                }
            }
        })
    }
}
