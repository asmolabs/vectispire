//! The two sources a scan's ingestion reads, on a real server — Java's `EndOfLifeServiceTest` and
//! `EnrichmentServiceTest`: end of life from the distribution and from the packages, deduplicated on the cycle, absent
//! on any failure and never empty, its answers cached for a day and an unknown product's absence cached with them,
//! switched off by its setting; the enrichment from the stored feeds only, spelled as the scan spelled it, nothing before
//! a feed's first synchronisation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::float_cmp)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine, Mode};
use vectispire_cp_scanning::ingestion::{EndOfLifeSource, Enricher, Enrichment};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_threatintel::end_of_life::{EndOfLifeCatalog, EndOfLifeService};
use vectispire_cp_threatintel::enrichment::EnrichmentService;
use vectispire_cp_threatintel::feeds::ThreatIntel;

/// endoflife.date stood in: an answer per URL, a failure for the ones listed, and every request counted.
#[derive(Default)]
struct Catalog {
    answers: Mutex<HashMap<String, Result<Option<Value>, String>>>,
    asked: Mutex<Vec<String>>,
}

impl Catalog {
    fn answer(&self, path: &str, answer: Result<Option<Value>, String>) {
        self.answers.lock().unwrap().insert(format!("https://endoflife.date/api/v1{path}"), answer);
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().drain(..).map(|url| url.replace("https://endoflife.date/api/v1", "")).collect()
    }
}

impl EndOfLifeCatalog for Catalog {
    fn get<'a>(&'a self, url: &'a str, _label: &'a str) -> BoxFuture<'a, Result<Option<Value>, String>> {
        self.asked.lock().unwrap().push(url.to_owned());
        let answer = self.answers.lock().unwrap().get(url).cloned().unwrap_or(Ok(None));
        Box::pin(async move { answer })
    }
}

fn product(name: &str, releases: Value) -> Option<Value> {
    Some(json!({"result": {"name": name, "releases": releases}}))
}

fn sbom(distro: Option<(&str, &str, &str)>, packages: &[(&str, &str, &str)]) -> Value {
    let artifacts: Vec<Value> =
        packages.iter().map(|(name, version, purl)| json!({"name": name, "version": version, "purl": purl})).collect();
    match distro {
        Some((id, version, name)) => {
            json!({"artifacts": artifacts, "distro": {"id": id, "versionID": version, "name": name}})
        }
        None => json!({"artifacts": artifacts}),
    }
}

async fn set(db: &Db, setting: Setting, value: &str) {
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    Settings::new(db.clone()).set(&mut tx, setting, value).await.unwrap();
    tx.commit().await.unwrap();
}

/// What each finding says, in one line.
fn said(findings: &[vectispire_cp_scanning::ingestion::ObservedFinding]) -> Vec<String> {
    findings
        .iter()
        .map(|f| {
            format!(
                "{} {} {} | {} {} {} | {} {} {}",
                f.type_,
                f.identifier.as_deref().unwrap_or("-"),
                f.severity.as_deref().unwrap_or("-"),
                f.package_name.as_deref().unwrap_or("-"),
                f.package_version.as_deref().unwrap_or("-"),
                f.purl.as_deref().unwrap_or("-"),
                f.fix_state.as_deref().unwrap_or("-"),
                f.fix_versions.as_deref().unwrap_or("-"),
                f.link.as_deref().unwrap_or("-"),
            )
        })
        .collect()
}

#[test]
fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = TestDatabase::start(Engine::MySql).await;
        let db = server.connect().await;
        end_of_life(&db).await;
        enrichment(&db, &server).await;
    });
}

async fn end_of_life(db: &Db) {
    let catalog = Arc::new(Catalog::default());
    let clock: Arc<dyn vectispire_cp_targets::Clock> = Arc::new(vectispire_cp_targets::SystemClock);
    let service = EndOfLifeService::new(Settings::new(db.clone()), catalog.clone(), clock);
    let expired = json!([{"name": "10", "eolFrom": "2024-06-30", "isEol": true, "isMaintained": false},
                         {"name": "12", "isEol": false, "isMaintained": true, "latest": {"name": "12.8"}}]);
    catalog.answer("/products/debian/", Ok(product("debian", expired.clone())));
    catalog.answer(
        "/products/python/",
        Ok(product(
            "python",
            json!([
        {"name": "3.9", "eolFrom": "2025-10-31", "isEol": true, "isMaintained": false},
        {"name": "3.14", "eolFrom": "2030-10-31", "isEol": false, "isMaintained": true, "latest": {"name": "3.14.2"}}]),
        )),
    );
    catalog.answer(
        "/identifiers/purl/",
        Ok(Some(json!({"result": [
        {"identifier": "pkg:generic/python", "product": {"name": "python"}},
        {"identifier": "pkg:pypi/django", "product": {"name": "django"}}]}))),
    );

    // The distribution, which carries no purl, and the packages by purl — a cycle reported once, however many
    // spellings it was found under; a product the catalog does not know asked once and not reported.
    let image = sbom(
        Some(("Debian", "10", "Debian GNU/Linux")),
        &[
            ("python3", "3.9.2", "pkg:generic/python@3.9.2?arch=amd64"),
            ("python", "3.9", "pkg:generic/python@3.9"),
            ("python", "3.14.0", "pkg:generic/python@3.14.0"),
            ("Django", "4.2", "pkg:pypi/django@4.2"),
            ("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
        ],
    );
    assert!(service.is_enabled());
    let findings = service.findings(&image).await.expect("ran");
    assert_eq!(
        said(&findings),
        [
            "eol EOL-debian-10 high | Debian GNU/Linux 10 - | fixed 12.8 https://endoflife.date/debian",
            "eol EOL-python-3.9 high | python3 3.9.2 pkg:generic/python@3.9.2?arch=amd64 | fixed 3.14.2 \
             https://endoflife.date/python",
        ]
    );
    assert_eq!(
        service.describe(&findings[1]),
        "python3 3.9.2 belongs to a cycle whose security support has ended or is about to. No fix will be published \
         for this component's next vulnerability, whatever it turns out to be."
    );
    assert_eq!(catalog.asked(), ["/products/debian/", "/identifiers/purl/", "/products/python/", "/products/django/"]);

    // A day's cache: nothing asked again, the unknown product's absence included.
    assert_eq!(service.findings(&image).await.map(|found| found.len()), Some(2));
    assert!(catalog.asked().is_empty(), "every answer cached");

    // The window: a cycle ending inside it is medium, beyond it nothing — the setting's, 180 when negative.
    let soon = (time::OffsetDateTime::now_utc().date() + time::Duration::days(100)).to_string();
    catalog
        .answer("/products/node/", Ok(product("node", json!([{"name": "20", "eolFrom": soon, "isMaintained": true}]))));
    let node = sbom(Some(("node", "20.1", "Node")), &[]);
    assert_eq!(
        said(&service.findings(&node).await.unwrap()),
        ["eol EOL-node-20 medium | Node 20.1 - | fixed 20 https://endoflife.date/node"]
    );
    set(db, Setting::EolWarnDays, "30").await;
    assert!(service.findings(&node).await.unwrap().is_empty(), "beyond a thirty-day window");
    set(db, Setting::EolWarnDays, "-1").await;
    assert_eq!(service.findings(&node).await.unwrap().len(), 1, "a negative window reads as 180 days");

    // **Absent on any failure, never empty**: a product's lookup, or the index's, failing.
    let fresh = Arc::new(Catalog::default());
    let failing =
        EndOfLifeService::new(Settings::new(db.clone()), fresh.clone(), Arc::new(vectispire_cp_targets::SystemClock));
    fresh.answer("/products/debian/", Err("end-of-life product debian: HTTP 503.".to_owned()));
    assert_eq!(failing.findings(&image).await, None);
    fresh.answer("/products/debian/", Ok(product("debian", expired)));
    fresh.answer("/identifiers/purl/", Err("end-of-life index: HTTP 500.".to_owned()));
    assert_eq!(failing.findings(&image).await, None);
    fresh.asked();
    // The failures were not cached: the next scan asks again, and the debian answer it did get is kept.
    fresh.answer("/identifiers/purl/", Ok(None));
    assert_eq!(said(&failing.findings(&image).await.unwrap()).len(), 1, "the distribution alone, the index absent");
    assert_eq!(fresh.asked(), ["/identifiers/purl/"]);
    // A version the catalog's cycles cannot read past an int: absent, as Java's NumberFormatException makes it.
    let huge = sbom(Some(("debian", "99999999999", "Debian")), &[]);
    assert_eq!(failing.findings(&huge).await, None);

    // Switched off: absent — "we stopped looking" is not "it is fixed".
    set(db, Setting::EolEnabled, "false").await;
    assert_eq!(service.findings(&image).await, None);
    set(db, Setting::EolEnabled, "true").await;
}

async fn enrichment(db: &Db, server: &TestDatabase) {
    let service = EnrichmentService::new(
        db.clone(),
        Settings::new(db.clone()),
        ThreatIntel::new(db.clone(), Arc::new(vectispire_cp_targets::SystemClock)),
    );
    let ids: Vec<String> = ["CVE-2021-44228", " cve-2021-44228 ", "CVE-2031-0001", "GHSA-xxxx-yyyy"]
        .iter()
        .map(|id| (*id).to_owned())
        .collect();

    // Before either feed's first synchronisation: asked, and nothing known — not zero, not "not exploited" measured —
    // even with rows in the tables: a catalogue no synchronisation finished is not the catalogue.
    server.sql_as_admin("insert into t_threat_intel_feed (cve_id, is_kev, date_added, updated_at) values ('CVE-2021-44228', true, '2021-12-10 00:00:00', '2026-01-01 00:00:00'), ('CVE-2031-0001', false, null, '2026-01-01 00:00:00')");
    server.sql_as_admin("insert into t_epss_score (generation, cve_id, score, percentile) values (7, 'CVE-2021-44228', 0.975, 0.9998), (7, 'CVE-2031-0001', 0.2, 0.9), (6, 'GHSA-XXXX-YYYY', 0.5, 0.5)");
    assert_eq!(service.enrich(&ids).await, Some(Enrichment::default()));
    assert_eq!(service.enrich(&[]).await, None, "nothing to ask");

    server.sql_as_admin("update t_threat_intel_sync set status = 'SYNCED', epss_status = 'SYNCED', cve_count = 2, kev_count = 1, epss_count = 2, epss_generation = 7, last_synced_at = '2026-01-01 00:00:00' where id = 1");

    let enriched = service.enrich(&ids).await.expect("enabled");
    assert_eq!(
        enriched.epss_scores,
        BTreeMap::from([
            (" cve-2021-44228 ".to_owned(), 0.975),
            ("CVE-2021-44228".to_owned(), 0.975),
            ("CVE-2031-0001".to_owned(), 0.2),
        ]),
        "keyed as the scan spelled it, the generation in use only, nothing but a CVE asked"
    );
    assert_eq!(
        enriched.exploited,
        BTreeSet::from([" cve-2021-44228 ".to_owned(), "CVE-2021-44228".to_owned()]),
        "listed, both spellings; delisted, not exploited"
    );

    set(db, Setting::EnrichmentEnabled, "false").await;
    assert_eq!(service.enrich(&ids).await, None, "switched off: not asked");
}
