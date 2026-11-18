//! The two synchronisations on a real server, with the sources stood in for as Java's suite stands them in
//! (`ThreatIntelFeedRoutesTest`, `EpssSyncRoutesTest`, `KevCatalogueIntegrationTest`, `EpssScoresIntegrationTest`):
//! the catalogue promoting, un-flagging and announcing once, refused when older, kept through an outage; the file
//! written beside the one in use, confirmed when the same, refused when older, cut short or much smaller, the
//! generation before the one replaced discarded; the schedule claiming only when due; each attempt audited in words.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::float_cmp)]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use vectispire_cp_audit::{AuditLog, RequestActor};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine, Tx};
use vectispire_cp_outbox::{RaiseError, SecurityEvents};
use vectispire_cp_threatintel::kev_catalog::KevCatalog;
use vectispire_cp_threatintel::sources::{EpssSource, Fetched, KevSource};
use vectispire_cp_threatintel::status::State;
use vectispire_cp_threatintel::sync::Origin;
use vectispire_cp_threatintel::{Services, ThreatIntelParts};
use vectispire_domain::instant::Instant;
use vectispire_domain::siem::CefEvent;

/// A source whose next answer the test sets.
struct Stub<T> {
    next: Mutex<Option<Result<T, String>>>,
}

impl<T> Default for Stub<T> {
    fn default() -> Self {
        Stub { next: Mutex::new(None) }
    }
}

impl<T: Clone> Stub<T> {
    fn answer(&self, answer: Result<T, String>) {
        *self.next.lock().unwrap() = Some(answer);
    }

    fn take(&self) -> Result<T, String> {
        self.next.lock().unwrap().clone().unwrap_or_else(|| Err("no answer stood in".to_owned()))
    }
}

impl KevSource for Stub<KevCatalog> {
    fn fetch(&self) -> Fetched<'_, KevCatalog> {
        let answer = self.take();
        Box::pin(async move { answer })
    }

    fn location(&self) -> &str {
        "https://kev.example/catalogue.json"
    }
}

impl EpssSource for Stub<Vec<u8>> {
    fn fetch(&self) -> Fetched<'_, Vec<u8>> {
        let answer = self.take();
        Box::pin(async move { answer })
    }

    fn location(&self) -> &str {
        "https://epss.example/epss.csv.gz"
    }
}

/// The SIEM's events, kept.
#[derive(Default)]
struct Raised(Mutex<Vec<CefEvent>>);

type Raising<'a> = Pin<Box<dyn Future<Output = Result<(), RaiseError>> + Send + 'a>>;

impl SecurityEvents for Raised {
    fn raise<'a>(&'a self, _: &'a mut Tx, event: &'a CefEvent) -> Raising<'a> {
        self.0.lock().unwrap().push(event.clone());
        Box::pin(async { Ok(()) })
    }

    fn raise_apart<'a>(&'a self, event: &'a CefEvent) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        self.0.lock().unwrap().push(event.clone());
        Box::pin(async {})
    }
}

impl Raised {
    fn drain(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .drain(..)
            .map(|event| {
                let field =
                    |key: &str| event.extensions().iter().find(|(name, _)| name == key).map(|(_, value)| value.clone());
                format!(
                    "{} | {} | {} | {} | {}",
                    event.event_type().wire_name(),
                    event.message().unwrap_or_default(),
                    field("cs1").unwrap_or_default(),
                    field("cs3").unwrap_or_default(),
                    field("cs4").unwrap_or_default()
                )
            })
            .collect()
    }
}

struct Feeds {
    services: Services,
    catalogue: Arc<Stub<KevCatalog>>,
    file: Arc<Stub<Vec<u8>>>,
    raised: Arc<Raised>,
    audit: Arc<AuditLog>,
}

fn feeds(db: &Db) -> Feeds {
    let audit = Arc::new(AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let catalogue = Arc::new(Stub::<KevCatalog>::default());
    let file = Arc::new(Stub::<Vec<u8>>::default());
    let raised = Arc::new(Raised::default());
    let clock: Arc<dyn vectispire_cp_targets::Clock> = Arc::new(vectispire_cp_targets::SystemClock);
    let config = vectispire_cp_crypto::EncryptionConfig {
        key: Some(vectispire_domain::secret::Secret::new("dGhyb3dhd2F5LXRhcmdldHMta2V5LTMyLWJ5dGVzISE=")),
        ..vectispire_cp_crypto::EncryptionConfig::default()
    };
    let door = vectispire_cp_crypto::VaultDoor {
        sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
    };
    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: Arc::new(vectispire_cp_targets::ScanningStandIn),
        backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
        purge: vectispire_cp_targets::PurgeRegistry::stand_ins(),
        encryption: Arc::new(vectispire_cp_crypto::Encryption::new(&config, door).unwrap()),
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        clock: clock.clone(),
        visibility: None,
    }));
    let services = Services::new(ThreatIntelParts {
        db: db.clone(),
        issues: Arc::new(vectispire_cp_issues::queries::IssueCatalog::new(db.clone())),
        targets,
        clock,
        events: raised.clone(),
        audit: audit.clone(),
        catalogue: catalogue.clone(),
        file: file.clone(),
    });
    Feeds { services, catalogue, file, raised, audit }
}

fn lead() -> RequestActor {
    RequestActor { username: Some("lead".to_owned()), ip_address: Some("10.0.0.1".to_owned()), user_agent: None }
}

fn day(text: &str) -> Instant {
    Instant::parse_iso(&format!("{text}T00:00:00Z")).unwrap()
}

fn catalogue(version: &str, released: &str, cves: &[&str]) -> KevCatalog {
    KevCatalog {
        version: Some(version.to_owned()),
        released: Some(day(released)),
        added: cves.iter().map(|cve| ((*cve).to_owned(), Some(day("2021-12-10")))).collect(),
    }
}

/// An EPSS file of `rows` scores, plain text: CVE-2020-<n>, then the ones named, each scored as given.
fn epss_file(date: &str, model: &str, rows: usize, named: &[(&str, f64)]) -> Vec<u8> {
    let mut text = format!("#model_version:{model},score_date:{date}T12:00:00Z\ncve,epss,percentile\n");
    for (cve, score) in named {
        text.push_str(&format!("{cve},{score},0.5\n"));
    }
    for n in 0..rows - named.len() {
        text.push_str(&format!("CVE-2020-{:07},0.00100,0.10000\n", n + 1));
    }
    text.into_bytes()
}

fn seed_issue(server: &TestDatabase, id: i64, repo: Option<i64>, identifier: &str, state: &str, kev: bool) {
    server.sql_as_admin(&format!(
        "insert into t_issue (id, repo_id, container_id, fingerprint, type, state, identifier, severity, is_kev, \
         package_name, first_seen_at, last_seen_at, times_seen, triage_status, reachability, revision) values \
         ({id}, {}, {}, 'fp-{id}', 'vulnerability', '{state}', '{identifier}', 'HIGH', {kev}, 'log4j-core', \
         '2026-01-01 00:00:00', '2026-01-01 00:00:00', 1, 'untriaged', 'unknown', 0)",
        repo.map_or_else(|| "null".to_owned(), |id| id.to_string()),
        if repo.is_some() { "null".to_owned() } else { "201".to_owned() },
    ));
}

async fn flags(db: &Db) -> Vec<(i64, bool)> {
    let catalog = vectispire_cp_issues::queries::IssueCatalog::new(db.clone());
    let mut seen: Vec<(i64, bool)> =
        catalog.find_by_ids(&[1, 2, 3, 4]).await.unwrap().into_iter().map(|issue| (issue.id, issue.is_kev)).collect();
    seen.sort_unstable();
    seen
}

async fn scores(db: &Db) -> Vec<(i64, Option<f64>)> {
    let catalog = vectispire_cp_issues::queries::IssueCatalog::new(db.clone());
    let mut seen: Vec<(i64, Option<f64>)> = catalog
        .find_by_ids(&[1, 2, 3, 4])
        .await
        .unwrap()
        .into_iter()
        .map(|issue| (issue.id, issue.epss_score))
        .collect();
    seen.sort_by_key(|(id, _)| *id);
    seen
}

async fn last_entry(audit: &AuditLog) -> (String, String) {
    let entry = audit.recent(1).await.unwrap().remove(0);
    (entry.user_id.unwrap_or_default(), entry.description)
}

#[test]
fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = TestDatabase::start(Engine::MySql).await;
        let db = server.connect().await;
        let feeds = feeds(&db);
        server.sql_as_admin("insert into t_repository (id, url, branch, name) values (101, 'https://forge.example/corp/auth.git', 'main', null)");
        server.sql_as_admin("insert into t_container (id, image_name, tag) values (201, 'registry.example/web', 'v1')");
        seed_issue(&server, 1, Some(101), "CVE-2021-44228", "open", false);
        seed_issue(&server, 2, Some(101), "CVE-2031-0002", "open", true);
        seed_issue(&server, 3, Some(101), "CVE-2021-44228", "resolved", false);
        seed_issue(&server, 4, None, " cve-2021-44228 ", "open", false);

        an_outage_is_a_failure_and_says_so(&feeds).await;
        the_catalogue_promotes_unflags_and_announces_once(&feeds, &db).await;
        an_older_catalogue_is_refused(&feeds, &db).await;
        the_schedule_reads_only_when_due(&feeds, &server).await;
        the_file_is_written_confirmed_and_refused(&feeds, &db, &server).await;
        a_running_sync_is_not_run_twice(&feeds, &server).await;
        a_delisted_cve_is_unflagged(&feeds, &db).await;
    });
}

async fn an_outage_is_a_failure_and_says_so(feeds: &Feeds) {
    feeds.catalogue.answer(Err("KEV catalogue: connection refused".to_owned()));
    feeds.file.answer(Err("EPSS file: connection refused".to_owned()));
    let status = feeds.services.sync.sync_threat_intel(&lead(), Origin::ThreatIntelligenceScreen).await.unwrap();
    assert_eq!(
        (status.status, status.last_error.as_deref(), status.last_synced_at, status.last_attempt_at.is_some()),
        (State::Failed, Some("KEV catalogue: connection refused"), None, true)
    );
    assert_eq!(
        (status.epss.status, status.epss.last_error.as_deref()),
        (State::Failed, Some("EPSS file: connection refused"))
    );
    let entries = feeds.audit.recent(2).await.unwrap();
    let mut said: Vec<&str> = entries.iter().map(|entry| entry.description.as_str()).collect();
    said.sort_unstable();
    assert_eq!(
        said,
        [
            "CISA KEV catalogue synchronization from the threat intelligence screen failed: KEV catalogue: connection \
             refused (catalogue in use kept, KEV=0)",
            "EPSS scores synchronization from the threat intelligence screen failed: EPSS file: connection refused \
             (scores in use kept: none)",
        ]
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry.operation_type == "THREAT_INTEL_SYNCED" && entry.resource_id == "threat_intel")
    );
    assert!(entries.iter().all(|entry| entry.user_id.as_deref() == Some("lead")));
}

async fn the_catalogue_promotes_unflags_and_announces_once(feeds: &Feeds, db: &Db) {
    feeds.catalogue.answer(Ok(catalogue("2026.09.26", "2026-09-26", &["CVE-2021-44228", "CVE-2031-0100"])));
    feeds.file.answer(Err("unreachable".to_owned()));
    let status = feeds.services.sync.sync_threat_intel(&lead(), Origin::EpssScreen).await.unwrap();
    assert_eq!(
        (status.status, status.total_cves, status.total_kev, status.backlog_updated_count),
        (State::Synced, 2, 2, 3),
        "two promoted — the trimmed, lower-case identifier among them — one un-flagged, the closed one untouched"
    );
    assert_eq!(
        (status.kev_catalog_version.as_deref(), status.last_error.as_deref(), status.last_synced_at.is_some()),
        (Some("2026.09.26"), None, true)
    );
    assert_eq!(flags(db).await, [(1, true), (2, false), (3, false), (4, true)]);
    assert_eq!(
        feeds.raised.drain(),
        [
            "CRITICAL_KEV_DETECTED | Vulnerability CVE-2021-44228 promoted to CISA Known Exploited Vulnerability (KEV) \
             | repository 101 | CVE-2021-44228 | log4j-core",
            "CRITICAL_KEV_DETECTED | Vulnerability  cve-2021-44228  promoted to CISA Known Exploited Vulnerability \
             (KEV) | container 201 |  cve-2021-44228  | log4j-core",
        ],
        "one per promoted issue, in id order, named as the issue names it"
    );
    let audit = feeds.audit.recent(2).await.unwrap();
    assert!(
        audit.iter().any(|entry| entry.description
            == "CISA KEV catalogue synchronized from the EPSS screen (version 2026.09.26, KEV=2, updated=3)"),
        "{audit:#?}"
    );

    // Again: the flags are compared, not toggled — nothing changes, nothing is announced.
    feeds.catalogue.answer(Ok(catalogue("2026.09.26", "2026-09-26", &["CVE-2021-44228", "CVE-2031-0100"])));
    let again = feeds.services.sync.sync_threat_intel(&lead(), Origin::EpssScreen).await.unwrap();
    assert_eq!((again.status, again.backlog_updated_count), (State::Synced, 0));
    assert!(feeds.raised.drain().is_empty(), "announced once");

    let record = feeds.services.feeds.lookup_cve(Some("cve-2021-44228")).await.unwrap().unwrap();
    assert_eq!((record.is_kev, record.notes.as_str()), (true, "Listed in the CISA KEV catalogue"));
}

async fn an_older_catalogue_is_refused(feeds: &Feeds, db: &Db) {
    feeds.catalogue.answer(Ok(catalogue("2026.08.01", "2026-08-01", &["CVE-2031-0002"])));
    let status = feeds.services.sync.sync_threat_intel(&lead(), Origin::ThreatIntelligenceScreen).await.unwrap();
    assert_eq!(
        (status.status, status.last_error.as_deref(), status.total_kev),
        (
            State::Failed,
            Some(
                "the catalogue read (released 2026-08-01T00:00:00Z) is older than the one in use (released \
                 2026-09-26T00:00:00Z); kept the newer"
            ),
            2
        )
    );
    assert_eq!(flags(db).await, [(1, true), (2, false), (3, false), (4, true)], "the catalogue in use kept");
}

async fn the_schedule_reads_only_when_due(feeds: &Feeds, server: &TestDatabase) {
    // Synchronised minutes ago, attempted just now: not due.
    feeds.catalogue.answer(Ok(catalogue("2026.09.27", "2026-09-27", &["CVE-2021-44228", "CVE-2031-0100"])));
    assert!(feeds.services.sync.sync_if_due().await.unwrap().is_none());
    // Seven hours old and attempted an hour ago: due, and audited as the schedule's.
    server.sql_as_admin(
        "update t_threat_intel_sync set last_synced_at = date_sub(utc_timestamp(), interval 7 hour), \
         last_attempt_at = date_sub(utc_timestamp(), interval 1 hour) where id = 1",
    );
    let status = feeds.services.sync.sync_if_due().await.unwrap().expect("due");
    assert_eq!((status.status, status.kev_catalog_version.as_deref()), (State::Synced, Some("2026.09.27")));
    assert_eq!(
        last_entry(&feeds.audit).await,
        (
            "system".to_owned(),
            "CISA KEV catalogue synchronized from the maintenance schedule (version 2026.09.27, KEV=2, updated=0)"
                .to_owned()
        )
    );
    // Claimed: the next turn finds nothing due.
    assert!(feeds.services.sync.sync_if_due().await.unwrap().is_none());
}

async fn the_file_is_written_confirmed_and_refused(feeds: &Feeds, db: &Db, server: &TestDatabase) {
    let sync = &feeds.services.sync;
    let named = [("CVE-2021-44228", 0.97), ("CVE-2031-0002", 0.25)];

    // The first file: 120,000 rows, the backlog re-scored where the file knows the CVE.
    feeds.file.answer(Ok(epss_file("2026-09-26", "v2025.03.14", 120_000, &named)));
    feeds.catalogue.answer(Err("unreachable".to_owned()));
    let status = sync.sync_threat_intel(&lead(), Origin::EpssScreen).await.unwrap().epss;
    assert_eq!(
        (status.status, status.total_scored, status.backlog_updated_count, status.model_version.as_deref()),
        (State::Synced, 120_000, 3, Some("v2025.03.14"))
    );
    assert_eq!(scores(db).await, [(1, Some(0.97)), (2, Some(0.25)), (3, None), (4, Some(0.97))]);
    assert_eq!(
        last_entry(&feeds.audit).await.1,
        "EPSS scores synchronized from the EPSS screen (model v2025.03.14, scores of 2026-09-26T12:00:00Z, 120000 CVE, \
         updated=3)"
    );
    let first = feeds.services.feeds.lookup_cve(Some("CVE-2021-44228")).await.unwrap().unwrap();
    assert_eq!((first.epss_score, first.epss_percentile), (Some(0.97), Some(0.5)));

    // The same file again: confirmed, not rewritten.
    feeds.file.answer(Ok(epss_file("2026-09-26", "v2025.03.14", 120_000, &named)));
    sync.sync_threat_intel(&lead(), Origin::EpssScreen).await.unwrap();
    assert_eq!(
        last_entry(&feeds.audit).await.1,
        "EPSS scores confirmed from the EPSS screen: the file read is the one in use (model v2025.03.14, scores of \
         2026-09-26T12:00:00Z, 120000 CVE)"
    );

    // Older, cut short, much smaller: refused, the scores in use kept, nothing of them left behind.
    let refusals = [
        (
            epss_file("2026-09-25", "v2025.03.14", 120_000, &named),
            "the file read (scores of 2026-09-25T12:00:00Z) is older than the one in use (scores of \
             2026-09-26T12:00:00Z); kept the newer",
        ),
        (
            epss_file("2026-09-27", "v2025.03.14", 50_000, &named),
            "the file carries 50000 scores; a whole EPSS file carries more than 100000: it is incomplete",
        ),
        (
            epss_file("2026-09-27", "v2025.03.14", 100_000, &named),
            "the file carries 100000 scores where the one in use carries 120000: an export that lost a tenth of the \
             population is incomplete; kept the one in use",
        ),
    ];
    for (file, reason) in refusals {
        feeds.file.answer(Ok(file));
        let status = sync.sync_threat_intel(&lead(), Origin::EpssScreen).await.unwrap().epss;
        assert_eq!(
            (status.status, status.last_error.as_deref(), status.total_scored),
            (State::Failed, Some(reason), 120_000)
        );
        // The audit log keeps a description to its column, as Java's does: the entry's opening is what it says.
        let said = last_entry(&feeds.audit).await.1;
        let full = format!(
            "EPSS scores synchronization from the EPSS screen failed: {reason} (scores in use kept: model v2025.03.14, \
             scores of 2026-09-26T12:00:00Z, 120000 CVE)"
        );
        assert!(full.starts_with(&said) && said.len() >= 200, "{said}");
        assert_eq!(generations(server).await, 1, "the refused generation discarded");
    }

    // Two newer files: each replaces the one in use, and the one before that is discarded — N-2, not N-1.
    feeds.file.answer(Ok(epss_file("2026-09-27", "v2025.03.14", 120_000, &[("CVE-2021-44228", 0.5)])));
    sync.sync_threat_intel(&lead(), Origin::EpssScreen).await.unwrap();
    assert_eq!(generations(server).await, 2, "the replaced generation kept for the readers mid-switch");
    assert_eq!(
        scores(db).await,
        [(1, Some(0.5)), (2, Some(0.25)), (3, None), (4, Some(0.5))],
        "a CVE no longer scored keeps its figure"
    );
    feeds.file.answer(Ok(epss_file("2026-09-28", "v2025.03.14", 120_000, &[("CVE-2021-44228", 0.6)])));
    let status = sync.sync_threat_intel(&lead(), Origin::EpssScreen).await.unwrap().epss;
    assert_eq!((status.status, status.backlog_updated_count), (State::Synced, 2));
    assert_eq!(generations(server).await, 2, "the one before the replaced one discarded");

    // Scheduled: synchronised just now, not due; a day old, due.
    assert!(sync.sync_epss_if_due().await.unwrap().is_none());
    server.sql_as_admin(
        "update t_threat_intel_sync set epss_synced_at = date_sub(utc_timestamp(), interval 24 hour), \
         epss_attempt_at = date_sub(utc_timestamp(), interval 1 hour) where id = 1",
    );
    feeds.file.answer(Ok(epss_file("2026-09-28", "v2025.03.14", 120_000, &[("CVE-2021-44228", 0.6)])));
    let scheduled = sync.sync_epss_if_due().await.unwrap().expect("due");
    assert_eq!(scheduled.epss.status, State::Synced);
    assert_eq!(
        last_entry(&feeds.audit).await,
        (
            "system".to_owned(),
            "EPSS scores confirmed from the maintenance schedule: the file read is the one in use (model v2025.03.14, \
             scores of 2026-09-28T12:00:00Z, 120000 CVE)"
                .to_owned()
        )
    );
}

async fn generations(server: &TestDatabase) -> i64 {
    server.sql_as_admin("select count(distinct generation) from t_epss_score").parse().unwrap()
}

async fn a_running_sync_is_not_run_twice(feeds: &Feeds, server: &TestDatabase) {
    server.sql_as_admin(
        "update t_threat_intel_sync set epss_lease_until = date_add(utc_timestamp(), interval 10 minute), \
         epss_claim = 42 where id = 1",
    );
    feeds.catalogue.answer(Err("unreachable".to_owned()));
    let status = feeds.services.sync.sync_threat_intel(&lead(), Origin::EpssScreen).await.unwrap().epss;
    assert!(status.in_progress);
    assert_eq!(
        last_entry(&feeds.audit).await.1,
        "EPSS scores synchronization from the EPSS screen not run: another one is in progress (scores in use: model \
         v2025.03.14, scores of 2026-09-28T12:00:00Z, 120000 CVE)"
    );
    server.sql_as_admin("update t_threat_intel_sync set epss_lease_until = null, epss_claim = null where id = 1");
}

async fn a_delisted_cve_is_unflagged(feeds: &Feeds, db: &Db) {
    feeds.catalogue.answer(Ok(catalogue("2026.09.29", "2026-09-29", &["CVE-2031-0100"])));
    feeds.file.answer(Err("unreachable".to_owned()));
    let status = feeds.services.sync.sync_threat_intel(&lead(), Origin::ThreatIntelligenceScreen).await.unwrap();
    assert_eq!(
        (status.status, status.total_cves, status.total_kev, status.backlog_updated_count),
        (State::Synced, 2, 1, 2)
    );
    assert_eq!(flags(db).await, [(1, false), (2, false), (3, false), (4, false)]);
    assert!(feeds.raised.drain().is_empty(), "un-flagging announces nothing");
    let record = feeds.services.feeds.lookup_cve(Some("CVE-2021-44228")).await.unwrap().unwrap();
    assert_eq!((record.is_kev, record.notes.as_str()), (false, "No longer listed in the CISA KEV catalogue"));
}
