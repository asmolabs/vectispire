//! The fleet's exploitation ranking on a real server — Java's `EpssRoutesTest` (the scores as measured, unknown left
//! null, the ranking cut and the counts not) and `VisibilityRoutesTest.everyAggregateIsScoped`, with the rules the
//! recordings do not reach: settled triage and closed states left out, the issue's own score before the feed's, the
//! feed's KEV word joined, the title's and the identifier's fallbacks, and ties kept in the backlog's order.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::float_cmp)]

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine, ScanTarget, Visibility};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_threatintel::feeds::ThreatIntel;
use vectispire_cp_threatintel::prioritization::{EpssPrioritizationService, FleetSummary, RANKED};
use vectispire_cp_threatintel::risk_matrix::RecommendedAction;

fn ranking(db: &Db) -> EpssPrioritizationService {
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let config = EncryptionConfig {
        key: Some(vectispire_domain::secret::Secret::new("dGhyb3dhd2F5LXRhcmdldHMta2V5LTMyLWJ5dGVzISE=")),
        ..EncryptionConfig::default()
    };
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    let encryption = Arc::new(Encryption::new(&config, door).expect("encryption"));
    let clock: Arc<dyn vectispire_cp_targets::Clock> = Arc::new(vectispire_cp_targets::SystemClock);
    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit,
        scans: Arc::new(vectispire_cp_targets::ScanningStandIn),
        backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
        purge: vectispire_cp_targets::PurgeRegistry::stand_ins(),
        encryption,
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        clock: clock.clone(),
        visibility: None,
    }));
    let issues = Arc::new(vectispire_cp_issues::queries::IssueCatalog::new(db.clone()));
    EpssPrioritizationService::new(issues, targets, ThreatIntel::new(db.clone(), clock))
}

struct Issue<'a> {
    id: i64,
    repo: Option<i64>,
    container: Option<i64>,
    identifier: Option<&'a str>,
    state: &'a str,
    triage: &'a str,
    cvss: Option<f64>,
    epss: Option<f64>,
    kev: bool,
    description: Option<&'a str>,
    package: Option<&'a str>,
}

fn issue(id: i64, repo: i64, identifier: &str) -> Issue<'_> {
    Issue {
        id,
        repo: Some(repo),
        container: None,
        identifier: Some(identifier),
        state: "open",
        triage: "untriaged",
        cvss: None,
        epss: None,
        kev: false,
        description: None,
        package: None,
    }
}

fn text(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| format!("'{value}'"))
}

fn number(value: Option<f64>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn seed(server: &TestDatabase, issue: &Issue<'_>) {
    server.sql_as_admin(&format!(
        "insert into t_issue (id, repo_id, container_id, fingerprint, type, state, identifier, severity, cvss_score, \
         epss_score, is_kev, description, package_name, first_seen_at, last_seen_at, times_seen, triage_status, \
         reachability, revision) values ({}, {}, {}, 'fp-{}', 'vulnerability', '{}', {}, 'HIGH', {}, {}, {}, {}, {}, \
         '2026-01-01 00:00:00', '2026-01-01 00:00:00', 1, '{}', 'unknown', 0)",
        issue.id,
        issue.repo.map_or_else(|| "null".to_owned(), |id| id.to_string()),
        issue.container.map_or_else(|| "null".to_owned(), |id| id.to_string()),
        issue.id,
        issue.state,
        text(issue.identifier),
        number(issue.cvss),
        number(issue.epss),
        issue.kev,
        text(issue.description),
        text(issue.package),
        issue.triage,
    ));
}

#[test]
fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = TestDatabase::start(Engine::MySql).await;
        let db = server.connect().await;
        let service = ranking(&db);
        server.sql_as_admin("insert into t_repository (id, url, branch, name) values (101, 'https://forge.example/corp/auth.git', 'main', null)");
        server.sql_as_admin("insert into t_repository (id, url, branch, name) values (102, 'https://forge.example/corp/other.git', 'main', 'Other')");
        server.sql_as_admin("insert into t_container (id, image_name, tag) values (201, 'registry.example/web', 'v1')");

        nothing_recorded_ranks_nothing(&service).await;
        seed_backlog(&server);
        // The feeds: Log4Shell listed and scored; CVE-2031-0001 scored by the file, which the issue's own figure beats.
        server.sql_as_admin("insert into t_threat_intel_feed (cve_id, is_kev, date_added, updated_at) values ('CVE-2021-44228', true, '2021-12-10 00:00:00', '2026-01-01 00:00:00')");
        server.sql_as_admin("insert into t_epss_score (generation, cve_id, score, percentile) values (5, 'CVE-2021-44228', 0.975, 0.9998), (5, 'CVE-2031-0001', 0.9, 0.99)");
        server.sql_as_admin("update t_threat_intel_sync set epss_generation = 5, epss_count = 2, last_synced_at = '2026-01-01 00:00:00' where id = 1");

        let all = service.fleet_summary(&Visibility::Everything).await.unwrap();
        the_scores_are_the_measured_ones(&all);
        the_counts_weigh_everything_the_list_is_cut(&all);
        let restricted =
            service.fleet_summary(&Visibility::Only(BTreeSet::from([ScanTarget::Repository(102)]))).await.unwrap();
        a_reader_ranks_their_own_alone(&restricted);
    });
}

async fn nothing_recorded_ranks_nothing(service: &EpssPrioritizationService) {
    let empty = service.fleet_summary(&Visibility::Everything).await.unwrap();
    assert_eq!(
        vectispire_domain::wire::to_wire_string(&empty),
        r#"{"totalVulnerabilities":0,"activeKevCount":0,"highEpssCount":0,"averageFleetEpss":0.0,"topPriorities":[],"breakdownByTier":{"MEDIUM_THEORETICAL":0,"HIGH_PROBABLE":0,"LOW_PROBABILITY":0,"CRITICAL_ARMED":0}}"#,
        "every tier present, in the order the wire has always carried"
    );
}

fn seed_backlog(server: &TestDatabase) {
    seed(
        server,
        &Issue {
            cvss: Some(10.0),
            description: Some("Remote Code Execution in Apache Log4j"),
            ..issue(1, 101, "CVE-2021-44228")
        },
    );
    seed(server, &Issue { epss: Some(0.4), ..issue(2, 101, " cve-2031-0001 ") });
    seed(server, &Issue { container: Some(201), repo: None, package: Some("lodash"), ..issue(3, 0, "GHSA-xxxx-yyyy") });
    seed(server, &Issue { identifier: None, epss: Some(0.1), ..issue(4, 101, "") });
    seed(server, &Issue { kev: true, epss: Some(0.2), ..issue(5, 102, "CVE-2031-0005") });
    // Left out: settled triage, and the closed states whatever their case.
    seed(server, &Issue { triage: "not_affected", cvss: Some(10.0), ..issue(6, 101, "CVE-2031-0006") });
    seed(server, &Issue { state: "resolved", cvss: Some(10.0), ..issue(7, 101, "CVE-2031-0007") });
    seed(server, &Issue { state: "Closed", cvss: Some(10.0), ..issue(8, 101, "CVE-2031-0008") });
    // Enough ties for the cut: 50 more, all scoring alike, after the five above.
    for id in 100..150 {
        seed(server, &issue(id, 101, "CVE-2030-0000"));
    }
}

fn the_scores_are_the_measured_ones(summary: &FleetSummary) {
    let first = &summary.top_priorities[0];
    assert_eq!(
        (first.issue_id, first.is_kev, first.epss_score, first.epss_percentile, first.priority_tier),
        (1, true, Some(0.975), Some(0.9998), "CRITICAL_ARMED"),
        "the feed's KEV word and both its figures joined"
    );
    assert_eq!(
        (first.title.as_str(), first.target_name.as_str(), first.target_kind),
        ("Remote Code Execution in Apache Log4j", "corp/auth", "REPOSITORY")
    );
    assert_eq!(first.recommended_action, RecommendedAction::P0Kev24h);
    let by_id = |id: i64| summary.top_priorities.iter().find(|issue| issue.issue_id == id).unwrap();
    assert_eq!((by_id(2).epss_score, by_id(2).epss_percentile), (Some(0.4), Some(0.99)), "the issue's own score first");
    assert_eq!(by_id(2).identifier, " cve-2031-0001 ", "the identifier as the issue carries it");
    let image = by_id(3);
    assert_eq!(
        (image.title.as_str(), image.target_name.as_str(), image.target_kind, image.epss_score),
        ("lodash", "registry.example/web:v1", "CONTAINER", None),
        "unknown stays unknown"
    );
    let unnamed = by_id(4);
    assert_eq!(
        (unnamed.identifier.as_str(), unnamed.title.as_str()),
        ("vulnerability", "Vulnerability 4"),
        "fallbacks"
    );
    assert_eq!(by_id(5).target_name, "Other", "a repository's own name when it has one");
    assert!(summary.top_priorities.iter().all(|issue| ![6, 7, 8].contains(&issue.issue_id)), "settled and closed out");
}

fn the_counts_weigh_everything_the_list_is_cut(summary: &FleetSummary) {
    assert_eq!(summary.total_vulnerabilities, 55, "five plus fifty, the three left out not counted");
    assert_eq!(summary.top_priorities.len(), RANKED, "the list is cut");
    assert_eq!(
        (summary.active_kev_count, summary.high_epss_count),
        (2, 3),
        "KEV by the issue or the feed; 0.20 counts"
    );
    // (0.975 + 0.4 + 0.1 + 0.2) / 4 = 0.41875, rounded half up to the thousandth.
    assert_eq!(summary.average_fleet_epss, 0.419, "the mean of the scores known");
    let ties: Vec<i64> = summary.top_priorities.iter().skip(5).map(|issue| issue.issue_id).collect();
    assert_eq!(ties, (100..145).collect::<Vec<_>>(), "ties in the backlog's order, the rest cut");
    let tiers = vectispire_domain::wire::to_wire_string(&summary.breakdown_by_tier);
    assert_eq!(
        tiers, r#"{"MEDIUM_THEORETICAL":0,"HIGH_PROBABLE":1,"LOW_PROBABILITY":52,"CRITICAL_ARMED":2}"#,
        "every issue"
    );
}

fn a_reader_ranks_their_own_alone(summary: &FleetSummary) {
    let ids: Vec<i64> = summary.top_priorities.iter().map(|issue| issue.issue_id).collect();
    assert_eq!(
        (summary.total_vulnerabilities, ids),
        (1, vec![5]),
        "another repository's issues neither ranked nor counted"
    );
}
