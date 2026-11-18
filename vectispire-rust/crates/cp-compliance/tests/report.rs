//! The OWASP report as read, on a real server — Java's `OwaspReportLinksRoutesTest` (the figure is the list's length,
//! counted by the list's rule; only the shown identifiers linked; not recorded is not none; a reader sees their own
//! alone), `OwaspReportTest.AroundTheCall.anAbandonedReviewIsSettled` and the visibility refusals.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use vectispire_cp_compliance::error::ComplianceError;
use vectispire_cp_compliance::markdown::Kind;
use vectispire_cp_compliance::review::{ABANDONED, Report};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Engine, ScanTarget, Visibility};

#[derive(Debug)]
struct Fixed(OffsetDateTime);

impl vectispire_cp_targets::Clock for Fixed {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_795_262_400).unwrap()
}

fn at(offset_seconds: i64) -> String {
    let at = now() + Duration::seconds(offset_seconds);
    format!("from_unixtime({})", at.unix_timestamp())
}

fn refusal(result: Result<Report, ComplianceError>) -> String {
    match result {
        Err(ComplianceError::NotFound(message)) => message,
        other => panic!("not a 404: {other:?}"),
    }
}

#[test]
fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = TestDatabase::start(Engine::MySql).await;
        let db = server.connect().await;
        let services = support::services_on(db, Arc::new(Fixed(now())));
        for id in [101, 102] {
            server.sql_as_admin(&format!(
                "insert into t_repository (id, url, branch) values ({id}, 'https://forge.example/r{id}.git', 'main')"
            ));
            server.sql_as_admin(&format!(
                "insert into t_scan (id, branch, status, created_at, repo_id) values ({}, 'main', 'completed', {}, {id})",
                id + 200,
                at(-3600)
            ));
        }
        seed_issues(&server);
        refusals(&server, &services).await;
        read(&server, &services).await;
    });
}

/// SAST issues placed in A03 by their column, so the figure is the backlog's A03 list.
fn seed_issues(server: &TestDatabase) {
    let issues = [
        (1, 101, "CVE-2026-1", "open", "under_review"),
        (2, 101, "ghsa-abcd", "open", "under_review"),
        (3, 101, "GHSA-ABCD", "open", "affected"),
        // Resolved: neither counted nor linked.
        (4, 101, "CVE-2026-9", "resolved", "under_review"),
        // Another repository's: neither.
        (5, 102, "CVE-2026-1", "open", "under_review"),
        // Settled: linked — it is an open issue carrying the identifier — but not in the unsettled list's figure.
        (6, 101, "CVE-2026-6", "open", "not_affected"),
        // Never shown to the model: the prose may cite it, nothing links it.
        (7, 101, "CVE-2026-7", "open", "under_review"),
    ];
    for (id, repo, identifier, state, triage) in issues {
        server.sql_as_admin(&format!(
            "insert into t_issue (id, repo_id, fingerprint, type, state, identifier, owasp_category, first_seen_at, \
             last_seen_at, is_kev, times_seen, triage_status, reachability, revision) values ({id}, {repo}, 'fp-{id}', \
             'sast', '{state}', '{identifier}', 'A03', '2026-01-01 00:00:00', '2026-01-01 00:00:00', false, 1, \
             '{triage}', 'unknown', 0)"
        ));
    }
}

fn review(server: &TestDatabase, id: i64, repo: i64, status: &str, created: i64, extra: &str) {
    server.sql_as_admin(&format!(
        "insert into t_ai_review_result (id, scan_id, repo_id, model, prompt, status, created_at{}) values \
         ({id}, {}, {repo}, 'gemma4:e4b', 'p', '{status}', {}{})",
        extra.split_once('|').map_or(String::new(), |(columns, _)| format!(", {columns}")),
        repo + 200,
        at(created),
        extra.split_once('|').map_or(String::new(), |(_, values)| format!(", {values}")),
    ));
}

async fn refusals(server: &TestDatabase, services: &vectispire_cp_compliance::Services) {
    let report = &services.report;
    // Hidden and absent read alike, and both before "never reviewed".
    let only_102 = Visibility::Only(BTreeSet::from([ScanTarget::Repository(102)]));
    assert_eq!(refusal(report.latest(101, &only_102).await), "Repository not found.");
    assert_eq!(refusal(report.latest(999, &Visibility::Everything).await), "Repository not found.");
    assert_eq!(
        refusal(report.latest(101, &Visibility::Everything).await),
        "No OWASP report has been produced for this target."
    );
    // A review of another repository is not this one's.
    review(server, 50, 102, "completed", -60, "response|'## A01'");
    assert_eq!(
        refusal(report.latest(101, &Visibility::Everything).await),
        "No OWASP report has been produced for this target."
    );
}

async fn read(server: &TestDatabase, services: &vectispire_cp_compliance::Services) {
    let report = &services.report;
    review(
        server,
        1,
        101,
        "completed",
        -120,
        "response, inputs, evidence_identifiers|'## A03 — Injection\n\n**CVE-2026-1** and CVE-2026-7.', '=== DATA ===', \
         '[\"CVE-2026-1\",\"GHSA-AbCd\",\"CVE-2026-9\",\"CVE-2026-6\",\"CVE-2026-404\"]'",
    );
    let read = report.latest(101, &Visibility::Everything).await.unwrap();
    assert_eq!((read.id, read.status.as_str(), read.scan_id), (1, "completed", 301));
    assert_eq!(read.inputs.as_deref(), Some("=== DATA ==="));
    let kinds: Vec<(Kind, Option<&str>)> =
        read.blocks.iter().map(|block| (block.kind, block.category.as_deref())).collect();
    assert_eq!(kinds, [(Kind::Category, Some("A03")), (Kind::Paragraph, None)]);
    assert_eq!(read.blocks[1].text, "CVE-2026-1 and CVE-2026-7.");

    // The list's figure: the open, unsettled issues of the repository — 1, 2, 3 and 7 — all ten categories present.
    let figures = serde_json::to_value(&read.category_findings).unwrap();
    assert_eq!(figures.as_object().unwrap().len(), 10);
    assert_eq!(figures["A03"], 4);
    assert_eq!(figures["A01"], 0);

    // Only the shown ones, in the order shown, matched by the list's key; one issue named, several counted.
    let links = serde_json::to_value(&read.issue_links).unwrap();
    assert_eq!(
        links,
        serde_json::json!({
            "CVE-2026-1": { "issueId": 1, "count": 1 },
            "GHSA-AbCd": { "issueId": null, "count": 2 },
            "CVE-2026-6": { "issueId": 6, "count": 1 },
        })
    );
    let order: Vec<&String> = links.as_object().unwrap().keys().collect();
    assert_eq!(order, ["CVE-2026-1", "GHSA-AbCd", "CVE-2026-6"], "the order shown");

    // A reader restricted to the repository sees the same; the figures follow the caller's visibility, not the route's.
    let only_101 = Visibility::Only(BTreeSet::from([ScanTarget::Repository(101)]));
    assert_eq!(report.latest(101, &only_101).await.unwrap(), read);

    // Not recorded is not none: a review without identifiers has no links at all, an empty list has an empty map.
    review(server, 2, 101, "completed", -60, "response|'## A06'");
    assert_eq!(report.latest(101, &Visibility::Everything).await.unwrap().issue_links, None);
    review(server, 3, 101, "completed", -60, "evidence_identifiers|'[]'");
    let empty = report.latest(101, &Visibility::Everything).await.unwrap();
    assert_eq!(empty.id, 3, "the same instant: the higher key is the latest");
    assert_eq!(serde_json::to_value(&empty.issue_links).unwrap(), serde_json::json!({}));
    assert!(empty.blocks.is_empty());

    // Running and still awaited: shown as running. Past its deadline: failed with the reason, before any sweep.
    review(server, 4, 101, "running", -30, &format!("deadline_at|{}", at(1)));
    let running = report.latest(101, &Visibility::Everything).await.unwrap();
    assert_eq!((running.status.as_str(), running.error.as_deref()), ("running", None));
    review(server, 5, 101, "running", -20, &format!("deadline_at, error|{}, 'kept'", at(-1)));
    let abandoned = report.latest(101, &Visibility::Everything).await.unwrap();
    assert_eq!((abandoned.id, abandoned.status.as_str()), (5, "failed"));
    assert_eq!(abandoned.error.as_deref(), Some(ABANDONED));
    assert_eq!(
        server.sql_as_admin("select status from t_ai_review_result where id = 5"),
        "running",
        "read, not written"
    );
}
