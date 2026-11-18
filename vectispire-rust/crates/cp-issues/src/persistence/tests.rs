//! `IssueRepository` on real servers, both engines: every statement it writes, run once, its answer held to what
//! the Java side's `IssueRepository` and `IssueSpecifications` answer.
//!
//! **Written before the repository was rewritten**, so that one suite judges both versions (the SeaORM spike,
//! 2026-10-26): until then the module's sixty statements were run by nothing — its only test checked the routes.
//!
//! Every check runs, and the failures are reported together: a baseline that stopped at its first difference would
//! say one thing about a repository that may have several.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;

use self::support::Migrated;
use crate::persistence::{
    IssueFilters, IssueRepository, IssueRow, Lifetime, NewIssue, NewTriageEvent, OwaspPlacement, TriageEventRepository,
};
use time::{Duration, OffsetDateTime};
use vectispire_cp_db::parity;
use vectispire_cp_db::types::to_microseconds;
use vectispire_cp_db::{Db, Engine, Mode, ScanTarget, Tx, Visibility};

const REPO_A: i64 = 101;
const REPO_B: i64 = 102;
const IMAGE_A: i64 = 201;
const IMAGE_B: i64 = 202;

#[test]
fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    run(Engine::MySql);
}

#[test]
fn on_postgresql() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    run(Engine::PostgreSql);
}

type Check = Result<(), String>;

macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($what:tt)+) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!("{}: {:?} != {:?}", format!($($what)+), left, right));
        }
    }};
}

fn run(engine: Engine) {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = Migrated::start(engine).await;
        seed_targets(&server);
        let db = server.connect().await;
        let mut failures = Vec::new();
        macro_rules! each {
            ($($check:ident),* $(,)?) => {$(
                // Each check in a transaction of its own, rolled back: none sees another's rows.
                let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
                if let Err(failure) = $check(&mut tx).await {
                    failures.push(format!("{}: {failure}", stringify!($check)));
                }
                tx.rollback().await.unwrap();
            )*};
        }
        each!(
            an_issue_reads_back_what_was_written,
            the_lookups_find_their_rows,
            the_open_issues_of_a_target_are_found_by_type_and_tool,
            an_update_is_refused_on_a_stale_revision,
            a_disappeared_issue_is_resolved_with_its_age,
            the_breach_sweep_pages_and_skips_what_it_signalled,
            an_expired_decision_is_found,
            the_open_counts_group_by_target,
            the_counts_by_severity_follow_the_reader_s_targets,
            the_ids_of_a_target_are_found_and_deleted,
            the_triage_history_is_written_and_read_in_both_orders,
            the_backlog_page_is_most_severe_first_and_filtered,
            the_owasp_filter_places_as_the_grid_does,
            the_dates_are_half_open_and_read_the_reopenings,
            the_reads_compliance_adds,
            the_backlog_shows_a_reader_only_what_it_was_granted,
            the_exceptions_register_pages_by_cursor_and_visibility,
            the_gate_weighs_a_state_whole_in_key_order_under_the_dual_target_rule,
            a_scan_raises_a_leak_once_when_it_creates_its_issue,
            the_aggregates_posture_reads_decode_and_count,
        );
        the_entities_agree_with_the_schema(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("the_entities_agree_with_the_schema: {failure}"));
        });
        one_transaction_runs_a_checked_query_and_the_repository(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("one_transaction_runs_a_checked_query_and_the_repository: {failure}"));
        });
        // Last: it commits its row, which the checks above would count.
        a_passed_deadline_is_raised_with_its_mark_and_not_again(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("a_passed_deadline_is_raised_with_its_mark_and_not_again: {failure}"));
        });
        // After it, committing its own rows of a type and tools nothing above writes.
        the_unsettled_counts_leave_settled_triage_out(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("the_unsettled_counts_leave_settled_triage_out: {failure}"));
        });
        db.close().await;
        assert!(failures.is_empty(), "{engine}: {} check(s) failed:\n  {}", failures.len(), failures.join("\n  "));
    });
}

/// Two repositories and two images, fixed ids, for the foreign keys.
fn seed_targets(server: &Migrated) {
    let overriding = match server.engine {
        Engine::MySql => "",
        Engine::PostgreSql => " overriding system value",
    };
    for id in [REPO_A, REPO_B] {
        server.sql_as_admin(&format!(
            "insert into t_repository (id, url, branch){overriding} values ({id}, 'https://forge.example/r{id}.git', 'main')"
        ));
    }
    for id in [IMAGE_A, IMAGE_B] {
        server.sql_as_admin(&format!(
            "insert into t_container (id, image_name, tag){overriding} values ({id}, 'registry.example/i{id}', 'v1')"
        ));
    }
}

fn at(seconds: i64) -> OffsetDateTime {
    to_microseconds(
        OffsetDateTime::from_unix_timestamp(1_760_000_000 + seconds).unwrap() + Duration::microseconds(123_456),
    )
}

fn issue(fingerprint: &str, repo_id: Option<i64>, container_id: Option<i64>) -> NewIssue {
    NewIssue {
        repo_id,
        container_id,
        fingerprint: fingerprint.to_owned(),
        type_: "DEPENDENCY".to_owned(),
        identifier: format!("CVE-2026-{fingerprint}"),
        package_name: None,
        package_version: None,
        purl: None,
        file_path: None,
        owasp_category: None,
        source: "grype".to_owned(),
        tool: None,
        tool_name: None,
        tool_version: None,
        import_source: None,
        severity: "HIGH".to_owned(),
        epss_score: None,
        is_kev: false,
        cvss_score: None,
        cvss_vector: None,
        fix_state: None,
        fix_versions: None,
        link: None,
        description: None,
        reachability: "UNKNOWN".to_owned(),
        reachable_symbols: None,
        state: "open".to_owned(),
        first_seen_at: at(0),
        last_seen_at: at(60),
        resolved_at: None,
        resolution_seconds: None,
        sla_breach_signalled_at: None,
        first_seen_scan_id: None,
        last_seen_scan_id: None,
        times_seen: 1,
        triage_status: "under_review".to_owned(),
        triage_justification: None,
        triage_comment: None,
        triaged_by: None,
        triaged_at: None,
        triage_expires_at: None,
        triage_requested_status: None,
        is_direct_dependency: None,
        line: None,
        ticket_ref: None,
        ticket_url: None,
        ticket_attached_by: None,
        revision: 0,
    }
}

fn as_row(id: i64, new: &NewIssue) -> IssueRow {
    IssueRow {
        id,
        repo_id: new.repo_id,
        container_id: new.container_id,
        fingerprint: new.fingerprint.clone(),
        type_: new.type_.clone(),
        identifier: new.identifier.clone(),
        package_name: new.package_name.clone(),
        package_version: new.package_version.clone(),
        purl: new.purl.clone(),
        file_path: new.file_path.clone(),
        owasp_category: new.owasp_category.clone(),
        source: Some(new.source.clone()),
        tool: new.tool.clone(),
        tool_name: new.tool_name.clone(),
        tool_version: new.tool_version.clone(),
        import_source: new.import_source.clone(),
        severity: new.severity.clone(),
        epss_score: new.epss_score,
        is_kev: new.is_kev,
        cvss_score: new.cvss_score,
        cvss_vector: new.cvss_vector.clone(),
        fix_state: new.fix_state.clone(),
        fix_versions: new.fix_versions.clone(),
        link: new.link.clone(),
        description: new.description.clone(),
        reachability: new.reachability.clone(),
        reachable_symbols: new.reachable_symbols.clone(),
        state: new.state.clone(),
        first_seen_at: new.first_seen_at,
        last_seen_at: new.last_seen_at,
        resolved_at: new.resolved_at,
        resolution_seconds: new.resolution_seconds,
        sla_breach_signalled_at: new.sla_breach_signalled_at,
        first_seen_scan_id: new.first_seen_scan_id,
        last_seen_scan_id: new.last_seen_scan_id,
        times_seen: new.times_seen,
        triage_status: new.triage_status.clone(),
        triage_justification: new.triage_justification.clone(),
        triage_comment: new.triage_comment.clone(),
        triaged_by: new.triaged_by.clone(),
        triaged_at: new.triaged_at,
        triage_expires_at: new.triage_expires_at,
        triage_requested_status: new.triage_requested_status.clone(),
        is_direct_dependency: new.is_direct_dependency,
        line: new.line,
        ticket_ref: new.ticket_ref.clone(),
        ticket_url: new.ticket_url.clone(),
        ticket_attached_by: new.ticket_attached_by.clone(),
        revision: new.revision,
    }
}

async fn insert(tx: &mut Tx, new: NewIssue) -> Result<IssueRow, String> {
    IssueRepository::insert_issue(tx, &new).await.map_err(|error| format!("insert {}: {error}", new.fingerprint))
}

fn ids(rows: &[IssueRow]) -> Vec<i64> {
    let mut ids: Vec<i64> = rows.iter().map(|row| row.id).collect();
    ids.sort_unstable();
    ids
}

fn fingerprints(rows: &[IssueRow]) -> Vec<&str> {
    rows.iter().map(|row| row.fingerprint.as_str()).collect()
}

async fn an_issue_reads_back_what_was_written(tx: &mut Tx) -> Check {
    let full = NewIssue {
        package_name: Some("org.example:lib".into()),
        package_version: Some("1.2.3".into()),
        purl: Some("pkg:maven/org.example/lib@1.2.3".into()),
        file_path: Some("pom.xml".into()),
        owasp_category: Some("A06".into()),
        tool: Some("grype".into()),
        tool_name: Some("Grype".into()),
        tool_version: Some("0.92.0".into()),
        import_source: Some("sarif".into()),
        epss_score: Some(0.4375),
        is_kev: true,
        cvss_score: Some(9.8),
        cvss_vector: Some("CVSS:3.1/AV:N".into()),
        fix_state: Some("fixed".into()),
        fix_versions: Some("1.2.4".into()),
        link: Some("https://advisories.example/1".into()),
        description: Some("é — a description with UTF-8 ✓".into()),
        reachability: "REACHABLE".into(),
        reachable_symbols: Some("a.b.C#d".into()),
        resolved_at: Some(at(120)),
        resolution_seconds: Some(120),
        sla_breach_signalled_at: Some(at(90)),
        times_seen: 3,
        triage_status: "not_affected".into(),
        triage_justification: Some("code_not_reachable".into()),
        triage_comment: Some("checked".into()),
        triaged_by: Some("alice".into()),
        triaged_at: Some(at(100)),
        triage_expires_at: Some(at(1_000)),
        triage_requested_status: Some("not_affected".into()),
        is_direct_dependency: Some(false),
        line: Some(42),
        ticket_ref: Some("ENG-1".into()),
        ticket_url: Some("https://tickets.example/ENG-1".into()),
        ticket_attached_by: Some("bob".into()),
        revision: 7,
        ..issue("full", Some(REPO_A), Some(IMAGE_A))
    };
    let written = insert(tx, full.clone()).await?;
    ensure_eq!(written, as_row(written.id, &full), "the inserted row as returned");
    let read = IssueRepository::find_by_id(tx, written.id).await.map_err(|e| e.to_string())?;
    ensure_eq!(read, Some(as_row(written.id, &full)), "the inserted row as read");

    let direct = NewIssue { is_direct_dependency: Some(true), ..issue("direct", None, Some(IMAGE_B)) };
    let written = insert(tx, direct.clone()).await?;
    ensure_eq!(written, as_row(written.id, &direct), "a true bit(1) and a null repository");
    let bare = issue("bare", Some(REPO_B), None);
    let written = insert(tx, bare.clone()).await?;
    ensure_eq!(written, as_row(written.id, &bare), "every optional column null");
    Ok(())
}

async fn the_lookups_find_their_rows(tx: &mut Tx) -> Check {
    let one = insert(tx, issue("look-1", Some(REPO_A), None)).await?;
    let two = insert(tx, issue("look-2", Some(REPO_A), None)).await?;
    ensure_eq!(IssueRepository::find_by_id(tx, -1).await.map_err(|e| e.to_string())?, None, "an absent id");

    // Past one IN list: the two real ids at either end of 1,500.
    let mut asked: Vec<i64> = (1_000_000..1_001_498).collect();
    asked.insert(0, one.id);
    asked.push(two.id);
    let found = IssueRepository::find_by_ids(tx, &asked).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(&found), vec![one.id, two.id], "ids across two IN lists");
    ensure_eq!(IssueRepository::find_by_ids(tx, &[]).await.map_err(|e| e.to_string())?.len(), 0, "no id");

    let found = IssueRepository::find_by_fingerprints(tx, &["look-2".into(), "nowhere".into()])
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(fingerprints(&found), vec!["look-2"], "by fingerprint");
    Ok(())
}

async fn the_open_issues_of_a_target_are_found_by_type_and_tool(tx: &mut Tx) -> Check {
    let tool = |fingerprint: &str, type_: &str, tool: &str, repo, container| NewIssue {
        type_: type_.into(),
        tool: Some(tool.into()),
        ..issue(fingerprint, repo, container)
    };
    let wanted = insert(tx, tool("t-1", "DEPENDENCY", "grype", Some(REPO_A), None)).await?;
    insert(tx, tool("t-2", "SECRET", "gitleaks", Some(REPO_A), None)).await?;
    insert(tx, NewIssue { state: "resolved".into(), ..tool("t-3", "DEPENDENCY", "grype", Some(REPO_A), None) }).await?;
    insert(tx, tool("t-4", "DEPENDENCY", "grype", Some(REPO_B), None)).await?;
    let image = insert(tx, tool("t-5", "DEPENDENCY", "trivy", None, Some(IMAGE_A))).await?;

    let types = vec!["DEPENDENCY".to_owned()];
    let found = IssueRepository::find_open_by_target(tx, "open", &types, Some(REPO_A), None)
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(ids(&found), vec![wanted.id], "a repository's open dependencies");
    let found = IssueRepository::find_open_by_target(tx, "open", &types, None, Some(IMAGE_A))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(ids(&found), vec![image.id], "an image's");
    let found = IssueRepository::find_open_by_target_and_tools(
        tx,
        "open",
        &types,
        &["trivy".into(), "osv".into()],
        None,
        Some(IMAGE_A),
    )
    .await
    .map_err(|e| e.to_string())?;
    ensure_eq!(ids(&found), vec![image.id], "an image's, by tool");
    let found =
        IssueRepository::find_open_by_target_and_tools(tx, "open", &types, &["trivy".into()], Some(REPO_A), None)
            .await
            .map_err(|e| e.to_string())?;
    ensure_eq!(found.len(), 0, "no tool of the repository's matches");
    Ok(())
}

async fn an_update_is_refused_on_a_stale_revision(tx: &mut Tx) -> Check {
    let written = insert(tx, issue("upd", Some(REPO_A), None)).await?;
    let changed =
        IssueRow { severity: "CRITICAL".into(), times_seen: 2, is_direct_dependency: Some(true), ..written.clone() };
    ensure_eq!(IssueRepository::update_issue(tx, &changed).await.map_err(|e| e.to_string())?, true, "the first update");
    let read = IssueRepository::find_by_id(tx, written.id).await.map_err(|e| e.to_string())?.unwrap();
    ensure_eq!(read, IssueRow { revision: 1, ..changed.clone() }, "the update read back, its revision moved");
    ensure_eq!(
        IssueRepository::update_issue(tx, &changed).await.map_err(|e| e.to_string())?,
        false,
        "a stale revision"
    );
    Ok(())
}

async fn a_disappeared_issue_is_resolved_with_its_age(tx: &mut Tx) -> Check {
    let gone = insert(tx, issue("gone", Some(REPO_A), None)).await?;
    let kept = insert(tx, issue("kept", Some(REPO_A), None)).await?;
    let moment = at(3_600);
    let resolved = IssueRepository::resolve_disappeared(tx, &[gone.id], moment).await.map_err(|e| e.to_string())?;
    ensure_eq!(resolved, 1, "rows resolved");
    let read = IssueRepository::find_by_id(tx, gone.id).await.map_err(|e| e.to_string())?.unwrap();
    ensure_eq!(
        (read.state.as_str(), read.resolved_at, read.resolution_seconds, read.revision),
        ("resolved", Some(moment), Some(3_600), 1),
        "state, instant, age in seconds, revision"
    );
    let read = IssueRepository::find_by_id(tx, kept.id).await.map_err(|e| e.to_string())?.unwrap();
    ensure_eq!(read.state, "open", "the other untouched");
    Ok(())
}

async fn the_breach_sweep_pages_and_skips_what_it_signalled(tx: &mut Tx) -> Check {
    let late = |fingerprint: &str, triage: &str| NewIssue {
        severity: "CRITICAL".into(),
        first_seen_at: at(-10_000),
        triage_status: triage.into(),
        ..issue(fingerprint, Some(REPO_A), None)
    };
    let one = insert(tx, late("b-1", "under_review")).await?;
    let two = insert(tx, late("b-2", "confirmed")).await?;
    insert(tx, late("b-3", "not_affected")).await?;
    insert(tx, NewIssue { first_seen_at: at(-50_000), ..late("b-4", "under_review") }).await?;
    insert(tx, NewIssue { severity: "LOW".into(), ..late("b-5", "under_review") }).await?;
    let settled = vec!["not_affected".to_owned(), "fixed".to_owned()];

    let first = IssueRepository::find_unsignalled_breaches(tx, "open", "CRITICAL", at(0), at(-20_000), &settled, 0, 1)
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(ids(&first), vec![one.id], "the first page of one");
    let next =
        IssueRepository::find_unsignalled_breaches(tx, "open", "CRITICAL", at(0), at(-20_000), &settled, one.id, 10)
            .await
            .map_err(|e| e.to_string())?;
    ensure_eq!(ids(&next), vec![two.id], "after the first");
    let unsettled = IssueRepository::find_unsignalled_breaches(tx, "open", "CRITICAL", at(0), at(-20_000), &[], 0, 10)
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(unsettled.len(), 3, "no settled status: the not_affected one too");

    let marked =
        IssueRepository::mark_sla_breach_signalled(tx, &[one.id, two.id], at(5)).await.map_err(|e| e.to_string())?;
    ensure_eq!(marked, 2, "rows marked");
    let after = IssueRepository::find_unsignalled_breaches(tx, "open", "CRITICAL", at(0), at(-20_000), &settled, 0, 10)
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(after.len(), 0, "a signalled breach is not found again");
    let read = IssueRepository::find_by_id(tx, one.id).await.map_err(|e| e.to_string())?.unwrap();
    ensure_eq!(read.sla_breach_signalled_at, Some(at(5)), "the instant written");
    Ok(())
}

async fn an_expired_decision_is_found(tx: &mut Tx) -> Check {
    let expired =
        insert(tx, NewIssue { triage_expires_at: Some(at(10)), ..issue("exp-1", Some(REPO_A), None) }).await?;
    insert(tx, NewIssue { triage_expires_at: Some(at(1_000)), ..issue("exp-2", Some(REPO_A), None) }).await?;
    insert(tx, issue("exp-3", Some(REPO_A), None)).await?;
    let found = IssueRepository::find_with_expired_triage(tx, at(10)).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(&found), vec![expired.id], "expired at or before now");
    Ok(())
}

async fn the_open_counts_group_by_target(tx: &mut Tx) -> Check {
    insert(tx, issue("c-1", Some(REPO_A), None)).await?;
    insert(tx, issue("c-2", Some(REPO_A), Some(IMAGE_A))).await?;
    insert(tx, NewIssue { state: "resolved".into(), ..issue("c-3", Some(REPO_B), None) }).await?;
    insert(tx, issue("c-4", None, Some(IMAGE_A))).await?;
    let mut by_repo = IssueRepository::count_open_by_repository(tx, "open").await.map_err(|e| e.to_string())?;
    by_repo.sort_unstable();
    ensure_eq!(by_repo, vec![(REPO_A, 2)], "open by repository");
    let mut by_image = IssueRepository::count_open_by_container(tx, "open").await.map_err(|e| e.to_string())?;
    by_image.sort_unstable();
    ensure_eq!(by_image, vec![(IMAGE_A, 2)], "open by image, every row naming it");
    ensure_eq!(
        IssueRepository::count_by_state_and_repository(tx, "open", REPO_A).await.map_err(|e| e.to_string())?,
        2,
        "open of one repository"
    );
    Ok(())
}

type SeverityCount = (Option<i64>, Option<i64>, String, i64);

async fn the_counts_by_severity_follow_the_reader_s_targets(tx: &mut Tx) -> Check {
    insert(tx, issue("s-1", Some(REPO_A), None)).await?;
    insert(tx, NewIssue { severity: "LOW".into(), ..issue("s-2", Some(REPO_A), None) }).await?;
    // Built from REPO_A into IMAGE_A: the repository's (`IssueEntity.target()`).
    insert(tx, issue("s-3", Some(REPO_A), Some(IMAGE_A))).await?;
    insert(tx, issue("s-4", None, Some(IMAGE_A))).await?;
    insert(tx, NewIssue { triage_status: "not_affected".into(), ..issue("s-5", None, Some(IMAGE_A)) }).await?;
    let counts = |rows: Vec<SeverityCount>| {
        let mut rows = rows;
        rows.sort();
        rows
    };
    let everything = IssueRepository::count_open_by_target_and_severity(tx, &Visibility::everything())
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(
        counts(everything),
        vec![
            (None, Some(IMAGE_A), "HIGH".to_owned(), 1),
            (Some(REPO_A), None, "HIGH".to_owned(), 1),
            (Some(REPO_A), None, "LOW".to_owned(), 1),
            (Some(REPO_A), Some(IMAGE_A), "HIGH".to_owned(), 1),
        ],
        "everything, settled excluded"
    );
    let image =
        IssueRepository::count_open_by_target_and_severity(tx, &Visibility::only([ScanTarget::Container(IMAGE_A)]))
            .await
            .map_err(|e| e.to_string())?;
    ensure_eq!(
        counts(image),
        vec![(None, Some(IMAGE_A), "HIGH".to_owned(), 1)],
        "an image's grant: not the repository's row"
    );
    let both = IssueRepository::count_open_by_target_and_severity(
        tx,
        &Visibility::only([ScanTarget::Repository(REPO_A), ScanTarget::Container(IMAGE_A)]),
    )
    .await
    .map_err(|e| e.to_string())?;
    ensure_eq!(counts(both).len(), 4, "both granted: each row counted once");
    let none = IssueRepository::count_open_by_target_and_severity(tx, &Visibility::only([]))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(none.len(), 0, "nothing granted");
    Ok(())
}

async fn the_ids_of_a_target_are_found_and_deleted(tx: &mut Tx) -> Check {
    let one = insert(tx, issue("i-1", Some(REPO_B), None)).await?;
    let two = insert(tx, issue("i-2", Some(REPO_B), Some(IMAGE_B))).await?;
    let mut found = IssueRepository::find_ids_by_repo_id(tx, REPO_B).await.map_err(|e| e.to_string())?;
    found.sort_unstable();
    ensure_eq!(found, vec![one.id, two.id], "a repository's ids");
    ensure_eq!(
        IssueRepository::find_ids_by_container_id(tx, IMAGE_B).await.map_err(|e| e.to_string())?,
        vec![two.id],
        "an image's ids"
    );
    // The foreign keys cascade: an orphan cannot be made here, and none is found.
    ensure_eq!(IssueRepository::find_orphaned_ids(tx).await.map_err(|e| e.to_string())?.len(), 0, "no orphan");
    ensure_eq!(IssueRepository::delete_by_ids(tx, &[one.id, -5]).await.map_err(|e| e.to_string())?, 1, "deleted");
    ensure_eq!(
        IssueRepository::find_ids_by_repo_id(tx, REPO_B).await.map_err(|e| e.to_string())?,
        vec![two.id],
        "left"
    );
    Ok(())
}

async fn the_triage_history_is_written_and_read_in_both_orders(tx: &mut Tx) -> Check {
    let one = insert(tx, issue("h-1", Some(REPO_A), None)).await?;
    let two = insert(tx, issue("h-2", Some(REPO_B), None)).await?;
    let event = |issue_id: i64, to: &str, origin: &str, seconds: i64| NewTriageEvent {
        issue_id,
        from_status: "under_review".into(),
        to_status: to.into(),
        justification: None,
        comment: Some("why".into()),
        actor: Some("alice".into()),
        origin: origin.into(),
        occurred_at: at(seconds),
        expires_at: Some(at(seconds + 100)),
        requested_status: None,
        scan_id: None,
        previous_resolved_at: Some(at(1)),
    };
    let events = vec![
        event(one.id, "confirmed", "user", 20),
        event(one.id, "not_affected", "user", 10),
        event(one.id, "under_review", "scan", 30),
        event(two.id, "confirmed", "user", 15),
    ];
    IssueRepository::insert_triage_events(tx, &events).await.map_err(|e| e.to_string())?;

    let ascending = IssueRepository::find_triage_events_by_issue_id(tx, one.id).await.map_err(|e| e.to_string())?;
    let order: Vec<(&str, OffsetDateTime)> = ascending.iter().map(|e| (e.to_status.as_str(), e.occurred_at)).collect();
    ensure_eq!(order, vec![("not_affected", at(10)), ("confirmed", at(20)), ("under_review", at(30))], "oldest first");
    let first = &ascending[0];
    ensure_eq!(
        (first.comment.as_deref(), first.actor.as_deref(), first.expires_at, first.previous_resolved_at, first.scan_id),
        (Some("why"), Some("alice"), Some(at(110)), Some(at(1)), None),
        "the optional columns"
    );
    let across = TriageEventRepository::find_for_issues(tx, &[one.id, two.id]).await.map_err(|e| e.to_string())?;
    let order: Vec<i64> = across.iter().map(|e| e.occurred_at.unix_timestamp() - 1_760_000_000).collect();
    ensure_eq!(order, vec![10, 15, 20, 30], "oldest first, across issues, as Java's findForIssues reads them");
    ensure_eq!(
        TriageEventRepository::count_for_repository(tx, REPO_A, "scan").await.map_err(|e| e.to_string())?,
        2,
        "a repository's decisions, the scan's own excluded"
    );
    ensure_eq!(
        IssueRepository::delete_triage_events_by_issue_ids(tx, &[one.id]).await.map_err(|e| e.to_string())?,
        3,
        "deleted"
    );
    ensure_eq!(
        TriageEventRepository::find_for_issues(tx, &[one.id, two.id]).await.map_err(|e| e.to_string())?.len(),
        1,
        "left"
    );
    Ok(())
}

async fn the_backlog_page_is_most_severe_first_and_filtered(tx: &mut Tx) -> Check {
    let sev = |fingerprint: &str, severity: &str, seconds: i64| NewIssue {
        severity: severity.into(),
        first_seen_at: at(seconds),
        ..issue(fingerprint, Some(REPO_A), None)
    };
    insert(tx, sev("p-low", "LOW", 0)).await?;
    insert(tx, sev("p-crit-old", "CRITICAL", 0)).await?;
    insert(tx, sev("p-crit-new", "critical", 50)).await?;
    insert(tx, sev("p-med", "MEDIUM", 0)).await?;
    insert(tx, sev("p-odd", "UNKNOWN", 0)).await?;
    insert(tx, NewIssue { is_kev: true, ..sev("p-kev", "HIGH", 0) }).await?;
    insert(tx, NewIssue { triage_status: "fixed".into(), ..sev("p-fixed", "HIGH", 0) }).await?;
    insert(
        tx,
        NewIssue {
            identifier: "GHSA-xxxx".into(),
            package_name: Some("Left-Pad".into()),
            is_direct_dependency: Some(true),
            ..sev("p-ghsa", "HIGH", 10)
        },
    )
    .await?;
    insert(tx, NewIssue { state: "resolved".into(), resolved_at: Some(at(5)), ..sev("p-res", "HIGH", 0) }).await?;

    let filters = IssueFilters::new(Visibility::everything());
    let (page, total) = IssueRepository::page_issues(tx, &filters, 4, 0).await.map_err(|e| e.to_string())?;
    ensure_eq!(total, 8, "open total");
    ensure_eq!(fingerprints(&page), vec!["p-crit-new", "p-crit-old", "p-ghsa", "p-fixed"], "the first page");
    let (page, _) = IssueRepository::page_issues(tx, &filters, 10, 6).await.map_err(|e| e.to_string())?;
    ensure_eq!(fingerprints(&page), vec!["p-low", "p-odd"], "the last page");

    let only = |change: &dyn Fn(&mut IssueFilters)| {
        let mut filters = IssueFilters::new(Visibility::everything());
        change(&mut filters);
        filters
    };
    let checks: Vec<(&str, IssueFilters, Vec<&str>)> = vec![
        ("kev", only(&|f| f.only_kev = true), vec!["p-kev"]),
        ("direct", only(&|f| f.only_direct = true), vec!["p-ghsa"]),
        ("search, any case", only(&|f| f.search = Some(" left-pad ".into())), vec!["p-ghsa"]),
        ("identifier, exact", only(&|f| f.identifier = Some("ghsa-XXXX".into())), vec!["p-ghsa"]),
        ("cve only", only(&|f| f.cve_only = true).severity_is("HIGH"), vec!["p-fixed", "p-kev"]),
        ("severity, any case", only(&|f| f.severity = Some("critical".into())), vec!["p-crit-new", "p-crit-old"]),
        ("unsettled", only(&|f| f.exclude_settled = true).severity_is("HIGH"), vec!["p-ghsa", "p-kev"]),
        (
            "overdue",
            only(&|f| f.overdue_before = BTreeMap::from([("CRITICAL".to_owned(), at(10))])),
            vec!["p-crit-old"],
        ),
        (
            "resolved in a window",
            only(&|f| {
                f.state = None;
                f.lifetime =
                    Some(Lifetime { resolved_from: Some(at(0)), resolved_before: Some(at(10)), ..Lifetime::default() });
            }),
            vec!["p-res"],
        ),
        ("another repository", only(&|f| f.repo_id = Some(REPO_B)), vec![]),
    ];
    for (what, filters, expected) in checks {
        let (page, total) = IssueRepository::page_issues(tx, &filters, 50, 0).await.map_err(|e| e.to_string())?;
        let mut found = fingerprints(&page);
        found.sort_unstable();
        ensure_eq!(found, expected, "{what}");
        ensure_eq!(total, i64::try_from(expected.len()).unwrap(), "{what}: the total");
        ensure_eq!(
            IssueRepository::count_issues(tx, &filters).await.map_err(|e| e.to_string())?,
            total,
            "{what}: the count alone"
        );
    }
    Ok(())
}

/// Java's `IssueSpecifications.placedIn`: a type placed by rule, or code analysis declaring the
/// category. Before, the port compared the column alone — a vulnerability (A06, no column) was in no
/// category, and a plugin declaring one was counted where the grid does not count it.
async fn the_owasp_filter_places_as_the_grid_does(tx: &mut Tx) -> Check {
    let typed = |fingerprint: &str, type_: &str, category: Option<&str>| NewIssue {
        type_: type_.into(),
        owasp_category: category.map(str::to_owned),
        ..issue(fingerprint, Some(REPO_A), None)
    };
    insert(tx, typed("o-vuln", "vulnerability", None)).await?;
    insert(tx, typed("o-eol", "eol", None)).await?;
    insert(tx, typed("o-iac", "iac", None)).await?;
    insert(tx, typed("o-secret", "secret", None)).await?;
    insert(tx, typed("o-sast-a03", "sast", Some("A03"))).await?;
    insert(tx, typed("o-sast-a06", "sast", Some("A06"))).await?;
    insert(tx, typed("o-sast-none", "sast", None)).await?;
    insert(tx, typed("o-sast-odd", "sast", Some("A11"))).await?;
    insert(tx, typed("o-plugin-a03", "plugin", Some("A03"))).await?;
    insert(tx, typed("o-licence", "license", None)).await?;

    let placed = |placement: OwaspPlacement| IssueFilters {
        owasp_placement: Some(placement),
        ..IssueFilters::new(Visibility::everything())
    };
    let checks: Vec<(&str, IssueFilters, Vec<&str>)> = vec![
        (
            "A06: both types and code analysis declaring it",
            placed(OwaspPlacement::In("A06".into())),
            vec!["o-eol", "o-sast-a06", "o-vuln"],
        ),
        ("A03: code analysis only, not a plugin", placed(OwaspPlacement::In("A03".into())), vec!["o-sast-a03"]),
        ("A05", placed(OwaspPlacement::In("A05".into())), vec!["o-iac"]),
        ("A01: nothing reaches it", placed(OwaspPlacement::In("A01".into())), vec![]),
        (
            "anywhere",
            placed(OwaspPlacement::Anywhere),
            vec!["o-eol", "o-iac", "o-sast-a03", "o-sast-a06", "o-secret", "o-vuln"],
        ),
    ];
    for (what, filters, expected) in checks {
        let (page, total) = IssueRepository::page_issues(tx, &filters, 50, 0).await.map_err(|e| e.to_string())?;
        let mut found = fingerprints(&page);
        found.sort_unstable();
        ensure_eq!(found, expected, "{what}");
        ensure_eq!(total, i64::try_from(expected.len()).unwrap(), "{what}: the total");
    }
    Ok(())
}

/// Java's `IssueSpecifications.openAt`, `resolvedWithin` and `reopenedWithin`: half open at both ends, and an earlier
/// resolution a reopening recorded (V68) is a time the issue was not open. The port compared `first_seen <= at` and
/// `resolved > at`, and read the issue alone.
async fn the_dates_are_half_open_and_read_the_reopenings(tx: &mut Tx) -> Check {
    // Seen at 0, resolved at 10, back at 20 — open again, its latest resolution cleared.
    let back = insert(tx, NewIssue { first_seen_at: at(0), ..issue("d-back", Some(REPO_A), None) }).await?;
    IssueRepository::insert_triage_events(
        tx,
        &[NewTriageEvent {
            issue_id: back.id,
            from_status: "untriaged".into(),
            to_status: "untriaged".into(),
            justification: None,
            comment: None,
            actor: None,
            origin: "reopen".into(),
            occurred_at: at(20),
            expires_at: None,
            requested_status: None,
            scan_id: None,
            previous_resolved_at: Some(at(10)),
        }],
    )
    .await
    .map_err(|e| e.to_string())?;
    // Seen at 0, resolved at 30, never back.
    insert(
        tx,
        NewIssue {
            first_seen_at: at(0),
            state: "resolved".into(),
            resolved_at: Some(at(30)),
            ..issue("d-closed", Some(REPO_A), None)
        },
    )
    .await?;

    let lived = |lifetime: Lifetime| IssueFilters {
        state: None,
        lifetime: Some(lifetime),
        ..IssueFilters::new(Visibility::everything())
    };
    let open_at = |seconds: i64| lived(Lifetime { open_at: Some(at(seconds)), ..Lifetime::default() });
    let checks: Vec<(&str, IssueFilters, Vec<&str>)> = vec![
        ("open at its first sighting: not yet", open_at(0), vec![]),
        ("open after it", open_at(5), vec!["d-back", "d-closed"]),
        ("open until the instant it was resolved", open_at(10), vec!["d-back", "d-closed"]),
        ("inside the earlier resolution, just after", open_at(11), vec!["d-closed"]),
        ("inside the earlier resolution", open_at(15), vec!["d-closed"]),
        ("at its reopening, not yet back", open_at(20), vec!["d-closed"]),
        ("back after it", open_at(21), vec!["d-back", "d-closed"]),
        ("open at the instant it resolves", open_at(30), vec!["d-back", "d-closed"]),
        ("after it resolved", open_at(31), vec!["d-back"]),
        (
            "resolved: an earlier resolution counts",
            lived(Lifetime { resolved_from: Some(at(10)), resolved_before: Some(at(11)), ..Lifetime::default() }),
            vec!["d-back"],
        ),
        (
            "resolved: the latest one, the end excluded",
            lived(Lifetime { resolved_from: Some(at(11)), resolved_before: Some(at(30)), ..Lifetime::default() }),
            vec![],
        ),
        (
            "reopened",
            lived(Lifetime { reopened_from: Some(at(20)), reopened_before: Some(at(21)), ..Lifetime::default() }),
            vec!["d-back"],
        ),
        (
            "reopened, the end excluded",
            lived(Lifetime { reopened_from: Some(at(0)), reopened_before: Some(at(20)), ..Lifetime::default() }),
            vec![],
        ),
    ];
    for (what, filters, expected) in checks {
        let (page, total) = IssueRepository::page_issues(tx, &filters, 50, 0).await.map_err(|e| e.to_string())?;
        let mut found = fingerprints(&page);
        found.sort_unstable();
        ensure_eq!(found, expected, "{what}");
        ensure_eq!(total, i64::try_from(expected.len()).unwrap(), "{what}: the total");
    }
    Ok(())
}

/// The reads the compliance module adds: the weekly flows over the backlog's own date clauses, thirteen weeks per
/// statement; the code findings by declared category; the estate's open groups, settled triage left out; the rows the
/// MTTR and the OWASP report's links are drawn from; and when V68 was applied.
async fn the_reads_compliance_adds(tx: &mut Tx) -> Check {
    use crate::persistence::aggregates::{IssueAggregates, TargetBreakdown, WeeklyFlow};
    let err = |e: crate::persistence::StoreError| e.to_string();
    const WEEK: i64 = 7 * 24 * 3600;
    let kind = |fingerprint: &str, type_: &str, seen: i64| NewIssue {
        type_: type_.into(),
        first_seen_at: at(seen),
        ..issue(fingerprint, Some(REPO_A), None)
    };

    // Seen in week 0, still open.
    let still = insert(tx, kind("w-a", "vulnerability", 100)).await?;
    // Seen in week 0, resolved in week 1.
    insert(
        tx,
        NewIssue {
            owasp_category: Some("A03".into()),
            state: "resolved".into(),
            resolved_at: Some(at(WEEK + 100)),
            ..kind("w-b", "sast", 100)
        },
    )
    .await?;
    // Seen at the very instant week 0 ends: week 1's, not week 0's.
    insert(tx, kind("w-e", "vulnerability", WEEK)).await?;
    // Resolved before the first week starts: no week reads it.
    insert(tx, NewIssue { state: "resolved".into(), resolved_at: Some(at(-5)), ..kind("w-c", "vulnerability", -10) })
        .await?;
    // Seen in week 0, resolved in it, back in week 1.
    let back = insert(tx, kind("w-d", "secret", 100)).await?;
    IssueRepository::insert_triage_events(
        tx,
        &[NewTriageEvent {
            issue_id: back.id,
            from_status: "untriaged".into(),
            to_status: "untriaged".into(),
            justification: None,
            comment: None,
            actor: None,
            origin: "reopen".into(),
            occurred_at: at(WEEK + 200),
            expires_at: None,
            requested_status: None,
            scan_id: None,
            previous_resolved_at: Some(at(200)),
        }],
    )
    .await
    .map_err(err)?;

    let every = IssueFilters { state: None, ..IssueFilters::new(Visibility::everything()) };
    // Fifteen weeks, one repeated: two statements, the second holding weeks 13 and 14.
    let mut weeks: Vec<OffsetDateTime> = (0..15).map(|week| at(week * WEEK)).collect();
    weeks.push(at(0));
    let mut flows = IssueAggregates::weekly_flows(tx, &every, &weeks).await.map_err(err)?;
    flows.sort_by(|a, b| (a.week_start, &a.type_).cmp(&(b.week_start, &b.type_)));
    let flow = |week: i64, type_: &str, category: Option<&str>, figures: [i64; 4]| WeeklyFlow {
        week_start: at(week * WEEK),
        type_: type_.into(),
        owasp_category: category.map(str::to_owned),
        open_at_end: figures[0],
        opened: figures[1],
        resolved: figures[2],
        reopened: figures[3],
    };
    let mut expected = vec![
        flow(0, "sast", Some("A03"), [1, 1, 0, 0]),
        flow(0, "secret", None, [0, 1, 1, 0]),
        flow(0, "vulnerability", None, [1, 1, 0, 0]),
        flow(1, "sast", Some("A03"), [0, 0, 1, 0]),
        flow(1, "secret", None, [1, 0, 0, 1]),
        flow(1, "vulnerability", None, [2, 1, 0, 0]),
    ];
    for week in 2..15 {
        expected.push(flow(week, "secret", None, [1, 0, 0, 0]));
        expected.push(flow(week, "vulnerability", None, [2, 0, 0, 0]));
    }
    ensure_eq!(flows, expected, "the weekly flows");
    ensure_eq!(IssueAggregates::weekly_flows(tx, &every, &[]).await.map_err(err)?, vec![], "no week");

    // Code findings by declared category: open, code analysis only, a category declared.
    insert(tx, NewIssue { owasp_category: Some("A03".into()), ..kind("s-1", "sast", 0) }).await?;
    insert(tx, NewIssue { owasp_category: Some("A03".into()), ..kind("s-2", "sast", 0) }).await?;
    insert(tx, kind("s-3", "sast", 0)).await?;
    insert(tx, NewIssue { owasp_category: Some("A03".into()), ..kind("s-4", "plugin", 0) }).await?;
    insert(
        tx,
        NewIssue { owasp_category: Some("A10".into()), triage_status: "fixed".into(), ..kind("s-5", "sast", 0) },
    )
    .await?;
    insert(tx, NewIssue { is_kev: true, ..kind("k-1", "vulnerability", 0) }).await?;
    let open = IssueFilters::new(Visibility::everything());
    let by_category = IssueAggregates::count_open_sast_by_owasp_category(tx, &open).await.map_err(err)?;
    let mut by_category: Vec<(String, i64)> = by_category.into_iter().map(|row| (row.owasp_category, row.c)).collect();
    by_category.sort();
    ensure_eq!(by_category, vec![("A03".to_owned(), 2), ("A10".to_owned(), 1)], "code findings by category");

    // The estate's open groups, settled triage left out — `s-5` is fixed.
    let mut groups =
        IssueAggregates::count_open_grouped_by_target(tx, "open", &["not_affected", "fixed", "will_not_fix"])
            .await
            .map_err(err)?;
    groups.sort_by(|a, b| (&a.type_, a.is_kev).cmp(&(&b.type_, b.is_kev)));
    let group = |type_: &str, is_kev: bool, c: i64| TargetBreakdown {
        repo_id: Some(REPO_A),
        container_id: None,
        severity: Some("HIGH".into()),
        type_: type_.into(),
        is_kev,
        c,
    };
    ensure_eq!(
        groups,
        vec![
            group("plugin", false, 1),
            group("sast", false, 3),
            group("secret", false, 1),
            group("vulnerability", false, 2),
            group("vulnerability", true, 1),
        ],
        "the open groups"
    );

    let resolved = IssueFilters { state: Some("resolved".into()), ..IssueFilters::new(Visibility::everything()) };
    let mut resolutions = IssueAggregates::resolutions(tx, &resolved).await.map_err(err)?;
    resolutions.sort_by_key(|row| row.first_seen_at);
    ensure_eq!(
        resolutions.into_iter().map(|row| (row.first_seen_at, row.resolved_at)).collect::<Vec<_>>(),
        vec![(at(-10), Some(at(-5))), (at(100), Some(at(WEEK + 100)))],
        "the resolutions"
    );
    let identified = IssueAggregates::identified(
        tx,
        &IssueFilters { identifier: Some("CVE-2026-w-a".into()), ..IssueFilters::new(Visibility::everything()) },
    )
    .await
    .map_err(err)?;
    ensure_eq!(
        identified.into_iter().map(|row| (row.id, row.identifier)).collect::<Vec<_>>(),
        vec![(still.id, Some("CVE-2026-w-a".to_owned()))],
        "the identified rows"
    );

    let installed = crate::persistence::checked::reopening_migration_installed_on(tx).await.map_err(err)?;
    ensure_eq!(installed.len(), 1, "V68 applied once");
    Ok(())
}

trait SeverityIs {
    fn severity_is(self, severity: &str) -> Self;
}

impl SeverityIs for IssueFilters {
    fn severity_is(mut self, severity: &str) -> Self {
        self.severity = Some(severity.to_owned());
        self
    }
}

async fn the_backlog_shows_a_reader_only_what_it_was_granted(tx: &mut Tx) -> Check {
    insert(tx, issue("v-repo", Some(REPO_A), None)).await?;
    insert(tx, issue("v-built", Some(REPO_A), Some(IMAGE_A))).await?;
    insert(tx, issue("v-image", None, Some(IMAGE_A))).await?;
    insert(tx, issue("v-other", Some(REPO_B), None)).await?;
    let cases: Vec<(&str, Visibility, Vec<&str>)> = vec![
        ("a repository", Visibility::only([ScanTarget::Repository(REPO_A)]), vec!["v-built", "v-repo"]),
        // `IssueSpecifications.visible`: a row naming both is its repository's.
        ("an image", Visibility::only([ScanTarget::Container(IMAGE_A)]), vec!["v-image"]),
        ("nothing", Visibility::only([]), vec![]),
    ];
    for (what, visibility, expected) in cases {
        let filters = IssueFilters::new(visibility.clone());
        let (page, total) = IssueRepository::page_issues(tx, &filters, 50, 0).await.map_err(|e| e.to_string())?;
        let mut found = fingerprints(&page);
        found.sort_unstable();
        ensure_eq!(found, expected, "granted {what}");
        ensure_eq!(total, i64::try_from(expected.len()).unwrap(), "granted {what}: the total");
        let within = IssueFilters::new(Visibility::everything()).within(match &visibility {
            Visibility::Only(targets) => targets.iter().copied().collect::<Vec<_>>(),
            Visibility::Everything => unreachable!(),
        });
        let (page, _) = IssueRepository::page_issues(tx, &within, 50, 0).await.map_err(|e| e.to_string())?;
        let mut found = fingerprints(&page);
        found.sort_unstable();
        ensure_eq!(found, expected, "a project holding {what}");
    }
    Ok(())
}

async fn the_exceptions_register_pages_by_cursor_and_visibility(tx: &mut Tx) -> Check {
    let accepted = |fingerprint: &str, status: &str, seconds: i64, repo, container| NewIssue {
        triage_status: status.into(),
        triaged_at: Some(at(seconds)),
        ..issue(fingerprint, repo, container)
    };
    let newest = insert(tx, accepted("e-1", "not_affected", 30, Some(REPO_A), None)).await?;
    let tie_low = insert(tx, accepted("e-2", "will_not_fix", 20, Some(REPO_A), None)).await?;
    let tie_high = insert(tx, accepted("e-3", "pending_approval", 20, Some(REPO_A), None)).await?;
    insert(tx, accepted("e-4", "confirmed", 25, Some(REPO_A), None)).await?;
    let built = insert(tx, accepted("e-5", "not_affected", 10, Some(REPO_A), Some(IMAGE_A))).await?;
    let image = insert(tx, accepted("e-6", "not_affected", 5, None, Some(IMAGE_A))).await?;

    let everything = Visibility::everything();
    let first = IssueRepository::register_exceptions(tx, &everything, None, 2).await.map_err(|e| e.to_string())?;
    ensure_eq!(
        first.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![newest.id, tie_high.id],
        "newest first, id breaking the tie"
    );
    let next = IssueRepository::register_exceptions(tx, &everything, Some((at(20), tie_high.id)), 10)
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(next.iter().map(|r| r.id).collect::<Vec<_>>(), vec![tie_low.id, built.id, image.id], "after the cursor");
    let granted =
        IssueRepository::register_exceptions(tx, &Visibility::only([ScanTarget::Container(IMAGE_A)]), None, 10)
            .await
            .map_err(|e| e.to_string())?;
    ensure_eq!(granted.iter().map(|r| r.id).collect::<Vec<_>>(), vec![image.id], "an image's grant");
    Ok(())
}

/// Condition 3 of the spike: the entities the statements are built from, held to the migrated schema as
/// `ddl-auto: validate` holds Java's — and a column renamed in a declaration is caught, not run.
async fn the_entities_agree_with_the_schema(db: &Db) -> Check {
    let tables = crate::persistence::entities::tables()?;
    parity::check_entities(db, &tables).await.map_err(|error| error.to_string())?;
    let mut renamed = tables.clone();
    let severity = renamed[0].columns.iter_mut().find(|column| column.name == "severity").unwrap();
    severity.name = "severity_level";
    match parity::check_entities(db, &renamed).await {
        Err(parity::ParityError::Mismatches { mismatches, .. }) => ensure_eq!(
            mismatches,
            vec![parity::Mismatch::MissingColumn { table: "t_issue", column: "severity_level" }],
            "a renamed column"
        ),
        other => return Err(format!("a renamed column: {other:?}")),
    }
    Ok(())
}

/// Condition 2 of the spike: a compile-checked `query!` and the repository's statements in one transaction —
/// each sees the other's uncommitted write, and a rollback takes both away.
async fn one_transaction_runs_a_checked_query_and_the_repository(db: &Db) -> Check {
    use crate::persistence::checked;
    let mut tx = db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    let written = insert(&mut tx, issue("tx-1", Some(REPO_B), None)).await?;
    let counted = checked::count_by_state_and_repository(&mut tx, "open", REPO_B).await.map_err(|e| e.to_string())?;
    ensure_eq!(counted, 1, "the checked query sees the repository's uncommitted row");
    let event = NewTriageEvent {
        issue_id: written.id,
        from_status: "under_review".into(),
        to_status: "confirmed".into(),
        justification: None,
        comment: None,
        actor: Some("alice".into()),
        origin: "user".into(),
        occurred_at: at(1),
        expires_at: None,
        requested_status: None,
        scan_id: None,
        previous_resolved_at: None,
    };
    checked::insert_triage_event(&mut tx, &event).await.map_err(|e| e.to_string())?;
    let read = IssueRepository::find_triage_events_by_issue_id(&mut tx, written.id).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 1, "the repository sees the checked query's uncommitted write");
    tx.rollback().await.map_err(|e| e.to_string())?;
    let mut tx = db.begin(Mode::ReadOnly).await.map_err(|e| e.to_string())?;
    let after = IssueRepository::find_by_fingerprints(&mut tx, &["tx-1".into()]).await.map_err(|e| e.to_string())?;
    tx.rollback().await.map_err(|e| e.to_string())?;
    ensure_eq!(after.len(), 0, "rolled back together");
    Ok(())
}

/// What the gate weighs: one state, of one target or all, in key order — Java's `findByStateAndRepoId`,
/// `findByStateAndRepoIdIsNullAndContainerId` and `findByState`. A row naming the repository and the image is the
/// repository's: never weighed — nor listed — on the image's gate.
async fn the_gate_weighs_a_state_whole_in_key_order_under_the_dual_target_rule(tx: &mut Tx) -> Check {
    let image = insert(tx, issue("gate-image", None, Some(IMAGE_A))).await?;
    let both = insert(tx, issue("gate-both", Some(REPO_B), Some(IMAGE_A))).await?;
    let repo = insert(tx, issue("gate-repo", Some(REPO_A), None)).await?;
    let image_again = insert(tx, issue("gate-image-2", None, Some(IMAGE_A))).await?;
    let mut resolved = issue("gate-resolved", None, Some(IMAGE_A));
    resolved.state = "resolved".to_owned();
    insert(tx, resolved).await?;

    let read = |rows: Vec<IssueRow>| rows.into_iter().map(|row| row.id).collect::<Vec<_>>();
    let of = IssueRepository::find_by_state(tx, "open", Some(ScanTarget::Container(IMAGE_A)))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(read(of), vec![image.id, image_again.id], "the image's open issues, not the repository's row");
    let of = IssueRepository::find_by_state(tx, "open", Some(ScanTarget::Repository(REPO_B)))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(read(of), vec![both.id], "the row naming both is the repository's");
    let all = IssueRepository::find_by_state(tx, "open", None).await.map_err(|e| e.to_string())?;
    ensure_eq!(read(all), vec![image.id, both.id, repo.id, image_again.id], "every open issue, in key order");
    Ok(())
}

// ---- the SIEM events the backlog raises (task 4.2: the emitters of issues) ----

/// What the backlog raised, in order, and in which transaction's keeping: a stand-in for the SIEM's queue.
#[derive(Default)]
struct Raised(std::sync::Mutex<Vec<vectispire_domain::siem::CefEvent>>);

impl Raised {
    fn taken(&self) -> Vec<vectispire_domain::siem::CefEvent> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

impl vectispire_cp_outbox::SecurityEvents for Raised {
    fn raise<'a>(
        &'a self,
        _: &'a mut Tx,
        event: &'a vectispire_domain::siem::CefEvent,
    ) -> vectispire_cp_http::credentials::BoxFuture<'a, Result<(), vectispire_cp_outbox::RaiseError>> {
        self.0.lock().unwrap().push(event.clone());
        Box::pin(async { Ok(()) })
    }

    fn raise_apart<'a>(
        &'a self,
        _: &'a vectispire_domain::siem::CefEvent,
    ) -> vectispire_cp_http::credentials::BoxFuture<'a, ()> {
        Box::pin(async { panic!("the backlog raises in its own transaction, never apart") })
    }
}

fn secret(rule: &str, severity: &str) -> vectispire_cp_scanning::ingestion::ObservedFinding {
    vectispire_cp_scanning::ingestion::ObservedFinding {
        type_: "secret".into(),
        source: "gitleaks".into(),
        identifier: Some(rule.into()),
        severity: Some(severity.into()),
        file_path: Some("config/prod.env".into()),
        ..Default::default()
    }
}

async fn fold(
    raised: &Raised,
    tx: &mut Tx,
    findings: &[vectispire_cp_scanning::ingestion::ObservedFinding],
) -> Result<(), String> {
    let types = std::collections::BTreeSet::from([vectispire_domain::FindingType::Secret]);
    crate::sync::IssueSyncService::fold(
        raised,
        tx,
        None,
        ScanTarget::Repository(REPO_A),
        findings,
        &types,
        &std::collections::BTreeSet::new(),
        None,
        &BTreeMap::new(),
    )
    .await
    .map(|_| ())
    .map_err(|error| error.to_string())
}

async fn a_scan_raises_a_leak_once_when_it_creates_its_issue(tx: &mut Tx) -> Check {
    use vectispire_domain::siem::SecurityEventType;
    let raised = Raised::default();
    fold(&raised, tx, &[secret("aws-access-token", "high"), secret("generic-api-key", "medium")]).await?;
    let first = raised.taken();
    ensure_eq!(first.len(), 1, "a high secret is a leak, a medium one is not");
    ensure_eq!(first[0].event_type(), SecurityEventType::SecretLeakDetected, "the event");
    let created = IssueRepository::find_open_by_target(tx, "open", &["secret".to_owned()], Some(REPO_A), None)
        .await
        .map_err(|e| e.to_string())?;
    let leak = created.iter().find(|row| row.identifier == "aws-access-token").ok_or("the leak's issue")?;
    let expected = format!("Secret matching rule aws-access-token found in config/prod.env (issue {})", leak.id);
    ensure_eq!(first[0].message(), Some(expected.as_str()), "the issue's number, never its description");
    // Seen again, the issue exists: nothing is announced a second time.
    fold(&raised, tx, &[secret("aws-access-token", "high"), secret("generic-api-key", "medium")]).await?;
    ensure_eq!(raised.taken().len(), 0, "a leak seen again");
    Ok(())
}

async fn a_passed_deadline_is_raised_with_its_mark_and_not_again(db: &Db) -> Check {
    use vectispire_domain::siem::SecurityEventType;
    let now = OffsetDateTime::now_utc();
    let mut tx = db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    let late = insert(
        &mut tx,
        NewIssue {
            severity: "critical".into(),
            first_seen_at: to_microseconds(now - Duration::days(18)),
            ..issue("sla-raised", Some(REPO_B), None)
        },
    )
    .await?;
    tx.commit().await.map_err(|e| e.to_string())?;

    let raised = std::sync::Arc::new(Raised::default());
    let settings = std::sync::Arc::new(vectispire_cp_settings::Settings::new(db.clone()));
    let sla = std::sync::Arc::new(crate::sla::SlaService::new(db.clone(), settings));
    let signals = crate::sla::SlaBreachSignals::new(db.clone(), sla, raised.clone());
    signals.signal_crossings().await.map_err(|e| e.to_string())?;
    let events = raised.taken();
    ensure_eq!(events.len(), 1, "one critical issue past its fifteen days");
    ensure_eq!(events[0].event_type(), SecurityEventType::SlaBreached, "the event");
    let due = to_microseconds(now - Duration::days(18)) + Duration::days(15);
    ensure_eq!(events[0].timestamp().epoch_second, due.unix_timestamp(), "dated when the window closed");
    let message = events[0].message().unwrap_or_default().to_owned();
    if !message.starts_with(&format!("CRITICAL issue {} (CVE-2026-sla-raised) passed its 15-day", late.id)) {
        return Err(format!("the message: {message}"));
    }
    let mut tx = db.begin(Mode::ReadOnly).await.map_err(|e| e.to_string())?;
    let marked = IssueRepository::find_by_id(&mut tx, late.id).await.map_err(|e| e.to_string())?.ok_or("the issue")?;
    tx.rollback().await.map_err(|e| e.to_string())?;
    if marked.sla_breach_signalled_at.is_none() {
        return Err("raised and not marked: the next turn would raise it again".into());
    }
    signals.signal_crossings().await.map_err(|e| e.to_string())?;
    ensure_eq!(raised.taken().len(), 0, "a deadline raised once");
    Ok(())
}

/// The aggregates `cp-posture` reads (`persistence/aggregates.rs`), each statement run and its rows decoded: a column
/// selected under one name and read under another fails here, not as a 500 on a dashboard — the derive's `from_col`,
/// which sea-orm ignores, was found by the replay that way.
async fn the_aggregates_posture_reads_decode_and_count(tx: &mut Tx) -> Check {
    use crate::persistence::aggregates::{Axis, IssueAggregates};

    let mut log4j = issue("agg-1", Some(REPO_A), None);
    log4j.type_ = "vulnerability".to_owned();
    log4j.severity = "critical".to_owned();
    log4j.package_name = Some("log4j".to_owned());
    log4j.package_version = Some("2.14".to_owned());
    log4j.fix_versions = Some("2.17.1, 2.15".to_owned());
    log4j.is_kev = true;
    log4j.epss_score = Some(0.97);
    insert(tx, log4j).await?;
    let mut unnamed = issue("agg-2", Some(REPO_A), None);
    unnamed.type_ = "vulnerability".to_owned();
    unnamed.package_name = Some("  ".to_owned());
    insert(tx, unnamed).await?;
    let mut leak = issue("agg-3", None, Some(IMAGE_A));
    leak.type_ = "secret".to_owned();
    leak.state = "resolved".to_owned();
    leak.resolved_at = Some(at(7_200));
    leak.resolution_seconds = Some(7_200);
    insert(tx, leak).await?;

    let every = IssueFilters { state: None, ..IssueFilters::new(Visibility::Everything) };
    let open = IssueFilters::new(Visibility::Everything);
    let err = |e: crate::persistence::StoreError| e.to_string();

    let mut by_type: Vec<(String, i64)> = IssueAggregates::count_grouped_by_severity_and_type(tx, &open)
        .await
        .map_err(err)?
        .into_iter()
        .map(|row| (row.type_, row.c))
        .collect();
    by_type.sort();
    ensure_eq!(by_type, vec![("vulnerability".to_owned(), 1), ("vulnerability".to_owned(), 1)], "severity and type");

    let packaging = IssueAggregates::count_open_by_type_and_packaging(tx, &open).await.map_err(err)?;
    ensure_eq!(
        packaging.iter().map(|row| (row.type_.as_str(), row.package_named, row.unnamed)).collect::<Vec<_>>(),
        vec![("vulnerability", 1, 1)],
        "packaging"
    );

    let weights = IssueAggregates::weigh_packages(tx, &open).await.map_err(err)?;
    ensure_eq!(
        weights
            .iter()
            .map(|w| (w.package_name.as_str(), w.version.as_deref(), w.distinct_identifiers, w.critical_count))
            .collect::<Vec<_>>(),
        vec![("log4j", Some("2.14"), 1, 1)],
        "package weights"
    );
    let details = IssueAggregates::detail_packages(tx, &open, &["log4j".to_owned()]).await.map_err(err)?;
    ensure_eq!(details.len(), 1, "package details");

    let nodes = IssueAggregates::unsettled_of_repositories(tx, "open", &[REPO_A], &["fixed"]).await.map_err(err)?;
    ensure_eq!(
        nodes.iter().map(|n| (n.type_.as_str(), n.is_kev, n.epss_score)).collect::<Vec<_>>(),
        vec![("vulnerability", true, Some(0.97)), ("vulnerability", false, None)],
        "graph nodes"
    );

    let grading = IssueAggregates::count_for_grading_by_target(tx, &every).await.map_err(err)?;
    ensure_eq!(grading.iter().map(|row| row.c).sum::<i64>(), 3, "grading counts");
    let resolved = IssueAggregates::count_resolved_by_target(tx, &every).await.map_err(err)?;
    ensure_eq!(
        resolved.iter().map(|row| (row.container_id, row.resolved, row.average_seconds)).collect::<Vec<_>>(),
        vec![(Some(IMAGE_A), 1, Some(7_200.0))],
        "resolutions"
    );
    let durations = IssueAggregates::resolved_durations_since(tx, &every, at(0)).await.map_err(err)?;
    ensure_eq!(durations.iter().map(|row| row.resolution_seconds).collect::<Vec<_>>(), vec![7_200], "durations");
    let backlog = IssueAggregates::open_backlog_by_severity(tx, &every).await.map_err(err)?;
    ensure_eq!(backlog.iter().map(|row| row.total).sum::<i64>(), 2, "open backlog");
    ensure_eq!(backlog[0].oldest_first_seen, Some(at(0)), "oldest");
    ensure_eq!(IssueAggregates::observations(tx, &every).await.map_err(err)?.len(), 3, "observations");
    ensure_eq!(IssueAggregates::count_distinct(tx, &every, Axis::Rule).await.map_err(err)?, 3, "distinct rules");
    let top = IssueAggregates::count_grouped_repository(tx, &every, 8).await.map_err(err)?;
    ensure_eq!(top, vec![(REPO_A, 2)], "top repositories");
    Ok(())
}

/// Java's `IssueCatalog.countUnsettledOfTypeWithin` and `countUnsettledOfToolWithin`: per repository, severity and
/// state; the three settled statuses left out, a status this version does not know counted, the resolved counted, an
/// image's issues and another type's or tool's never — read through `IssueCatalog`, on committed rows.
async fn the_unsettled_counts_leave_settled_triage_out(db: &Db) -> Check {
    let mut tx = db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    let rows = [
        ("u1", Some(REPO_A), None, "sast", None, "HIGH", "open", "under_review"),
        ("u2", Some(REPO_A), None, "sast", None, "HIGH", "open", "affected"),
        ("u3", Some(REPO_A), None, "sast", None, "HIGH", "open", "not_affected"),
        ("u4", Some(REPO_A), None, "sast", None, "HIGH", "resolved", "pending_approval"),
        ("u5", Some(REPO_A), None, "sast", None, "LOW", "open", "will_not_fix"),
        ("u6", Some(REPO_A), None, "sast", None, "LOW", "open", "fixed"),
        ("u7", Some(REPO_A), None, "sast", None, "LOW", "open", "a_later_status"),
        ("u8", Some(REPO_B), None, "sast", None, "CRITICAL", "open", "under_review"),
        ("u9", None, Some(IMAGE_A), "sast", None, "HIGH", "open", "under_review"),
        ("u10", Some(REPO_A), None, "iac", None, "HIGH", "open", "under_review"),
        ("t1", Some(REPO_A), None, "plugin", Some("plugin:java"), "MEDIUM", "open", "under_review"),
        ("t2", Some(REPO_A), None, "plugin", Some("plugin:java-arch"), "MEDIUM", "open", "under_review"),
        ("t3", Some(REPO_B), None, "plugin", Some("plugin:java"), "MEDIUM", "open", "fixed"),
    ];
    for (fingerprint, repo, image, kind, tool, severity, state, triage) in rows {
        let new = NewIssue {
            type_: kind.to_owned(),
            tool: tool.map(str::to_owned),
            severity: severity.to_owned(),
            state: state.to_owned(),
            triage_status: triage.to_owned(),
            ..issue(&format!("scope-{fingerprint}"), repo, image)
        };
        insert(&mut tx, new).await?;
    }
    tx.commit().await.map_err(|e| e.to_string())?;

    let catalog = crate::IssueCatalog::new(db.clone());
    let sorted = |mut counts: Vec<crate::catalog::ScopeCount>| {
        counts.sort_by(|left, right| {
            (left.repository_id, &left.severity, &left.state).cmp(&(right.repository_id, &right.severity, &right.state))
        });
        counts
            .into_iter()
            .map(|count| (count.repository_id, count.severity.unwrap_or_default(), count.state, count.count))
            .collect::<Vec<_>>()
    };
    let owned = |repository: i64, severity: &str, state: &str, count: i64| {
        (repository, severity.to_owned(), state.to_owned(), count)
    };
    let read = catalog
        .count_unsettled_of_type_within("sast", &[REPO_A, REPO_B, REPO_A, IMAGE_A])
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(
        sorted(read),
        vec![
            owned(REPO_A, "HIGH", "open", 2),
            owned(REPO_A, "HIGH", "resolved", 1),
            owned(REPO_A, "LOW", "open", 1),
            owned(REPO_B, "CRITICAL", "open", 1),
        ],
        "a type's issues per repository, severity and state, settled triage left out and an unknown status counted"
    );
    // Past one batch, a repository named at both ends is still counted once: the list is made distinct first.
    let wide: Vec<i64> = std::iter::once(REPO_B).chain(1_000_000..1_001_000).chain(std::iter::once(REPO_B)).collect();
    let read = catalog.count_unsettled_of_type_within("sast", &wide).await.map_err(|e| e.to_string())?;
    ensure_eq!(sorted(read), vec![owned(REPO_B, "CRITICAL", "open", 1)], "a repository in two batches, counted once");
    let read = catalog.count_unsettled_of_type_within("sast", &[]).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 0, "no repository, nothing counted");
    let read =
        catalog.count_unsettled_of_tool_within("plugin:java", &[REPO_A, REPO_B]).await.map_err(|e| e.to_string())?;
    ensure_eq!(
        sorted(read),
        vec![owned(REPO_A, "MEDIUM", "open", 1)],
        "one tool's issues, never another's whose key it prefixes, its settled ones left out"
    );
    Ok(())
}
