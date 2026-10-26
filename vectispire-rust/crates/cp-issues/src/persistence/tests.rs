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
    IssueFilters, IssueRepository, IssueRow, Lifetime, NewIssue, NewTriageEvent, TriageEventRepository,
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
    run(Engine::MySql);
}

#[test]
fn on_postgresql() {
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
            the_backlog_shows_a_reader_only_what_it_was_granted,
            the_exceptions_register_pages_by_cursor_and_visibility,
        );
        the_entities_agree_with_the_schema(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("the_entities_agree_with_the_schema: {failure}"));
        });
        one_transaction_runs_a_checked_query_and_the_repository(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("one_transaction_runs_a_checked_query_and_the_repository: {failure}"));
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
        source: new.source.clone(),
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
    let descending = TriageEventRepository::find_for_issues(tx, &[one.id, two.id]).await.map_err(|e| e.to_string())?;
    let order: Vec<i64> = descending.iter().map(|e| e.occurred_at.unix_timestamp() - 1_760_000_000).collect();
    ensure_eq!(order, vec![30, 20, 15, 10], "newest first, across issues");
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
