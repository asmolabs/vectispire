//! The governance services on a real server — Java's `ControlDeclarationTest`, `CertifiedScopeTest` and
//! `ComplianceCaptureTest.readsBackAsAttributedSeries` / `unknownFrameworkIsDropped`: the declaration's refusals and
//! its write, the certified scope's membership and coverage, and the history read back.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use vectispire_cp_audit::RequestActor;
use vectispire_cp_compliance::certified::TargetKind;
use vectispire_cp_compliance::decisions::{Applicability, ComplianceFramework, EvidenceSource, Implementation};
use vectispire_cp_compliance::declarations::Submission;
use vectispire_cp_compliance::error::ComplianceError;
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Engine, ScanTarget, Visibility};
use vectispire_domain::instant::Instant;

#[derive(Debug)]
struct Fixed(OffsetDateTime);

impl vectispire_cp_targets::Clock for Fixed {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_795_000_000).unwrap() + Duration::microseconds(123_456)
}

fn instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}

fn applicable(implementation: Implementation) -> Submission {
    Submission {
        applicability: Some(Applicability::Applicable),
        justification: None,
        implementation: Some(implementation),
        evidence_source: Some(EvidenceSource::Vectispire),
        external_evidence: None,
        owner: Some("ciso".to_owned()),
        review_due_at: None,
    }
}

fn refusal<T: std::fmt::Debug>(result: Result<T, ComplianceError>) -> String {
    match result {
        Err(ComplianceError::Invalid(message)) => format!("400 {message}"),
        Err(ComplianceError::NotFound(message)) => format!("404 {message}"),
        other => panic!("not a refusal: {other:?}"),
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
        declarations(&server, &services).await;
        refusals(&services).await;
        scope(&server, &services).await;
        history(&server, &services).await;
    });
}

async fn declarations(server: &TestDatabase, services: &vectispire_cp_compliance::Services) {
    let soa = &services.soa;
    let due = now() + Duration::days(30);
    let first = soa
        .declare(
            ComplianceFramework::Iso27001,
            "ISO-A.8.8",
            Submission { review_due_at: Some(instant(due)), ..applicable(Implementation::Implemented) },
            Some("alice"),
        )
        .await
        .unwrap();
    assert_eq!(first.decided_by.as_deref(), Some("alice"));
    assert_eq!(first.decided_at, Some(instant(now())));
    assert_eq!(first.reviewed_at, Some(instant(now())));
    assert_eq!(first.implementation, Some(Implementation::Implemented));
    let id = server.sql_as_admin("select id from t_control_declaration where control_id = 'ISO-A.8.8'");

    // Revised in place, and an exclusion clears the implementation it carried; writing the line confirms it again.
    server.sql_as_admin("update t_control_declaration set reviewed_at = '2020-01-01 00:00:00'");
    let excluded = Submission {
        applicability: Some(Applicability::Excluded),
        justification: Some("no such system".to_owned()),
        ..applicable(Implementation::Implemented)
    };
    let second = soa.declare(ComplianceFramework::Iso27001, "ISO-A.8.8", excluded, None).await.unwrap();
    assert_eq!(second.implementation, None);
    assert_eq!(second.decided_by, None);
    assert_eq!(server.sql_as_admin("select id from t_control_declaration where control_id = 'ISO-A.8.8'"), id);
    assert_eq!(server.sql_as_admin("select count(*) from t_control_declaration"), "1");
    assert_eq!(server.sql_as_admin("select reviewed_at > '2025-01-01' from t_control_declaration"), "1");
    assert_eq!(
        server.sql_as_admin("select coalesce(implementation, 'none'), applicability from t_control_declaration"),
        "none\tEXCLUDED"
    );
    let read = soa.declarations("ISO_27001").await.unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read.first().and_then(|line| line.justification.clone()).as_deref(), Some("no such system"));

    // The audit log says who claimed what.
    assert_eq!(
        server.sql_as_admin(
            "select resource_id, description, coalesce(user_id, 'none') from t_audit_log \
             where operation_type = 'CONTROL_DECLARED' order by timestamp, description"
        ),
        "ISO_27001/ISO-A.8.8\tDeclared ISO-A.8.8 of ISO/IEC 27001:2022 applicable, IMPLEMENTED, evidenced \
         VECTISPIRE\talice\nISO_27001/ISO-A.8.8\tExcluded ISO-A.8.8 from ISO/IEC 27001:2022: no such system\tnone"
            .replace("ISO/IEC 27001:2022", ComplianceFramework::Iso27001.title())
    );

    // Lapsed reviews, the most lapsed first; one due this very instant has not lapsed yet.
    let controls: Vec<&str> = ComplianceFramework::Nis2.controls().iter().map(|control| control.id).collect();
    for (control, days_ago) in controls.iter().zip([1i64, 2, 0]) {
        let due = Some(instant(now() - Duration::days(days_ago)));
        let line = Submission { review_due_at: due, ..applicable(Implementation::Planned) };
        soa.declare(ComplianceFramework::Nis2, control, line, Some("alice")).await.unwrap();
    }
    let overdue: Vec<String> = soa.review_overdue().await.unwrap().into_iter().map(|line| line.control_id).collect();
    let expected: Vec<String> = controls.iter().take(2).rev().map(|id| (*id).to_owned()).collect();
    assert_eq!(overdue, expected);

    // The statement reconciles the declaration against the caller's evaluation; every framework, in order.
    let statements = soa.statements(&Visibility::everything()).await.unwrap();
    let order: Vec<ComplianceFramework> = statements.iter().map(|statement| statement.framework).collect();
    assert_eq!(order, ComplianceFramework::ALL.to_vec());
    let iso = soa.statement(ComplianceFramework::Iso27001, &Visibility::everything()).await.unwrap();
    assert_eq!(iso.declared, 1);
    assert_eq!(Some(&iso), statements.get(1));
}

async fn refusals(services: &vectispire_cp_compliance::Services) {
    let soa = &services.soa;
    let iso = ComplianceFramework::Iso27001;
    let declare = |submission: Submission| soa.declare(iso, "ISO-A.8.28", submission, Some("alice"));

    assert_eq!(
        refusal(soa.declare(iso, "A.99", applicable(Implementation::Implemented), None).await),
        format!("404 A.99 is not a control of {}.", iso.title())
    );
    assert_eq!(
        refusal(declare(Submission { applicability: None, ..applicable(Implementation::Implemented) }).await),
        "400 A declaration says two things at minimum: whether the control applies, and where its evidence lives."
    );
    assert_eq!(
        refusal(declare(Submission { evidence_source: None, ..applicable(Implementation::Implemented) }).await),
        "400 A declaration says two things at minimum: whether the control applies, and where its evidence lives."
    );
    assert!(
        refusal(declare(Submission { implementation: None, ..applicable(Implementation::Implemented) }).await)
            .starts_with("400 An applicable control needs an implementation state")
    );
    let bare = Submission {
        applicability: Some(Applicability::Excluded),
        justification: Some(" \t".to_owned()),
        ..applicable(Implementation::Implemented)
    };
    assert_eq!(
        refusal(declare(bare).await),
        "400 An excluded control needs a justification: ISO 27001 clause 6.1.3 d requires one."
    );
    for source in [EvidenceSource::External, EvidenceSource::Both] {
        let unlocated = Submission {
            evidence_source: Some(source),
            external_evidence: Some(" ".to_owned()),
            ..applicable(Implementation::Implemented)
        };
        assert_eq!(
            refusal(declare(unlocated).await),
            "400 Evidence held outside Vectispire must say where: name the document, register or review."
        );
    }
    let located = Submission {
        evidence_source: Some(EvidenceSource::External),
        external_evidence: Some("register R-12".to_owned()),
        ..applicable(Implementation::Implemented)
    };
    declare(located).await.unwrap();

    assert_eq!(
        refusal(soa.declare_key("OWASP_2021", &"A".repeat(65), applicable(Implementation::Planned), None).await),
        "400 The control identifier is longer than 64 characters."
    );
    let long_owner = Submission { owner: Some("o".repeat(256)), ..applicable(Implementation::Implemented) };
    assert_eq!(refusal(declare(long_owner).await), "400 The control owner is longer than 255 characters.");
    let long_justification =
        Submission { justification: Some("j".repeat(16_001)), ..applicable(Implementation::Implemented) };
    assert_eq!(refusal(declare(long_justification).await), "400 The justification is longer than 16000 characters.");
    let long_evidence = Submission {
        evidence_source: Some(EvidenceSource::Both),
        external_evidence: Some("e".repeat(16_001)),
        ..applicable(Implementation::Implemented)
    };
    assert_eq!(refusal(declare(long_evidence).await), "400 The external evidence is longer than 16000 characters.");

    // Ten years either side of today, both ends included.
    let span = Duration::days(3650);
    let micro = Duration::microseconds(1);
    for (due, accepted) in
        [(now() + span, true), (now() - span, true), (now() + span + micro, false), (now() - span - micro, false)]
    {
        let line = Submission { review_due_at: Some(instant(due)), ..applicable(Implementation::Implemented) };
        let outcome = declare(line).await;
        if accepted {
            assert_eq!(outcome.unwrap().review_due_at, Some(instant(due)));
        } else {
            assert_eq!(refusal(outcome), "400 The review date is at most 3650 days from today, either way.");
        }
    }
}

async fn scope(server: &TestDatabase, services: &vectispire_cp_compliance::Services) {
    // The column's own text, UTC to the microsecond: a scan exactly at the cutoff must land exactly there.
    let at = |days: i64| {
        let when = now() - Duration::days(days);
        format!(
            "'{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}'",
            when.year(),
            u8::from(when.month()),
            when.day(),
            when.hour(),
            when.minute(),
            when.second(),
            when.microsecond()
        )
    };
    for id in [101, 102, 103] {
        server.sql_as_admin(&format!(
            "insert into t_repository (id, url, branch) values ({id}, 'https://forge.example/r{id}.git', 'main')"
        ));
    }
    server.sql_as_admin("insert into t_container (id, image_name, tag) values (201, 'registry.example/i', 'v1')");
    // 101 fresh, 102 stale (its latest is its highest id, as Java reads it), 103 scanned exactly at the cutoff: still fresh.
    for (scan, repository, days) in [(1, 101, 1), (2, 102, 50), (3, 102, 40), (4, 103, 30)] {
        server.sql_as_admin(&format!(
            "insert into t_scan (id, branch, status, created_at, repo_id) values ({scan}, 'main', 'failed', {}, \
             {repository})",
            at(days)
        ));
    }
    let actor = RequestActor { username: Some("alice".to_owned()), ip_address: None, user_agent: None };
    let everything = Visibility::everything();
    let certified = &services.certified;

    assert!(certified.view(&everything).await.unwrap().targets.is_empty(), "nothing is in scope by default");
    for (kind, id) in [(TargetKind::Repository, 101), (TargetKind::Repository, 102), (TargetKind::Container, 201)] {
        assert!(certified.set_in_scope(kind, id, &everything, true, &actor).await.unwrap());
    }
    assert!(certified.set_in_scope(TargetKind::Repository, 103, &everything, true, &actor).await.unwrap());
    assert!(!certified.set_in_scope(TargetKind::Repository, 101, &everything, true, &actor).await.unwrap());

    let view = certified.view(&everything).await.unwrap();
    let kinds: Vec<(&str, i64)> = view.targets.iter().map(|target| (target.kind, target.id)).collect();
    assert_eq!(kinds, [("REPOSITORY", 101), ("REPOSITORY", 102), ("REPOSITORY", 103), ("CONTAINER", 201)]);
    let coverage = view.coverage;
    assert_eq!(
        (
            coverage.declared_assets,
            coverage.in_scope,
            coverage.scanned_recently,
            coverage.stale,
            coverage.never_scanned
        ),
        (0, 4, 2, 1, 1)
    );

    // A window of zero falls back to thirty days; the declared count is never negative, never narrowed.
    server.sql_as_admin("insert into t_setting (`key`, value) values ('compliance_freshness_days', '0')");
    server.sql_as_admin("insert into t_setting (`key`, value) values ('isms_scope_assets', '-5')");
    let fallback = certified.view(&everything).await.unwrap().coverage;
    assert_eq!((fallback.declared_assets, fallback.scanned_recently, fallback.stale), (0, 2, 1));
    server.sql_as_admin("update t_setting set value = '45' where `key` = 'compliance_freshness_days'");
    server.sql_as_admin("update t_setting set value = '9' where `key` = 'isms_scope_assets'");
    let wider = certified.view(&everything).await.unwrap().coverage;
    assert_eq!((wider.declared_assets, wider.scanned_recently, wider.stale), (9, 3, 0));

    // A restricted reader sees their slice, and the statement's count whole.
    let slice = Visibility::Only(BTreeSet::from([ScanTarget::Repository(101)]));
    let restricted = certified.view(&slice).await.unwrap();
    assert_eq!(restricted.targets.len(), 1);
    assert_eq!((restricted.coverage.in_scope, restricted.coverage.declared_assets), (1, 9));

    // Hidden and absent read alike.
    for (kind, id, seen) in [
        (TargetKind::Repository, 102, &slice),
        (TargetKind::Repository, 999, &everything),
        (TargetKind::Container, 998, &everything),
    ] {
        assert_eq!(refusal(certified.set_in_scope(kind, id, seen, false, &actor).await), "404 Target not found.");
    }

    assert!(certified.set_in_scope(TargetKind::Repository, 101, &everything, false, &actor).await.unwrap());
    assert_eq!(
        server.sql_as_admin(
            "select resource_id, description, user_id from t_audit_log where operation_type = \
             'CERTIFIED_SCOPE_CHANGED' order by timestamp"
        ),
        "101\tRepository 101 put in the certified scope\talice\n\
         102\tRepository 102 put in the certified scope\talice\n\
         201\tImage 201 put in the certified scope\talice\n\
         103\tRepository 103 put in the certified scope\talice\n\
         101\tRepository 101 taken out of the certified scope\talice"
    );
}

async fn history(server: &TestDatabase, services: &vectispire_cp_compliance::Services) {
    assert!(services.history.history().await.unwrap().is_empty(), "a framework never captured is left out");
    for (id, period, framework, score) in [
        ("a", "2026-10", "ISO_27001", 70),
        ("b", "2026-09", "ISO_27001", 60),
        ("c", "2026-10", "GONE_FRAMEWORK", 10),
        ("d", "2026-10", "NIS_2", 50),
    ] {
        server.sql_as_admin(&format!(
            "insert into t_compliance_snapshot (id, period, framework, score, status, targets, observed_targets, \
             fresh_targets, freshness_days, captured_at) values ('{id}', '{period}', '{framework}', {score}, \
             'PARTIAL', 3, 3, 3, 30, '2026-10-31 12:00:00')"
        ));
    }
    let series = services.history.history().await.unwrap();
    let shape: Vec<(ComplianceFramework, Vec<i32>)> =
        series.iter().map(|one| (one.framework, one.steps.iter().map(|step| step.snapshot.score).collect())).collect();
    assert_eq!(
        shape,
        [(ComplianceFramework::Nis2, vec![50]), (ComplianceFramework::Iso27001, vec![60, 70])],
        "in the enum's order, oldest month first, the unknown framework dropped"
    );
}
