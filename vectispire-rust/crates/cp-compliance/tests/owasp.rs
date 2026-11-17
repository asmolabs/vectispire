//! The OWASP grid's services on a real server — Java's `OwaspWeeklyCoverageDatabaseTest` (`theSixHourGate`,
//! `capturesEveryTarget`, `aNeverScannedTarget`), `OwaspCoverageCsvRoutesTest.tenRowsInOrder`, the declaration beside
//! its category, `OwaspWeeklyCoverageRoutesTest.theWindow` / `refusals`, and `ComplianceCaptureTest`'s month rewritten
//! in place and an unmeasured framework's row removed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::{Arc, Mutex};

use time::{Duration, OffsetDateTime};
use vectispire_cp_access::Allowance;
use vectispire_cp_compliance::decisions::{Applicability, EvidenceSource, Implementation};
use vectispire_cp_compliance::declarations::Submission;
use vectispire_cp_compliance::error::ComplianceError;
use vectispire_cp_compliance::weekly::Request;
use vectispire_cp_compliance::weekly_capture::Outcome;
use vectispire_cp_db::Engine;
use vectispire_cp_db::testing::TestDatabase;
use vectispire_domain::owasp_coverage::{Gap, ReasonCode};

/// A clock the test moves.
#[derive(Debug)]
struct Moving(Mutex<OffsetDateTime>);

impl vectispire_cp_targets::Clock for Moving {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

impl Moving {
    fn set(&self, at: OffsetDateTime) {
        *self.0.lock().unwrap() = at;
    }
}

/// A Wednesday at noon UTC, microseconds as the column keeps them.
fn wednesday() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_795_262_400).unwrap() + Duration::microseconds(250_000)
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
        let clock = Arc::new(Moving(Mutex::new(wednesday())));
        let services = support::services_on(db, clock.clone());
        for id in [101, 102] {
            server.sql_as_admin(&format!(
                "insert into t_repository (id, url, branch) values ({id}, 'https://forge.example/r{id}.git', 'main')"
            ));
        }
        server.sql_as_admin("insert into t_container (id, image_name, tag) values (201, 'registry.example/i', 'v1')");

        weekly_record(&server, &services, &clock).await;
        grid(&services).await;
        window(&services, &clock).await;
        month(&server, &services, &clock).await;
    });
}

async fn weekly_record(server: &TestDatabase, services: &vectispire_cp_compliance::Services, clock: &Moving) {
    let capture = &services.weekly_capture;
    assert_eq!(capture.capture().await, Outcome::Captured);
    // Every target, never scanned ones included, ten categories each.
    assert_eq!(server.sql_as_admin("select count(*) from t_owasp_weekly_coverage"), "30");
    assert_eq!(
        server.sql_as_admin(
            "select target_kind, count(*) from t_owasp_weekly_coverage group by target_kind order by target_kind"
        ),
        "container\t10\nrepository\t20"
    );
    assert_eq!(
        server
            .sql_as_admin("select distinct date_format(week_start, '%Y-%m-%d %H:%i:%s') from t_owasp_weekly_coverage"),
        "2026-11-23 00:00:00".replace("2026-11-23", &monday_text(wednesday()))
    );

    // The six-hour gate, both sides of it, the boundary included.
    clock.set(wednesday() + Duration::hours(6) - Duration::microseconds(1));
    assert_eq!(capture.capture().await, Outcome::NotDue);
    clock.set(wednesday() + Duration::hours(6));
    assert_eq!(capture.capture().await, Outcome::Captured);
    assert_eq!(server.sql_as_admin("select count(*) from t_owasp_weekly_coverage"), "30", "the week rewritten whole");
    assert_eq!(server.sql_as_admin("select count(distinct captured_at) from t_owasp_weekly_coverage"), "1");
    clock.set(wednesday());
}

fn monday_text(at: OffsetDateTime) -> String {
    let date = at.date();
    let monday = date - Duration::days(i64::from(date.weekday().number_days_from_monday()));
    format!("{:04}-{:02}-{:02}", monday.year(), u8::from(monday.month()), monday.day())
}

async fn grid(services: &vectispire_cp_compliance::Services) {
    let everything = Allowance::everything();
    let declared = Submission {
        applicability: Some(Applicability::Applicable),
        justification: None,
        implementation: Some(Implementation::Implemented),
        evidence_source: Some(EvidenceSource::External),
        external_evidence: Some("design review register".to_owned()),
        owner: Some("ciso".to_owned()),
        review_due_at: None,
    };
    services.soa.declare_key("OWASP_2021", "A04", declared, Some("unknown")).await.unwrap();

    let grid = services.grid.grid(None, None, &everything).await.unwrap();
    let ids: Vec<&str> = grid.lines.iter().map(|line| line.id).collect();
    assert_eq!(ids, ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]);
    let a04 = grid.lines.iter().find(|line| line.id == "A04").unwrap();
    assert_eq!(a04.declaration.as_ref().map(|d| d.decided_by.clone()), Some(Some("unknown".to_owned())));
    assert!(grid.lines.iter().filter(|line| line.id != "A04").all(|line| line.declaration.is_none()));
    assert!(grid.scope.is_none());
    // Three targets, never scanned: not "nothing scanned" — three targets not examined, said by name.
    assert!(grid.lines.iter().all(|line| line.reason.code != ReasonCode::NothingScanned), "{:?}", grid.lines);
    assert!(
        grid.lines.iter().any(|line| line
            .reason
            .gaps
            .iter()
            .any(|gap| gap.gap == Gap::NeverScanned && gap.targets > 0)),
        "{:?}",
        grid.lines
    );
    assert_eq!(grid.unplaced_code, 0);

    let csv = services.grid.csv(None, None, &everything, None).await.unwrap();
    let rows: Vec<&str> = csv.split("\r\n").collect();
    assert_eq!(rows.len(), 12, "a header, ten rows, and the empty text after the last CRLF");
    assert!(rows.first().unwrap().starts_with("category,title,state,findings,reason_code,reason,"));
    assert_eq!(rows.last(), Some(&""));
    let a04_row = rows.get(4).unwrap();
    assert!(a04_row.starts_with("\"A04\",\"Insecure Design\","), "{a04_row}");
    assert!(a04_row.contains("\"APPLICABLE\",\"\",\"IMPLEMENTED\",\"EXTERNAL\",\"design review register\",\"ciso\""));
    assert!(a04_row.ends_with("\"estate\",\"\",\"\",\"\""), "{a04_row}");
    let french = services.grid.csv(None, None, &everything, Some("FR")).await.unwrap();
    assert!(french.contains("Aucun scanner") || french.contains("Rien n'a encore été scanné"), "{french}");
    assert_eq!(
        refusal(services.grid.csv(None, None, &everything, Some("de")).await),
        "400 language must be one of en, fr."
    );
    assert_eq!(
        refusal(services.grid.csv(Some(999), None, &everything, Some("de")).await),
        "400 language must be one of en, fr.",
        "the language is read before the scope"
    );
    assert_eq!(
        refusal(services.grid.grid(Some(1), Some(2), &everything).await),
        "400 Name a project or a solution, not both."
    );
    assert_eq!(refusal(services.grid.grid(Some(999), None, &everything).await), "404 Project not found.");
}

async fn window(services: &vectispire_cp_compliance::Services, clock: &Moving) {
    let everything = Allowance::everything();
    let weekly = &services.weekly;
    let ask = |from: Option<&str>, to: Option<&str>| Request {
        from: from.map(str::to_owned),
        to: to.map(str::to_owned),
        project_id: None,
        solution_id: None,
    };

    let default = weekly.weeks(&ask(None, None), &everything).await.unwrap();
    assert_eq!(default.weeks.len(), 12);
    let last = default.weeks.last().unwrap();
    assert!(!last.reconstructed, "the current week was captured");
    assert!(last.categories_measured.is_some() && last.settled.is_some());
    assert!(default.weeks.first().unwrap().reconstructed);
    assert!(default.weeks.first().unwrap().settled.is_none());

    // A `to` past the current week is the current week; a `to` inside a week is its Monday.
    let future = weekly.weeks(&ask(None, Some("2099-01-01")), &everything).await.unwrap();
    assert_eq!(future.weeks.len(), 12);
    assert_eq!(serde_json::to_value(future.to).unwrap(), serde_json::to_value(default.to).unwrap());
    let one = weekly.weeks(&ask(Some("2026-01-07"), Some("2026-01-08")), &everything).await.unwrap();
    assert_eq!(one.weeks.len(), 1);
    assert_eq!(serde_json::to_value(one.from).unwrap(), "2026-01-05");

    assert_eq!(
        refusal(weekly.weeks(&ask(Some("2026-02-02"), Some("2026-01-05")), &everything).await),
        "400 from comes after to."
    );
    assert_eq!(
        refusal(weekly.weeks(&ask(Some("2025-01-06"), Some("2026-01-05")), &everything).await),
        "400 At most 52 weeks per request; this one spans 53."
    );
    assert_eq!(weekly.weeks(&ask(Some("2025-01-13"), Some("2026-01-05")), &everything).await.unwrap().weeks.len(), 52);
    assert_eq!(
        refusal(weekly.weeks(&ask(Some("yesterday"), None), &everything).await),
        "400 from must be an ISO date, YYYY-MM-DD: \"yesterday\"."
    );
    let both = Request { project_id: Some(1), solution_id: Some(2), ..ask(Some("yesterday"), None) };
    assert_eq!(
        refusal(weekly.weeks(&both, &everything).await),
        "400 Name a project or a solution, not both.",
        "both scopes are refused before the window"
    );
    let hidden = Request { solution_id: Some(77), ..ask(None, None) };
    assert_eq!(refusal(weekly.weeks(&hidden, &everything).await), "404 Solution not found.");
    clock.set(wednesday());
}

async fn month(server: &TestDatabase, services: &vectispire_cp_compliance::Services, clock: &Moving) {
    let period = format!("{:04}-{:02}", wednesday().year(), u8::from(wednesday().month()));
    // An earlier pass's row of the running month.
    server.sql_as_admin(&format!(
        "insert into t_compliance_snapshot (id, period, framework, score, status, targets, observed_targets, \
         fresh_targets, freshness_days, captured_at) values ('earlier', '{period}', 'NIS_2', 50, 'PARTIAL', 1, 1, 1, \
         30, '2026-01-01 00:00:00')"
    ));
    // Nothing scanned: nothing measured, nothing charted, and the earlier pass's row goes with the month rewritten.
    assert_eq!(services.history.capture().await, 0);
    assert_eq!(server.sql_as_admin("select count(*) from t_compliance_snapshot"), "0");
    server.sql_as_admin(&format!(
        "insert into t_compliance_snapshot (id, period, framework, score, status, targets, observed_targets, \
         fresh_targets, freshness_days, captured_at) values ('earlier', '{period}', 'NIS_2', 50, 'PARTIAL', 1, 1, 1, \
         30, '2026-01-01 00:00:00')"
    ));

    // Every target scanned yesterday: the estate is observed, and every framework measured.
    let yesterday = wednesday() - Duration::days(1);
    for (scan, column, id) in [(1, "repo_id", 101), (2, "repo_id", 102), (3, "container_id", 201)] {
        server.sql_as_admin(&format!(
            "insert into t_scan (id, branch, status, created_at, {column}) values ({scan}, 'main', 'completed',              from_unixtime({}), {id})",
            yesterday.unix_timestamp()
        ));
    }
    let captured = services.history.capture().await;
    assert_eq!(captured, 6, "one per framework");
    let rows = server.sql_as_admin(&format!(
        "select framework, status from t_compliance_snapshot where period = '{period}' order by framework"
    ));
    assert_eq!(rows.lines().count(), 6, "{rows}");
    assert!(!rows.contains("NO_DATA"), "{rows}");
    assert_eq!(
        server.sql_as_admin(
            "select count(*) from t_compliance_snapshot where id = 'earlier' and freshness_days = 30 \
                             and targets = 3"
        ),
        "1",
        "the month's row rewritten in place, not a second one beside it"
    );

    // Rewritten in place through the month: the same rows, a later capture.
    clock.set(wednesday() + Duration::hours(1));
    assert_eq!(services.history.capture().await, captured);
    assert_eq!(
        server.sql_as_admin(&format!("select count(*) from t_compliance_snapshot where period = '{period}'")),
        captured.to_string()
    );
}
