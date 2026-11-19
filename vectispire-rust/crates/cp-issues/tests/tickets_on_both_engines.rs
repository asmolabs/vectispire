//! What `tickets` and `notifications` ask of the issues, on real servers: the ticket catalogue's reads and its
//! conditional writes (Java's `IssueRepository` ticket section, `TicketSweepDatabaseTest`'s cases), the decision to
//! attach a ticket in Java's order of refusals, the scan's delta handed to its sink inside the scan's transaction, and
//! a purge's issues in batches.
//!
//! The claims worth checking are about the statements: that the sweep's read excludes what is dismissed and what
//! already has a ticket and serves the most severe first — a `case` in SQL, which no fake can show — and that a claim's
//! row count names one winner, its own holder refused while it runs.
//!
//! **Docker is required, and its absence fails the test.**
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use time::{Duration, OffsetDateTime};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine, Mode, ScanTarget, Tx, Visibility};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_issues::decision::Caller;
use vectispire_cp_issues::purge::PurgedIssues;
use vectispire_cp_issues::{
    IssueBacklog, IssueCatalog, IssueDecisionService, IssueError, ScanDelta, ScanDeltaSink, TicketReferenceError,
    TicketReferences,
};
use vectispire_cp_scanning::ingestion::{Backlog, Observation, ObservedFinding};
use vectispire_cp_scanning::ports::PortError;
use vectispire_cp_targets::TargetPurge;
use vectispire_cp_targets::deletion::PurgeError;
use vectispire_domain::FindingType;
use vectispire_domain::integrations::Integration;

const REPO_A: i64 = 101;
const REPO_B: i64 = 102;

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

struct World {
    server: TestDatabase,
    db: Db,
}

fn run(engine: Engine) {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = TestDatabase::start(engine).await;
        seed_targets(&server);
        let db = server.connect().await;
        let world = World { server, db };
        let mut failures = Vec::new();
        macro_rules! each {
            ($($check:ident),* $(,)?) => {$(
                // Each check on an empty backlog: the catalogue commits, so the rows are cleared rather than rolled back.
                world.server.sql_as_admin("delete from t_issue");
                if let Err(failure) = $check(&world).await {
                    failures.push(format!("{}: {failure}", stringify!($check)));
                }
            )*};
        }
        each!(
            the_sweep_reads_the_actionable_worst_first_and_leaves_out_the_dismissed,
            a_closed_or_attached_ticket_is_not_the_sweep_s_to_close,
            a_reference_finds_its_issues_with_or_without_its_hash,
            a_sweep_s_reference_never_overwrites_one_attached_meanwhile,
            a_claim_names_one_winner_its_own_holder_included_until_it_lapses,
            a_closed_ticket_is_marked_only_while_the_issue_carries_it,
            attaching_a_ticket_refuses_in_java_s_order,
            attaching_a_ticket_records_its_author_whatever_it_replaces,
            a_scan_s_delta_is_handed_over_in_its_transaction_in_the_findings_order,
            a_sink_that_fails_rolls_the_scan_back,
            a_purge_hands_its_issues_over_in_batches,
        );
        world.db.close().await;
        assert!(failures.is_empty(), "{engine}: {} check(s) failed:\n  {}", failures.len(), failures.join("\n  "));
    });
}

fn seed_targets(server: &TestDatabase) {
    let overriding = overriding(server);
    for id in [REPO_A, REPO_B] {
        server.sql_as_admin(&format!(
            "insert into t_repository (id, url, branch){overriding} values ({id}, 'https://forge.example/r{id}.git', 'main')"
        ));
    }
}

fn overriding(server: &TestDatabase) -> &'static str {
    match server.engine {
        Engine::MySql => "",
        Engine::PostgreSql => " overriding system value",
    }
}

fn instant(server: &TestDatabase) -> &'static str {
    match server.engine {
        Engine::MySql => "'2026-01-01 00:00:00'",
        Engine::PostgreSql => "'2026-01-01 00:00:00+00'",
    }
}

/// One issue written behind the module's back, as the Java test saves an entity: its key.
#[derive(Clone, Copy)]
struct Seed<'a> {
    repo: i64,
    severity: &'a str,
    state: &'a str,
    triage: &'a str,
    ticket_ref: Option<&'a str>,
    attached_by: Option<&'a str>,
}

const OPEN: Seed<'static> = Seed {
    repo: REPO_A,
    severity: "critical",
    state: "open",
    triage: "under_review",
    ticket_ref: None,
    attached_by: None,
};

fn quoted(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), |text| format!("'{text}'"))
}

fn seed(world: &World, fingerprint: &str, issue: Seed<'_>) -> i64 {
    let server = &world.server;
    let at = instant(server);
    let falsity = match server.engine {
        Engine::MySql => "0",
        Engine::PostgreSql => "false",
    };
    server.sql_as_admin(&format!(
        "insert into t_issue (repo_id, fingerprint, type, identifier, severity, state, first_seen_at, last_seen_at, \
         is_kev, times_seen, triage_status, reachability, revision, fix_versions, ticket_ref, ticket_attached_by) \
         values ({}, '{fingerprint}', 'vulnerability', 'CVE-{fingerprint}', '{}', '{}', {at}, {at}, {falsity}, 1, '{}', \
         'UNKNOWN', 0, '3.5.2', {}, {})",
        issue.repo,
        issue.severity,
        issue.state,
        issue.triage,
        quoted(issue.ticket_ref),
        quoted(issue.attached_by),
    ));
    column(world, &format!("select id from t_issue where fingerprint = '{fingerprint}'")).parse().unwrap()
}

/// One value, null read as `-` on both engines.
fn column(world: &World, statement: &str) -> String {
    world.server.sql_as_admin(statement)
}

fn stored(world: &World, id: i64, expression: &str) -> String {
    column(world, &format!("select coalesce({expression}, '-') from t_issue where id = {id}"))
}

fn revision(world: &World, id: i64) -> i64 {
    column(world, &format!("select revision from t_issue where id = {id}")).parse().unwrap()
}

fn ids(views: &[vectispire_cp_issues::IssueView]) -> Vec<i64> {
    views.iter().map(|view| view.id).collect()
}

fn excluded() -> Vec<String> {
    vec!["not_affected".to_owned(), "fixed".to_owned()]
}

// ------------------------------------------------------------------ the catalogue

async fn the_sweep_reads_the_actionable_worst_first_and_leaves_out_the_dismissed(world: &World) -> Check {
    let catalog = IssueCatalog::new(world.db.clone());
    let low = seed(world, "low", Seed { severity: "low", ..OPEN });
    let medium = seed(world, "medium", Seed { severity: "medium", ..OPEN });
    let unknown = seed(world, "unknown", Seed { severity: "whatever", ..OPEN });
    let negligible = seed(world, "negligible", Seed { severity: "negligible", ..OPEN });
    let critical = seed(world, "critical", OPEN);
    let high = seed(world, "high", Seed { severity: "high", triage: "affected", ..OPEN });
    seed(world, "not-affected", Seed { triage: "not_affected", ..OPEN });
    seed(world, "fixed", Seed { triage: "fixed", ..OPEN });
    seed(world, "ticketed", Seed { ticket_ref: Some("#9"), ..OPEN });
    seed(world, "resolved", Seed { state: "resolved", ..OPEN });

    let read = catalog.actionable_without_ticket("open", &excluded(), 20).await.map_err(|e| e.to_string())?;
    ensure_eq!(
        ids(&read),
        vec![critical, high, medium, low, negligible, unknown],
        "most severe first, the dismissed, the ticketed and the resolved left out, `under_review` kept"
    );
    // One ticket allowed: a backlog ordered by key would spend it on the harmless finding inserted first.
    let read = catalog.actionable_without_ticket("open", &excluded(), 1).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(&read), vec![critical], "the ceiling serves what matters");
    let read = catalog.actionable_without_ticket("open", &[], 20).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 8, "nothing excluded, every open issue without a ticket");
    Ok(())
}

async fn a_closed_or_attached_ticket_is_not_the_sweep_s_to_close(world: &World) -> Check {
    let catalog = IssueCatalog::new(world.db.clone());
    let resolved = Seed { state: "resolved", ..OPEN };
    let first = seed(world, "opened-1", Seed { ticket_ref: Some("#1"), ..resolved });
    seed(world, "closed", Seed { ticket_ref: Some("CLOSED:#2"), ..resolved });
    seed(world, "attached", Seed { ticket_ref: Some("#3"), attached_by: Some("alice"), ..resolved });
    seed(world, "still-open", Seed { ticket_ref: Some("#4"), ..OPEN });
    seed(world, "no-ticket", resolved);
    let second = seed(world, "opened-2", Seed { ticket_ref: Some("PROJ-5"), ..resolved });

    let read = catalog.resolved_with_open_ticket(20).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(&read), vec![first, second], "resolved, a ticket Vectispire opened and has not closed");
    let read = catalog.resolved_with_open_ticket(1).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(&read), vec![first], "at most the limit");
    Ok(())
}

async fn a_reference_finds_its_issues_with_or_without_its_hash(world: &World) -> Check {
    let catalog = IssueCatalog::new(world.db.clone());
    let plain = seed(world, "plain", Seed { ticket_ref: Some("12"), ..OPEN });
    let hashed = seed(world, "hashed", Seed { ticket_ref: Some("#12"), ..OPEN });
    let again = seed(world, "again", Seed { ticket_ref: Some("12"), repo: REPO_B, ..OPEN });
    seed(world, "other", Seed { ticket_ref: Some("123"), ..OPEN });

    let read = catalog.with_ticket("12").await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(&read), vec![plain, hashed, again], "as stored or behind its '#', several, oldest first");
    let read = catalog.with_ticket("#12").await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(&read), vec![hashed], "a reference given with its hash is not stripped of it");
    ensure_eq!(catalog.with_ticket("13").await.map_err(|e| e.to_string())?.len(), 0, "an unknown reference");
    Ok(())
}

async fn a_sweep_s_reference_never_overwrites_one_attached_meanwhile(world: &World) -> Check {
    let catalog = IssueCatalog::new(world.db.clone());
    let at = OffsetDateTime::now_utc();
    let id = seed(world, "attach", OPEN);
    ensure_eq!(
        catalog.claim_ticket(id, "instance-a", at, at + Duration::minutes(5)).await.map_err(|e| e.to_string())?,
        true,
        "the claim"
    );
    ensure_eq!(
        catalog.attach_ticket(id, "#1", Some("https://tracker.invalid/1")).await.map_err(|e| e.to_string())?,
        1,
        "attached"
    );
    ensure_eq!(stored(world, id, "ticket_ref"), "#1", "the reference");
    ensure_eq!(stored(world, id, "ticket_url"), "https://tracker.invalid/1", "its URL");
    ensure_eq!(stored(world, id, "ticket_claimed_by"), "-", "attaching clears the claim");
    ensure_eq!(stored(world, id, "ticket_attached_by"), "-", "a sweep's ticket names no person");
    ensure_eq!(revision(world, id), 1, "a revision");

    ensure_eq!(catalog.attach_ticket(id, "#2", None).await.map_err(|e| e.to_string())?, 0, "a second reference");
    ensure_eq!(stored(world, id, "ticket_ref"), "#1", "the first is kept");
    ensure_eq!(revision(world, id), 1, "and nothing moved");
    Ok(())
}

async fn a_claim_names_one_winner_its_own_holder_included_until_it_lapses(world: &World) -> Check {
    let catalog = IssueCatalog::new(world.db.clone());
    let now = OffsetDateTime::now_utc();
    let later = now + Duration::minutes(5);
    let id = seed(world, "claimed", OPEN);
    let claim = async |holder: &str, at: OffsetDateTime, until: OffsetDateTime| {
        catalog.claim_ticket(id, holder, at, until).await.map_err(|e| e.to_string())
    };

    ensure_eq!(claim("another-instance", now, later).await?, true, "the first asker");
    ensure_eq!(claim("this-instance", now, later).await?, false, "another holder, while the claim runs");
    // Two passes in one process are two askers too: the first version let a holder reclaim.
    ensure_eq!(claim("another-instance", now, later).await?, false, "the same holder, while its claim runs");
    ensure_eq!(stored(world, id, "ticket_claimed_by"), "another-instance", "the winner holds it");
    ensure_eq!(revision(world, id), 0, "a claim is no revision: nothing a person edits has changed");

    catalog.release_ticket_claim(id, "this-instance").await.map_err(|e| e.to_string())?;
    ensure_eq!(stored(world, id, "ticket_claimed_by"), "another-instance", "only the holder gives a claim up");
    catalog.release_ticket_claim(id, "another-instance").await.map_err(|e| e.to_string())?;
    ensure_eq!(stored(world, id, "ticket_claimed_by"), "-", "given up");
    ensure_eq!(stored(world, id, "ticket_claim_until"), "-", "and its deadline with it");

    // That instance died between its claim and the reference: once the claim lapses, the issue is taken over.
    ensure_eq!(
        claim("another-instance", now - Duration::seconds(60), now - Duration::seconds(1)).await?,
        true,
        "a claim"
    );
    ensure_eq!(claim("this-instance", now, later).await?, true, "taken over once lapsed");
    ensure_eq!(stored(world, id, "ticket_claimed_by"), "this-instance", "the new holder");

    let ticketed = seed(world, "ticketed", Seed { ticket_ref: Some("#7"), ..OPEN });
    ensure_eq!(
        catalog.claim_ticket(ticketed, "this-instance", now, later).await.map_err(|e| e.to_string())?,
        false,
        "an issue with a reference"
    );
    ensure_eq!(
        catalog.claim_ticket(999_999, "this-instance", now, later).await.map_err(|e| e.to_string())?,
        false,
        "no such issue"
    );
    Ok(())
}

async fn a_closed_ticket_is_marked_only_while_the_issue_carries_it(world: &World) -> Check {
    let catalog = IssueCatalog::new(world.db.clone());
    let id = seed(world, "closing", Seed { state: "resolved", ticket_ref: Some("#1"), ..OPEN });
    ensure_eq!(catalog.mark_ticket_closed(id, "#2").await.map_err(|e| e.to_string())?, 0, "another reference");
    ensure_eq!(stored(world, id, "ticket_ref"), "#1", "a person's replacement is not described by it");
    ensure_eq!(catalog.mark_ticket_closed(id, "#1").await.map_err(|e| e.to_string())?, 1, "its own reference");
    ensure_eq!(stored(world, id, "ticket_ref"), "CLOSED:#1", "marked");
    ensure_eq!(revision(world, id), 1, "a revision");
    ensure_eq!(catalog.mark_ticket_closed(id, "#1").await.map_err(|e| e.to_string())?, 0, "closed once");
    let read = catalog.resolved_with_open_ticket(20).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 0, "a closed ticket is no longer the sweep's");
    Ok(())
}

// ------------------------------------------------------------------ the decision

/// A tracker that refuses `BAD`, is suspended for `OFF`, and records what it was asked.
#[derive(Default)]
struct Tracker(Mutex<Vec<String>>);

impl TicketReferences for Tracker {
    fn refusal<'a>(&'a self, reference: &'a str) -> BoxFuture<'a, Result<Option<String>, TicketReferenceError>> {
        self.0.lock().unwrap().push(reference.to_owned());
        Box::pin(async move {
            match reference {
                "BAD" => Ok(Some("\"BAD\" is not a jira reference in project PROJ.".to_owned())),
                "OFF" => Err(TicketReferenceError::IntegrationDisabled(Integration::by_key("tracker.jira").unwrap())),
                _ => Ok(None),
            }
        })
    }
}

impl Tracker {
    fn asked(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

fn decisions(world: &World, tracker: Arc<Tracker>) -> IssueDecisionService {
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        world.db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let settings = Arc::new(vectispire_cp_settings::Settings::new(world.db.clone()));
    IssueDecisionService::new(world.db.clone(), settings, audit).with_ticket_references(tracker)
}

fn caller(visibility: Visibility) -> Caller {
    Caller {
        username: Some("lead".to_owned()),
        role: Some(vectispire_cp_http::Role::SecurityChampion),
        visibility,
        ip_address: None,
        user_agent: None,
    }
}

fn refusal(result: Result<vectispire_cp_issues::IssueView, IssueError>) -> String {
    match result {
        Ok(view) => format!("accepted {:?}", view.ticket_ref),
        Err(IssueError::NotFound(message)) => format!("404 {message}"),
        Err(IssueError::InvalidInput(message)) => format!("400 {message}"),
        Err(IssueError::IntegrationDisabled(integration)) => format!("409 {}", integration.key()),
        Err(other) => format!("other {other}"),
    }
}

async fn attaching_a_ticket_refuses_in_java_s_order(world: &World) -> Check {
    let tracker = Arc::new(Tracker::default());
    let service = decisions(world, tracker.clone());
    let everything = || caller(Visibility::Everything);
    let id = seed(world, "decided", OPEN);
    let hidden = seed(world, "hidden", Seed { repo: REPO_B, ..OPEN });
    let only_a = || caller(Visibility::Only(BTreeSet::from([ScanTarget::Repository(REPO_A)])));
    let attach = async |id: i64, reference: Option<&str>, url: Option<&str>, caller: Caller| {
        refusal(service.attach_ticket(id, reference.map(str::to_owned), url.map(str::to_owned), caller).await)
    };

    // The visibility first: a hidden or absent issue answers 404 whatever was sent.
    ensure_eq!(attach(hidden, None, None, only_a()).await, "404 Issue not found.", "hidden, no reference");
    ensure_eq!(attach(999_999, Some("#1"), None, everything()).await, "404 Issue not found.", "absent");
    ensure_eq!(attach(id, Some(" \t "), None, everything()).await, "400 A ticket reference is required.", "blank");
    ensure_eq!(attach(id, None, None, everything()).await, "400 A ticket reference is required.", "none");
    // UTF-16 units, as `String.length()` counts: 33 emoji are 66 units, refused; 64 'é' are 128 bytes, accepted.
    let astral = "\u{1F600}".repeat(33);
    ensure_eq!(
        attach(id, Some(&astral), None, everything()).await,
        "400 That reference is longer than 64 characters.",
        "an astral reference"
    );
    ensure_eq!(tracker.asked(), Vec::<String>::new(), "the tracker is asked nothing before the reference is valid");
    // The tracker's sentence before the URL's length: refused for what it is, not for its link.
    let long_url = format!("https://tracker.invalid/{}", "x".repeat(480));
    ensure_eq!(
        attach(id, Some(" BAD "), Some(&long_url), everything()).await,
        "400 \"BAD\" is not a jira reference in project PROJ.",
        "the tracker's refusal"
    );
    ensure_eq!(tracker.asked(), vec!["BAD".to_owned()], "asked with the trimmed reference");
    ensure_eq!(attach(id, Some("OFF"), None, everything()).await, "409 tracker.jira", "a suspended tracker");
    ensure_eq!(
        attach(id, Some("#1"), Some(&long_url), everything()).await,
        "400 That URL is longer than 500 characters.",
        "a URL too long"
    );
    ensure_eq!(stored(world, id, "ticket_ref"), "-", "nothing refused was written");
    ensure_eq!(revision(world, id), 0, "and nothing moved");

    let accented = "\u{e9}".repeat(64);
    ensure_eq!(
        attach(id, Some(&accented), None, everything()).await,
        format!("accepted Some({accented:?})"),
        "64 units, whatever their bytes"
    );
    Ok(())
}

async fn attaching_a_ticket_records_its_author_whatever_it_replaces(world: &World) -> Check {
    let service = decisions(world, Arc::new(Tracker::default()));
    let id = seed(world, "replaced", Seed { ticket_ref: Some("#1"), ..OPEN });
    let view = service
        .attach_ticket(
            id,
            Some(" PROJ-7 ".to_owned()),
            Some("  https://tracker.invalid/7 ".to_owned()),
            caller(Visibility::Everything),
        )
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(view.ticket_ref.as_deref(), Some("PROJ-7"), "the answer reads the stored row");
    ensure_eq!(view.ticket_url.as_deref(), Some("https://tracker.invalid/7"), "the URL, trimmed");
    ensure_eq!(view.ticket_attached_by.as_deref(), Some("lead"), "its author: the sweep will not close it");
    ensure_eq!(revision(world, id), 1, "a revision");
    // A blank URL is none, and replaces the one stored.
    let view = service
        .attach_ticket(id, Some("PROJ-8".to_owned()), Some(" ".to_owned()), caller(Visibility::Everything))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(view.ticket_url, None, "a blank URL");
    ensure_eq!(revision(world, id), 2, "unconditional on the revision read");
    let audited = column(
        world,
        &format!("select description from t_audit_log where resource_id = '{id}' order by timestamp desc limit 1"),
    );
    ensure_eq!(audited, "Ticket reference changed from PROJ-7 to PROJ-8", "the audit entry names both");
    Ok(())
}

// ------------------------------------------------------------------ the scan's delta

#[derive(Default)]
struct Deltas {
    taken: Mutex<Vec<ScanDelta>>,
    fail: bool,
}

impl ScanDeltaSink for Deltas {
    fn enqueue<'a>(&'a self, tx: &'a mut Tx, delta: &'a ScanDelta) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async move {
            // In the scan's transaction: the issues it names are visible there, before any commit.
            let named = vectispire_cp_issues::purge::issues_of(tx, &TargetPurge::Deleted(delta.target))
                .await
                .map_err(|e| Box::new(e) as PortError)?;
            if delta.new_issues.iter().any(|issue| !named.contains(&issue.id)) {
                return Err("a new issue the transaction does not hold".into());
            }
            self.taken.lock().unwrap().push(delta.clone());
            if self.fail { Err("the outbox refused".into()) } else { Ok(()) }
        })
    }
}

fn finding(identifier: &str, severity: &str) -> ObservedFinding {
    ObservedFinding {
        type_: "vulnerability".into(),
        source: "grype".into(),
        identifier: Some(identifier.into()),
        severity: Some(severity.into()),
        package_name: Some(format!("pkg-{identifier}")),
        fix_versions: Some("2.0.0".into()),
        link: Some(format!("https://advisories.invalid/{identifier}")),
        kev: identifier == "CVE-KEV",
        epss_score: Some(0.25),
        ..ObservedFinding::default()
    }
}

fn scan(world: &World, id: i64) {
    let server = &world.server;
    server.sql_as_admin(&format!(
        "insert into t_scan (id, branch, status, created_at, repo_id){} values ({id}, 'main', 'running', {}, {REPO_A})",
        overriding(server),
        instant(server)
    ));
}

fn observation(scan_id: i64, findings: Vec<ObservedFinding>) -> Observation {
    Observation {
        scan_id,
        target: Some(ScanTarget::Repository(REPO_A)),
        findings,
        scanned_types: BTreeSet::from([FindingType::Vulnerability]),
        scanned_tools: BTreeSet::new(),
        descriptions: BTreeMap::new(),
    }
}

async fn reconcile(world: &World, backlog: &IssueBacklog, observation: &Observation) -> Result<(), String> {
    let mut tx = world.db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    match backlog.reconcile(&mut tx, observation).await {
        Ok(_) => tx.commit().await.map_err(|e| e.to_string()),
        Err(failure) => {
            tx.rollback().await.map_err(|e| e.to_string())?;
            Err(failure.to_string())
        }
    }
}

async fn a_scan_s_delta_is_handed_over_in_its_transaction_in_the_findings_order(world: &World) -> Check {
    world.server.sql_as_admin("delete from t_scan");
    for id in [1, 2, 3] {
        scan(world, id);
    }
    let sink = Arc::new(Deltas::default());
    let backlog = IssueBacklog::new(Arc::new(vectispire_cp_outbox::NotExported)).with_deltas(sink.clone());

    // Six issues, one named twice: the delta, and the keys, follow the findings' order — one chance in 720 that the
    // fingerprints' order, which a sorted map would give, agrees with it.
    let first_scan = ["CVE-Z", "CVE-KEV", "CVE-M", "CVE-B", "CVE-Y", "CVE-C", "CVE-Z"];
    let findings =
        first_scan.iter().map(|id| finding(id, if *id == "CVE-KEV" { "critical" } else { "high" })).collect();
    reconcile(world, &backlog, &observation(1, findings)).await?;
    reconcile(world, &backlog, &observation(2, vec![finding("CVE-Z", "high")])).await?;
    reconcile(world, &backlog, &observation(3, vec![finding("CVE-A", "low"), finding("CVE-KEV", "critical")])).await?;

    let taken = std::mem::take(&mut *sink.taken.lock().unwrap());
    let shape = |delta: &ScanDelta| {
        (
            delta.scan_id,
            delta.new_issues.iter().map(|issue| issue.identifier.clone()).collect::<Vec<_>>(),
            delta.reopened_issues.iter().map(|issue| issue.identifier.clone()).collect::<Vec<_>>(),
            delta.resolved,
        )
    };
    let owned = |list: &[&str]| list.iter().map(|text| (*text).to_owned()).collect::<Vec<_>>();
    ensure_eq!(
        taken.iter().map(shape).collect::<Vec<_>>(),
        vec![
            (1, owned(&first_scan[..6]), owned(&[]), 0),
            (2, owned(&[]), owned(&[]), 5),
            (3, owned(&["CVE-A"]), owned(&["CVE-KEV"]), 1),
        ],
        "one delta per scan: the new in the findings' order, the reopened, the resolved count"
    );
    let keys = ids(&taken[0].new_issues);
    if !keys.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(format!("the keys follow the findings' order: {keys:?}"));
    }
    ensure_eq!(taken[0].target, ScanTarget::Repository(REPO_A), "the target");
    let kev = &taken[0].new_issues[1];
    ensure_eq!(
        (kev.severity.as_str(), kev.is_kev, kev.epss_score, kev.package_name.as_deref(), kev.fix_versions.as_deref()),
        ("critical", true, Some(0.25), Some("pkg-CVE-KEV"), Some("2.0.0")),
        "what a notification reads of a new issue"
    );
    ensure_eq!(kev.link.as_deref(), Some("https://advisories.invalid/CVE-KEV"), "its link");
    let reopened = &taken[2].reopened_issues[0];
    ensure_eq!((reopened.state.as_str(), reopened.times_seen), ("open", 2), "a reopened issue as it now stands");
    Ok(())
}

async fn a_sink_that_fails_rolls_the_scan_back(world: &World) -> Check {
    world.server.sql_as_admin("delete from t_scan");
    scan(world, 4);
    let sink = Arc::new(Deltas { fail: true, ..Deltas::default() });
    let backlog = IssueBacklog::new(Arc::new(vectispire_cp_outbox::NotExported)).with_deltas(sink.clone());
    let failed = reconcile(world, &backlog, &observation(4, vec![finding("CVE-LOST", "high")])).await;
    ensure_eq!(failed, Err("the outbox refused".to_owned()), "the sink's failure is the scan's");
    ensure_eq!(sink.taken.lock().unwrap().len(), 1, "it was handed the delta");
    ensure_eq!(column(world, "select count(*) from t_issue"), "0", "and the issues went with the scan");
    Ok(())
}

// ------------------------------------------------------------------ purges

/// How many issues a purge took, and the batches it handed over.
type Handed = (usize, Vec<Vec<i64>>);

async fn a_purge_hands_its_issues_over_in_batches(world: &World) -> Check {
    let mut created = Vec::new();
    for index in 0..3 {
        created.push(seed(world, &format!("purged-{index}"), OPEN));
    }
    seed(world, "kept", Seed { repo: REPO_B, ..OPEN });
    let purge = TargetPurge::Deleted(ScanTarget::Repository(REPO_A));
    let mut tx = world.db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    // As a listener holds it: inside a boxed, `Send` future, each batch run on the deletion's transaction.
    let future: BoxFuture<'_, Result<Handed, PurgeError>> = Box::pin(async {
        let purged = PurgedIssues::of(&mut tx, &purge).await?;
        let mut handed = Vec::new();
        for batch in purged.batches() {
            // A statement on the deletion's transaction per batch, as a deleting listener runs one.
            vectispire_cp_issues::purge::issues_of(&mut tx, &purge).await?;
            handed.push(batch.to_vec());
        }
        Ok((purged.len(), handed))
    });
    let (count, handed) = future.await.map_err(|e| e.to_string())?;
    tx.rollback().await.map_err(|e| e.to_string())?;
    ensure_eq!(count, 3, "how many there were");
    let mut flat: Vec<i64> = handed.concat();
    flat.sort_unstable();
    ensure_eq!(flat, created, "the deleted target's issues, and no other's");
    ensure_eq!(handed.len(), 1, "three issues are one batch");
    Ok(())
}
