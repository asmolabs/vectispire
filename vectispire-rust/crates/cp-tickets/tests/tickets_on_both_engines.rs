//! The tickets on real servers, against a GitLab stand-in on loopback reached through the real outbound door: the
//! sweep opening a ticket for what the gate fails on and closing it once resolved (Java's `TicketSweepServiceTest`,
//! `TicketClosingTest`), a suspended tracker sending nothing (`TrackerSuspensionTest`), the token refused and announced
//! once (`TrackerTokenCheckTest`), the links attached by hand in Java's order of refusals, the webhook's doors
//! (`TicketingWebhookServiceTest`'s cases: no secret, a wrong one, a replay, a suspended tracker, a refusal queued for
//! approval, a settled decision kept), the reference port and the link purge.
//!
//! **Docker is required, and its absence fails the test.**
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use time::OffsetDateTime;
use vectispire_cp_audit::RequestActor;
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine, Mode, Tx, Visibility};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_outbound::{OutboundPost, OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_outbox::{RaiseError, TokenAlertSink};
use vectispire_cp_settings::{Integrations, Setting, Settings};
use vectispire_cp_tickets::webhook::Outcome;
use vectispire_cp_tickets::{TicketError, Tickets, TicketsConfig};
use vectispire_domain::integrations::Integration;
use vectispire_domain::notifications::{Notice, TokenAlert};
use vectispire_domain::secret::Secret;
use vectispire_domain::tickets::{Presented, TicketProvider};

const KEY: &str = "cmVmZXJlbmNlLXNjYW5uaW5nLWtleS0zMi1ieXRlcyE="; // gitleaks:allow — test fixture
const REPO: i64 = 501;

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

/// What the stand-in received, and how it answers the token's description.
#[derive(Default)]
struct Tracker {
    calls: Mutex<Vec<String>>,
    token_status: Mutex<u16>,
}

async fn gitlab(addr_tracker: Arc<Tracker>) -> String {
    let created = |State(tracker): State<Arc<Tracker>>, body: String| async move {
        tracker.calls.lock().unwrap().push(format!("POST issues {body}"));
        (StatusCode::CREATED, r#"{"iid":7,"web_url":"https://gitlab.example/group/proj/-/issues/7"}"#)
    };
    let closed = |State(tracker): State<Arc<Tracker>>, body: String| async move {
        tracker.calls.lock().unwrap().push(format!("PUT issue {body}"));
        (StatusCode::OK, "{}")
    };
    let token = |State(tracker): State<Arc<Tracker>>| async move {
        tracker.calls.lock().unwrap().push("GET token".to_owned());
        let status = *tracker.token_status.lock().unwrap();
        (StatusCode::from_u16(status).unwrap(), r#"{"expires_at":null}"#)
    };
    let app = Router::new()
        .route("/api/v4/projects/{project}/issues", post(created))
        .route("/api/v4/projects/{project}/issues/{iid}", put(closed))
        .route("/api/v4/personal_access_tokens/self", get(token))
        .with_state(addr_tracker);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

/// The alerts raised, as `notifications` would queue them.
#[derive(Default)]
struct Told(Mutex<Vec<Notice>>);

impl TokenAlertSink for Told {
    fn changed<'a>(&'a self, _: &'a mut Tx, alert: &'a TokenAlert) -> BoxFuture<'a, Result<(), RaiseError>> {
        self.0.lock().unwrap().push(alert.notice);
        Box::pin(async { Ok(()) })
    }
}

struct World {
    server: TestDatabase,
    db: Db,
    settings: Settings,
    integrations: Integrations,
    tickets: Tickets,
    tracker: Arc<Tracker>,
    told: Arc<Told>,
    base: String,
}

fn run(engine: Engine) {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = TestDatabase::start(engine).await;
        let overriding = if engine == Engine::PostgreSql { " overriding system value" } else { "" };
        server.sql_as_admin(&format!(
            "insert into t_repository (id, url, branch, name){overriding} values ({REPO}, \
             'https://forge.example/web.git', 'main', 'web')"
        ));
        let db = server.connect().await;
        let door = VaultDoor {
            sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
            guard: OutboundUrlGuard::new(Vec::new()),
        };
        let settings = Settings::new(db.clone());
        let integrations = Integrations::new(db.clone(), Vec::new(), Arc::new(OffsetDateTime::now_utc));
        let told = Arc::new(Told::default());
        let tickets = Tickets::new(TicketsConfig {
            db: db.clone(),
            settings: settings.clone(),
            encryption: Arc::new(
                Encryption::new(&EncryptionConfig { key: Some(Secret::new(KEY)), ..EncryptionConfig::default() }, door)
                    .unwrap(),
            ),
            post: OutboundPost::new(
                OutboundUrlGuard::new(Vec::new()),
                PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
            ),
            integrations: integrations.clone(),
            audit: Arc::new(vectispire_cp_audit::AuditLog::new(
                db.clone(),
                Arc::new(vectispire_cp_audit::NoMirror),
                Arc::new(vectispire_cp_audit::SystemClock),
                Vec::new(),
            )),
            alerts: told.clone(),
            clock: Arc::new(vectispire_cp_audit::SystemClock),
        });
        let tracker = Arc::new(Tracker::default());
        *tracker.token_status.lock().unwrap() = 200;
        let base = gitlab(tracker.clone()).await;
        let world = World { server, db, settings, integrations, tickets, tracker, told, base };
        let mut failures = Vec::new();
        macro_rules! each {
            ($($check:ident),* $(,)?) => {$(
                for table in ["t_issue_ticket", "t_webhook_delivery", "t_issue_triage_event", "t_issue", "t_setting"] {
                    world.server.sql_as_admin(&format!("delete from {table}"));
                }
                world.server.sql_as_admin("update t_integration set enabled = true where integration_key like 'tracker.%'");
                world.tracker.calls.lock().unwrap().clear();
                world.told.0.lock().unwrap().clear();
                if let Err(failure) = $check(&world).await {
                    failures.push(format!("{}: {failure}", stringify!($check)));
                }
            )*};
        }
        each!(
            the_sweep_opens_a_ticket_for_what_the_gate_fails_and_closes_it_once_resolved,
            a_suspended_tracker_is_sent_nothing,
            a_refused_token_is_announced_once,
            a_link_is_refused_in_java_s_order_and_listed_newest_first,
            the_webhook_s_doors,
            a_tracker_s_refusal_is_queued_and_a_settled_decision_kept,
            a_reference_is_the_configured_tracker_s,
        );
        world.db.close().await;
        assert!(failures.is_empty(), "{engine}: {} check(s) failed:\n  {}", failures.len(), failures.join("\n  "));
    });
}

async fn set(world: &World, setting: Setting, value: &str) {
    let mut tx = world.db.begin(Mode::ReadWrite).await.unwrap();
    world.settings.set(&mut tx, setting, value).await.unwrap();
    tx.commit().await.unwrap();
}

async fn configure_gitlab(world: &World) {
    set(world, Setting::TicketProvider, "gitlab").await;
    set(world, Setting::TicketBaseUrl, &format!("{}/", world.base)).await;
    set(world, Setting::TicketProject, "group/proj").await;
    // A clear value, as one written before the setting was encrypted: still the token.
    set(world, Setting::TicketToken, "glpat-test").await;
    set(world, Setting::TicketAllowPrivateUrl, "true").await;
}

fn seed(world: &World, fingerprint: &str, severity: &str, state: &str, triage: &str, ticket: Option<&str>) -> i64 {
    let server = &world.server;
    let (at, falsity) = match server.engine {
        Engine::MySql => ("'2026-01-01 00:00:00'", "0"),
        Engine::PostgreSql => ("'2026-01-01 00:00:00+00'", "false"),
    };
    let ticket = ticket.map_or_else(|| "null".to_owned(), |reference| format!("'{reference}'"));
    server.sql_as_admin(&format!(
        "insert into t_issue (repo_id, fingerprint, type, identifier, severity, state, first_seen_at, last_seen_at, \
         is_kev, times_seen, triage_status, reachability, revision, ticket_ref) \
         values ({REPO}, '{fingerprint}', 'vulnerability', 'CVE-{fingerprint}', '{severity}', '{state}', {at}, {at}, \
         {falsity}, 1, '{triage}', 'UNKNOWN', 0, {ticket})"
    ));
    server.sql_as_admin(&format!("select id from t_issue where fingerprint = '{fingerprint}'")).trim().parse().unwrap()
}

fn column(world: &World, statement: &str) -> String {
    world.server.sql_as_admin(statement).trim().to_owned()
}

async fn the_sweep_opens_a_ticket_for_what_the_gate_fails_and_closes_it_once_resolved(world: &World) -> Check {
    configure_gitlab(world).await;
    let critical = seed(world, "c1", "critical", "open", "under_review", None);
    let low = seed(world, "l1", "low", "open", "under_review", None);
    let opened = world.tickets.sweep.sweep().await.map_err(|e| e.to_string())?;
    ensure_eq!(opened, 1, "one ticket, for what the built-in policy fails on");
    ensure_eq!(column(world, &format!("select ticket_ref from t_issue where id = {critical}")), "#7", "the reference");
    ensure_eq!(column(world, &format!("select coalesce(ticket_ref, '-') from t_issue where id = {low}")), "-", "low");
    let calls = world.tracker.calls.lock().unwrap().clone();
    if !(calls.len() == 1 && calls[0].contains("[Vectispire][CRITICAL] CVE-c1 (web)")) {
        return Err(format!("calls: {calls:?}"));
    }
    // A second pass asks nothing: the reference is the deduplication key.
    ensure_eq!(world.tickets.sweep.sweep().await.map_err(|e| e.to_string())?, 0, "the second pass");
    world.server.sql_as_admin(&format!("update t_issue set state = 'resolved' where id = {critical}"));
    ensure_eq!(world.tickets.sweep.sweep().await.map_err(|e| e.to_string())?, 1, "the close");
    ensure_eq!(column(world, &format!("select ticket_ref from t_issue where id = {critical}")), "CLOSED:#7", "marked");
    let calls = world.tracker.calls.lock().unwrap().clone();
    if !calls.last().is_some_and(|call| call == r#"PUT issue {"state_event":"close"}"#) {
        return Err(format!("calls: {calls:?}"));
    }
    ensure_eq!(world.told.0.lock().unwrap().clone(), Vec::<Notice>::new(), "nothing to announce of a working token");
    Ok(())
}

async fn a_suspended_tracker_is_sent_nothing(world: &World) -> Check {
    configure_gitlab(world).await;
    seed(world, "c2", "critical", "open", "under_review", None);
    world.integrations.switch_to(Integration::by_key("tracker.gitlab").unwrap(), false, "g").await.unwrap();
    ensure_eq!(world.tickets.sweep.sweep().await.map_err(|e| e.to_string())?, 0, "no ticket");
    world.tickets.service.check_token_if_due().await;
    ensure_eq!(world.tracker.calls.lock().unwrap().len(), 0, "nothing sent");
    match world.tickets.service.token().await {
        Err(TicketError::IntegrationDisabled(integration)) => {
            ensure_eq!(integration.key(), "tracker.gitlab".to_owned(), "the refusal names the tracker");
        }
        other => return Err(format!("the token was handed out: {other:?}")),
    }
    Ok(())
}

async fn a_refused_token_is_announced_once(world: &World) -> Check {
    configure_gitlab(world).await;
    *world.tracker.token_status.lock().unwrap() = 401;
    let health = world.tickets.service.check_token_now().await.map_err(|e| e.to_string())?;
    ensure_eq!(health.refused.map(|refusal| refusal.status), Some(401), "the refusal recorded");
    world.tickets.service.check_token_now().await.map_err(|e| e.to_string())?;
    ensure_eq!(world.told.0.lock().unwrap().clone(), vec![Notice::Refused], "announced once");
    *world.tracker.token_status.lock().unwrap() = 200;
    world.tickets.service.check_token_now().await.map_err(|e| e.to_string())?;
    ensure_eq!(world.told.0.lock().unwrap().clone(), vec![Notice::Refused, Notice::None], "and its end");
    *world.tracker.token_status.lock().unwrap() = 200;
    Ok(())
}

fn actor() -> RequestActor {
    RequestActor { username: Some("ana".into()), ip_address: Some("203.0.113.1".into()), user_agent: None }
}

async fn a_link_is_refused_in_java_s_order_and_listed_newest_first(world: &World) -> Check {
    let issue = seed(world, "k1", "high", "open", "under_review", None);
    let links = &world.tickets.links;
    let hidden = Visibility::only([]);
    let everything = Visibility::everything();
    let refused = |result: Result<_, TicketError>| match result {
        Err(error) => error.to_string(),
        Ok(_) => "accepted".to_owned(),
    };
    // Hidden reads as absent, whatever the body holds.
    ensure_eq!(refused(links.attach(issue, &hidden, None, None, None, actor()).await), "Issue not found.", "hidden");
    ensure_eq!(
        refused(links.attach(issue, &everything, Some("jira"), None, Some("u"), actor()).await),
        "Provider, ticket key and URL are required.",
        "a field missing"
    );
    ensure_eq!(
        refused(links.attach(issue, &everything, Some("trello"), Some("K-1"), Some("u"), actor()).await),
        "Unknown ticketing provider \"trello\". Expected one of: jira, github, gitlab.",
        "an unknown provider"
    );
    world.integrations.switch_to(Integration::by_key("tracker.jira").unwrap(), false, "g").await.unwrap();
    match links.attach(issue, &everything, Some("JIRA"), Some(""), Some("u"), actor()).await {
        Err(TicketError::IntegrationDisabled(_)) => {}
        other => return Err(format!("the switch comes before the key: {other:?}")),
    }
    let first = links.attach(issue, &everything, Some("github"), Some("#1"), Some("https://g/1"), actor()).await;
    let second = links.attach(issue, &everything, Some("gitlab"), Some("#2"), Some("https://g/2"), actor()).await;
    let (first, second) = (first.map_err(|e| e.to_string())?, second.map_err(|e| e.to_string())?);
    ensure_eq!((first.provider.as_str(), first.status.as_str()), ("GITHUB", "OPEN"), "the stored link");
    let listed: Vec<String> = links
        .list(issue, &everything, None, None)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|view| view.ticket_key)
        .collect();
    // Newest first, and by id among links made in the same instant: #2 leads either way.
    let _ = (first.created_at, second.created_at);
    ensure_eq!(listed, vec!["#2", "#1"], "newest first, by id among equals");
    match links.list(issue, &hidden, Some(0), None).await {
        Err(TicketError::NotFound(_)) => {}
        other => return Err(format!("the visibility comes before the window: {other:?}")),
    }
    // The purge takes the links with the target's issues.
    world.server.sql_as_admin(&format!("delete from t_issue_ticket where issue_id = {issue}"));
    Ok(())
}

async fn the_webhook_s_doors(world: &World) -> Check {
    let webhooks = &world.tickets.webhooks;
    let origin = RequestActor { username: None, ip_address: Some("198.51.100.7".into()), user_agent: None };
    let body = r#"{"issue":{"key":"SEC-1","fields":{"status":{"name":"Done"},"resolution":{"name":"Done"}}}}"#;
    let token = Presented { shared_token: Some("s3cret".into()), ..Presented::default() };
    let origin = &origin;
    let handle = |presented: Presented, raw: &'static str| async move {
        webhooks.handle(TicketProvider::Jira, raw, &presented, origin).await.map_err(|e| e.to_string())
    };
    ensure_eq!(handle(token.clone(), body).await?, Outcome::NotConfigured, "no secret");
    set(world, Setting::TicketWebhookSecret, "s3cret").await;
    ensure_eq!(handle(Presented::default(), body).await?, Outcome::Rejected, "no token");
    ensure_eq!(handle(token.clone(), body).await?, Outcome::NoMatchingIssue("SEC-1".into()), "authenticated");
    ensure_eq!(handle(token.clone(), body).await?, Outcome::AlreadyProcessed, "the same body twice");
    world.integrations.switch_to(Integration::by_key("tracker.jira").unwrap(), false, "g").await.unwrap();
    let other = r#"{"issue":{"key":"SEC-2"}}"#;
    ensure_eq!(
        handle(token.clone(), other).await?,
        Outcome::IgnoredIntegrationDisabled(Integration::by_key("tracker.jira").unwrap()),
        "a suspended tracker's delivery"
    );
    // Read no further: not even whether it is JSON.
    ensure_eq!(
        handle(token, "not json").await?,
        Outcome::IgnoredIntegrationDisabled(Integration::by_key("tracker.jira").unwrap()),
        "ignored before it is read"
    );
    Ok(())
}

async fn a_tracker_s_refusal_is_queued_and_a_settled_decision_kept(world: &World) -> Check {
    set(world, Setting::TicketWebhookSecret, "s3cret").await;
    let open = seed(world, "w1", "high", "open", "under_review", Some("SEC-9"));
    let settled = seed(world, "w2", "high", "open", "not_affected", Some("SEC-9"));
    let origin = RequestActor { username: None, ip_address: Some("198.51.100.7".into()), user_agent: None };
    let body = r#"{"issue":{"key":"SEC-9","fields":{"status":{"name":"Closed"},"resolution":{"name":"Won't Fix"}}},"user":{"displayName":"Mallory"}}"#;
    let token = Presented { shared_token: Some("s3cret".into()), ..Presented::default() };
    let outcome =
        world.tickets.webhooks.handle(TicketProvider::Jira, body, &token, &origin).await.map_err(|e| e.to_string())?;
    let Outcome::Synced { issue_ids, action_taken, .. } = outcome else { return Err(format!("{outcome:?}")) };
    ensure_eq!(issue_ids, vec![open, settled], "every issue carrying it, oldest first");
    ensure_eq!(
        action_taken,
        format!(
            "issue {open}: Queued as pending_approval (will_not_fix) from JIRA_webhook; issue {settled}: Tracker says \
             will_not_fix, the issue stays not_affected; nothing changed"
        ),
        "queued, never settled; the settled one kept"
    );
    ensure_eq!(
        column(world, &format!("select triage_requested_status from t_issue where id = {open}")),
        "will_not_fix",
        "the request awaits a person"
    );
    Ok(())
}

async fn a_reference_is_the_configured_tracker_s(world: &World) -> Check {
    let references = world.tickets.references();
    ensure_eq!(references.refusal("anything").await.map_err(|e| e.to_string())?, None, "no tracker: a label");
    set(world, Setting::TicketProvider, "jira").await;
    set(world, Setting::TicketProject, "SEC").await;
    ensure_eq!(references.refusal("SEC-4").await.map_err(|e| e.to_string())?, None, "in the project");
    ensure_eq!(
        references.refusal("OPS-4").await.map_err(|e| e.to_string())?,
        Some("\"OPS-4\" is not a jira reference in project SEC.".to_owned()),
        "another project's"
    );
    world.integrations.switch_to(Integration::by_key("tracker.jira").unwrap(), false, "g").await.unwrap();
    match references.refusal("SEC-4").await {
        Err(vectispire_cp_issues::TicketReferenceError::IntegrationDisabled(_)) => Ok(()),
        other => Err(format!("a suspended tracker: {other:?}")),
    }
}
