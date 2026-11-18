//! **The settings save as the binary composes it asks the modules it should** — the composition itself, exercised:
//! every rule of `SettingsAdministration` passes its own suite with stand-ins, whether or not `main` hands it
//! `access`' approvers, the registry the governor's switches write, and the guard built at start. `cp-platform`'s
//! `Approvers` was a trait nothing filled for as long as the settings routes were not served; this is what keeps it
//! filled.
//!
//! On a real database, with [`settings_screen::compose`] as `main` calls it: switching four-eyes on is refused while no
//! account can approve and accepted once two administrators exist (`TriageApprovers`, counting the accounts table);
//! a leaf pasted as the tracker CA is refused in the tracker's words (`TrackerCaPinning`); a tracker the governor
//! switched off is not chosen (`registry::integrations`, the switches' registry); an Ollama address on an endpoint the
//! process reserves is refused, internal as it is (the guard handed in, not a fresh one); and the endpoint check, whose
//! route is not served, fails rather than inventing an answer (`EndpointNotPorted`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use vectispire_cp_app::{registry, settings_screen};
use vectispire_cp_audit::{AuditLog, NoMirror, RequestActor, SystemClock};
use vectispire_cp_db::Engine;
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_outbound::{OutboundUrlGuard, ReservedEndpoint};
use vectispire_cp_platform::{AdministrationError, Caller, SettingsAdministration};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::integrations::Integration;

#[tokio::test(flavor = "multi_thread")]
async fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    run(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn on_postgresql() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    run(Engine::PostgreSql).await;
}

fn encryption() -> Arc<vectispire_cp_crypto::Encryption> {
    let door = vectispire_cp_crypto::VaultDoor {
        sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    Arc::new(vectispire_cp_crypto::Encryption::new(&vectispire_cp_crypto::EncryptionConfig::default(), door).unwrap())
}

fn governor() -> Caller {
    Caller { username: "governor".to_owned(), administrative: true, governs_platform: true }
}

fn actor() -> RequestActor {
    RequestActor {
        username: Some("governor".to_owned()),
        ip_address: Some("203.0.113.5".to_owned()),
        user_agent: Some("composition".to_owned()),
    }
}

async fn save(service: &SettingsAdministration, key: &str, value: &str) -> Result<usize, AdministrationError> {
    let body = vec![(key.to_owned(), Some(value.to_owned()))];
    service.update(&body, Some(&governor()), &actor()).await.map(|applied| applied.count)
}

fn words(refusal: AdministrationError) -> String {
    match refusal {
        AdministrationError::InvalidInput(words) | AdministrationError::UnsafeUrl(words) => words,
        other => panic!("expected a refusal in words, got {other:?}"),
    }
}

async fn run(engine: Engine) {
    let server = TestDatabase::start(engine).await;
    let db = server.connect().await;
    let audit = AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(SystemClock), Vec::new());
    // The guard `main` builds holds the process' own endpoints; port 9090 stands for one here. Not Ollama's default
    // port: every save judges the AI destination it leaves, the default included, so reserving that refuses them all.
    let guard = OutboundUrlGuard::new(vec![ReservedEndpoint::on_every_host(9_090, "an endpoint of this deployment")]);
    // `tickets` as `main` composes it: its own CA pinning answers the save.
    let tickets = vectispire_cp_app::tickets::compose(vectispire_cp_app::tickets::TicketParts {
        db: db.clone(),
        encryption: encryption(),
        post: vectispire_cp_outbound::OutboundPost::new(
            OutboundUrlGuard::new(Vec::new()),
            vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        ),
        audit: Arc::new(audit.clone()),
        alerts: Arc::new(vectispire_cp_outbox::NotTold),
        clock: Arc::new(SystemClock),
    });
    let service = settings_screen::compose(
        &db,
        audit,
        guard,
        Arc::new(vectispire_cp_app::tickets::TrackerCa(tickets)),
        Arc::new(SystemClock),
    );
    let settings = Settings::new(db.clone());

    // `access`: no account can approve yet.
    let refused = words(save(&service, "triage_four_eyes_required", "true").await.expect_err("nobody to approve"));
    assert!(refused.starts_with("No active account can approve a triage"), "{refused}");
    let (active, now) = match engine {
        Engine::MySql => ("1", "current_timestamp(6)"),
        Engine::PostgreSql => ("true", "current_timestamp"),
    };
    let inactive = if engine == Engine::MySql { "0" } else { "false" };
    for name in ["first", "second"] {
        server.sql_as_admin(&format!(
            "insert into t_user (username, role, is_active, created_at, updated_at, must_change_password) \
             values ('{name}', 'ADMIN', {active}, {now}, {now}, {inactive})"
        ));
    }
    assert_eq!(save(&service, "triage_four_eyes_required", "true").await.unwrap(), 1, "two administrators approve");
    assert_eq!(settings.get(Setting::FourEyesApprovalRequired).await.unwrap(), "true");

    // `tickets`' CA pinning, in the tracker's words.
    let leaf =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/siem/collector-ca/03-leaf.pem"))
            .unwrap();
    let refused = words(save(&service, "ticket_ca_pem", &leaf).await.expect_err("a leaf is no CA"));
    assert!(refused.contains("pin the CA that issued the tracker's certificate"), "{refused}");

    // The registry the governor's switches write.
    let jira = Integration::by_key("tracker.jira").unwrap();
    registry::integrations(&db).switch_to(jira, false, "governor").await.unwrap();
    match save(&service, "ticket_provider", "jira").await.expect_err("switched off") {
        AdministrationError::IntegrationDisabled { integration, .. } => assert_eq!(integration, jira),
        other => panic!("expected 409 integration-disabled, got {other:?}"),
    }

    // The guard handed in: loopback is internal, and still refused on an endpoint the process reserves.
    let refused =
        words(save(&service, "ai_review_ollama_url", "http://localhost:9090").await.expect_err("a reserved endpoint"));
    assert!(refused.starts_with("Ollama URL"), "{refused}");
    assert_eq!(save(&service, "ai_review_ollama_url", "http://localhost:11500").await.unwrap(), 1);

    // The endpoint check is not served, and its seam says so rather than answering.
    match service.check_ai_endpoint(Some(&governor())).await.expect_err("not ported") {
        AdministrationError::Collaborator(failure) => {
            assert_eq!(failure.to_string(), settings_screen::ENDPOINT_NOT_PORTED)
        }
        other => panic!("expected the stand-in's failure, got {other:?}"),
    }
    db.close().await;
}
