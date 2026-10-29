//! **The SIEM export as the binary composes it reaches a collector** — the composition itself, exercised, because a
//! wiring that is not exercised is not wired: every service of `cp-siem` passes its own suite whether or not the
//! binary hands its handler to the outbox, its listener to the audit log, or its queue to the modules that raise
//! events.
//!
//! On MySQL 9.4 and PostgreSQL 17, with the pieces `main` builds — [`siem::compose`], [`siem::audit_listeners`],
//! [`siem::chain_broken_listeners`], [`maintenance::outbox_registry`], [`siem::service`] — and a UDP collector on
//! loopback: a save the configuration's own route would make is audited and that entry's event reaches the collector
//! through the relaying outbox; so does an event raised through the port the issues and the gate are handed, and the
//! chain-broken alarm. And the guard the binary built at start is the one the sender asks: a collector on a reserved
//! endpoint is refused even with private destinations allowed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use vectispire_cp_app::{maintenance, siem};
use vectispire_cp_audit::{AuditChainBroken, AuditLog, NoMirror, RequestActor, SystemClock};
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine, Mode};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender, reserved};
use vectispire_cp_outbox::Outbox;
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_siem::{REFUSED_BY_POLICY, SiemConfigUpdate};
use vectispire_domain::instant::Instant;
use vectispire_domain::secret::Secret;
use vectispire_domain::siem::{CefEvent, SecurityEventType};
use vectispire_tls::TlsTrust;

const KEY: &str = "cmVmZXJlbmNlLXNjYW5uaW5nLWtleS0zMi1ieXRlcyE="; // gitleaks:allow — test fixture

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

fn encryption() -> Arc<Encryption> {
    let config = EncryptionConfig { key: Some(Secret::new(KEY)), ..EncryptionConfig::default() };
    let door = VaultDoor { sender: PinnedHttpSender::new(TlsTrust::BuiltIn), guard: OutboundUrlGuard::new(Vec::new()) };
    Arc::new(Encryption::new(&config, door).unwrap())
}

/// The binary's composition, in `main`'s order, over `guard`.
struct Composed {
    siem: siem::Siem,
    outbox: Outbox,
    service: Arc<vectispire_cp_siem::SiemExporterService>,
}

fn compose(db: &Db, guard: OutboundUrlGuard) -> Composed {
    let encryption = encryption();
    let siem = siem::compose(
        siem::SiemSetup {
            db: db.clone(),
            guard,
            trust: TlsTrust::BuiltIn,
            encryption: encryption.clone(),
            version: Some("0.12.0".to_owned()),
        },
        Arc::new(SystemClock),
    )
    .unwrap();
    let audit = AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(SystemClock), siem::audit_listeners(&siem));
    let outbox = Outbox::on_database(
        db.clone(),
        maintenance::outbox_registry(Arc::new(audit.clone()), &siem),
        Arc::new(vectispire_cp_maintenance::SystemClock),
    );
    let service = siem::service(&siem, db.clone(), encryption, audit, Arc::new(SystemClock));
    Composed { siem, outbox, service }
}

fn lead() -> RequestActor {
    RequestActor {
        username: Some("lead".into()),
        ip_address: Some("10.0.0.1".into()),
        user_agent: Some("composition-test".into()),
    }
}

async fn allow_private(db: &Db) {
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    Settings::new(db.clone()).set(&mut tx, Setting::SiemAllowPrivateDestination, "true").await.unwrap();
    tx.commit().await.unwrap();
}

/// The datagrams a collector received within `wait`, as text.
async fn datagrams(socket: &tokio::net::UdpSocket, wait: Duration) -> Vec<String> {
    let mut received = Vec::new();
    let mut buffer = vec![0u8; 70_000];
    let mut window = wait;
    while let Ok(Ok(length)) = tokio::time::timeout(window, socket.recv(&mut buffer)).await {
        received.push(String::from_utf8_lossy(&buffer[..length]).into_owned());
        window = Duration::from_millis(300);
    }
    received
}

fn kev() -> CefEvent {
    let at = OffsetDateTime::now_utc();
    CefEvent::builder(
        SecurityEventType::CriticalKevDetected,
        Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() },
    )
    .identifier("CVE-2026-0001")
    .build()
    .unwrap()
}

async fn run(engine: Engine) {
    let server = TestDatabase::start(engine).await;
    let db = server.connect().await;
    allow_private(&db).await;

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let composed = compose(&db, OutboundUrlGuard::new(Vec::new()));

    // The save is audited with SECURITY_SETTING_CHANGED: the entry's listener queues it, in the entry's transaction.
    composed
        .service
        .save_config(
            SiemConfigUpdate {
                enabled: true,
                protocol: Some("SYSLOG_UDP".into()),
                endpoint: Some(format!("127.0.0.1:{port}")),
                min_severity: Some("LOW".into()),
                ..SiemConfigUpdate::default()
            },
            &lead(),
        )
        .await
        .unwrap();

    // The port the issues and the gate are handed queues in the raiser's transaction.
    let events = composed.siem.security_events();
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    events.raise(&mut tx, &kev()).await.unwrap();
    tx.commit().await.unwrap();
    // Rolled back with what it described, it is never sent.
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    events.raise(&mut tx, &kev()).await.unwrap();
    tx.rollback().await.unwrap();

    // The verification's alarm.
    for listener in siem::chain_broken_listeners(&composed.siem) {
        listener.chain_broken(&AuditChainBroken { broken_at: Some("42".into()), missing_from_table: 0 }).await;
    }

    let relayed = composed.outbox.relay(10).await.unwrap();
    assert_eq!((relayed.sent, relayed.failed, relayed.abandoned), (3, 0, 0), "{engine}");
    let received = datagrams(&socket, Duration::from_secs(5)).await;
    assert_eq!(received.len(), 3, "{engine}: {received:?}");
    for (name, expected) in [
        ("the save's audit entry", SecurityEventType::SecuritySettingChanged),
        ("the raised event", SecurityEventType::CriticalKevDetected),
        ("the chain's alarm", SecurityEventType::AuditChainBroken),
    ] {
        let signature = format!("|{}|", expected.signature_id());
        assert!(received.iter().any(|line| line.contains(&signature)), "{engine}: {name} missing from {received:?}");
    }
    // The binary's guard is the sender's: a collector on a reserved endpoint — here, the database's own address as
    // the datasource reserves it — is refused whatever the private switch says.
    let reserved = reserved::of_datasource(Some(&format!("jdbc:mysql://127.0.0.1:{port}/vectispire"))).unwrap();
    let guarded = compose(&db, OutboundUrlGuard::new(reserved));
    let tested = guarded
        .service
        .test_connection(Some("SYSLOG_UDP"), Some(&format!("127.0.0.1:{port}")), None, None)
        .await
        .unwrap();
    assert_eq!((tested.success, tested.message.as_str()), (false, REFUSED_BY_POLICY), "{engine}");
    assert!(
        datagrams(&socket, Duration::from_millis(500)).await.is_empty(),
        "{engine}: the reserved endpoint was reached"
    );
    // The open guard reaches the same collector: the refusal was the reservation's, not the network's.
    let open = compose(&db, OutboundUrlGuard::new(Vec::new()));
    let tested =
        open.service.test_connection(Some("SYSLOG_UDP"), Some(&format!("127.0.0.1:{port}")), None, None).await.unwrap();
    assert!(tested.success, "{engine}: {}", tested.message);

    db.close().await;
}
