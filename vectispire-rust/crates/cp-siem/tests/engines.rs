//! The module on MySQL 9.4 and PostgreSQL 17, migrated by `vectispire-migrate`.
//!
//! - **`reference/siem/module.json`, through the real services**: every payload an audit entry or a broken chain
//!   queues (the real listener, in a real transaction, read back from `t_outbox_message`), what every stored row
//!   becomes at delivery, what every save writes, refuses, audits and tells the collector being left, what every
//!   connection test answers — each compared with what Java's services did with the same input
//!   (`SiemModuleReferenceSetTest`). The transport is a recording one there, as Java's `SiemSender` was a mock.
//! - **The wiring, end to end**, with the real sender on loopback sockets — `SiemExportRoutesTest`,
//!   `SiemCollectorCaRoutesTest` and `SiemRoutesTest` at the level that can see them: an audited action reaches a UDP
//!   collector once the relay runs; an event rolled back is never sent; a collector that is down is retried with the
//!   backoff and reached afterwards; the minimum decides what is queued; a switched-off export abandons what was
//!   queued; the collector left behind is told, or the audit says it was not; a TLS collector is reached through its
//!   pinned CA and only through it; a lapsed CA abandons the row; the private-destination switch decides the reach;
//!   the header is encrypted at rest; the listener's failure costs the audit entry nothing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::BoxFuture;
use serde_json::Value;
use sqlx::Row as _;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_audit::{
    AuditChainBroken, AuditLog, AuditOperation, ChainBrokenListener, Listener, ListenerError, NoMirror, Record,
    RequestActor, Signal,
};
use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::types::UtcInstant;
use vectispire_cp_db::{Db, Engine, Mode, Tx};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender, UnsafeUrl};
use vectispire_cp_outbox::{DeliveryError, Outbox, Registry};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_siem::{
    AUTH_HEADER_CONTEXT, NOT_DELIVERED, QueuedEvent, REFUSED_BY_POLICY, SendError, SiemConfigUpdate, SiemDelivery,
    SiemError, SiemEvents, SiemExporterService, SiemSender, SyslogSender, TYPE, Transport, body,
};
use vectispire_domain::instant::Instant;
use vectispire_domain::secret::Secret;
use vectispire_domain::siem::{CefEvent, SecurityEventType, SiemEndpoint, syslog};
use vectispire_tls::TlsTrust;

use support::{Migrated, Pki, Recording, TestClock};

const VERSION: &str = "2.3.0";
const HOSTNAME: &str = "collector-host";

#[tokio::test(flavor = "multi_thread")]
async fn on_mysql() {
    run(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn on_postgresql() {
    run(Engine::PostgreSql).await;
}

async fn run(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let reference = vectispire_testkit::read_json("siem/module.json");

    reference_queued(&db, &reference).await;
    reference_delivered(&db, &reference).await;
    reference_saves(&db, &reference).await;
    reference_tests(&db, &reference).await;

    the_entry_and_its_event_commit_together(&db).await;
    a_failing_listener_costs_the_entry_nothing(&db).await;
    the_fallback_queues_after_the_entry_commits(&db).await;
    an_event_rolled_back_is_never_sent(&db).await;
    an_audited_action_reaches_the_collector_after_the_relay(&db).await;
    a_collector_that_is_down_gets_the_event_later(&db).await;
    the_minimum_decides_what_is_queued(&db).await;
    an_export_switched_off_abandons_what_was_queued(&db).await;
    the_collector_left_behind_is_told(&db).await;
    a_tls_collector_is_reached_through_its_pinned_ca(&db).await;
    a_lapsed_stored_ca_abandons_the_event(&db).await;
    the_private_switch_decides_the_reach(&db).await;
    the_header_is_encrypted_at_rest(&db).await;
}

// ---- the fixtures ----

fn reference_now(reference: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(reference["now"].as_str().unwrap(), &time::format_description::well_known::Rfc3339).unwrap()
}

fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

async fn sql(db: &Db, mysql: &'static str, postgres: &'static str) {
    match db {
        Db::MySql(pool) => {
            sqlx::query(mysql).execute(pool).await.unwrap();
        }
        Db::PostgreSql(pool) => {
            sqlx::query(postgres).execute(pool).await.unwrap();
        }
    }
}

async fn reset(db: &Db) {
    sql(db, "delete from t_siem_config", "delete from t_siem_config").await;
    sql(db, "delete from t_outbox_message", "delete from t_outbox_message").await;
    sql(
        db,
        "delete from t_setting where `key` = 'siem_allow_private_destination'",
        "delete from t_setting where key = 'siem_allow_private_destination'",
    )
    .await;
}

async fn allow_private(db: &Db, allowed: bool) {
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    Settings::new(db.clone())
        .set(&mut tx, Setting::SiemAllowPrivateDestination, if allowed { "true" } else { "false" })
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// A row as an operator — or the save, or a hand edit — left it.
struct Row<'a> {
    enabled: bool,
    protocol: &'a str,
    endpoint: Option<&'a str>,
    /// Already as stored: a ciphertext, a clear legacy value, or nothing.
    header: Option<String>,
    ca: Option<&'a str>,
    min_severity: &'a str,
    at: OffsetDateTime,
}

async fn put(db: &Db, row: &Row<'_>) {
    sql(db, "delete from t_siem_config", "delete from t_siem_config").await;
    let (mysql, postgres) = (
        "insert into t_siem_config (id, enabled, protocol, endpoint, auth_header, tls_ca_pem, min_severity, created_at, \
         updated_at) values (1, ?, ?, ?, ?, ?, ?, ?, ?)",
        "insert into t_siem_config (id, enabled, protocol, endpoint, auth_header, tls_ca_pem, min_severity, created_at, \
         updated_at) values (1, $1, $2, $3, $4, $5, $6, $7, $8)",
    );
    macro_rules! bound {
        ($query:expr) => {
            $query
                .bind(row.enabled)
                .bind(row.protocol)
                .bind(row.endpoint)
                .bind(row.header.as_deref())
                .bind(row.ca)
                .bind(row.min_severity)
                .bind(UtcInstant(row.at))
                .bind(UtcInstant(row.at))
        };
    }
    match db {
        Db::MySql(pool) => {
            bound!(sqlx::query(mysql)).execute(pool).await.unwrap();
        }
        Db::PostgreSql(pool) => {
            bound!(sqlx::query(postgres)).execute(pool).await.unwrap();
        }
    }
}

async fn stored_header(db: &Db) -> Option<String> {
    let statement = "select auth_header from t_siem_config where id = 1";
    let found: Option<Option<String>> = match db {
        Db::MySql(pool) => sqlx::query_scalar(statement).fetch_optional(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar(statement).fetch_optional(pool).await.unwrap(),
    };
    found.flatten()
}

/// One outbox row as the relay settled it.
#[derive(Debug, Clone)]
struct OutboxRow {
    id: String,
    message_type: String,
    team_id: Option<i64>,
    payload: String,
    status: String,
    attempts: i32,
    last_error: Option<String>,
    next_attempt_at: bool,
}

async fn outbox_rows(db: &Db) -> Vec<OutboxRow> {
    let statement = "select id, message_type, team_id, payload, status, attempts, last_error, \
                     case when next_attempt_at is null then 'no' else 'yes' end as scheduled \
                     from t_outbox_message order by created_at, id";
    macro_rules! read {
        ($rows:expr) => {
            $rows
                .into_iter()
                .map(|row| OutboxRow {
                    id: row.get::<String, _>(0),
                    message_type: row.get(1),
                    team_id: row.get(2),
                    payload: row.get(3),
                    status: row.get(4),
                    attempts: row.get(5),
                    last_error: row.get(6),
                    next_attempt_at: row.get::<String, _>(7) == "yes",
                })
                .collect()
        };
    }
    match db {
        Db::MySql(pool) => read!(sqlx::query(statement).fetch_all(pool).await.unwrap()),
        Db::PostgreSql(pool) => read!(sqlx::query(statement).fetch_all(pool).await.unwrap()),
    }
}

/// The audit entries' descriptions, oldest first.
async fn audit_descriptions(db: &Db) -> Vec<String> {
    let statement = "select description from t_audit_log order by timestamp, id";
    match db {
        Db::MySql(pool) => sqlx::query_scalar(statement).fetch_all(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar(statement).fetch_all(pool).await.unwrap(),
    }
}

fn java_string(at: OffsetDateTime) -> String {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }.to_java_string().unwrap()
}

/// A listener that keeps what the audit log hands it — the signal included, which no column holds.
#[derive(Default)]
struct Heard(Mutex<Vec<Record>>);

impl Listener for Heard {
    fn recorded_in_transaction<'a>(
        &'a self,
        entry: &'a Record,
        _at: OffsetDateTime,
        _tx: &'a mut Tx,
    ) -> BoxFuture<'a, Result<(), ListenerError>> {
        self.0.lock().unwrap().push(entry.clone());
        Box::pin(async { Ok(()) })
    }

    fn recorded<'a>(&'a self, _entry: &'a Record, _at: OffsetDateTime) -> BoxFuture<'a, Result<(), ListenerError>> {
        Box::pin(async { Ok(()) })
    }

    fn name(&self) -> &str {
        "Heard"
    }
}

fn signal(name: &Value) -> Option<Signal> {
    name.as_str().map(|name| Signal(SecurityEventType::from_wire_name(name).unwrap().wire_name()))
}

fn operation(name: &str) -> AuditOperation {
    AuditOperation::ALL.iter().copied().find(|operation| operation.wire_name() == name).unwrap()
}

/// The module as the binary will compose it, over `transport`.
struct Module {
    events: Arc<SiemEvents>,
    delivery: Arc<SiemDelivery>,
    outbox: Arc<Outbox>,
    audit: AuditLog,
    exporter: SiemExporterService,
    encryption: Arc<Encryption>,
}

fn compose(db: &Db, transport: Arc<dyn Transport>, clock: Arc<TestClock>, heard: Option<Arc<Heard>>) -> Module {
    let encryption = support::encryption();
    let delivery = Arc::new(SiemDelivery::new(db.clone(), transport.clone(), encryption.clone(), clock.clone()));
    let outbox =
        Arc::new(Outbox::on_database(db.clone(), Registry::new(vec![delivery.clone()], Vec::new()), clock.clone()));
    let events = Arc::new(SiemEvents::new(db.clone(), outbox.clone(), clock.clone()));
    let mut listeners: Vec<Arc<dyn Listener>> = vec![events.clone()];
    if let Some(heard) = heard {
        listeners.push(heard);
    }
    let audit = AuditLog::new(db.clone(), Arc::new(NoMirror), clock.clone(), listeners);
    let exporter = SiemExporterService::new(db.clone(), transport, encryption.clone(), audit.clone(), clock);
    Module { events, delivery, outbox, audit, exporter, encryption }
}

/// The real sender: the system's resolver, no reserved endpoint, the private switch read from the settings.
fn real_sender(db: &Db, trust: &TlsTrust) -> Arc<SiemSender> {
    Arc::new(
        SiemSender::new(
            OutboundUrlGuard::new(Vec::new()),
            PinnedHttpSender::new(trust.clone()),
            SyslogSender::new(trust).unwrap(),
            Arc::new(Settings::new(db.clone())),
            Some(VERSION.to_owned()),
        )
        .with_hostname(HOSTNAME),
    )
}

fn admin() -> RequestActor {
    RequestActor {
        username: Some("admin".into()),
        ip_address: Some("10.0.0.1".into()),
        user_agent: Some("Mozilla/5.0".into()),
    }
}

fn update(enabled: bool, protocol: &str, endpoint: &str, minimum: &str) -> SiemConfigUpdate {
    SiemConfigUpdate {
        enabled,
        protocol: Some(protocol.into()),
        endpoint: Some(endpoint.into()),
        min_severity: Some(minimum.into()),
        ..SiemConfigUpdate::default()
    }
}

fn kev(cve: &str) -> CefEvent {
    let at = OffsetDateTime::now_utc();
    CefEvent::builder(
        SecurityEventType::CriticalKevDetected,
        Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() },
    )
    .identifier(cve)
    .build()
    .unwrap()
}

async fn enqueue_committed(events: &SiemEvents, db: &Db, event: &CefEvent) {
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    events.enqueue(&mut tx, event).await.unwrap();
    tx.commit().await.unwrap();
}

async fn udp() -> (tokio::net::UdpSocket, u16) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    (socket, port)
}

// ---- the reference set ----

/// What an audit entry, or a broken chain, queues: the real listener in a real transaction, the row read back.
async fn reference_queued(db: &Db, reference: &Value) {
    let now = reference_now(reference);
    let module = compose(db, Arc::new(Recording::default()), TestClock::at(now), None);
    let cases = reference["queued"].as_array().unwrap();
    assert_eq!(cases.len(), 16);
    assert_eq!(reference["type"].as_str().unwrap(), TYPE);
    // The context every stored header's ciphertext is bound to, Java's included: moved, none of them decrypts.
    assert_eq!(reference["authHeaderContext"].as_str().unwrap(), AUTH_HEADER_CONTEXT);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        reset(db).await;
        put(
            db,
            &Row {
                enabled: true,
                protocol: "SYSLOG_UDP",
                endpoint: Some("127.0.0.1:514"),
                header: None,
                ca: None,
                min_severity: case["minSeverity"].as_str().unwrap(),
                at: now,
            },
        )
        .await;
        if let Some(record) = case.get("record") {
            let entry = Record {
                operation: operation(record["operation"].as_str().unwrap()),
                resource_id: text(&record["resourceId"]),
                description: text(&record["description"]),
                user_id: text(&record["user"]),
                ip_address: text(&record["ip"]),
                user_agent: text(&record["userAgent"]),
                signal: signal(&record["signal"]),
            };
            let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
            module.events.recorded_in_transaction(&entry, now, &mut tx).await.unwrap();
            tx.commit().await.unwrap();
        } else {
            let broken = &case["chainBroken"];
            let event = AuditChainBroken {
                broken_at: text(&broken["brokenAt"]),
                missing_from_table: usize::try_from(broken["missingFromTable"].as_u64().unwrap()).unwrap(),
            };
            module.events.chain_broken(&event).await;
        }
        let rows = outbox_rows(db).await;
        match case["payload"].as_str() {
            None => assert!(rows.is_empty(), "{name}: queued {rows:?}"),
            Some(java) => {
                assert_eq!(rows.len(), 1, "{name}");
                let row = &rows[0];
                assert_eq!((row.message_type.as_str(), row.team_id, row.status.as_str()), (TYPE, None, "pending"));
                assert_eq!(row.payload.replace(&row.id, "{message_id}"), java, "{name}");
            }
        }
    }
}

/// What each stored row becomes at delivery: the real handler over the row, the transport recording.
async fn reference_delivered(db: &Db, reference: &Value) {
    let now = reference_now(reference);
    let recording = Arc::new(Recording::default());
    let module = compose(db, recording.clone(), TestClock::at(now), None);
    let message_id = Uuid::parse_str(reference["messageId"].as_str().unwrap()).unwrap();
    let cases = reference["delivered"].as_array().unwrap();
    assert_eq!(cases.len(), 25);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let config = &case["config"];
        let header = match config["header"].as_str() {
            Some(plain) => Some(module.encryption.encrypt(plain, AUTH_HEADER_CONTEXT).await.unwrap()),
            None => None,
        };
        put(
            db,
            &Row {
                enabled: config["enabled"].as_bool().unwrap(),
                protocol: config["protocol"].as_str().unwrap(),
                endpoint: config["endpoint"].as_str(),
                header,
                ca: config["ca"].as_str(),
                min_severity: "HIGH",
                at: now,
            },
        )
        .await;
        recording.events.lock().unwrap().clear();
        let answer = &case["answer"];
        let delivered = module.delivery.deliver_message(message_id, case["payload"].as_str().unwrap()).await;
        if let Some(gone) = answer["gone"].as_str() {
            assert_eq!(delivered, Err(DeliveryError::Gone(gone.to_owned())), "{name}");
            continue;
        }
        if let Some(kind) = answer["kind"].as_str() {
            let Err(DeliveryError::Failed { kind: ours, message }) = delivered else { panic!("{name}: {delivered:?}") };
            assert_eq!(ours, kind, "{name}");
            let java = answer["message"].as_str().unwrap();
            match java.strip_suffix("{jackson}") {
                // Jackson's sentence is not ported; the prefix is Java's.
                Some(prefix) => assert!(message.as_deref().unwrap().starts_with(prefix), "{name}: {message:?}"),
                None => assert_eq!(message.as_deref(), Some(java), "{name}"),
            }
            continue;
        }
        delivered.unwrap_or_else(|failed| panic!("{name}: {failed:?}"));
        let events = recording.events.lock().unwrap().clone();
        assert_eq!(events.len(), 1, "{name}");
        let (endpoint, header, ca, event) = &events[0];
        let cef = event.to_cef_string(Some(VERSION));
        if let Some(webhook) = answer.get("webhook") {
            assert_eq!(endpoint, &SiemEndpoint::Webhook { url: webhook["url"].as_str().unwrap().to_owned() }, "{name}");
            assert_eq!(body(&cef), webhook["body"].as_str().unwrap(), "{name}");
            let sent = header.as_deref().filter(|header| !vectispire_domain::java::is_blank(header));
            assert_eq!(sent, webhook["headers"]["Authorization"].as_str(), "{name}");
            assert_eq!(webhook["label"], "SIEM export");
            assert_eq!(webhook["policy"], "INTERNAL_ALLOWED");
        } else {
            let sent = &answer["syslog"];
            let SiemEndpoint::Syslog { protocol, host, port } = endpoint else { panic!("{name}: {endpoint:?}") };
            assert_eq!(protocol.name(), sent["protocol"].as_str().unwrap(), "{name}");
            assert_eq!(host.as_str(), answer["guard"]["host"].as_str().unwrap(), "{name}");
            assert_eq!(u64::from(*port), sent["port"].as_u64().unwrap(), "{name}");
            assert_eq!(
                syslog::format(event, Some(HOSTNAME), &cef),
                sent["message"].as_str().unwrap().replace("{hostname}", HOSTNAME),
                "{name}"
            );
            assert_eq!(ca.as_deref(), sent["pinnedCa"].as_str(), "{name}");
            assert_eq!(*header, None, "{name}: a syslog frame carries no header");
        }
    }
}

/// What every save writes, refuses, audits and tells the collector being left.
async fn reference_saves(db: &Db, reference: &Value) {
    let now = reference_now(reference);
    let recording = Arc::new(Recording::default());
    let heard = Arc::new(Heard::default());
    let module = compose(db, recording.clone(), TestClock::at(now), Some(heard.clone()));
    let cases = reference["saves"].as_array().unwrap();
    assert_eq!(cases.len(), 40);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        reset(db).await;
        heard.0.lock().unwrap().clear();
        recording.take();
        let before = case.get("before");
        if let Some(before) = before {
            let header = match before["header"].as_str() {
                Some(plain) => Some(module.encryption.encrypt(plain, AUTH_HEADER_CONTEXT).await.unwrap()),
                None => None,
            };
            put(
                db,
                &Row {
                    enabled: before["enabled"].as_bool().unwrap(),
                    protocol: before["protocol"].as_str().unwrap(),
                    endpoint: before["endpoint"].as_str(),
                    header,
                    ca: before["ca"].as_str(),
                    min_severity: before["minSeverity"].as_str().unwrap(),
                    at: OffsetDateTime::from_unix_timestamp(now.unix_timestamp() - 3_600).unwrap(),
                },
            )
            .await;
        }
        let header_before = stored_header(db).await.filter(|_| before.is_some());
        let request = &case["request"];
        recording.answering(
            request["noticeFails"]
                .as_bool()
                .unwrap()
                .then(|| SendError::failed("OutboundFailureException", "SIEM export: closed")),
        );
        let saved = module
            .exporter
            .save_config(
                SiemConfigUpdate {
                    enabled: request["enabled"].as_bool().unwrap(),
                    protocol: text(&request["protocol"]),
                    endpoint: text(&request["endpoint"]),
                    auth_header: text(&request["header"]).map(Secret::new),
                    min_severity: text(&request["minSeverity"]),
                    tls_ca_pem: text(&request["ca"]),
                },
                &admin(),
            )
            .await;
        let answer = &case["answer"];
        if let Some(refused) = answer["refused"].as_str() {
            let Err(SiemError::InvalidInput(ours)) = &saved else { panic!("{name}: {saved:?}") };
            assert_eq!(ours, refused, "{name}");
            // Refused before the row was touched.
            match before {
                None => assert_eq!(module.exporter.get_config().await.unwrap(), None, "{name}"),
                Some(_) => assert_eq!(stored_header(db).await, header_before, "{name}"),
            }
            assert!(recording.take().is_empty() && heard.0.lock().unwrap().is_empty(), "{name}");
            continue;
        }
        let view = saved.unwrap_or_else(|failed| panic!("{name}: {failed:?}"));
        let java = &answer["row"];
        let stored = module.exporter.get_config().await.unwrap().unwrap();
        assert_eq!(stored.enabled, java["enabled"].as_bool().unwrap(), "{name}");
        assert_eq!(stored.protocol, java["protocol"].as_str().unwrap(), "{name}");
        assert_eq!(stored.endpoint.as_deref(), java["endpoint"].as_str(), "{name}");
        assert_eq!(stored.tls_ca_pem.as_deref(), java["caPem"].as_str(), "{name}");
        assert_eq!(stored.min_severity, java["minSeverity"].as_str().unwrap(), "{name}");
        let header = match stored_header(db).await {
            Some(ciphertext) => {
                assert!(Encryption::is_ciphertext(&ciphertext), "{name}: stored in the clear");
                let plain = module.encryption.read_secret(&ciphertext, AUTH_HEADER_CONTEXT, "test").await;
                Some(format!("v2:{}", plain.expose()))
            }
            None => None,
        };
        assert_eq!(header.as_deref(), java["header"].as_str(), "{name}");
        assert_eq!(view.tls_ca_subject.as_deref(), java["caSubject"].as_str(), "{name}");
        assert_eq!(view.has_auth_header, answer["hasAuthHeader"].as_bool().unwrap(), "{name}");
        assert_eq!(view.tls_ca_not_after.map(|at| at.to_java_string().unwrap()), text(&answer["caNotAfter"]), "{name}");
        assert_eq!(java_string(view.created_at), java["createdAt"].as_str().unwrap(), "{name}");
        assert_eq!(java_string(view.updated_at), java["updatedAt"].as_str().unwrap(), "{name}");
        let notices: Vec<String> =
            answer["notices"].as_array().unwrap().iter().map(|notice| notice.as_str().unwrap().to_owned()).collect();
        assert_eq!(recording.take(), notices, "{name}");
        let entries = heard.0.lock().unwrap().clone();
        assert_eq!(entries.len(), 1, "{name}");
        let (entry, audit) = (&entries[0], &answer["audit"]);
        assert_eq!(entry.operation.wire_name(), audit["operation"].as_str().unwrap(), "{name}");
        assert_eq!(entry.resource_id.as_deref(), audit["resourceId"].as_str(), "{name}");
        assert_eq!(entry.description.as_deref(), audit["description"].as_str(), "{name}");
        assert_eq!(entry.user_id.as_deref(), audit["user"].as_str(), "{name}");
        assert_eq!(entry.ip_address.as_deref(), audit["ip"].as_str(), "{name}");
        assert_eq!(entry.user_agent.as_deref(), audit["userAgent"].as_str(), "{name}");
        assert_eq!(entry.signal.map(|signal| signal.0), audit["signal"].as_str(), "{name}");
    }
}

/// What every connection test answers, and what it sent.
async fn reference_tests(db: &Db, reference: &Value) {
    let now = reference_now(reference);
    let recording = Arc::new(Recording::default());
    let module = compose(db, recording.clone(), TestClock::at(now), None);
    let cases = reference["tests"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    assert_eq!(reference["refusedByPolicy"].as_str().unwrap(), REFUSED_BY_POLICY);
    assert_eq!(reference["notDelivered"].as_str().unwrap(), NOT_DELIVERED);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        reset(db).await;
        recording.take();
        if let Some(stored) = case.get("stored") {
            put(
                db,
                &Row {
                    enabled: true,
                    protocol: stored["protocol"].as_str().unwrap(),
                    endpoint: stored["endpoint"].as_str(),
                    header: None,
                    ca: stored["ca"].as_str(),
                    min_severity: "HIGH",
                    at: now,
                },
            )
            .await;
        }
        let request = &case["request"];
        recording.answering(match request["outcome"].as_str().unwrap() {
            "unsafe" => Some(SendError::Refused(UnsafeUrl("SIEM export: loopback refused".into()))),
            "failed" => Some(SendError::failed("OutboundFailureException", "SIEM export: Connection refused")),
            _ => None,
        });
        let header = text(&request["header"]).map(Secret::new);
        let result = module
            .exporter
            .test_connection(
                request["protocol"].as_str(),
                request["endpoint"].as_str(),
                header.as_ref(),
                request["ca"].as_str(),
            )
            .await
            .unwrap();
        let answer = &case["answer"];
        assert_eq!(result.success, answer["success"].as_bool().unwrap(), "{name}");
        assert_eq!(result.message, answer["message"].as_str().unwrap(), "{name}");
        assert_eq!(i64::from(result.status_code), answer["statusCode"].as_i64().unwrap(), "{name}");
        let sent: Vec<String> =
            answer["sent"].as_array().unwrap().iter().map(|line| line.as_str().unwrap().to_owned()).collect();
        assert_eq!(recording.take(), sent, "{name}");
    }
}

// ---- the wiring ----

/// An entry and its outbox row commit together, in the entry's transaction; the event is the entry's.
async fn the_entry_and_its_event_commit_together(db: &Db) {
    reset(db).await;
    let module = compose(db, Arc::new(Recording::default()), TestClock::system(), None);
    put(
        db,
        &Row {
            enabled: true,
            protocol: "SYSLOG_UDP",
            endpoint: Some("127.0.0.1:9"),
            header: None,
            ca: None,
            min_severity: "LOW",
            at: OffsetDateTime::now_utc(),
        },
    )
    .await;
    let before = audit_descriptions(db).await.len();
    module
        .audit
        .append(Record::of(AuditOperation::ApiKeyCreated, "42", "API key issued: together", Some("alice")))
        .await
        .unwrap();
    assert_eq!(audit_descriptions(db).await.len(), before + 1);
    let rows = outbox_rows(db).await;
    assert_eq!(rows.len(), 1);
    let entry = module.audit.recent(1).await.unwrap().remove(0);
    let queued = QueuedEvent::read(&rows[0].payload).unwrap();
    assert_eq!(queued.event_type.as_deref(), Some("API_KEY_ISSUED"));
    assert_eq!(queued.message.as_deref(), Some("API key issued: together"));
    // The event's moment is the entry's, to the millisecond CEF carries.
    assert_eq!(i128::from(queued.timestamp), entry.timestamp.unix_timestamp_nanos() / 1_000_000);
}

/// A listener before the SIEM's that refuses in the transaction: the entry is written again alone, and the SIEM hears
/// it after the commit — its event queued apart, by the fallback.
async fn the_fallback_queues_after_the_entry_commits(db: &Db) {
    reset(db).await;
    put(
        db,
        &Row {
            enabled: true,
            protocol: "SYSLOG_UDP",
            endpoint: Some("127.0.0.1:9"),
            header: None,
            ca: None,
            min_severity: "LOW",
            at: OffsetDateTime::now_utc(),
        },
    )
    .await;
    let module = compose(db, Arc::new(Recording::default()), TestClock::system(), None);
    let audit = AuditLog::new(
        db.clone(),
        Arc::new(NoMirror),
        TestClock::system(),
        vec![Arc::new(Refusing) as Arc<dyn Listener>, module.events.clone()],
    );
    audit
        .append(Record::of(AuditOperation::ApiKeyCreated, "44", "API key issued: apart", Some("carol")))
        .await
        .unwrap();
    assert!(audit_descriptions(db).await.contains(&"API key issued: apart".to_owned()));
    let rows = outbox_rows(db).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(QueuedEvent::read(&rows[0].payload).unwrap().message.as_deref(), Some("API key issued: apart"));
}

/// Refuses every entry in its transaction.
struct Refusing;

impl Listener for Refusing {
    fn recorded_in_transaction<'a>(
        &'a self,
        _entry: &'a Record,
        _at: OffsetDateTime,
        _tx: &'a mut Tx,
    ) -> BoxFuture<'a, Result<(), ListenerError>> {
        Box::pin(async { Err::<(), ListenerError>("refused on purpose".into()) })
    }

    fn recorded<'a>(&'a self, _entry: &'a Record, _at: OffsetDateTime) -> BoxFuture<'a, Result<(), ListenerError>> {
        Box::pin(async { Ok(()) })
    }

    fn name(&self) -> &str {
        "Refusing"
    }
}

/// The listener's failure aborts the entry's transaction; the entry is written again alone, and the fallback's
/// failure is logged — the entry is never lost to the export.
async fn a_failing_listener_costs_the_entry_nothing(db: &Db) {
    reset(db).await;
    let module = compose(db, Arc::new(Recording::default()), TestClock::system(), None);
    put(
        db,
        &Row {
            enabled: true,
            protocol: "SYSLOG_UDP",
            endpoint: Some("127.0.0.1:9"),
            header: None,
            ca: None,
            min_severity: "LOW",
            at: OffsetDateTime::now_utc(),
        },
    )
    .await;
    sql(
        db,
        "rename table t_outbox_message to t_outbox_message_away",
        "alter table t_outbox_message rename to t_outbox_message_away",
    )
    .await;
    let written = module
        .audit
        .append(Record::of(AuditOperation::ApiKeyCreated, "43", "API key issued: alone", Some("bob")))
        .await;
    sql(
        db,
        "rename table t_outbox_message_away to t_outbox_message",
        "alter table t_outbox_message_away rename to t_outbox_message",
    )
    .await;
    written.unwrap();
    assert!(audit_descriptions(db).await.contains(&"API key issued: alone".to_owned()));
    assert!(outbox_rows(db).await.is_empty());
}

async fn an_event_rolled_back_is_never_sent(db: &Db) {
    reset(db).await;
    allow_private(db, true).await;
    let (collector, port) = udp().await;
    let module = compose(db, real_sender(db, &TlsTrust::BuiltIn), TestClock::system(), None);
    module
        .exporter
        .save_config(update(true, "SYSLOG_UDP", &format!("127.0.0.1:{port}"), "LOW"), &admin())
        .await
        .unwrap();
    sql(db, "delete from t_outbox_message", "delete from t_outbox_message").await;

    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    module.events.enqueue(&mut tx, &kev("CVE-2026-0001")).await.unwrap();
    tx.rollback().await.unwrap();
    module.outbox.relay(20).await.unwrap();
    assert!(outbox_rows(db).await.is_empty());
    assert!(support::datagrams(&collector, Duration::from_millis(500)).await.is_empty());

    // The same event, committed, is: the difference is the transaction and nothing else.
    enqueue_committed(&module.events, db, &kev("CVE-2026-0002")).await;
    module.outbox.relay(20).await.unwrap();
    let received = support::datagrams(&collector, Duration::from_secs(3)).await;
    assert_eq!(received.len(), 1, "{received:?}");
    assert!(received[0].contains("cs3=CVE-2026-0002"), "{}", received[0]);
}

async fn an_audited_action_reaches_the_collector_after_the_relay(db: &Db) {
    reset(db).await;
    allow_private(db, true).await;
    let (collector, port) = udp().await;
    let module = compose(db, real_sender(db, &TlsTrust::BuiltIn), TestClock::system(), None);
    module
        .exporter
        .save_config(update(true, "SYSLOG_UDP", &format!("127.0.0.1:{port}"), "LOW"), &admin())
        .await
        .unwrap();
    module.audit.record(admin().entry(AuditOperation::ApiKeyCreated, "7", "API key issued: ci-pipeline")).await;

    // Queued, not sent: nothing leaves on the request path.
    let rows = outbox_rows(db).await;
    assert_eq!(rows.len(), 2, "the save's own change and the key: {rows:?}");
    assert!(support::datagrams(&collector, Duration::from_millis(300)).await.is_empty());

    let relayed = module.outbox.relay(20).await.unwrap();
    assert_eq!(relayed.sent, 2);
    let received = support::datagrams(&collector, Duration::from_secs(3)).await;
    let key = received.iter().find(|message| message.contains("|VECTI-SEC-012|")).expect("the key's event");
    assert!(key.starts_with('<'), "{key}");
    assert!(
        key.contains(&format!(" {HOSTNAME} vectispire - VECTI-SEC-012 - CEF:0|Vectispire|ASPM|{VERSION}|")),
        "{key}"
    );
    assert!(key.contains("|VECTI-SEC-012|API key issued|5|"), "{key}");
    assert!(
        key.contains("act=API_KEY_CREATED") && key.contains("suser=admin") && key.contains("src=10.0.0.1"),
        "{key}"
    );
    let id = rows.iter().find(|row| row.payload.contains("API_KEY_ISSUED")).unwrap().id.clone();
    assert!(key.contains(&format!("externalId={id}")), "{key}");
    // The save of the configuration is a security-relevant change, and says so.
    assert!(received.iter().any(|message| message.contains("|VECTI-SEC-019|")), "{received:?}");
    assert!(outbox_rows(db).await.iter().all(|row| row.status == "sent"));
}

async fn a_collector_that_is_down_gets_the_event_later(db: &Db) {
    reset(db).await;
    allow_private(db, true).await;
    let port = support::closed_port();
    let module = compose(db, real_sender(db, &TlsTrust::BuiltIn), TestClock::system(), None);
    module
        .exporter
        .save_config(update(true, "SYSLOG_TCP", &format!("127.0.0.1:{port}"), "LOW"), &admin())
        .await
        .unwrap();
    sql(db, "delete from t_outbox_message", "delete from t_outbox_message").await;
    enqueue_committed(&module.events, db, &kev("CVE-2026-0004")).await;
    module.outbox.relay(20).await.unwrap();

    let failed = outbox_rows(db).await.remove(0);
    assert_eq!((failed.status.as_str(), failed.attempts, failed.next_attempt_at), ("pending", 1, true));
    let reason = failed.last_error.clone().unwrap();
    assert!(
        reason.starts_with(&format!("OutboundFailureException: SIEM export: 127.0.0.1:{port} is unreachable")),
        "{reason}"
    );

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let frame = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        String::from_utf8(bytes).unwrap()
    });
    // The backoff is a minute; the test brings the next attempt forward rather than waiting.
    sql(db, "update t_outbox_message set next_attempt_at = null", "update t_outbox_message set next_attempt_at = null")
        .await;
    module.outbox.relay(20).await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(10), frame).await.unwrap().unwrap();
    // Octet-counted: the length, a space, then the RFC 5424 message.
    let (length, message) = received.split_once(' ').unwrap();
    assert_eq!(length.parse::<usize>().unwrap(), message.len());
    assert!(message.starts_with("<82>1 "), "{message}");
    assert!(
        message.contains(&format!("externalId={}", failed.id)) && message.contains("cs3=CVE-2026-0004"),
        "{message}"
    );
    let sent = outbox_rows(db).await.remove(0);
    assert_eq!((sent.status.as_str(), sent.attempts), ("sent", 2));
}

async fn the_minimum_decides_what_is_queued(db: &Db) {
    reset(db).await;
    let module = compose(db, Arc::new(Recording::default()), TestClock::system(), None);
    module.exporter.save_config(update(true, "SYSLOG_UDP", "127.0.0.1:9", "CRITICAL"), &admin()).await.unwrap();
    assert!(outbox_rows(db).await.is_empty(), "the save's own change is 6, below CRITICAL");
    module.audit.record(admin().entry(AuditOperation::ApiKeyCreated, "8", "API key issued: below")).await;
    assert!(outbox_rows(db).await.is_empty());
    enqueue_committed(&module.events, db, &kev("CVE-2026-0005")).await;
    assert_eq!(outbox_rows(db).await.len(), 1);

    // An export switched off, or with no endpoint, queues nothing at all.
    for (enabled, endpoint) in [(false, Some("127.0.0.1:9")), (true, Some(" \t")), (true, None)] {
        sql(db, "delete from t_outbox_message", "delete from t_outbox_message").await;
        put(
            db,
            &Row {
                enabled,
                protocol: "SYSLOG_UDP",
                endpoint,
                header: None,
                ca: None,
                min_severity: "LOW",
                at: OffsetDateTime::now_utc(),
            },
        )
        .await;
        enqueue_committed(&module.events, db, &kev("CVE-2026-0008")).await;
        assert!(outbox_rows(db).await.is_empty(), "enabled={enabled}, endpoint={endpoint:?}");
    }
}

async fn an_export_switched_off_abandons_what_was_queued(db: &Db) {
    reset(db).await;
    let module = compose(db, Arc::new(Recording::default()), TestClock::system(), None);
    module.exporter.save_config(update(true, "SYSLOG_UDP", "127.0.0.1:9", "LOW"), &admin()).await.unwrap();
    sql(db, "delete from t_outbox_message", "delete from t_outbox_message").await;
    enqueue_committed(&module.events, db, &kev("CVE-2026-0006")).await;
    module.exporter.save_config(update(false, "SYSLOG_UDP", "127.0.0.1:9", "LOW"), &admin()).await.unwrap();
    module.outbox.relay(20).await.unwrap();

    let abandoned = outbox_rows(db).await.remove(0);
    assert_eq!((abandoned.status.as_str(), abandoned.attempts), ("failed", 1));
    assert_eq!(
        abandoned.last_error.as_deref(),
        Some("the SIEM export was switched off or its endpoint cleared after this event was queued")
    );
}

async fn the_collector_left_behind_is_told(db: &Db) {
    reset(db).await;
    allow_private(db, true).await;
    let module = compose(db, real_sender(db, &TlsTrust::BuiltIn), TestClock::system(), None);
    let (left, left_port) = udp().await;
    let (next, next_port) = udp().await;
    // CRITICAL: the notice is 7, and a threshold must not swallow the message explaining the silence after it.
    module
        .exporter
        .save_config(update(true, "SYSLOG_UDP", &format!("127.0.0.1:{left_port}"), "CRITICAL"), &admin())
        .await
        .unwrap();
    assert!(support::datagrams(&left, Duration::from_millis(300)).await.is_empty());

    module
        .exporter
        .save_config(update(true, "SYSLOG_UDP", &format!("127.0.0.1:{next_port}"), "CRITICAL"), &admin())
        .await
        .unwrap();
    let told = support::datagrams(&left, Duration::from_secs(3)).await;
    assert_eq!(told.len(), 1, "{told:?}");
    assert!(told[0].contains(" VECTI-SEC-028 - ") && told[0].contains("pointed at another collector"), "{}", told[0]);
    assert!(!told[0].contains(&next_port.to_string()), "the new destination is not named: {}", told[0]);
    assert!(support::datagrams(&next, Duration::from_millis(300)).await.is_empty());

    // A save that keeps the destination — a new threshold — leaves nobody.
    module
        .exporter
        .save_config(update(true, "SYSLOG_UDP", &format!("127.0.0.1:{next_port}"), "HIGH"), &admin())
        .await
        .unwrap();
    assert!(support::datagrams(&next, Duration::from_millis(500)).await.iter().all(|m| !m.contains("VECTI-SEC-028")));

    // Switched off: told at once, whatever the threshold, and nothing left in the outbox to deliver it later.
    sql(db, "delete from t_outbox_message", "delete from t_outbox_message").await;
    module
        .exporter
        .save_config(update(false, "SYSLOG_UDP", &format!("127.0.0.1:{next_port}"), "CRITICAL"), &admin())
        .await
        .unwrap();
    let off = support::datagrams(&next, Duration::from_secs(3)).await;
    assert_eq!(off.len(), 1, "{off:?}");
    for expected in [
        " VECTI-SEC-028 - CEF:0|Vectispire|ASPM|",
        "SIEM export switched off or redirected",
        "suser=admin",
        "switched off: no further events",
    ] {
        assert!(off[0].contains(expected), "{expected}: {}", off[0]);
    }
    assert!(outbox_rows(db).await.is_empty());
    let last = audit_descriptions(db).await.pop().unwrap();
    assert!(last.contains("enabled=false") && last.contains("stop notice delivered"), "{last}");

    // A collector that cannot be told does not keep the export on: the audit says the notice did not arrive.
    let closed = support::closed_port();
    module
        .exporter
        .save_config(update(true, "SYSLOG_TCP", &format!("127.0.0.1:{closed}"), "HIGH"), &admin())
        .await
        .unwrap();
    module
        .exporter
        .save_config(update(false, "SYSLOG_TCP", &format!("127.0.0.1:{closed}"), "HIGH"), &admin())
        .await
        .unwrap();
    let last = audit_descriptions(db).await.pop().unwrap();
    assert!(last.contains("enabled=false") && last.contains("stop notice NOT delivered"), "{last}");
}

async fn a_tls_collector_is_reached_through_its_pinned_ca(db: &Db) {
    reset(db).await;
    allow_private(db, true).await;
    let pki = Pki::create("Corp SOC Root");
    let (port, mut received) = pki.listen().await;
    let endpoint = format!("127.0.0.1:{port}");
    let module = compose(db, real_sender(db, &TlsTrust::BuiltIn), TestClock::system(), None);

    // The connection test: the runtime's authorities do not hold the private CA, another CA is no better, the
    // collector's own CA reaches it.
    let blank = module.exporter.test_connection(Some("SYSLOG_TLS"), Some(&endpoint), None, Some("")).await.unwrap();
    assert_eq!((blank.success, blank.message.as_str()), (false, NOT_DELIVERED));
    assert!(received.recv().await.unwrap().is_empty());
    let other = Pki::create("Someone Else").ca_pem;
    let wrong = module.exporter.test_connection(Some("SYSLOG_TLS"), Some(&endpoint), None, Some(&other)).await.unwrap();
    assert!(!wrong.success);
    assert!(received.recv().await.unwrap().is_empty());
    let pinned =
        module.exporter.test_connection(Some("SYSLOG_TLS"), Some(&endpoint), None, Some(&pki.ca_pem)).await.unwrap();
    assert_eq!(
        (pinned.success, pinned.message.as_str(), pinned.status_code),
        (true, "Event delivered over SYSLOG_TLS.", 0)
    );
    let ping = String::from_utf8(received.recv().await.unwrap()).unwrap();
    assert!(ping.contains(" VECTI-SEC-999 - CEF:0|Vectispire|ASPM|"), "{ping}");

    // A queued event, through the stored CA.
    module
        .exporter
        .save_config(
            SiemConfigUpdate { tls_ca_pem: Some(pki.ca_pem.clone()), ..update(true, "SYSLOG_TLS", &endpoint, "HIGH") },
            &admin(),
        )
        .await
        .unwrap();
    let event = CefEvent::builder(SecurityEventType::SecuritySettingChanged, Instant { epoch_second: 1, nano: 0 })
        .message("probe")
        .build()
        .unwrap();
    let id = Uuid::new_v4();
    let payload = vectispire_cp_outbox::stamped(&QueuedEvent::of(&event), id).unwrap();
    module.delivery.deliver_message(id, &payload).await.unwrap();
    let frame = String::from_utf8(received.recv().await.unwrap()).unwrap();
    assert!(
        frame.contains(" VECTI-SEC-019 - CEF:0|Vectispire|ASPM|") && frame.contains(&format!("externalId={id}")),
        "{frame}"
    );

    // A runtime whose bundle is that CA reaches it with nothing pinned: the bundle replaces the authorities.
    let bundled =
        compose(db, real_sender(db, &TlsTrust::from_bundle(&pki.ca_path()).unwrap()), TestClock::system(), None);
    let runtime = bundled.exporter.test_connection(Some("SYSLOG_TLS"), Some(&endpoint), None, Some("")).await.unwrap();
    assert!(runtime.success, "{runtime:?}");
    assert!(!received.recv().await.unwrap().is_empty());
}

async fn a_lapsed_stored_ca_abandons_the_event(db: &Db) {
    reset(db).await;
    let module = compose(db, Arc::new(Recording::default()), TestClock::system(), None);
    let lapsed = vectispire_testkit::read("siem/collector-ca/05-expired.pem");
    // Written past the save, as a CA that was current when saved and lapsed since would be.
    put(
        db,
        &Row {
            enabled: true,
            protocol: "SYSLOG_TLS",
            endpoint: Some("127.0.0.1:6514"),
            header: None,
            ca: Some(&lapsed),
            min_severity: "HIGH",
            at: OffsetDateTime::now_utc(),
        },
    )
    .await;
    let id = Uuid::new_v4();
    let payload = vectispire_cp_outbox::stamped(&QueuedEvent::of(&kev("CVE-2026-0007")), id).unwrap();
    let Err(DeliveryError::Gone(reason)) = module.delivery.deliver_message(id, &payload).await else { panic!() };
    assert!(reason.contains("collector CA") && reason.contains("expired"), "{reason}");
    let view = module.exporter.get_config().await.unwrap().unwrap();
    assert_eq!(view.tls_ca_subject.as_deref(), Some("CN=Old Root"));
}

async fn the_private_switch_decides_the_reach(db: &Db) {
    reset(db).await;
    let module = compose(db, real_sender(db, &TlsTrust::BuiltIn), TestClock::system(), None);
    let closed = format!("http://127.0.0.1:{}/events", support::closed_port());

    // Off — the default, and what an administrator alone may change.
    let refused = module.exporter.test_connection(None, Some(&closed), None, None).await.unwrap();
    assert_eq!((refused.success, refused.message.as_str()), (false, REFUSED_BY_POLICY));
    let syslog_port = support::closed_port();
    let syslog = module
        .exporter
        .test_connection(Some("SYSLOG_TCP"), Some(&format!("127.0.0.1:{syslog_port}")), None, None)
        .await
        .unwrap();
    assert_eq!(syslog.message, REFUSED_BY_POLICY);

    // On, the attempt is made, and fails on the closed port — answered in the same words as a server answering 404:
    // the outcome, never the socket's.
    allow_private(db, true).await;
    let attempted = module.exporter.test_connection(None, Some(&closed), None, None).await.unwrap();
    assert_eq!((attempted.success, attempted.message.as_str()), (false, NOT_DELIVERED));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 8192];
        let _ = stream.read(&mut buffer).await;
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
    });
    let answering = module
        .exporter
        .test_connection(None, Some(&format!("http://127.0.0.1:{port}/events")), None, None)
        .await
        .unwrap();
    assert_eq!(answering, attempted);
    allow_private(db, false).await;
}

async fn the_header_is_encrypted_at_rest(db: &Db) {
    reset(db).await;
    let module = compose(db, Arc::new(Recording::default()), TestClock::system(), None);
    let saved = module
        .exporter
        .save_config(
            SiemConfigUpdate {
                auth_header: Some(Secret::new("Bearer secret-siem-token-123")),
                ..update(true, "WEBHOOK", "https://siem.example.com/e", "HIGH")
            },
            &admin(),
        )
        .await
        .unwrap();
    assert!(saved.has_auth_header);
    let stored = stored_header(db).await.unwrap();
    assert!(stored.starts_with("v2:") && !stored.contains("secret-siem-token-123"), "{stored}");
    // Bound to its column: under another context it does not read.
    assert_eq!(module.encryption.read_secret(&stored, "elsewhere", "test").await.expose(), "");
    assert_eq!(
        module.encryption.read_secret(&stored, AUTH_HEADER_CONTEXT, "test").await.expose(),
        "Bearer secret-siem-token-123"
    );
    // The audit entry never holds it.
    assert!(audit_descriptions(db).await.iter().all(|entry| !entry.contains("secret-siem-token")));
}
