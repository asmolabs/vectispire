//! **The Java suite's recorded traffic, replayed against the forty-nine routes of `targets`, `scanning` and `agents`**
//! (tasks 2.11, 2.7 and 2.9, plan §4.3) — on MySQL 9.4 and PostgreSQL 17, each migrated by `vectispire-migrate`.
//!
//! **One replay for the three modules, here.** The targets' listings show each target's latest scan and "scan now"
//! queues one — answers of `scanning`'s `TargetScans`, which `cp-targets` cannot compose; an agent's claim, result and
//! failure answer through `scanning`'s dispatcher, and an agent's key resolves only once `agents` is composed, which
//! `cp-scanning` cannot do (the dependencies run from `agents` to `scanning` to `targets`). The deferred list is checked
//! against one set of served routes, so the replay that serves the agents' routes has to serve the others too: it moved
//! here from `cp-scanning` with task 2.9's audit (2026-10-22).
//!
//! Every test of the recording with at least one request to a route this module serves is replayed through
//! `cp-contract`'s `recorded` module: its seed rows written, each of its requests to these routes sent through the real
//! chain — sessions and keys resolved by `cp-access`'s `CredentialService` from the rows the seed minted, the
//! visibility by `VisibilityService` over the stored setting, the entries written by `cp-audit`'s `AuditLog` — and the
//! answer and every row it changed held to Java's; its requests to routes not ported yet are played in Java's place.
//! A recording that does not replay green on **both** engines must be listed in `golden/deferred/` with its reason;
//! one listed that replays green fails, so the list only shrinks. A route of a composed module that a `route` line
//! still covers is not owed: its recordings are played in Java's place until the line goes.
//!
//! The recording is generated, not committed (66 MB at 0.11.1): `crates/cp-contract/scripts/replay-goldens.sh` records
//! the Java suite at this commit and runs this test on it. Without a recording it is ignored — reported as such by
//! `cargo test`, never passed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::print_stdout)]

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use vectispire_cp_access::credentials::{
    CredentialService, ScimToken, SessionPolicy, SystemClock as AccessClock, hash_of, keys, phc,
};
use vectispire_cp_access::{AccessError, AccessSettings, CallerVisibility, PrincipalGrounds, VisibilityService};
use vectispire_cp_agents::{
    AgentAdministrationService, AgentDirectoryImpl, AgentJobPoller, AgentProtocolService, AgentResultAuditDelivery,
    AgentRowLock, Agents, NoAgentPlugins,
};
use vectispire_cp_audit::{AuditLog, AuditOperation, NoMirror, Record, Signal, SystemClock as AuditClock};
use vectispire_cp_contract::recorded::deferred::{Deferred, coverage, describe, listed, served_outside};
use vectispire_cp_contract::recorded::format::Recording;
use vectispire_cp_contract::recorded::placeholders::Minting;
use vectispire_cp_contract::recorded::replay::{Outcome, Replayed, Replayer};
use vectispire_cp_contract::recorded::rows::{self, Schema};
use vectispire_cp_contract::{Document, Schemas};
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_http::buckets::Clock as BucketClock;
use vectispire_cp_http::credentials::{AccessDenied, Audit, BoxFuture};
use vectispire_cp_http::routes::Routes;
use vectispire_cp_http::{Chain, ChainConfig};
use vectispire_cp_outbox::{Outbox, Registry};
use vectispire_cp_scanning::ports::{BundledRules, NoPlugins};
use vectispire_cp_scanning::{Scanning, ScanningConfig};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::deletion::PurgeRegistry;
use vectispire_cp_targets::{SystemClock, Targets, TargetsConfig, TargetsForAccess};
use vectispire_domain::git_host_allowlist::GitHostAllowlist;

use support::Migrated;

/// The credentials, minted and checked with `cp-access`'s own code: what the chain will accept is what it wrote.
struct AccessMinting;

/// `vectispire.scim.token` in the Java suite's `application-apitest.yaml`: the replay's control plane takes it as Java's
/// context does, so that the SCIM recordings' bearer opens `/scim` here too.
const SCIM_TOKEN: &str = "apitest-scim-token-0123456789abcdef";

impl Minting for AccessMinting {
    fn scim_token(&self) -> Option<String> {
        Some(SCIM_TOKEN.to_owned())
    }

    fn session_token(&self) -> String {
        keys::issue_session_token().token.expose().to_owned()
    }

    fn api_key(&self) -> String {
        keys::generate().full_key.expose().to_owned()
    }

    fn sha256_hex(&self, text: &str) -> String {
        hash_of(text)
    }

    fn password_hash(&self, plain: &str) -> String {
        phc::hash(plain)
    }

    fn password_verifies(&self, plain: &str, hash: &str) -> bool {
        phc::verify(plain, hash)
    }

    /// The agent's own signature (`vectispire-crypto`, what the Rust agent sends), for the context it signs: `v2`. An
    /// agent from before bound envelopes signed `v1`, which no Rust code makes — that announcement is not replayed.
    fn sealing_signature(&self, version: &str, seed: &str, agent: &str, generation: i64, key: &str) -> Option<String> {
        let agent = uuid::Uuid::parse_str(agent).ok()?;
        let signer = vectispire_crypto::ResultSigner::from_base64_seed(seed).ok()?;
        match version {
            "v2" => signer.sign_sealing_key(agent, generation, key).ok(),
            // What an agent older than the control plane signs: the replay sends it for the refusal that names it.
            "v1" => signer.sign_sealing_key_as_previous_agent(agent, generation, key).ok(),
            _ => None,
        }
    }

    /// What the Rust agent puts on a result or a failure report: the same `ResultSigner`, over the bytes sent.
    fn result_signature(&self, kind: &str, seed: &str, scan_id: i64, body: &[u8]) -> Option<String> {
        let signer = vectispire_crypto::ResultSigner::from_base64_seed(seed).ok()?;
        match kind {
            "result" => Some(signer.sign_result(scan_id, body)),
            "failure" => Some(signer.sign_failure(scan_id, body)),
            _ => None,
        }
    }

    /// `cp-audit`'s own chain over the entry as seeded: the timestamp read as the column holds it, in UTC, as the
    /// server reads it back to verify.
    fn audit_entry_hash(&self, fields: [Option<&str>; 8]) -> Option<String> {
        let [previous, timestamp, operation, resource, user, ip, agent, description] = fields;
        let format =
            time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second][optional [.[subsecond]]]");
        let timestamp = time::PrimitiveDateTime::parse(timestamp?, format).ok()?.assume_utc();
        let owned = |field: Option<&str>| field.map(str::to_owned);
        Some(vectispire_cp_audit::chain::entry_hash(&vectispire_cp_audit::chain::Entry {
            previous_hash: owned(previous),
            timestamp: Some(timestamp),
            operation_type: owned(operation),
            resource_id: owned(resource),
            user_id: owned(user),
            ip_address: owned(ip),
            user_agent: owned(agent),
            description: owned(description),
        }))
    }
}

/// `target_visibility` as the settings store holds it — a test that switches the installation to `assigned` seeds
/// the row, and the visibility must read it.
struct StoredSettings(Settings);

impl AccessSettings for StoredSettings {
    fn target_visibility(&self) -> BoxFuture<'_, Result<String, AccessError>> {
        Box::pin(async move {
            self.0.get(Setting::TargetVisibility).await.map_err(|error| AccessError::Port(error.to_string()))
        })
    }
}

/// The chain's own entries (`ACCESS_DENIED`), written to the audit log as Java's filter writes them: in the request,
/// before the answer. No crate composes this yet — the binary will (2.11); without it every refusal of the routes
/// differs from Java's by its missing row.
#[derive(Debug)]
struct ChainEntries(AuditLog);

impl ChainEntries {
    fn write(&self, entry: AccessDenied, signal: Option<Signal>) {
        let record = Record {
            operation: AuditOperation::AccessDenied,
            resource_id: Some(entry.path),
            description: Some(entry.detail),
            user_id: entry.who,
            ip_address: Some(entry.address),
            user_agent: entry.user_agent,
            signal,
        };
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(self.0.record(record)));
    }
}

impl Audit for ChainEntries {
    fn access_denied(&self, entry: AccessDenied) {
        self.write(entry, None);
    }

    fn bearer_throttled(&self, entry: AccessDenied) {
        self.write(entry, Some(Signal("BEARER_TOKEN_THROTTLED")));
    }
}

/// The limiters' clock, running only while the router answers. Java's suite sends a test's requests back to back; the
/// replay seeds, snapshots and compares every table between two of them, which takes the throttles' refill period
/// several times over: sixty refused bearers left a token back before the sixtieth, and the refusals that followed were
/// 401 instead of 429, or waited two seconds where Java's waited four. Paused between requests, the buckets see about
/// the time Java's did — less, by Java's own test overhead, which `Retry-After` rounds away.
#[derive(Debug, Default)]
struct AnsweringTime(Mutex<(u128, Option<Instant>)>);

impl AnsweringTime {
    fn start(&self) {
        self.0.lock().unwrap().1 = Some(Instant::now());
    }

    fn stop(&self) {
        let mut state = self.0.lock().unwrap();
        if let Some(since) = state.1.take() {
            state.0 += since.elapsed().as_nanos();
        }
    }
}

impl BucketClock for AnsweringTime {
    fn nanos(&self) -> u128 {
        let state = self.0.lock().unwrap();
        state.0 + state.1.map_or(0, |since| since.elapsed().as_nanos())
    }
}

/// The agents' screens read at the test's start plus the time the router spent answering — the instant Java's
/// back-to-back requests saw, its suite's own overhead aside. The wall clock would add the replay's: it seeds, snapshots
/// and compares every table between two requests, and a scan seeded at the start read as waiting a second
/// (`AgentExecutorsRoutesTest`: 1 where Java's read 0) depending on how loaded the machine was.
#[derive(Debug)]
struct AnsweringClock {
    since: time::OffsetDateTime,
    time: Arc<AnsweringTime>,
}

impl vectispire_cp_targets::Clock for AnsweringClock {
    fn now(&self) -> time::OffsetDateTime {
        let answered = i64::try_from(self.time.nanos()).unwrap_or(i64::MAX);
        self.since + time::Duration::nanoseconds(answered)
    }
}

async fn answering(
    axum::extract::State(time): axum::extract::State<Arc<AnsweringTime>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    time.start();
    let response = next.run(request).await;
    time.stop();
    response
}

/// `cp-runtime`'s actuator as the chain's router asks it — `cp-app/src/actuator.rs`'s `Pages`.
struct ActuatorPagesOf(Arc<vectispire_cp_runtime::actuator::Actuator>);

impl vectispire_cp_http::actuator::ActuatorPages for ActuatorPagesOf {
    fn page<'a>(
        &'a self,
        path: &'a str,
        query: &'a str,
        base_url: &'a str,
    ) -> BoxFuture<'a, Result<Option<vectispire_cp_http::actuator::ActuatorPage>, String>> {
        Box::pin(async move {
            let answer = self.0.respond(path, query, base_url).await?;
            Ok(answer.map(|answer| vectispire_cp_http::actuator::ActuatorPage {
                status: answer.status,
                content_type: answer.content_type,
                body: answer.body,
            }))
        })
    }
}

/// `/actuator/encryption` — `cp-app/src/actuator.rs`'s `Census`.
struct CensusReport(vectispire_cp_crypto::EncryptionCensus);

impl vectispire_cp_runtime::actuator::Report for CensusReport {
    fn read(&self) -> vectispire_cp_runtime::actuator::ReportFuture<'_> {
        Box::pin(self.0.report())
    }
}

/// The scrape token of the Java suite's configuration (`application-apitest.yaml`), which the recorder hides as a
/// `«secret:N»` the replay mints anew: a scrape the recording made with it cannot be sent with it, and is listed.
#[derive(Debug)]
struct ReplayScrapeToken;

impl vectispire_cp_http::credentials::ScrapeToken for ReplayScrapeToken {
    fn token(&self) -> Result<Option<vectispire_domain::secret::Secret>, String> {
        Ok(Some(vectispire_domain::secret::Secret::new("apitest-scrape-token-0123456789abcdef")))
    }
}

/// **What a test class's own context sets** — its `@TestPropertySource` — which the recording does not carry: Java ran
/// that class in a context of its own, so its answers were made under those values, and replayed under the defaults
/// they would be another test's. Copied from the class, one line per property; a class not here ran on
/// `application-apitest.yaml` alone.
/// **A collector a test stood up, run again**: `(class, test, «port:N», CA name)`. The Java test listened with a
/// certificate issued by `CollectorPki.fixture`'s CA, whose key is [`FIXTURE_CA_SCALAR`]; the CA's certificate is in the
/// recording, the collector's never crossed HTTP. So the replay issues its own under the same key and name, listens, and
/// binds the port — the pinned certificate vouches for it, any other CA the test pinned is refused, as in Java.
const COLLECTORS: &[(&str, &str, u32, &str)] =
    &[("api.SiemCollectorCaRoutesTest", "theTestVerifiesAgainstThePinnedCa", 1, "Corp SOC Root")];

/// `CollectorPki.FIXTURE_CA_SCALAR`: the P-256 private scalar of the collector's CA, as ASCII.
const FIXTURE_CA_SCALAR: &[u8; 32] = b"vectispire collector fixture ca.";

fn openssl(directory: &std::path::Path, arguments: &[&str]) {
    let output = std::process::Command::new("openssl")
        .args(arguments)
        .current_dir(directory)
        .output()
        .expect("the openssl command");
    assert!(output.status.success(), "openssl {arguments:?}: {}", String::from_utf8_lossy(&output.stderr));
}

/// A TLS collector on loopback under the fixture CA named `ca_name`, accepting until the runtime ends: its port.
async fn collector(ca_name: &str) -> u16 {
    use p256::pkcs8::EncodePrivateKey;
    use rustls_pki_types::pem::PemObject;
    use tokio::io::AsyncReadExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let ca_key = p256::SecretKey::from_slice(FIXTURE_CA_SCALAR).expect("the fixture scalar is below the order");
    std::fs::write(path.join("ca.key"), ca_key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap().as_bytes()).unwrap();
    // The issuer as Java named it; the certificate itself is never sent — the client holds Java's.
    openssl(
        path,
        &[
            "req",
            "-x509",
            "-new",
            "-key",
            "ca.key",
            "-sha256",
            "-days",
            "2",
            "-subj",
            &format!("/CN={ca_name}"),
            "-out",
            "ca.pem",
        ],
    );
    openssl(path, &["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "server.key"]);
    openssl(path, &["req", "-new", "-key", "server.key", "-subj", "/CN=collector", "-out", "server.csr"]);
    std::fs::write(path.join("server.ext"), "subjectAltName=IP:127.0.0.1\n").unwrap();
    openssl(
        path,
        &[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-sha256",
            "-extfile",
            "server.ext",
            "-out",
            "server.pem",
        ],
    );
    let chain: Vec<_> = rustls_pki_types::CertificateDer::pem_file_iter(path.join("server.pem"))
        .unwrap()
        .map(|certificate| certificate.unwrap())
        .collect();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(path.join("server.key")).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut bytes = Vec::new();
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), tls.read_to_end(&mut bytes)).await;
                }
            });
        }
    });
    port
}

/// The properties a test class sets with `@TestPropertySource`, which its recordings were made under.
const TEST_PROPERTIES: &[(&str, &str, &str)] = &[
    ("api.GitHostAllowlistRoutesTest", "vectispire.git.allowed-hosts", "gitlab.corp.example,*.forge.example"),
    // MockMvc's peer declared a proxy, so `X-Forwarded-For` names the client the audit entry records.
    ("api.ClientAddressRoutesTest", "vectispire.security.trusted-proxies", "127.0.0.1"),
    // The suite's SCIM token, switched off for the class that proves a disabled one is refused.
    ("access.web.scim.ScimTokenDisabledTest", "vectispire.scim.enabled", "false"),
];

fn property(class: &str, key: &str) -> Option<&'static str> {
    TEST_PROPERTIES.iter().find(|(of, named, _)| *of == class && *named == key).map(|(_, _, value)| *value)
}

/// The three modules as the binary composes them, and Phase 3's three, behind the real chain: a fresh set per test. Ingestion is
/// the binary's (task 2.8), over Phase 3's backlog and inventory.
fn router(db: &Db, signing: Arc<vectispire_cp_crypto::SigningKeys>, class: &str) -> axum::Router {
    let allowed_hosts = GitHostAllowlist::parse(property(class, "vectispire.git.allowed-hosts")).unwrap();
    let time = Arc::new(AnsweringTime::default());
    let siem = Siem::over(db);
    let audit = Arc::new(AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(AuditClock), siem.listeners()));
    let targets = Arc::new(Targets::new(TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: vectispire_cp_scanning::target_scans(db.clone(), Arc::new(SystemClock)),
        backlog: Arc::new(vectispire_cp_issues::TargetBacklogFigures::new(db.clone())),
        purge: PurgeRegistry::stand_ins()
            .with(vectispire_cp_scanning::purge::listeners())
            .with_projects(vec![Arc::new(vectispire_cp_checklists::ChecklistPurge)]),
        encryption: support::encryption(),
        allowed_hosts: allowed_hosts.clone(),
        clock: Arc::new(SystemClock),
        visibility: None,
    }));
    let (issues, inventory) = issues_and_inventory(db, &targets, &audit, &siem);
    let scanning = Arc::new(Scanning::new(ScanningConfig {
        db: db.clone(),
        clock: Arc::new(SystemClock),
        targets: targets.clone(),
        encryption: support::encryption(),
        audit: audit.clone(),
        claim_lock: Arc::new(AgentRowLock),
        rule_sets: Arc::new(BundledRules),
        plugins: Arc::new(NoPlugins),
        ingestor: Arc::new(ingestor(db, &issues, &inventory)),
        policy: vectispire_domain::scan_queue::Policy::default(),
        leader_lease: vectispire_cp_scanning::DEFAULT_LEASE,
        allowed_hosts,
        image_platform: None,
        runner: None,
        // The checklists' `RepositoryScanned`: the `checklist_answer` message queued in the scan's transaction, on an
        // enqueue-only outbox over the same table — what the replay compares is the row.
        scanned: vec![Arc::new(vectispire_cp_checklists::AnswersFromEvidence {
            outbox: Arc::new(Outbox::on_database(
                db.clone(),
                Registry::new(Vec::new(), Vec::new()),
                Arc::new(vectispire_cp_maintenance::SystemClock),
            )),
            settings: Arc::new(Settings::new(db.clone())),
        })],
    }));
    // The actuator as `cp-app/src/actuator.rs` composes it: the runtime's pages, the census of the stores the port has.
    let census_exporter = Arc::new(vectispire_cp_siem::SiemExporterService::new(
        db.clone(),
        siem.sender.clone(),
        support::encryption(),
        (*audit).clone(),
        Arc::new(AuditClock),
    ));
    let census = vectispire_cp_crypto::EncryptionCensus::new(vec![signing.clone(), targets.clone(), census_exporter]);
    let actuator = Arc::new(vectispire_cp_runtime::actuator::Actuator::new(
        Arc::new(vectispire_cp_runtime::actuator::Health::default()),
        Arc::new(vectispire_cp_runtime::metrics::Metrics::new("vectispire")),
        vectispire_cp_runtime::actuator::BuildInfo {
            group: "vectispire".to_owned(),
            artifact: "vectispire-core".to_owned(),
            name: "vectispire-core".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            time: None,
        },
    ));
    actuator.serve_encryption(Arc::new(CensusReport(census)));
    let checklist_routes = checklists(db, &targets, &audit, &signing);
    let mut modules = phase_three(db, targets.clone(), audit.clone(), &siem, signing, issues, inventory);
    modules.extend(checklist_routes);
    let credentials = Arc::new(CredentialService::new(
        db.clone(),
        Arc::new(AccessClock),
        SessionPolicy::default(),
        Arc::new(AgentDirectoryImpl::new(db.clone())),
        ScimToken {
            enabled: property(class, "vectispire.scim.enabled") != Some("false"),
            token: Some(vectispire_domain::secret::Secret::new(SCIM_TOKEN)),
        },
    ));
    let outbox = Arc::new(Outbox::on_database(
        db.clone(),
        Registry::new(vec![Arc::new(AgentResultAuditDelivery::new(audit.clone()))], Vec::new()),
        Arc::new(vectispire_cp_maintenance::SystemClock),
    ));
    let dispatcher = scanning.dispatcher_arc();
    let admin = Arc::new(
        AgentAdministrationService::new(
            db.clone(),
            credentials.clone(),
            Arc::new(scanning.catalog().clone()),
            targets.clone(),
            audit.clone(),
            Vec::new(),
            false,
        )
        .with_clock(Arc::new(AnsweringClock { since: time::OffsetDateTime::now_utc(), time: time.clone() })),
    );
    let protocol = Arc::new(AgentProtocolService::new(
        db.clone(),
        dispatcher.clone(),
        audit,
        outbox,
        Arc::new(BundledRules),
        Arc::new(NoAgentPlugins),
    ));
    let poller = Arc::new(AgentJobPoller::new(dispatcher, protocol.clone()));
    let agents = Arc::new(Agents::new(admin, protocol, poller));

    let settings = Arc::new(StoredSettings(Settings::new(db.clone())));
    let visibility = VisibilityService::new(db.clone(), settings, Arc::new(TargetsForAccess(db.clone())));
    let mut routes = Routes::new(CallerVisibility::new(visibility, Arc::new(PrincipalGrounds)))
        .actuator(Arc::new(ActuatorPagesOf(actuator)));
    for entry in vectispire_cp_targets::routes(targets)
        .into_iter()
        .chain(vectispire_cp_scanning::routes(scanning))
        .chain(vectispire_cp_agents::routes(agents))
        .chain(modules)
    {
        routes = routes.route(entry);
    }
    // The chain's entries signal too (`BEARER_TOKEN_THROTTLED`): the SIEM hears them as it hears the routes'.
    let entries = ChainEntries(AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(AuditClock), siem.listeners()));
    let chain = Arc::new(
        Chain::with_clock(
            ChainConfig {
                trusted_proxies: vectispire_cp_http::address::TrustedProxies::parse(
                    property(class, "vectispire.security.trusted-proxies").unwrap_or(""),
                )
                .unwrap(),
                ..ChainConfig::default()
            },
            credentials,
            Arc::new(entries),
            time.clone(),
        )
        .with_scrape_token(Arc::new(ReplayScrapeToken)),
    );
    routes.build(&chain, None).unwrap().layer(axum::middleware::from_fn_with_state(time, answering))
}

/// The SIEM export as `cp-app/src/siem.rs` composes it: the real sender (no reserved endpoint, the private switch read
/// from the settings the recording seeds), the events queued through an enqueue-only outbox over the same table — the
/// audit log's listener, and the issues' and the gate's `SecurityEvents`. Nothing is relayed: what the replay compares
/// is the row each request queues.
struct Siem {
    events: Arc<vectispire_cp_siem::SiemEvents>,
    sender: Arc<vectispire_cp_siem::SiemSender>,
}

impl Siem {
    fn over(db: &Db) -> Siem {
        let sender = Arc::new(vectispire_cp_siem::SiemSender::new(
            vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
            vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
            vectispire_cp_siem::SyslogSender::new(&vectispire_tls::TlsTrust::BuiltIn).unwrap(),
            Arc::new(Settings::new(db.clone())),
            None,
        ));
        let queue = Arc::new(Outbox::on_database(
            db.clone(),
            Registry::new(Vec::new(), Vec::new()),
            Arc::new(vectispire_cp_maintenance::SystemClock),
        ));
        let events = Arc::new(vectispire_cp_siem::SiemEvents::new(db.clone(), queue, Arc::new(AuditClock)));
        Siem { events, sender }
    }

    fn listeners(&self) -> Vec<Arc<dyn vectispire_cp_audit::Listener>> {
        vec![self.events.clone()]
    }
}

/// The Java suite's own `vectispire.signing.key`, `FixtureSigningKey`: the P-256 key whose scalar is these thirty-two
/// ASCII bytes, in PKCS#8 PEM. The same key on both sides, so that a signature the suite made and recorded as it is
/// (`/api/v1/crypto/verify`) verifies here, and the published public key is Java's byte for byte. A fixture, not a
/// secret: it signs test documents only.
fn signing_key_pem() -> String {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    p256::SecretKey::from_slice(b"vectispire golden replay fixture")
        .unwrap()
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string()
}

/// The issues, gate, posture, inventory, SIEM and platform modules as the binary composes them, on the scan catalog and the
/// targets above.
/// The integrations' registry as `cp-app/src/registry.rs` composes it: the SIEM's transport and a notification
/// channel with a destination are the uses that refuse a switch-off.
fn integrations(db: &Db) -> vectispire_cp_settings::Integrations {
    let uses: Vec<Arc<dyn vectispire_cp_settings::InUse>> = vec![
        Arc::new(vectispire_cp_siem::SiemTransportInUse),
        Arc::new(vectispire_cp_notifications::NotificationChannelInUse::new(
            vectispire_cp_notifications::NotificationDestinations::new(Settings::new(db.clone())),
        )),
    ];
    vectispire_cp_settings::Integrations::new(db.clone(), uses, Arc::new(time::OffsetDateTime::now_utc))
}

/// The notifications module as `cp-app/src/notifications.rs` composes it (`compose_plain`): no public address, no mail
/// relay, a guard reserving nothing.
fn notifications(db: &Db) -> (vectispire_cp_notifications::NotificationsConfig, vectispire_cp_notifications::Channels) {
    let config = vectispire_cp_notifications::NotificationsConfig {
        db: db.clone(),
        settings: Settings::new(db.clone()),
        integrations: integrations(db),
        encryption: support::encryption(),
        post: vectispire_cp_outbound::OutboundPost::new(
            vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
            vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        ),
        public_url: None,
        mail: None,
        mail_from: "vectispire@localhost".to_owned(),
        clock: Arc::new(AuditClock),
    };
    let channels = vectispire_cp_notifications::channels(&config);
    (config, channels)
}

/// The issues and inventory modules as `cp-app` composes them — before scanning, whose ingestion writes into both.
fn issues_and_inventory(
    db: &Db,
    targets: &Arc<Targets>,
    audit: &Arc<AuditLog>,
    siem: &Siem,
) -> (Arc<vectispire_cp_issues::Issues>, Arc<vectispire_cp_inventory::Inventory>) {
    let scans = Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(SystemClock)));
    // A scan's delta routed to the channels in the scan's transaction, on an enqueue-only outbox over the same table.
    let (notifications, channels) = notifications(db);
    let deltas = Arc::new(vectispire_cp_notifications::ScanDeltaNotifier::new(
        channels.service.clone(),
        channels.all(),
        Arc::new(Outbox::on_database(
            db.clone(),
            Registry::new(Vec::new(), Vec::new()),
            Arc::new(vectispire_cp_maintenance::SystemClock),
        )),
        Arc::new(vectispire_cp_notifications::routing::TargetsDirectory::new(targets.clone(), db.clone())),
        notifications.integrations.clone(),
    ));
    let issues = Arc::new(
        vectispire_cp_issues::Issues::new(vectispire_cp_issues::IssuesConfig {
            db: db.clone(),
            targets: targets.clone(),
            scans: (*scans).clone(),
            settings: Arc::new(Settings::new(db.clone())),
            audit: audit.clone(),
            events: siem.events.clone(),
        })
        .with_scan_deltas(deltas),
    );
    let inventory = Arc::new(vectispire_cp_inventory::Inventory::new(vectispire_cp_inventory::InventoryConfig {
        db: db.clone(),
        scans,
        targets: targets.clone(),
        audit: audit.clone(),
    }));
    (issues, inventory)
}

/// `cp-app::ingestion::ingestor`, which this crate cannot depend on: the backlog and inventory above, the licences read
/// from the settings, the two `threatintel` sources as their named stand-ins. `cp-app/tests/ingestion_composition.rs`
/// holds the binary to the same three sources.
fn ingestor(
    db: &Db,
    issues: &vectispire_cp_issues::Issues,
    inventory: &vectispire_cp_inventory::Inventory,
) -> vectispire_cp_scanning::ingestion::ScanIngestor {
    use vectispire_cp_scanning::ingestion::{EndOfLifeStandIn, EnrichmentStandIn, LicenseService, ScanIngestor};
    ScanIngestor::new(
        issues.backlog().clone(),
        inventory.sink(),
        Some(Arc::new(EnrichmentStandIn)),
        Some(Arc::new(EndOfLifeStandIn)),
        Some(Arc::new(LicenseService::from_settings(Settings::new(db.clone())))),
        Arc::new(SystemClock),
    )
}

/// The version the recorded suite's `BuildProperties` carried — `gradle.properties`' — which `ProductVersion` stamps on
/// a signed checklist document: the recording's rows name it.
fn java_build_version() -> Option<String> {
    let properties =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vectispire-java/gradle.properties");
    std::fs::read_to_string(properties)
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("version=").map(|version| version.trim().to_owned()))
}

/// The checklists module (wave 1) as `cp-app` composes it: its measurements over the owners' catalogues, the plugins'
/// imports and the forges' readings as their stand-ins, documents signed with the suite's fixture key.
fn checklists(
    db: &Db,
    targets: &Arc<Targets>,
    audit: &Arc<AuditLog>,
    signing: &Arc<vectispire_cp_crypto::SigningKeys>,
) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    use vectispire_cp_checklists as checklists;
    let settings = Arc::new(Settings::new(db.clone()));
    let clock: Arc<dyn vectispire_cp_targets::Clock> = Arc::new(SystemClock);
    let measurer = checklists::measurer::Measurer::new(
        Arc::new(checklists::OwnerCatalogs {
            scans: vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(SystemClock)),
            issues: vectispire_cp_issues::IssueCatalog::new(db.clone()),
            components: vectispire_cp_inventory::component_catalog::ComponentCatalog::new(db.clone()),
            targets: targets.clone(),
        }),
        Arc::new(checklists::measurer::NoImports),
        Arc::new(checklists::measurer::NoReviews),
    );
    let projects: Arc<dyn checklists::ports::ProjectDirectory> = Arc::new(checklists::TargetProjects(targets.clone()));
    let independence = vectispire_cp_access::independence::ApproverIndependence::new(db.clone(), settings.clone());
    let documents = Arc::new(checklists::documents::Documents::new(
        db.clone(),
        projects.clone(),
        measurer.clone(),
        Arc::new(checklists::PlatformSigner(signing.clone())),
        java_build_version(),
        audit.clone(),
        clock.clone(),
    ));
    let templates = Arc::new(checklists::templates::ChecklistTemplates::new(
        db.clone(),
        settings.clone(),
        audit.clone(),
        independence.clone(),
        clock.clone(),
        10 * 1024 * 1024,
    ));
    let project_checklists = Arc::new(checklists::project_checklists::ProjectChecklists::new(
        checklists::project_checklists::ProjectChecklistsConfig {
            db: db.clone(),
            projects: projects.clone(),
            measurer,
            documents: documents.clone(),
            trials: Arc::new(checklists::trials::VersionTrials::new()),
            settings,
            audit: audit.clone(),
            independence,
            clock: clock.clone(),
            max_file_bytes: 25 * 1024 * 1024,
        },
    ));
    let accounts = Arc::new(checklists::AccessAccounts {
        directory: vectispire_cp_access::account_names::AccountDirectory::new(
            vectispire_cp_access::SqlAccountStore::new(db.clone(), vectispire_cp_access::CredentialTables),
        ),
        visibility: VisibilityService::new(
            db.clone(),
            Arc::new(StoredSettings(Settings::new(db.clone()))),
            Arc::new(TargetsForAccess(db.clone())),
        ),
    });
    let contacts = Arc::new(checklists::contact_service::ChecklistContacts::new(
        db.clone(),
        projects,
        accounts,
        audit.clone(),
        clock,
    ));
    checklists::routes(checklists::ChecklistServices { templates, checklists: project_checklists, documents, contacts })
}

#[allow(clippy::too_many_arguments)]
fn phase_three(
    db: &Db,
    targets: Arc<Targets>,
    audit: Arc<AuditLog>,
    siem: &Siem,
    signing: Arc<vectispire_cp_crypto::SigningKeys>,
    issues: Arc<vectispire_cp_issues::Issues>,
    inventory: Arc<vectispire_cp_inventory::Inventory>,
) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    let rules = vectispire_cp_rules::RulesModule::new(
        db.clone(),
        Arc::new(vectispire_cp_rules::StandInInventory),
        Arc::new(vectispire_cp_rules::StandInIssues),
        audit.clone(),
    );
    let exporter = Arc::new(vectispire_cp_siem::SiemExporterService::new(
        db.clone(),
        siem.sender.clone(),
        support::encryption(),
        (*audit).clone(),
        Arc::new(AuditClock),
    ));
    // The platform routes served so far, as `cp-app`'s registry composes them: the trail's reader tells a break to the
    // SIEM's listener.
    let trail = Arc::new(vectispire_cp_audit::AuditLogQuery::new(
        (*audit).clone(),
        Arc::new(AuditClock),
        vec![siem.events.clone() as Arc<dyn vectispire_cp_audit::ChainBrokenListener>],
    ));
    // The integrations' registry and its routes, as `cp-app`'s registry composes them: the SIEM's transport is the use
    // that refuses a switch-off.
    let integrations = integrations(db);
    let integration_administration =
        Arc::new(vectispire_cp_platform::IntegrationAdministration::new(integrations.clone(), (*audit).clone()));
    // The settings screen as `cp-app/src/settings_screen.rs` composes it: `access`' approvers, the two narrow parts of
    // `tickets` and `ai` `cp-platform` holds, the switches' registry, and a guard with no reserved endpoint — the Java
    // suite's context reserves none either.
    let settings_screen =
        Arc::new(vectispire_cp_platform::SettingsAdministration::new(vectispire_cp_platform::SettingsParts {
            db: db.clone(),
            audit: (*audit).clone(),
            approvers: Arc::new(AccessApprovers(vectispire_cp_access::TriageApprovers::new(db.clone()))),
            tracker: Arc::new(vectispire_cp_platform::TrackerCaPinning::new(Arc::new(AuditClock))),
            ai: Arc::new(vectispire_cp_platform::GuardedAiDestination::new(
                Settings::new(db.clone()),
                vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
            )),
            endpoint: Arc::new(EndpointNotPorted),
            integrations,
            clock: Arc::new(AuditClock),
        }));
    let audit_for_access = audit.clone();
    let targets_for_access: Arc<dyn vectispire_cp_access::GrantableTargets> = Arc::new(TargetsForAccess(db.clone()));
    let gate = vectispire_cp_gate::GateModule::new(
        db.clone(),
        issues.catalog().clone(),
        Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(SystemClock))),
        targets.clone(),
        rules.coverage.clone(),
        audit.clone(),
        Arc::new(SystemClock),
        siem.events.clone(),
    );
    // As `cp-app` composes it: the weekly report's channels are the notifications module's stand-in, which no route
    // reaches.
    let compliance_audit = audit.clone();
    let governance_audit = audit.clone();
    let compliance_rules = rules.coverage.clone();
    let posture = vectispire_cp_posture::PostureModule::new(vectispire_cp_posture::PostureConfig {
        db: db.clone(),
        gate: gate.gate.clone(),
        issues: issues.catalog().clone(),
        sla: issues.sla().clone(),
        scans: Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(SystemClock))),
        targets: targets.clone(),
        licences: inventory.licenses().clone(),
        apis: inventory.apis().clone(),
        settings: Arc::new(Settings::new(db.clone())),
        audit_log: Arc::new(vectispire_cp_audit::AuditLogQuery::new(
            (*audit).clone(),
            Arc::new(AuditClock),
            Vec::new(),
        )),
        audit,
        channels: Arc::new(vectispire_cp_posture::NotificationsStandIn),
        clock: Arc::new(SystemClock),
    });
    // As `cp-app` composes it, its two ports reproduced below: the Java suite's context names no identity provider
    // and keeps password sign-in on.
    let compliance_service = vectispire_cp_compliance::matrix::ComplianceService::new(
        gate.gate.clone(),
        issues.catalog().clone(),
        issues.sla().clone(),
        Settings::new(db.clone()),
        Arc::new(CompliancePlatform {
            encryption: support::encryption(),
            audit: compliance_audit,
            settings: Settings::new(db.clone()),
            sign_in: vectispire_cp_access::sign_in::SignInMethodPolicy::new(false, true),
            accounts: vectispire_cp_access::SqlSignInStore::new(db.clone()),
        }),
        Arc::new(ComplianceInventories(inventory.query().clone())),
        Arc::new(SystemClock),
    );
    let compliance = Arc::new(vectispire_cp_compliance::Services::new(
        compliance_service.clone(),
        vectispire_cp_compliance::scope::ScopeComplianceService::new(
            targets.clone(),
            compliance_service,
            posture.scorecards.clone(),
        ),
        db.clone(),
        targets.clone(),
        Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(SystemClock))),
        issues.catalog().clone(),
        issues.queries().clone(),
        compliance_rules,
        Settings::new(db.clone()),
        governance_audit,
        Arc::new(SystemClock),
    ));
    let mut routes = vectispire_cp_issues::routes(issues);
    routes.extend(gate.routes());
    routes.extend(posture.routes());
    routes.extend(vectispire_cp_compliance::routes(compliance));
    routes.extend(vectispire_cp_inventory::routes(inventory, targets));
    routes.extend(vectispire_cp_siem::routes(exporter));
    // The notification centre (wave 2).
    let (notifications, channels) = notifications(db);
    routes.extend(vectispire_cp_notifications::routes(Arc::new(
        vectispire_cp_notifications::NotificationTestService::new(notifications, channels.all()),
    )));
    routes.extend(vectispire_cp_platform::routes(trail, signing));
    routes.extend(vectispire_cp_platform::integration_routes(integration_administration));
    routes.extend(vectispire_cp_platform::settings_routes(settings_screen));
    routes.extend(access_administration(db, audit_for_access.clone(), targets_for_access));
    routes.extend(access_sign_in(db, audit_for_access.clone()));
    // `cp-app`'s `access::scim_routes`, as the Java suite's context composes it: no privileged account linked.
    routes.extend(vectispire_cp_access::scim_routes(Arc::new(vectispire_cp_access::scim::ScimProvisioning::new(
        vectispire_cp_access::scim::ScimParts {
            db: db.clone(),
            audit: AccessAudit(audit_for_access),
            clock: Arc::new(AccessClock) as vectispire_cp_access::throttle::SharedClock,
            link_privileged: false,
        },
    ))));
    routes
}

/// `cp-app`'s `access::administration_routes`, composed here as the binary composes it (the replay cannot name
/// `cp-app`, which names this crate): accounts under four-eyes read from the settings, their writes closing sessions
/// and revoking keys in the account's transaction.
fn access_administration(
    db: &Db,
    audit: Arc<AuditLog>,
    targets: Arc<dyn vectispire_cp_access::GrantableTargets>,
) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    use vectispire_cp_access::accounts::{Accounts, ApproverIndependence};
    let clock: vectispire_cp_access::throttle::SharedClock = Arc::new(AccessClock);
    let credentials = CredentialService::new(
        db.clone(),
        clock.clone(),
        SessionPolicy::default(),
        Arc::new(AgentDirectoryImpl::new(db.clone())),
        ScimToken::default(),
    );
    let audit = AccessAudit(audit);
    let settings = Arc::new(Settings::new(db.clone()));
    let accounts = Accounts::new(
        vectispire_cp_access::SqlAccountStore::new(db.clone(), vectispire_cp_access::CredentialTables),
        audit.clone(),
        clock.clone(),
    )
    .with_four_eyes(ApproverIndependence::new(db.clone(), settings.clone()));
    let visibility = VisibilityService::new(
        db.clone(),
        Arc::new(StoredSettings(Settings::new(db.clone()))),
        Arc::new(TargetsForAccess(db.clone())),
    );
    let teams = vectispire_cp_access::teams::TeamAdministration::new(vectispire_cp_access::teams::TeamParts {
        db: db.clone(),
        audit: audit.clone(),
        clock: clock.clone(),
        outbound: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
        policy: settings,
        targets: targets.clone(),
        integrations: integrations(db),
    });
    let keys = vectispire_cp_access::api_key_administration::ApiKeyAdministration::new(
        vectispire_cp_access::api_key_administration::ApiKeyParts {
            db: db.clone(),
            credentials,
            targets: targets.clone(),
            issuer_sees: Arc::new(vectispire_cp_access::IssuerVisibility::new(db.clone(), visibility, targets.clone())),
            audit: audit.clone(),
            clock,
        },
    );
    vectispire_cp_access::administration_routes(vectispire_cp_access::Administration {
        accounts: Arc::new(accounts),
        account_targets: Arc::new(vectispire_cp_access::account_targets::AccountTargets::new(
            db.clone(),
            audit,
            targets,
        )),
        teams: Arc::new(teams),
        keys: Arc::new(keys),
    })
}

/// `cp-app`'s `access::sign_in_routes`, composed here as the binary composes it for the Java suite's context: no identity
/// provider named, password sign-in on, the shipped branding and ceilings.
fn access_sign_in(db: &Db, audit: Arc<AuditLog>) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    let clock: vectispire_cp_access::throttle::SharedClock = Arc::new(AccessClock);
    let credentials = Arc::new(CredentialService::new(
        db.clone(),
        clock.clone(),
        SessionPolicy::default(),
        Arc::new(AgentDirectoryImpl::new(db.clone())),
        ScimToken::default(),
    ));
    let flow = vectispire_cp_access::sign_in::SignInFlow::new(vectispire_cp_access::sign_in::SignInParts {
        users: vectispire_cp_access::SqlAccountStore::new(db.clone(), vectispire_cp_access::CredentialTables),
        audit: AccessAudit(audit),
        store: vectispire_cp_access::SqlSignInStore::new(db.clone()),
        sessions: credentials.clone(),
        seal: support::encryption(),
        clock,
        methods: vectispire_cp_access::sign_in::SignInMethodPolicy::new(false, true),
        provider_label: None,
    });
    vectispire_cp_access::auth_routes(Arc::new(flow), credentials, vectispire_cp_access::Branding::of(None, None))
}

/// `cp-app`'s `access::AccessAudit`: the access services' audit port on the audit log.
#[derive(Clone)]
struct AccessAudit(Arc<AuditLog>);

impl vectispire_cp_access::accounts::Audit for AccessAudit {
    async fn record(&self, record: vectispire_cp_access::accounts::AuditRecord) {
        let operation = vectispire_cp_audit::AuditOperation::from_wire(record.operation.name())
            .expect("every access operation is the log's");
        self.0
            .record(vectispire_cp_audit::Record {
                operation,
                resource_id: Some(record.resource),
                description: Some(record.description),
                user_id: record.username,
                ip_address: record.ip_address,
                user_agent: record.user_agent,
                signal: record.signal.map(vectispire_cp_audit::Signal),
            })
            .await;
    }
}

type Answer<'a, T> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<T, vectispire_cp_platform::CollaboratorError>> + Send + 'a>,
>;

/// `cp-app`'s `compliance::PlatformFacts`: the deployment's controls, read on every evaluation.
struct CompliancePlatform {
    encryption: Arc<vectispire_cp_crypto::Encryption>,
    audit: Arc<AuditLog>,
    settings: Settings,
    sign_in: vectispire_cp_access::sign_in::SignInMethodPolicy,
    accounts: vectispire_cp_access::SqlSignInStore,
}

impl vectispire_cp_compliance::ports::Platform for CompliancePlatform {
    fn posture(
        &self,
    ) -> vectispire_cp_http::credentials::BoxFuture<
        '_,
        Result<vectispire_cp_compliance::decisions::PlatformPosture, String>,
    > {
        use vectispire_cp_access::sign_in::SignInStore;
        Box::pin(async move {
            let password_accounts = if self.sign_in.single_sign_on_available() {
                vectispire_cp_compliance::decisions::PasswordAccounts { accounts: 0, without_second_factor: 0 }
            } else {
                let accounts = self.accounts.count_active_with_password().await.map_err(|e| e.to_string())?;
                let without =
                    self.accounts.count_active_with_password_and_no_second_factor().await.map_err(|e| e.to_string())?;
                let long = |count: u64| i64::try_from(count).unwrap_or(i64::MAX);
                vectispire_cp_compliance::decisions::PasswordAccounts {
                    accounts: long(accounts),
                    without_second_factor: long(accounts.min(without)),
                }
            };
            Ok(vectispire_cp_compliance::decisions::PlatformPosture {
                encryption_configured: self.encryption.is_configured(),
                external_kms: self.encryption.is_externally_managed(),
                audit_mirror_configured: self.audit.mirror_configured(),
                four_eyes_required: self
                    .settings
                    .is_enabled(vectispire_cp_settings::Setting::FourEyesApprovalRequired)
                    .await
                    .map_err(|e| e.to_string())?,
                single_sign_on_configured: self.sign_in.single_sign_on_available(),
                password_login_open: self.sign_in.password_allowed(),
                password_accounts,
            })
        })
    }

    fn audit_chain_valid(&self) -> vectispire_cp_http::credentials::BoxFuture<'_, Result<bool, String>> {
        Box::pin(async move { self.audit.recent_entries_match_their_hashes().await.map_err(|e| e.to_string()) })
    }
}

/// `cp-app`'s `compliance::InventoryFacts`.
struct ComplianceInventories(Arc<vectispire_cp_inventory::inventory_query::InventoryQueryService>);

impl vectispire_cp_compliance::ports::Inventories for ComplianceInventories {
    fn targets_with_inventory(
        &self,
    ) -> vectispire_cp_http::credentials::BoxFuture<
        '_,
        Result<std::collections::BTreeSet<vectispire_cp_db::ScanTarget>, String>,
    > {
        Box::pin(async move {
            let mut held = std::collections::BTreeSet::new();
            for id in self.0.distinct_repositories_with_components().await.map_err(|e| e.to_string())? {
                held.insert(vectispire_cp_db::ScanTarget::Repository(id));
            }
            for id in self.0.distinct_containers_with_components().await.map_err(|e| e.to_string())? {
                held.insert(vectispire_cp_db::ScanTarget::Container(id));
            }
            Ok(held)
        })
    }
}

/// `cp-app`'s `settings_screen::AccessApprovers`: `access`' `TriageApprovers` behind the settings save's seam.
struct AccessApprovers(vectispire_cp_access::TriageApprovers);

impl vectispire_cp_platform::Approvers for AccessApprovers {
    fn any_active(&self) -> Answer<'_, bool> {
        Box::pin(async move { Ok(self.0.any_active().await?) })
    }
    fn two_can_publish_templates(&self) -> Answer<'_, bool> {
        Box::pin(async move { Ok(self.0.two_can_publish_templates().await?) })
    }
    fn two_can_sign_off_checklists(&self) -> Answer<'_, bool> {
        Box::pin(async move { Ok(self.0.two_can_sign_off_checklists().await?) })
    }
}

/// `cp-app`'s `settings_screen::EndpointNotPorted`: the endpoint check's route is not served, so nothing asks.
struct EndpointNotPorted;

impl vectispire_cp_platform::AiEndpoint for EndpointNotPorted {
    fn provider(&self) -> Answer<'_, String> {
        Box::pin(async { Err("not ported".into()) })
    }
    fn selected_model(&self) -> Answer<'_, String> {
        Box::pin(async { Err("not ported".into()) })
    }
    fn allow_remote(&self) -> Answer<'_, bool> {
        Box::pin(async { Err("not ported".into()) })
    }
    fn validated_url(&self) -> Answer<'_, Result<String, String>> {
        Box::pin(async { Err("not ported".into()) })
    }
    fn base_url(&self) -> Answer<'_, String> {
        Box::pin(async { Err("not ported".into()) })
    }
    fn has_openai_key(&self) -> Answer<'_, bool> {
        Box::pin(async { Err("not ported".into()) })
    }
    fn available_models(&self) -> Answer<'_, Option<Vec<String>>> {
        Box::pin(async { Err("not ported".into()) })
    }
}

/// The routes this test owes a replay: every route the router composes, but those a `route` line of
/// `golden/deferred/` still covers — their recordings are played in Java's place, as for a route not served, until the
/// line is removed in the commit that makes them replay green. Derived, so that a module's port that brings its
/// routes to green edits its own file of the list and not a list here.
fn served(deferred: &Deferred) -> BTreeSet<(String, String)> {
    let db = support::unreachable();
    let composed = support::compose(&db, support::system_clock());
    let siem = Siem::over(&db);
    let audit = Arc::new(AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(AuditClock), siem.listeners()));
    // Only the routes are read here, never served: a key over the unreachable database is never asked for its record.
    let signing = Arc::new(
        vectispire_cp_crypto::SigningKeys::new(&signing_key_pem(), Settings::new(db.clone()), support::encryption())
            .unwrap(),
    );
    let (issues, inventory) = issues_and_inventory(&db, &composed.targets, &audit, &siem);
    let checklist_routes = checklists(&db, &composed.targets, &audit, &signing);
    let mut phase_three = phase_three(&db, composed.targets.clone(), audit, &siem, signing, issues, inventory);
    phase_three.extend(checklist_routes);
    vectispire_cp_targets::routes(composed.targets)
        .into_iter()
        .chain(vectispire_cp_scanning::routes(composed.scanning))
        .chain(vectispire_cp_agents::routes(composed.agents))
        .chain(phase_three)
        .map(|entry| (entry.decl().method.clone(), entry.decl().path.clone()))
        .filter(|route| !deferred.routes.contains_key(route))
        // And the actuator's pages, outside the contract, but those an `outside` line still covers.
        .chain(served_outside(deferred, &vectispire_cp_runtime::actuator::PAGES))
        .collect()
}

/// A recording's outcome on both engines: green only when green on each.
fn merged(by_engine: &[(Engine, Vec<Replayed>)]) -> Vec<Replayed> {
    let mut out: BTreeMap<String, Replayed> = BTreeMap::new();
    for (engine, outcomes) in by_engine {
        for replayed in outcomes {
            let entry = out
                .entry(replayed.name.clone())
                .or_insert_with(|| Replayed { outcome: Outcome::Green, ..replayed.clone() });
            let worse = match (&entry.outcome, &replayed.outcome) {
                (_, Outcome::Green) => None,
                (Outcome::Green, other) => Some(match other {
                    Outcome::Differs(lines) => {
                        Outcome::Differs(lines.iter().map(|line| format!("{engine}: {line}")).collect())
                    }
                    other => other.clone(),
                }),
                (Outcome::Differs(mine), Outcome::Differs(theirs)) => Some(Outcome::Differs(
                    mine.iter().cloned().chain(theirs.iter().map(|line| format!("{engine}: {line}"))).collect(),
                )),
                _ => None,
            };
            if let Some(worse) = worse {
                entry.outcome = worse;
            }
        }
    }
    out.into_values().collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "replays a recording of the Java suite: crates/cp-contract/scripts/replay-goldens.sh records one and runs this"]
async fn the_recorded_traffic_of_the_routes_replays_on_both_engines() {
    let dir = PathBuf::from(std::env::var("VECTISPIRE_GOLDEN_DIR").expect(
        "VECTISPIRE_GOLDEN_DIR names the recording to replay (crates/cp-contract/scripts/replay-goldens.sh records one)",
    ));
    // Narrowing knobs while a difference is being chased; a narrowed run always fails at the end, since it proves
    // nothing about what it left out.
    let only = std::env::var("VECTISPIRE_GOLDEN_ONLY").ok();
    let pinned: Option<Vec<Engine>> = match std::env::var("VECTISPIRE_GOLDEN_ENGINES").ok().as_deref() {
        Some("mysql") => Some(vec![Engine::MySql]),
        Some("postgresql") => Some(vec![Engine::PostgreSql]),
        _ => None,
    };
    let narrowed = only.is_some() || pinned.is_some();
    // Otherwise the run's engines (`VECTISPIRE_TEST_ENGINES`, cp-db's `testing`): pull requests replay on MySQL and
    // the nightly on both; an engine left out says so here, and the replay passes on the ones it ran.
    let engines = pinned.unwrap_or_else(|| {
        Engine::ALL.into_iter().filter(|engine| vectispire_cp_db::testing::runs_on(*engine)).collect()
    });

    let recording = Recording::open(&dir).unwrap();
    let document = Document::embedded();
    let schemas = Schemas::of(&document).admitting_null_in_nullable_enums(true).reading_one_of_as_any_of(true);
    let deferred = Deferred::committed();
    let served = served(&deferred);
    println!("{} routes owed a replay: every route composed, but those a `route` line still covers", served.len());
    let all = listed(&recording, &document, &served).unwrap();
    let owing: BTreeSet<&str> =
        all.iter().filter(|listed| listed.served).filter_map(|listed| listed.name.split('/').next()).collect();
    let tests: Vec<_> = recording
        .tests
        .iter()
        .filter(|test| test.outcome == "passed" && owing.contains(test.directory.as_str()))
        .filter(|test| {
            test.files
                .iter()
                .any(|file| all.iter().any(|listed| listed.served && listed.name == test.golden_name(file)))
        })
        .filter(|test| only.as_deref().is_none_or(|only| test.golden_name("").contains(only)))
        .collect();

    let mut by_engine = Vec::new();
    for engine in engines {
        let database = Migrated::start(engine).await;
        let db = database.connect().await;
        let schema = Schema::read(&db, &recording.id_bases).await.unwrap();
        // **One signing key per engine, as `vectispire.signing.key` configures it, and its record written once, before
        // the snapshot.** Java's context made its key and sealed the record of known keys before the recorded tests ran,
        // and the record survived the cleaning between them: no recording holds its insertion, and the published keys'
        // `activeFrom` is read from it in every test. A key per test would write it at each test's first signature — an
        // insertion Java never made; written after the snapshot, every test's database would lack it.
        let signing = Arc::new(
            vectispire_cp_crypto::SigningKeys::new(
                &signing_key_pem(),
                Settings::new(db.clone()),
                support::encryption(),
            )
            .unwrap(),
        );
        signing.key_id().await.unwrap();
        let pristine = rows::snapshot(&db, &schema).await.unwrap();
        let replayer = Replayer {
            recording: &recording,
            db: &db,
            schema: &schema,
            pristine: &pristine,
            document: &document,
            schemas: &schemas,
            minting: &AccessMinting,
            served: &served,
        };
        let mut outcomes = Vec::new();
        for test in &tests {
            let mut ports = Vec::new();
            for (_, _, ordinal, ca) in
                COLLECTORS.iter().filter(|(class, name, _, _)| *class == test.class && *name == test.name)
            {
                ports.push((*ordinal, collector(ca).await));
            }
            outcomes.extend(replayer.test_with_ports(test, router(&db, signing.clone(), &test.class), &ports).await);
        }
        let green = outcomes.iter().filter(|replayed| replayed.served && replayed.outcome == Outcome::Green).count();
        let owed = outcomes.iter().filter(|replayed| replayed.served).count();
        println!("{engine}: {} tests, {owed} recordings of the routes, {green} green", tests.len());
        by_engine.push((engine, outcomes));
        db.close().await;
    }
    let outcomes = merged(&by_engine);
    for replayed in outcomes.iter().filter(|replayed| replayed.served && replayed.outcome != Outcome::Green) {
        let listed = deferred.goldens.get(&replayed.name).map_or("", |_| " [listed]");
        println!("{}{listed}: {}", replayed.name, describe(&replayed.outcome));
    }
    if narrowed {
        panic!("a narrowed replay (VECTISPIRE_GOLDEN_ONLY or _ENGINES) checks nothing it left out: run it whole");
    }
    let problems = coverage(&deferred, &all, Some(&outcomes));
    assert!(problems.is_empty(), "{} problem(s):\n{}", problems.len(), problems.join("\n"));
}
