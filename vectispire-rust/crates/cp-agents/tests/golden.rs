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
use vectispire_cp_scanning::ports::{BundledRules, IngestionStandIn, NoPlugins};
use vectispire_cp_scanning::{Scanning, ScanningConfig};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::deletion::PurgeRegistry;
use vectispire_cp_targets::{SystemClock, Targets, TargetsConfig, TargetsForAccess};
use vectispire_domain::git_host_allowlist::GitHostAllowlist;

use support::Migrated;

/// The credentials, minted and checked with `cp-access`'s own code: what the chain will accept is what it wrote.
struct AccessMinting;

impl Minting for AccessMinting {
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
const TEST_PROPERTIES: &[(&str, &str, &str)] =
    &[("api.GitHostAllowlistRoutesTest", "vectispire.git.allowed-hosts", "gitlab.corp.example,*.forge.example")];

fn property(class: &str, key: &str) -> Option<&'static str> {
    TEST_PROPERTIES.iter().find(|(of, named, _)| *of == class && *named == key).map(|(_, _, value)| *value)
}

/// The three modules as the binary composes them, and Phase 3's three, behind the real chain: a fresh set per test. Ingestion is the
/// stand-in: its backlog and inventory are Phase 3's, composed only by `cp-app`.
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
        purge: PurgeRegistry::stand_ins().with(vectispire_cp_scanning::purge::listeners()),
        encryption: support::encryption(),
        allowed_hosts: allowed_hosts.clone(),
        clock: Arc::new(SystemClock),
        visibility: None,
    }));
    let scanning = Arc::new(Scanning::new(ScanningConfig {
        db: db.clone(),
        clock: Arc::new(SystemClock),
        targets: targets.clone(),
        encryption: support::encryption(),
        audit: audit.clone(),
        claim_lock: Arc::new(AgentRowLock),
        rule_sets: Arc::new(BundledRules),
        plugins: Arc::new(NoPlugins),
        ingestor: Arc::new(IngestionStandIn::default()),
        policy: vectispire_domain::scan_queue::Policy::default(),
        leader_lease: vectispire_cp_scanning::DEFAULT_LEASE,
        allowed_hosts,
        image_platform: None,
        runner: None,
        scanned: Vec::new(),
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
    let modules = phase_three(db, targets.clone(), audit.clone(), &siem, signing);
    let credentials = Arc::new(CredentialService::new(
        db.clone(),
        Arc::new(AccessClock),
        SessionPolicy::default(),
        Arc::new(AgentDirectoryImpl::new(db.clone())),
        ScimToken::default(),
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
        Chain::with_clock(ChainConfig::default(), credentials, Arc::new(entries), time.clone())
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

/// The issues, gate, inventory, SIEM and platform modules as the binary composes them, on the scan catalog and the
/// targets above.
fn phase_three(
    db: &Db,
    targets: Arc<Targets>,
    audit: Arc<AuditLog>,
    siem: &Siem,
    signing: Arc<vectispire_cp_crypto::SigningKeys>,
) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    let scans = Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(SystemClock)));
    let issues = Arc::new(vectispire_cp_issues::Issues::new(vectispire_cp_issues::IssuesConfig {
        db: db.clone(),
        targets: targets.clone(),
        scans: (*scans).clone(),
        settings: Arc::new(Settings::new(db.clone())),
        audit: audit.clone(),
        events: siem.events.clone(),
    }));
    let rules = vectispire_cp_rules::RulesModule::new(
        db.clone(),
        Arc::new(vectispire_cp_rules::StandInInventory),
        Arc::new(vectispire_cp_rules::StandInIssues),
        audit.clone(),
    );
    let inventory = Arc::new(vectispire_cp_inventory::Inventory::new(vectispire_cp_inventory::InventoryConfig {
        db: db.clone(),
        scans: scans.clone(),
        targets: targets.clone(),
        audit: audit.clone(),
    }));
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
    let uses: Vec<Arc<dyn vectispire_cp_settings::InUse>> = vec![Arc::new(vectispire_cp_siem::SiemTransportInUse)];
    let integrations =
        vectispire_cp_settings::Integrations::new(db.clone(), uses, Arc::new(time::OffsetDateTime::now_utc));
    let integration_administration =
        Arc::new(vectispire_cp_platform::IntegrationAdministration::new(integrations, (*audit).clone()));
    let gate = vectispire_cp_gate::GateModule::new(
        db.clone(),
        issues.catalog().clone(),
        scans,
        targets.clone(),
        rules.coverage.clone(),
        audit,
        Arc::new(SystemClock),
        siem.events.clone(),
    );
    let mut routes = vectispire_cp_issues::routes(issues);
    routes.extend(gate.routes());
    routes.extend(vectispire_cp_inventory::routes(inventory, targets));
    routes.extend(vectispire_cp_siem::routes(exporter));
    routes.extend(vectispire_cp_platform::routes(trail, signing));
    routes.extend(vectispire_cp_platform::integration_routes(integration_administration));
    routes
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
    let phase_three = phase_three(&db, composed.targets.clone(), audit, &siem, signing);
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
    let schemas = Schemas::of(&document).admitting_null_in_nullable_enums(true);
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
            outcomes.extend(replayer.test(test, router(&db, signing.clone(), &test.class)).await);
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
