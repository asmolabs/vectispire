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
use vectispire_cp_contract::recorded::deferred::{Deferred, coverage, describe, listed};
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

/// The three modules as the binary composes them, and Phase 3's three, behind the real chain: a fresh set per test. Ingestion is the
/// stand-in: its backlog and inventory are Phase 3's, composed only by `cp-app`.
fn router(db: &Db) -> axum::Router {
    let audit = Arc::new(AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(AuditClock), Vec::new()));
    let targets = Arc::new(Targets::new(TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: vectispire_cp_scanning::target_scans(db.clone(), Arc::new(SystemClock)),
        backlog: Arc::new(vectispire_cp_issues::TargetBacklogFigures::new(db.clone())),
        purge: PurgeRegistry::stand_ins().with(vectispire_cp_scanning::purge::listeners()),
        encryption: support::encryption(),
        allowed_hosts: GitHostAllowlist::default(),
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
        allowed_hosts: GitHostAllowlist::default(),
        image_platform: None,
        runner: None,
        scanned: Vec::new(),
    }));
    let modules = phase_three(db, targets.clone(), audit.clone());
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
    let admin = Arc::new(AgentAdministrationService::new(
        db.clone(),
        credentials.clone(),
        Arc::new(scanning.catalog().clone()),
        targets.clone(),
        audit.clone(),
        Vec::new(),
        false,
    ));
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
    let mut routes = Routes::new(CallerVisibility::new(visibility, Arc::new(PrincipalGrounds)));
    for entry in vectispire_cp_targets::routes(targets)
        .into_iter()
        .chain(vectispire_cp_scanning::routes(scanning))
        .chain(vectispire_cp_agents::routes(agents))
        .chain(modules)
    {
        routes = routes.route(entry);
    }
    let entries = ChainEntries(AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(AuditClock), Vec::new()));
    let time = Arc::new(AnsweringTime::default());
    let chain = Arc::new(Chain::with_clock(ChainConfig::default(), credentials, Arc::new(entries), time.clone()));
    routes.build(&chain, None).unwrap().layer(axum::middleware::from_fn_with_state(time, answering))
}

/// The issues, gate and inventory modules as the binary composes them, on the scan catalog and the targets above.
fn phase_three(db: &Db, targets: Arc<Targets>, audit: Arc<AuditLog>) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    let scans = Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(SystemClock)));
    let issues = Arc::new(vectispire_cp_issues::Issues::new(vectispire_cp_issues::IssuesConfig {
        db: db.clone(),
        targets: targets.clone(),
        scans: (*scans).clone(),
        settings: Arc::new(Settings::new(db.clone())),
        audit: audit.clone(),
        events: Arc::new(vectispire_cp_outbox::NotExported),
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
    let gate = vectispire_cp_gate::GateModule::new(
        db.clone(),
        issues.catalog().clone(),
        scans,
        targets.clone(),
        rules.coverage.clone(),
        audit,
        Arc::new(SystemClock),
        Arc::new(vectispire_cp_outbox::NotExported),
    );
    let mut routes = vectispire_cp_issues::routes(issues);
    routes.extend(gate.routes());
    routes.extend(vectispire_cp_inventory::routes(inventory, targets));
    routes
}

/// The routes this test owes a replay: every route the router composes, but those a `route` line of
/// `golden/deferred/` still covers — their recordings are played in Java's place, as for a route not served, until the
/// line is removed in the commit that makes them replay green. Derived, so that a module's port that brings its
/// routes to green edits its own file of the list and not a list here.
fn served(deferred: &Deferred) -> BTreeSet<(String, String)> {
    let db = support::unreachable();
    let composed = support::compose(&db, support::system_clock());
    let audit = Arc::new(AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(AuditClock), Vec::new()));
    let phase_three = phase_three(&db, composed.targets.clone(), audit);
    vectispire_cp_targets::routes(composed.targets)
        .into_iter()
        .chain(vectispire_cp_scanning::routes(composed.scanning))
        .chain(vectispire_cp_agents::routes(composed.agents))
        .chain(phase_three)
        .map(|entry| (entry.decl().method.clone(), entry.decl().path.clone()))
        .filter(|route| !deferred.routes.contains_key(route))
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
    let engines: Vec<Engine> = match std::env::var("VECTISPIRE_GOLDEN_ENGINES").ok().as_deref() {
        Some("mysql") => vec![Engine::MySql],
        Some("postgresql") => vec![Engine::PostgreSql],
        _ => vec![Engine::MySql, Engine::PostgreSql],
    };
    let narrowed = only.is_some() || engines.len() < 2;

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
            outcomes.extend(replayer.test(test, router(&db)).await);
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
