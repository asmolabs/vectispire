//! The module's decisions against Java's answers in `reference/scanning/java-answers.json` (`ScanningReferenceSetTest`,
//! written before this port): what a scan that could not run says, the 412's two sentences, what the three text columns
//! read back as, and — case by case, over the ports, as `ScanDispatcherTest` drives Java's — what a claim hands an
//! agent: the task with each sealed credential replaced by the context it opens under and what it opens to, the
//! refusal, the attempt ended and its sentence, the audit entry, the rule languages recorded.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::Tx;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_scanning::dispatcher::{
    ClaimError, DispatchQueue, DispatcherConfig, SastSwitch, ScanResult, TargetRows, sentence,
};
use vectispire_cp_scanning::ports::{IngestionStandIn, PortError, ScanPlugins, ScanRuleSets};
use vectispire_cp_scanning::views::{PluginOutcome, ScanView, detected_languages, examined_types};
use vectispire_cp_scanning::{Abandoned, AgentClaim, ClaimingAgent, Exclusion, Reclaimed, ScanDispatcher};
use vectispire_cp_targets::credentials::{StoredGitToken, StoredSshKey};
use vectispire_cp_targets::views::{ContainerView, RepositoryView};
use vectispire_crypto::{SealContext, SealingKeyPair};
use vectispire_domain::FailureKind;
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::instant::Instant;
use vectispire_domain::scan_queue::Next;
use vectispire_protocol::{PluginRef, StoredFile, Target};

/// `2026-10-18T12:34:56.789Z`.
const NOW: Instant = Instant { epoch_second: 1_792_326_896, nano: 789_000_000 };
const KEY_ID: Uuid = Uuid::from_u128(0xaa);
const TOKEN_ID: Uuid = Uuid::from_u128(0xcc);
const AGENT_ID: Uuid = Uuid::from_u128(0xbb);
const PRIVATE_KEY: &str = "test-ssh-private-key-material";
const TOKEN: &str = "invented-https-token";

fn answers() -> Value {
    vectispire_testkit::read_json("scanning/java-answers.json")
}

#[test]
fn a_scan_that_could_not_run_says_what_java_says() {
    let answers = answers();
    let nexts = [
        Next::Retry { not_before: NOW },
        Next::Retry { not_before: Instant { epoch_second: 1_792_326_956, nano: 1 } },
        Next::Retry { not_before: Instant { epoch_second: 1_792_324_800, nano: 0 } },
        Next::Fail { permanent: true },
        Next::Fail { permanent: false },
    ];
    for (index, next) in nexts.into_iter().enumerate() {
        for place in ["on agent \"edge\"", "on the built-in worker"] {
            let outcome = Abandoned { next, attempt: 2, max_attempts: 3 };
            assert_eq!(
                answers["sentences"][format!("{index}|{place}")],
                sentence(&outcome, place, "clone refused: «é»"),
                "{index} {place}"
            );
        }
    }
    let withheld = |not_pinned| vectispire_cp_scanning::dispatcher::CredentialWithheld { not_pinned }.message();
    assert_eq!(answers["sentences"]["withheld:notPinned"], withheld(true));
    assert_eq!(answers["sentences"]["withheld:notProved"], withheld(false));
}

#[test]
fn the_columns_read_back_as_java_reads_them() {
    let answers = answers();
    let columns = &answers["columns"];
    for (input, expected) in columns["languagesWritten"].as_object().unwrap() {
        let names: Vec<&str> = if input.is_empty() { Vec::new() } else { input.split(',').collect() };
        let written = detected_languages::write(Some(names.into_iter()));
        assert_eq!(expected.as_str(), written.as_deref(), "{input:?}");
    }
    for (column, expected) in columns["languagesRead"].as_object().unwrap() {
        let read = detected_languages::read(Some(column)).map(|names| format!("[{}]", names.join(", ")));
        assert_eq!(expected.as_str(), read.as_deref(), "{column:?}");
    }
    for (column, expected) in columns["examinedRead"].as_object().unwrap() {
        let read = examined_types::read(Some(column))
            .map(|types| format!("[{}]", types.iter().map(|kind| kind.wire_name()).collect::<Vec<_>>().join(", ")));
        assert_eq!(expected.as_str(), read.as_deref(), "{column:?}");
    }
    for (column, expected) in columns["pluginsRead"].as_object().unwrap() {
        let read = match PluginOutcome::read(Some(column)) {
            Ok(outcomes) => vectispire_domain::wire::to_wire_string(&outcomes),
            Err(_) => "throws:NullPointerException".to_owned(),
        };
        assert_eq!(expected.as_str().unwrap(), read, "{column:?}");
    }
    assert!(detected_languages::read(None).is_none(), "an absent column is unknown, not the empty set");
    assert!(examined_types::read(None).is_none(), "an absent column is unknown, not the empty set");
}

// ── the claims ─────────────────────────────────────────────────────────────────────────────

/// One case's world, as `ScanningReferenceSetTest.Claim` sets it up.
#[derive(Clone)]
struct Case {
    name: &'static str,
    repository: Option<RepositoryView>,
    container: Option<ContainerView>,
    scan: ScanView,
    ssh_key_stored: bool,
    token: Option<(String, Option<String>, bool)>,
    mode: &'static str,
    sealing_key: bool,
    signing_key: bool,
    sast: bool,
    rules_hash: Option<String>,
    rules_languages: BTreeSet<&'static str>,
    plugins: Vec<PluginRef>,
    allowed_hosts: &'static str,
    exclusion_honoured: bool,
    held: i64,
    key_at_delivery: bool,
}

fn repository() -> RepositoryView {
    RepositoryView {
        id: 1,
        url: "git@example.invalid:team/service.git".to_owned(),
        branch: "main".to_owned(),
        sub_path: None,
        name: None,
        scan_interval_minutes: None,
        scan_cron: None,
        scan_manual_only: false,
        required_agent_label: None,
        last_scheduled_scan_at: None,
        ssh_key_id: Some(KEY_ID),
        https_token_id: None,
        tier: "standard".to_owned(),
        in_certified_scope: false,
        project_id: None,
    }
}

fn container() -> ContainerView {
    ContainerView {
        id: 4,
        registry: Some("registry.example.invalid".to_owned()),
        image_name: "team/service".to_owned(),
        tag: "1.4.0".to_owned(),
        scan_interval_minutes: None,
        scan_cron: None,
        scan_manual_only: false,
        required_agent_label: None,
        last_scheduled_scan_at: None,
        tier: "standard".to_owned(),
        in_certified_scope: false,
        project_id: None,
    }
}

fn scan_view(id: i64, repo: Option<i64>, container: Option<i64>, branch: &str, attempts: i32) -> ScanView {
    ScanView {
        id,
        branch: branch.to_owned(),
        sub_path: None,
        status: "scanning".to_owned(),
        duration_ms: None,
        findings_count: 0,
        new_issues_count: 0,
        resolved_issues_count: 0,
        error: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        version: None,
        project_type: None,
        repo_id: repo,
        container_id: container,
        required_agent_label: None,
        claimed_by: None,
        claimed_at: None,
        lease_expires_at: None,
        attempts,
        not_before: None,
        plugin_steps: None,
        examined_types: None,
        detected_languages: None,
        sast_languages: None,
        has_sbom: false,
    }
}

fn repository_scan() -> ScanView {
    scan_view(7, Some(1), None, "main", 1)
}

fn image_scan() -> ScanView {
    scan_view(8, None, Some(4), "n/a", 2)
}

fn case(name: &'static str, set_up: impl FnOnce(&mut Case)) -> Case {
    let mut case = Case {
        name,
        repository: Some(repository()),
        container: None,
        scan: repository_scan(),
        ssh_key_stored: true,
        token: None,
        mode: "local",
        sealing_key: false,
        signing_key: false,
        sast: false,
        rules_hash: None,
        rules_languages: BTreeSet::new(),
        plugins: Vec::new(),
        allowed_hosts: "",
        exclusion_honoured: false,
        held: 0,
        key_at_delivery: false,
    };
    set_up(&mut case);
    case
}

fn https_repository(case: &mut Case, keep_key: bool) {
    let repository = case.repository.as_mut().unwrap();
    repository.url = "https://gitlab.example.com/team/service.git".to_owned();
    if !keep_key {
        repository.ssh_key_id = None;
    }
    repository.https_token_id = Some(TOKEN_ID);
}

fn cases() -> Vec<Case> {
    vec![
        case("local mode receives no key", |_| {}),
        case("delegated with a verified sealing key receives the key sealed", |c| {
            c.mode = "delegated";
            c.sealing_key = true;
        }),
        case("delegated, no signing key pinned", |c| {
            c.mode = "delegated";
            c.exclusion_honoured = true;
        }),
        case("delegated, pinned but no sealing key proved", |c| {
            c.mode = "delegated";
            c.signing_key = true;
            c.exclusion_honoured = true;
        }),
        case("delegated and full is told nothing", |c| {
            c.mode = "delegated";
            c.exclusion_honoured = true;
            c.held = 2;
        }),
        case("a key added since the selection is put back refunded", |c| {
            c.mode = "delegated";
            c.repository.as_mut().unwrap().ssh_key_id = None;
            c.key_at_delivery = true;
        }),
        case("a key and a token, both sealed", |c| {
            c.mode = "delegated";
            c.sealing_key = true;
            https_repository(c, true);
            c.token = Some(("gitlab.example.com".to_owned(), Some("oauth2".to_owned()), true));
        }),
        case("a token alone, no user name", |c| {
            c.mode = "delegated";
            c.sealing_key = true;
            https_repository(c, false);
            c.token = Some(("gitlab.example.com".to_owned(), None, true));
        }),
        case("local mode never decrypts the token", |c| {
            https_repository(c, false);
            c.token = Some(("gitlab.example.com".to_owned(), Some("oauth2".to_owned()), true));
        }),
        case("an unreadable mode reads as local", |c| c.mode = "something-a-later-version-wrote"),
        case("an image scan carries no key whatever the mode", |c| {
            c.mode = "delegated";
            c.container = Some(container());
            c.scan = image_scan();
        }),
        case("SAST, the active rule set and its languages, a branch, a sub-path, plugins", |c| {
            c.mode = "delegated";
            c.sealing_key = true;
            c.sast = true;
            c.rules_hash = Some("f".repeat(64));
            c.rules_languages = ["python", "java"].into_iter().collect();
            c.repository.as_mut().unwrap().sub_path = Some("services/api".to_owned());
            c.scan.branch = "release".to_owned();
            c.plugins = vec![
                PluginRef { id: "acme-lint".to_owned(), digest: "a".repeat(64), runs_unsigned: false },
                PluginRef { id: "acme-sarif".to_owned(), digest: "b".repeat(64), runs_unsigned: false },
            ];
        }),
        case("a blank branch on the scan reads the repository's", |c| c.scan.branch = "  ".to_owned()),
        case("a deleted SSH key fails the scan for good", |c| {
            c.mode = "delegated";
            c.sealing_key = true;
            c.ssh_key_stored = false;
        }),
        case("a deleted token fails the scan for good", |c| {
            c.mode = "delegated";
            c.sealing_key = true;
            https_repository(c, false);
        }),
        case("a token no key opens fails the scan for good", |c| {
            c.mode = "delegated";
            c.sealing_key = true;
            https_repository(c, false);
            c.token = Some(("gitlab.example.com".to_owned(), None, false));
        }),
        case("an ambiguous stored URL is refused", |c| {
            let repository = c.repository.as_mut().unwrap();
            repository.url = "https://forge.example#@elsewhere.example/team/service.git".to_owned();
            repository.ssh_key_id = None;
        }),
        case("a host the allow-list does not name is refused", |c| c.allowed_hosts = "gitlab.corp.example"),
        case("a repository since deleted", |c| c.repository = None),
        case("an image since deleted", |c| c.scan = image_scan()),
        case("a scan naming no target", |c| {
            c.scan = image_scan();
            c.scan.container_id = None;
        }),
    ]
}

/// What the queue was asked, as the Java test's mocks capture it.
#[derive(Default)]
struct Asked {
    excludes: bool,
    refunded: bool,
    abandoned: Option<String>,
    sast_languages: Option<Option<String>>,
}

struct FakeQueue {
    case: Case,
    targets: Arc<FakeTargets>,
    asked: Mutex<Asked>,
}

impl DispatchQueue for FakeQueue {
    fn claim<'a>(&'a self, _: i64, _: &'a str, _: &'a [String]) -> BoxFuture<'a, Result<Vec<ScanView>, PortError>> {
        unreachable!("the agents' claim only")
    }

    fn claim_within<'a>(
        &'a self,
        _agent: Uuid,
        limit: i64,
        _labels: &'a [String],
        exclusion: &'a dyn Exclusion,
    ) -> BoxFuture<'a, Result<AgentClaim, PortError>> {
        Box::pin(async move {
            assert_eq!(limit, 2, "the agent's limit as the queue applies it");
            self.asked.lock().unwrap().excludes |= !exclusion.excludes_nothing();
            let kept =
                self.case.exclusion_honoured && exclusion.among(&[1].into_iter().collect()).await.unwrap().contains(&1);
            if kept {
                return Ok(AgentClaim { scan: None, kept: true });
            }
            if self.case.key_at_delivery {
                self.targets.repository.lock().unwrap().as_mut().unwrap().ssh_key_id = Some(KEY_ID);
            }
            Ok(AgentClaim { scan: Some(self.case.scan.clone()), kept: false })
        })
    }

    fn count_held<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<i64, PortError>> {
        Box::pin(async move { Ok(self.case.held) })
    }

    fn by_id(&self, _: i64) -> BoxFuture<'_, Result<Option<ScanView>, PortError>> {
        unreachable!()
    }

    fn renew_lease<'a>(&'a self, _: i64, _: &'a str) -> BoxFuture<'a, Result<bool, PortError>> {
        unreachable!()
    }

    fn requeue<'a>(&'a self, _: i64, _: &'a str) -> BoxFuture<'a, Result<bool, PortError>> {
        unreachable!("a claim never requeues without its refund")
    }

    fn requeue_refunded<'a>(&'a self, _: i64, _: &'a str) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async move {
            self.asked.lock().unwrap().refunded = true;
            Ok(true)
        })
    }

    fn abandon<'a>(
        &'a self,
        _id: i64,
        worker: &'a str,
        attempt: i32,
        kind: FailureKind,
        reason: &'a (dyn Fn(&Abandoned) -> String + Send + Sync),
    ) -> BoxFuture<'a, Result<Option<Abandoned>, PortError>> {
        Box::pin(async move {
            assert_eq!(worker, AGENT_ID.as_hyphenated().to_string());
            let next = match kind {
                FailureKind::Permanent => Next::Fail { permanent: true },
                FailureKind::Transient => Next::Retry { not_before: NOW },
            };
            let outcome = Abandoned { next, attempt, max_attempts: 3 };
            let name = match kind {
                FailureKind::Permanent => "PERMANENT",
                FailureKind::Transient => "TRANSIENT",
            };
            self.asked.lock().unwrap().abandoned = Some(format!("{name}|{attempt}|{}", reason(&outcome)));
            Ok(Some(outcome))
        })
    }

    fn reclaim_lapsed_leases(&self) -> BoxFuture<'_, Result<Reclaimed, PortError>> {
        unreachable!()
    }

    fn record_sast_languages<'a>(&'a self, _: i64, column: Option<&'a str>) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async move {
            self.asked.lock().unwrap().sast_languages = Some(column.map(str::to_owned));
            Ok(())
        })
    }

    fn lease(&self) -> Duration {
        Duration::from_secs(1_200)
    }

    fn hold_for_write<'a>(&'a self, _: &'a mut Tx, _: i64, _: &'a str) -> BoxFuture<'a, Result<bool, PortError>> {
        unreachable!()
    }

    fn by_id_in<'a>(&'a self, _: &'a mut Tx, _: i64) -> BoxFuture<'a, Result<Option<ScanView>, PortError>> {
        unreachable!()
    }

    fn write_result<'a>(&'a self, _: &'a mut Tx, _: &'a ScanResult) -> BoxFuture<'a, Result<(), PortError>> {
        unreachable!()
    }

    fn begin(&self) -> BoxFuture<'_, Result<Tx, PortError>> {
        unreachable!()
    }
}

struct FakeTargets {
    repository: Mutex<Option<RepositoryView>>,
    container: Option<ContainerView>,
    token: Option<StoredGitToken>,
    key: Option<StoredSshKey>,
}

impl TargetRows for FakeTargets {
    fn repository(&self, id: i64) -> BoxFuture<'_, Result<Option<RepositoryView>, PortError>> {
        let found = self.repository.lock().unwrap().clone().filter(|repository| repository.id == id);
        Box::pin(async move { Ok(found) })
    }

    fn container(&self, id: i64) -> BoxFuture<'_, Result<Option<ContainerView>, PortError>> {
        let found = self.container.clone().filter(|container| container.id == id);
        Box::pin(async move { Ok(found) })
    }

    fn carrying_credentials<'a>(&'a self, ids: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<BTreeSet<i64>, PortError>> {
        let carrying: BTreeSet<i64> = self
            .repository
            .lock()
            .unwrap()
            .iter()
            .filter(|repository| ids.contains(&repository.id))
            .filter(|repository| repository.ssh_key_id.is_some() || repository.https_token_id.is_some())
            .map(|repository| repository.id)
            .collect();
        Box::pin(async move { Ok(carrying) })
    }

    fn git_token(&self, id: Uuid) -> BoxFuture<'_, Result<Option<StoredGitToken>, PortError>> {
        let found = self.token.clone().filter(|token| token.id == id);
        Box::pin(async move { Ok(found) })
    }

    fn ssh_key(&self, id: Uuid) -> BoxFuture<'_, Result<Option<StoredSshKey>, PortError>> {
        let found = self.key.clone().filter(|key| key.id == id);
        Box::pin(async move { Ok(found) })
    }
}

struct Switch(bool);

impl SastSwitch for Switch {
    fn sast_enabled(&self) -> BoxFuture<'_, Result<bool, PortError>> {
        Box::pin(async move { Ok(self.0) })
    }
}

struct Rules(Option<String>, BTreeSet<&'static str>);

impl ScanRuleSets for Rules {
    fn active_hash(&self) -> BoxFuture<'_, Result<Option<String>, PortError>> {
        Box::pin(async move { Ok(self.0.clone()) })
    }

    fn files_of<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<StoredFile>, PortError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn languages_read<'a>(&'a self, _: Option<&'a str>) -> BoxFuture<'a, Result<BTreeSet<&'static str>, PortError>> {
        Box::pin(async move { Ok(self.1.clone()) })
    }
}

struct Plugins(Vec<PluginRef>);

impl ScanPlugins for Plugins {
    fn for_repository(&self, _: i64) -> BoxFuture<'_, Result<Vec<PluginRef>, PortError>> {
        Box::pin(async move { Ok(self.0.clone()) })
    }
}

/// `null`, the context a sealed value opens under and what it opens to, or the clear value.
fn opened(value: Option<&str>, recipient: &SealingKeyPair, context: &SealContext) -> Value {
    match value {
        None => Value::Null,
        Some(value) if !value.starts_with("sealed:") => json!(format!("clear:{value}")),
        Some(value) => match recipient.open(value, context) {
            Some(plain) => json!(format!("sealed:{}:{plain}", context.value())),
            None => json!("sealed:unopened"),
        },
    }
}

fn describe(task: &vectispire_protocol::ScanTask, recipient: &SealingKeyPair) -> Value {
    let mut out = serde_json::Map::new();
    match &task.target {
        Target::Repository(repository) => {
            out.insert("kind".into(), json!("repository"));
            out.insert("url".into(), json!(repository.url));
            out.insert("branch".into(), json!(repository.branch));
            out.insert("subPath".into(), json!(repository.sub_path));
            out.insert(
                "privateKey".into(),
                opened(
                    repository.private_key.as_ref().map(|key| key.expose()),
                    recipient,
                    &SealContext::deployment_key(),
                ),
            );
            out.insert(
                "https".into(),
                repository.https.as_ref().map_or(Value::Null, |https| {
                    let context = SealContext::https_token(https.host.as_deref(), https.username.as_deref());
                    json!({
                        "host": https.host,
                        "username": https.username,
                        "token": opened(https.token.as_ref().map(|token| token.expose()), recipient, &context),
                    })
                }),
            );
        }
        Target::Image(image) => {
            out.insert("kind".into(), json!("image"));
            out.insert("registry".into(), json!(image.reference.registry));
            out.insert("imageName".into(), json!(image.reference.image_name));
            out.insert("tag".into(), json!(image.reference.tag));
            out.insert("platform".into(), json!(image.platform));
        }
    }
    out.insert("rulesHash".into(), json!(task.rules_hash));
    let steps: Vec<String> =
        task.steps.iter().map(|step| serde_json::to_value(step).unwrap().as_str().unwrap().to_owned()).collect();
    out.insert("steps".into(), json!(steps));
    let plugins: Vec<String> = task.plugins.iter().map(|plugin| format!("{}@{}", plugin.id, plugin.digest)).collect();
    out.insert("plugins".into(), json!(plugins));
    Value::Object(out)
}

async fn claim(case: &Case) -> Value {
    let encryption = support::encryption();
    let recipient = SealingKeyPair::generate();
    let key = if case.ssh_key_stored {
        Some(StoredSshKey {
            id: KEY_ID,
            name: "deploy".to_owned(),
            ciphertext: encryption
                .encrypt(PRIVATE_KEY, &vectispire_cp_crypto::private_key_context(&KEY_ID.to_string()))
                .await
                .unwrap(),
        })
    } else {
        None
    };
    let token = match &case.token {
        None => None,
        Some((host, username, readable)) => Some(StoredGitToken {
            id: TOKEN_ID,
            name: "gitlab".to_owned(),
            host: host.clone(),
            username: username.clone(),
            ciphertext: if *readable {
                encryption
                    .encrypt(TOKEN, &vectispire_cp_crypto::git_token_context(&TOKEN_ID.to_string()))
                    .await
                    .unwrap()
            } else {
                "v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()
            },
        }),
    };
    let targets = Arc::new(FakeTargets {
        repository: Mutex::new(case.repository.clone()),
        container: case.container.clone(),
        token,
        key,
    });
    let queue =
        Arc::new(FakeQueue { case: case.clone(), targets: targets.clone(), asked: Mutex::new(Asked::default()) });
    let entries = Arc::new(support::Entries::default());
    let dispatcher = ScanDispatcher::new(DispatcherConfig {
        queue: queue.clone(),
        targets,
        encryption,
        sast: Arc::new(Switch(case.sast)),
        rule_sets: Arc::new(Rules(case.rules_hash.clone(), case.rules_languages.clone())),
        plugins: Arc::new(Plugins(case.plugins.clone())),
        ingestor: Arc::new(IngestionStandIn::default()),
        audit: entries.clone(),
        allowed_hosts: GitHostAllowlist::parse(Some(case.allowed_hosts)).unwrap(),
        image_platform: Some("linux/amd64".to_owned()),
        runner: None,
        scanned: Vec::new(),
    });
    let agent = ClaimingAgent {
        id: AGENT_ID,
        name: Some("edge".to_owned()),
        labels: None,
        max_concurrent: Some(2),
        credentials_mode: Some(case.mode.to_owned()),
        sealing_public_key: case.sealing_key.then(|| recipient.public_key()),
        signing_public_key: case.signing_key.then(|| "MCowBQYDK2VwAyEAinvented".to_owned()),
    };
    let mut answer = serde_json::Map::new();
    answer.insert("case".into(), json!(case.name));
    match dispatcher.claim_for_agent(&agent).await {
        Ok(Some(task)) => {
            answer.insert("outcome".into(), json!("task"));
            answer.insert("scanId".into(), json!(task.scan_id));
            answer.insert("attempt".into(), json!(task.attempt));
            answer.insert("task".into(), describe(&task.task, &recipient));
        }
        Ok(None) => {
            answer.insert("outcome".into(), json!("nothing"));
        }
        Err(ClaimError::Withheld(withheld)) => {
            answer.insert("outcome".into(), json!("withheld"));
            answer.insert("message".into(), json!(withheld.message()));
        }
        Err(ClaimError::Failed(failure)) => panic!("{}: {failure}", case.name),
    }
    let asked = queue.asked.lock().unwrap();
    answer.insert("limit".into(), json!(2));
    answer.insert("excludes".into(), json!(asked.excludes));
    answer.insert("requeuedRefunded".into(), json!(asked.refunded));
    answer.insert("abandoned".into(), json!(asked.abandoned.clone().unwrap_or_else(|| "~".to_owned())));
    answer.insert(
        "sastLanguages".into(),
        json!(match &asked.sast_languages {
            None => "not recorded".to_owned(),
            Some(column) => column.clone().unwrap_or_else(|| "null".to_owned()),
        }),
    );
    let audited: Vec<String> = entries
        .taken()
        .iter()
        .map(|entry| {
            format!(
                "{}|{}|{}|{}",
                entry.operation.wire_name(),
                entry.resource_id.as_deref().unwrap_or("null"),
                entry.user_id.as_deref().unwrap_or("null"),
                entry.description.as_deref().unwrap_or("null")
            )
        })
        .collect();
    answer.insert("audit".into(), json!(audited));
    Value::Object(answer)
}

#[tokio::test]
async fn every_claim_hands_the_agent_what_java_hands_it() {
    let answers = answers();
    let expected: BTreeMap<String, Value> = answers["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|answer| (answer["case"].as_str().unwrap().to_owned(), answer.clone()))
        .collect();
    let cases = cases();
    assert_eq!(cases.len(), expected.len(), "every case Java answered");
    let mut differences = Vec::new();
    for case in &cases {
        let answer = claim(case).await;
        if Some(&answer) != expected.get(case.name) {
            differences.push(format!("{}:\n  java {}\n  rust {answer}", case.name, expected[case.name]));
        }
    }
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
}
