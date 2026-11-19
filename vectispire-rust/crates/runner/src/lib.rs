//! One claimed scan, run — `ScanRunner` on the Java side, which the agent and the built-in worker share.
//!
//! **Each step is independent of the others.** One scanner failing does not sink the scan: its result
//! stays absent — "not looked at", which protects that type's backlog (decision 0007) — and the step
//! is recorded as a failure with what happened. Only the clone and the sub-path are blocking: with no
//! tree there is nothing to analyse, and carrying on would produce empty lists that resolve everything.
//!
//! **The tree is read in process before any container runs**: the project manifest and the language census, which
//! are not steps — a file read and a count of names, whose absence fails nothing — and the API discovery, which is
//! one, and fails as one. Each reads the repository's content in this process, through `vectispire_scanners`'
//! bounded, link-refusing readers.
//!
//! **The plugins run** (`with_plugins`), last and each on its own, decided on that census: a plugin none of whose
//! languages the tree holds is not applicable; an incomplete census runs every plugin, since "not applicable" is a
//! claim.
//!
//! **An image is one step**: exported by this process through the daemon, inventoried from the
//! archive, matched — secrets, IaC and source analysis stay absent, since they look inside source code
//! and declaring them scanned would resolve their whole history for the target.

pub mod configuration_files;

use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use vectispire_container::Executor;
use vectispire_container::{ContainerRunner, ScannerLimits};
pub use vectispire_domain::FailureKind;
pub use vectispire_git::WithoutKey;
use vectispire_git::{CloneRequest, HostKeyPolicy, HttpsCredential};
pub use vectispire_protocol::ScanArtifacts;
use vectispire_protocol::{Findings, Image, PluginRef, PluginStep, Project, ScanTask, Step, Target};
use vectispire_scanners::dependencies::{self, StepError};
use vectispire_scanners::plugins::{self, PluginScanner};
pub use vectispire_scanners::rules::StoredFile;
use vectispire_scanners::rules::{self, RulePlacement};
use vectispire_scanners::vulnerability_database::VulnerabilityDatabase;
use vectispire_scanners::{api_discovery, census, container_paths, iac, jackson, manifest, sast, secrets};
use vectispire_tls::TlsTrust;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The provider for uploaded rule sets — fetched over the protocol by the agent, or read from its own
/// tables by the control plane's built-in worker.
pub trait RuleProvider: Send + Sync {
    fn fetch_rule_set<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<Vec<StoredFile>, String>>;
}

impl<F> RuleProvider for F
where
    F: for<'a> Fn(&'a str) -> BoxFuture<'a, Result<Vec<StoredFile>, String>> + Send + Sync,
{
    fn fetch_rule_set<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<Vec<StoredFile>, String>> {
        (self)(hash)
    }
}

/// Where a plugin's manifest comes from — fetched over the protocol by the agent, read from the control plane's
/// tables by its built-in worker (`PluginProvider`). `Value::Null` for none; the error says why it could not be had.
pub trait PluginSource: Send + Sync {
    fn fetch_manifest<'a>(&'a self, reference: &'a PluginRef) -> BoxFuture<'a, Result<serde_json::Value, String>>;
}

/// The source a runner has when it was given none — `PluginProvider.NONE`: every plugin a task names is absent,
/// loudly.
struct NoPluginSource;

impl PluginSource for NoPluginSource {
    fn fetch_manifest<'a>(&'a self, reference: &'a PluginRef) -> BoxFuture<'a, Result<serde_json::Value, String>> {
        Box::pin(async move { Err(format!("This executor has no way to fetch plugin {}.", reference.id)) })
    }
}

/// A [`PluginSource`] as the plugin steps take it.
struct Provider<'a>(&'a dyn PluginSource);

impl plugins::PluginProvider for Provider<'_> {
    fn manifest<'a>(
        &'a self,
        reference: &'a PluginRef,
    ) -> impl Future<Output = Result<serde_json::Value, String>> + Send + 'a {
        self.0.fetch_manifest(reference)
    }
}

/// Why a claimed scan produced no result — what the runner hands the loop or dispatcher instead of artifacts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ExecutionFailure {
    pub message: String,
    pub kind: FailureKind,
}

/// The images a scan runs, the pinned digests unless the operator named others — `ScannerImages`.
#[derive(Debug, Clone)]
pub struct Images {
    pub syft: String,
    pub grype: String,
    pub gitleaks: String,
    pub checkov: String,
    pub semgrep: String,
}

impl Images {
    /// `ScannerImages.PINNED.withOverrides`, from the Java agent's variables: blank keeps the pin.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Images {
        let image = |variable: &str, pinned: &str| {
            lookup(variable)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| pinned.to_owned())
        };
        use vectispire_scanners::images as pinned;
        Images {
            syft: image("VECTISPIRE_IMAGE_SYFT", pinned::SYFT),
            grype: image("VECTISPIRE_IMAGE_GRYPE", pinned::GRYPE),
            gitleaks: image("VECTISPIRE_IMAGE_GITLEAKS", pinned::GITLEAKS),
            checkov: image("VECTISPIRE_IMAGE_CHECKOV", pinned::CHECKOV),
            semgrep: image("VECTISPIRE_IMAGE_SEMGREP", pinned::SEMGREP),
        }
    }
}

/// Where this process keeps what it writes — the Java agent's `java.io.tmpdir` and `user.home`.
///
/// **Read from the same place the Java agent reads them**, so that swapping the image is the whole
/// migration: `VECTISPIRE_WORK_DIR` first, then the `-Djava.io.tmpdir=` and `-Duser.home=` the
/// composition passes in `JDK_JAVA_OPTIONS`, then `TMPDIR` and `HOME`. The workspaces must be on a path
/// the daemon resolves the same way (the composition mounts it at the same absolute path).
#[derive(Debug, Clone)]
pub struct Places {
    pub work: PathBuf,
    pub home: PathBuf,
}

impl Places {
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Places {
        let java_option = |name: &str| {
            lookup("JDK_JAVA_OPTIONS").and_then(|options| {
                options
                    .split_whitespace()
                    .find_map(|option| option.strip_prefix(&format!("-D{name}=")).map(str::to_owned))
            })
        };
        let set = |value: Option<String>| value.map(|value| value.trim().to_owned()).filter(|value| !value.is_empty());
        let work = set(lookup("VECTISPIRE_WORK_DIR"))
            .or_else(|| set(java_option("java.io.tmpdir")))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let home = set(java_option("user.home"))
            .or_else(|| set(lookup("HOME")))
            .map(PathBuf::from)
            .unwrap_or_else(|| work.join("home"));
        Places { work, home }
    }
}

/// What differs between the agent's runner and the built-in worker's — `ScanRunner`'s constructor arguments that the
/// two sides answer differently.
#[derive(Debug, Clone)]
pub struct Options {
    /// What a repository with no deployment key is cloned with. The agent in `local` mode uses the host's git access,
    /// which is what that mode means; the built-in worker does only when `vectispire.scanning.host-ssh` says so,
    /// since inside the control plane it lets any target added to Vectispire be cloned with the host's identity.
    pub without_key: WithoutKey,
    /// `vectispire.scanning.bundled-rules`: a directory read in place of the rules this binary carries, or `None`
    /// to unpack those.
    pub bundled_rules: Option<PathBuf>,
}

impl Default for Options {
    /// The agent's: the host's SSH, the bundled rules.
    fn default() -> Options {
        Options { without_key: WithoutKey::HostSsh, bundled_rules: None }
    }
}

/// What every scan of this process shares — the runner used by both the agent and the built-in worker.
pub struct Runner {
    containers: Arc<Executor>,
    images: Images,
    database: VulnerabilityDatabase<Executor>,
    placement: RulePlacement,
    /// Kept for as long as the process runs: its drop removes the materialised tree. `None` when the operator named
    /// a directory of their own, which is theirs and is never removed.
    _bundled: Option<rules::MaterialisedRules>,
    rule_provider: Option<Arc<dyn RuleProvider>>,
    /// Where the plugins' manifests come from, and what this executor decides about them for itself.
    plugin_source: Arc<dyn PluginSource>,
    plugin_settings: plugins::Settings,
    places: Places,
    trust: TlsTrust,
    without_key: WithoutKey,
}

impl std::fmt::Debug for Runner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Runner").field("images", &self.images).field("places", &self.places).finish()
    }
}

/// The step names and reasons of `ScanRunner`, word for word: they reach the scan's page.
const SECRETS_ABSENT: &str = "the search for hardcoded secrets did not complete.";
const IAC_ABSENT: &str = "the infrastructure manifest check did not complete.";
const SAST_ABSENT: &str = "the source analysis did not run, or covered too few files to be worth reading.";

impl Runner {
    /// `vulnerability_root`: `VECTISPIRE_VULNERABILITY_DB_DIR`, blank for a directory beside the
    /// workspaces, as on the Java agent. The agent's [`Options`].
    pub fn new(
        rule_provider: Option<Arc<dyn RuleProvider>>,
        images: Images,
        places: Places,
        vulnerability_root: Option<PathBuf>,
        trust: TlsTrust,
    ) -> Result<Runner, String> {
        Runner::with_options(rule_provider, images, places, vulnerability_root, trust, Options::default())
    }

    /// The same, with the side's own [`Options`].
    pub fn with_options(
        rule_provider: Option<Arc<dyn RuleProvider>>,
        images: Images,
        places: Places,
        vulnerability_root: Option<PathBuf>,
        trust: TlsTrust,
        options: Options,
    ) -> Result<Runner, String> {
        let limits = ScannerLimits::default_for_this_host();
        let docker = ContainerRunner::for_scans(&places.home, limits)?;
        Runner::with_executor(rule_provider, images, places, vulnerability_root, trust, options, Executor::new(docker))
    }

    /// The same, running its scanners on `executor` — the agent's choice of Docker or Kubernetes (decision 0045). The
    /// control plane's built-in worker never comes here with anything but Docker: it holds the encryption key, and
    /// the Kubernetes executor is not in its graph.
    pub fn with_executor(
        rule_provider: Option<Arc<dyn RuleProvider>>,
        images: Images,
        places: Places,
        vulnerability_root: Option<PathBuf>,
        trust: TlsTrust,
        options: Options,
        executor: Executor,
    ) -> Result<Runner, String> {
        let timeout = executor.scanner_timeout();
        let containers = Arc::new(executor);
        let root = database_root(&places, vulnerability_root);
        let database = VulnerabilityDatabase::with_defaults(containers.clone(), images.grype.clone(), &root, timeout);
        // Unpacked from the binary, as Java unpacks them from its jar: no rules directory ships beside it, and one
        // read from the current directory would be whatever is there. An operator's directory is taken as named,
        // as `ScanningConfiguration.bundledRules` takes it — read at each scan, so a missing one fails the scans.
        let (bundled, placement) = match options.bundled_rules.filter(|path| !path.as_os_str().is_empty()) {
            Some(directory) => (None, RulePlacement::new(directory)),
            None => {
                let bundled = rules::materialise_in(&places.work)
                    .map_err(|error| format!("the bundled rules could not be unpacked: {error}"))?;
                let placement = RulePlacement::new(bundled.tree());
                (Some(bundled), placement)
            }
        };
        Ok(Runner {
            containers,
            images,
            database,
            placement,
            _bundled: bundled,
            rule_provider,
            plugin_source: Arc::new(NoPluginSource),
            plugin_settings: plugins::Settings::default(),
            places,
            trust,
            without_key: options.without_key,
        })
    }

    /// This runner, fetching plugin manifests from `source` and deciding about them by `settings` — the mirror their
    /// images are pulled from, and whether a signer is required (on unless the operator switched it off).
    #[must_use]
    pub fn with_plugins(mut self, source: Arc<dyn PluginSource>, settings: plugins::Settings) -> Runner {
        self.plugin_source = source;
        self.plugin_settings = settings;
        self
    }

    /// Why the executor cannot run anything now — `None` when its daemon answers. Asked before claiming.
    pub async fn why_unavailable(&self) -> Option<String> {
        self.containers.why_unavailable().await
    }

    /// Whether this runner scans container images — `ContainerExecutor.exportsImages`: true for the Docker backend,
    /// false for the Kubernetes one until its copy step is built (decision 0045 §8). What the worker's executor
    /// announces (`ScanDispatcher.probe`): the agents screen lists `container` among the targets it serves only when
    /// this says so, and the claim hands it no image otherwise.
    pub fn exports_images(&self) -> bool {
        self.containers.exports_images()
    }

    pub async fn run(&self, task: ScanTask) -> Result<ScanArtifacts, ExecutionFailure> {
        let started = Instant::now();
        let repository = match &task.target {
            Target::Repository(repository) => repository.clone(),
            Target::Image(image) => return self.run_image(image, started).await,
        };
        let workspace = Workspace::create(&self.places.work)?;
        let mut artifacts = ScanArtifacts::default();

        self.clone_into(&repository, &workspace.source).await?;
        let sub_path = vectispire_domain::sub_path::normalize(repository.sub_path.as_deref())
            .map_err(|problem| permanent(format!("The repository's sub-path is refused: {problem}")))?;
        let branch = repository.branch.clone().unwrap_or_default();
        let scan_root = prepare_tree(&workspace.source, &sub_path, &branch)?;
        let sub = (!sub_path.is_empty()).then_some(sub_path.as_str());

        // The census is kept for the plugins below: an incomplete one runs every plugin.
        let census = read_in_process(scan_root.clone(), &mut artifacts).await;

        if task.runs(Step::Dependencies) {
            let (step, sbom) = dependencies::tree_step(
                self.containers.as_ref(),
                &self.database,
                &self.images.syft,
                &self.images.grype,
                &workspace.root,
                sub,
            )
            .await;
            // The SBOM is kept when the match fails, as `artifacts.sbom` is set before the match runs.
            if let Some(sbom) = sbom {
                artifacts.sbom = raw(&sbom);
            }
            match step {
                Ok(done) => artifacts.dependencies = findings(&done.dependencies),
                Err(StepError::DidNotRun(reason)) => artifacts.failed("dependencies", reason),
                Err(StepError::Failed(error)) => artifacts.failed("dependencies", error.to_string()),
            }
        }

        // **Placed before the scanners, not inside the SAST step**: the secrets scanner needs its
        // configuration from here rather than from the analysed tree.
        self.placement
            .place_bundled(&workspace.rules)
            .map_err(|error| transient(format!("the bundled rules could not be placed: {error}")))?;

        if task.runs(Step::Secrets) {
            match secrets::scan(self.containers.as_ref(), &workspace.root, sub, &self.images.gitleaks).await {
                Ok(Some(found)) => artifacts.secrets = findings(&found),
                Ok(None) => artifacts.failed("secrets", SECRETS_ABSENT),
                Err(error) => artifacts.failed("secrets", error.to_string()),
            }
        }
        if task.runs(Step::Iac) {
            match iac::scan(self.containers.as_ref(), &workspace.root, sub, &self.images.checkov).await {
                Some(found) => artifacts.iac = findings(&found),
                None => artifacts.failed("IaC", IAC_ABSENT),
            }
        }
        if task.runs(Step::Sast) {
            match self.sast(&task, &workspace, sub).await {
                Ok(Some(found)) => artifacts.sast = findings(&found),
                Ok(None) => artifacts.failed("SAST", SAST_ABSENT),
                Err(reason) => artifacts.failed("SAST", reason),
            }
        }

        // Last, and each on its own: see `run_plugins`.
        self.run_plugins(&task, &workspace.root, &scan_root, &census, &mut artifacts).await;

        artifacts.duration = started.elapsed();
        Ok(artifacts)
    }

    /// `runPlugins`: the task's plugins, after every scanner. **Each on its own**: a plugin's failure is its own
    /// step's — recorded as a failure of the scan under the plugin's name, its issues left alone, no scanner touched.
    /// A plugin the executor refused to start is a failure too, under the same name; one whose languages the tree
    /// does not hold is not run and not a failure.
    async fn run_plugins(
        &self,
        task: &ScanTask,
        workspace_root: &Path,
        scan_root: &Path,
        census: &census::Census,
        artifacts: &mut ScanArtifacts,
    ) {
        if task.plugins.is_empty() {
            return;
        }
        let scanner = PluginScanner::new(self.containers.as_ref(), self.plugin_settings.clone());
        // The runner's census of the whole tree, as Java decides the plugins on it (`runPlugins(…, census, …)`).
        let steps = plugins::run_steps(
            &scanner,
            &Provider(self.plugin_source.as_ref()),
            &task.plugins,
            workspace_root,
            Some(scan_root),
            |declared| census.applies(declared),
        )
        .await;
        record_plugins(steps, artifacts);
    }

    /// `runImage`: one step, over an archive this process exported. Nothing else applies to an image, and nothing
    /// else is declared scanned — each stays absent, "not looked at", which is the truth.
    async fn run_image(&self, image: &Image, started: Instant) -> Result<ScanArtifacts, ExecutionFailure> {
        let workspace = Workspace::create(&self.places.work)?;
        let mut artifacts = ScanArtifacts::default();
        let (step, sbom) = dependencies::image_step(
            self.containers.as_ref(),
            &self.database,
            &self.images.syft,
            &self.images.grype,
            &workspace.root,
            &image.reference.format(),
            image.platform.as_deref().unwrap_or_default(),
        )
        .await;
        if let Some(sbom) = sbom {
            artifacts.sbom = raw(&sbom);
        }
        match step {
            Ok(done) => artifacts.dependencies = findings(&done.dependencies),
            Err(StepError::DidNotRun(reason)) => artifacts.failed("dependencies", reason),
            Err(StepError::Failed(error)) => artifacts.failed("dependencies", error.to_string()),
        }
        artifacts.duration = started.elapsed();
        Ok(artifacts)
    }

    async fn clone_into(
        &self,
        repository: &vectispire_protocol::Repository,
        into: &Path,
    ) -> Result<(), ExecutionFailure> {
        let https = repository.https.as_ref().and_then(|https| {
            https.token.clone().map(|token| HttpsCredential {
                host: https.host.clone().unwrap_or_default(),
                username: https.username.clone(),
                token,
            })
        });
        let request = CloneRequest {
            url: repository.url.clone(),
            branch: repository.branch.clone().unwrap_or_default(),
            into: into.to_owned(),
            private_key: repository.private_key.clone(),
            timeout: Duration::from_secs(300),
            // As the Java agent: the hosts recorded in this process's home, a changed key refused.
            host_keys: HostKeyPolicy::AcceptNew(self.places.home.join(".ssh").join("known_hosts")),
            without_key: self.without_key,
            https,
            trust: self.trust.clone(),
        };
        tokio::task::spawn_blocking(move || vectispire_git::clone(&request))
            .await
            .map_err(|error| transient(format!("the clone did not finish: {error}")))?
            .map_err(|error| ExecutionFailure { message: error.message, kind: error.kind.failure_kind() })
    }

    /// The SAST step: the rule set first — inside the step, so that a set that cannot be had fails SAST
    /// alone and never lets the analyser run with the bundled rules and report a shorter, clean list.
    async fn sast(
        &self,
        task: &ScanTask,
        workspace: &Workspace,
        sub: Option<&str>,
    ) -> Result<Option<Vec<sast::SastFinding>>, String> {
        let hash = task.rules_hash.as_deref().filter(|hash| !hash.trim().is_empty());
        let fetched: Option<Result<Vec<StoredFile>, String>> = match (hash, &self.rule_provider) {
            (None, _) => None,
            (Some(_), None) => {
                Some(Err("uploaded rule sets are not supported: no rule provider is configured".to_owned()))
            }
            (Some(hash), Some(provider)) => Some(provider.fetch_rule_set(hash).await),
        };
        let provider = |_: &str| -> Result<Vec<StoredFile>, String> {
            fetched.clone().unwrap_or_else(|| Err("no rule set was fetched".to_owned()))
        };
        self.placement
            .place_rule_set(&workspace.rules, hash, Some(&provider), RulePlacement::environment_directory().as_deref())
            .map_err(|error| error.to_string())?;
        sast::scan(self.containers.as_ref(), &workspace.root, sub, &self.images.semgrep)
            .await
            .map_err(|error| error.to_string())
    }
}

/// Where the matcher's database is kept for every scan: `VECTISPIRE_VULNERABILITY_DB_DIR`, or a directory beside the
/// workspaces. The Kubernetes executor serves this root's generations to scan pods from its cache volume, so the agent
/// asks it here rather than computing it a second time.
pub fn database_root(places: &Places, configured: Option<PathBuf>) -> PathBuf {
    configured.unwrap_or_else(|| places.work.join("vectispire-vulnerability-db"))
}

/// A step's findings as the protocol carries them, each written as the Java agent's mapper writes it.
/// What `ScanRunner.analyse` learns from the tree in its own process, in its order: the manifest, the census, and
/// the API discovery — on a blocking thread, since each walks or reads the tree.
async fn read_in_process(scan_root: PathBuf, artifacts: &mut ScanArtifacts) -> census::Census {
    let read = tokio::task::spawn_blocking(move || {
        (manifest::read(&scan_root), census::of(&scan_root, &BTreeSet::new()), api_discovery::scan(&scan_root))
    })
    .await;
    let (project, census, discovery) = match read {
        Ok(read) => read,
        Err(_) => {
            // The thread did not finish: nothing was learnt, and the discovery says so.
            artifacts.failed(api_discovery::STEP, "the API discovery did not complete.");
            return census::Census { found: BTreeSet::new(), complete: false };
        }
    };
    // **Not a step, and not wrapped in one**: a missing manifest is an ordinary property of a repository.
    artifacts.project =
        project.map(|project| Project { kind: Some(project.kind.to_owned()), version: project.version });
    // An incomplete census records nothing: absent reads as unknown, where a partial set would say a Java
    // repository holds no Java.
    artifacts.languages = census.recorded();
    // A step like the others: failed, never empty, when it did not happen — empty would replace the inventory.
    match discovery {
        Ok(discovery) => {
            artifacts.api_endpoints = findings(&discovery.endpoints);
            artifacts.api_contracts = findings(&discovery.contracts);
        }
        Err(failed) => artifacts.failed(api_discovery::STEP, failed.0),
    }
    census
}

/// Each step into the artifacts, and the absent and refused ones into the scan's failures under `plugin <id>`.
fn record_plugins(steps: Vec<PluginStep>, artifacts: &mut ScanArtifacts) {
    for step in steps {
        match &step {
            PluginStep::Absent { plugin_id, reason, .. } | PluginStep::Refused { plugin_id, reason, .. } => {
                // Refused is a failure of the scan too — nothing was examined, and somebody has to act: sign the
                // image, or have the governor waive the requirement in writing.
                artifacts.failed(format!("plugin {plugin_id}"), reason.clone());
            }
            PluginStep::Produced { .. } | PluginStep::NotApplicable { .. } => {}
        }
        artifacts.plugins.push(step);
    }
}

fn findings<T: serde::Serialize>(found: &[T]) -> Option<Findings> {
    // A finding that does not serialize cannot happen for these types; were it to, the step reads as
    // absent rather than as a shorter list.
    Findings::from_documents(found.iter().map(jackson::to_wire_string)).ok()
}

fn raw(document: &serde_json::Value) -> Option<Box<serde_json::value::RawValue>> {
    serde_json::value::RawValue::from_string(jackson::to_wire_string(document)).ok()
}

/// The cloned tree made ready for the scanners: **their own configuration files taken out before anything reads it**
/// (`configuration_files`, `ScanRunner.analyse`) — outside any step, like the clone, since every scanner would read
/// a tree that could not be cleared — then the directory they examine, proven to lie inside the clone.
fn prepare_tree(source: &Path, sub_path: &str, branch: &str) -> Result<PathBuf, ExecutionFailure> {
    let removed = configuration_files::remove_from(source).map_err(|error| {
        transient(format!("The scanners' configuration files could not be removed from the clone: {error}"))
    })?;
    if !removed.is_empty() {
        // A signal, not a finding: a finding of a new type would enter the backlog and the gate on a file that, once
        // removed, changes nothing.
        tracing::info!(?removed, "the tree carried scanner configuration files; removed before any scanner ran");
    }
    scan_root(source, sub_path, branch)
}

fn permanent(message: String) -> ExecutionFailure {
    ExecutionFailure { message, kind: FailureKind::Permanent }
}

fn transient(message: String) -> ExecutionFailure {
    ExecutionFailure { message, kind: FailureKind::Transient }
}

/// The directory the scan examines, proven to lie inside the clone and to be there — `scanRoot` and
/// `SourceFiles.within`. A directory of the repository may itself be a link out of it.
pub fn scan_root(source: &Path, sub_path: &str, branch: &str) -> Result<PathBuf, ExecutionFailure> {
    let root = source.canonicalize().map_err(|_| transient("The clone could not be resolved.".to_owned()))?;
    let candidate = if sub_path.is_empty() { root.clone() } else { root.join(sub_path) };
    if std::fs::symlink_metadata(&candidate).is_err() {
        return Err(permanent(format!("The sub-path \"{sub_path}\" is not a directory of branch \"{branch}\".")));
    }
    let real = candidate.canonicalize().map_err(|_| transient("The clone could not be resolved.".to_owned()))?;
    if !real.starts_with(&root) {
        return Err(permanent(format!("The sub-path \"{sub_path}\" leads outside the repository.")));
    }
    if !real.is_dir() {
        return Err(permanent(format!("The sub-path \"{sub_path}\" is not a directory of branch \"{branch}\".")));
    }
    Ok(real)
}

/// A scan's workspace: a 0700 directory with the tree in `source/` and the rules in `rules/` beside it
/// — never inside it: the secrets report and the SBOM land at the root. Removed when dropped, failure
/// included: a failed scan leaves a clone, and often the secrets report.
#[derive(Debug)]
pub struct Workspace {
    pub root: PathBuf,
    pub source: PathBuf,
    pub rules: PathBuf,
    _directory: tempfile::TempDir,
}

impl Workspace {
    pub fn create(work: &Path) -> Result<Workspace, ExecutionFailure> {
        std::fs::create_dir_all(work)
            .map_err(|error| transient(format!("could not create a scan workspace: {error}")))?;
        let directory = tempfile::Builder::new()
            .prefix("vectispire-scan-")
            .tempdir_in(work)
            .map_err(|error| transient(format!("could not create a scan workspace: {error}")))?;
        let root = directory.path().to_owned();
        Ok(Workspace {
            source: root.join(container_paths::SOURCE_SUBDIR),
            rules: root.join(container_paths::RULES_SUBDIR),
            root,
            _directory: directory,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| pairs.iter().find(|(key, _)| *key == name).map(|(_, value)| (*value).to_owned())
    }

    #[test]
    fn the_places_are_read_where_the_java_agent_reads_them() {
        let composition = Places::from_lookup(lookup(&[(
            "JDK_JAVA_OPTIONS",
            "-Djava.io.tmpdir=/var/lib/vectispire/agent-work -Duser.home=/var/lib/vectispire/agent-work/home",
        )]));
        assert_eq!(composition.work, PathBuf::from("/var/lib/vectispire/agent-work"));
        assert_eq!(composition.home, PathBuf::from("/var/lib/vectispire/agent-work/home"));
        let explicit = Places::from_lookup(lookup(&[("VECTISPIRE_WORK_DIR", "/w"), ("HOME", "/h")]));
        assert_eq!((explicit.work, explicit.home), (PathBuf::from("/w"), PathBuf::from("/h")));
    }

    fn runner(work: &Path, bundled_rules: Option<PathBuf>) -> Runner {
        let places = Places { work: work.to_owned(), home: work.join("home") };
        let options = Options { without_key: WithoutKey::None, bundled_rules };
        Runner::with_options(None, Images::from_lookup(|_| None), places, None, TlsTrust::BuiltIn, options).unwrap()
    }

    fn unpacked(work: &Path) -> usize {
        std::fs::read_dir(work)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(rules::PREFIX))
            .count()
    }

    /// `vectispire.scanning.bundled-rules`: the operator's directory is what a scan places, and the binary's own rules
    /// are not unpacked beside it. Blank is no override.
    #[test]
    fn an_operator_s_rules_directory_is_placed_in_place_of_the_bundled_rules() {
        let work = tempfile::tempdir().unwrap();
        let operator = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(operator.path().join("semgrep")).unwrap();
        std::fs::write(operator.path().join("semgrep/house.yml"), "rules: []\n").unwrap();

        let configured = runner(work.path(), Some(operator.path().to_owned()));
        assert_eq!(unpacked(work.path()), 0, "nothing unpacked when the operator names a directory");
        let placed = tempfile::tempdir().unwrap();
        configured.placement.place_bundled(placed.path()).unwrap();
        assert!(placed.path().join("semgrep/house.yml").is_file(), "the operator's rules are the ones placed");
        drop(configured);
        assert!(operator.path().join("semgrep/house.yml").is_file(), "the operator's directory is never removed");

        let _bundled = runner(work.path(), Some(PathBuf::new()));
        assert_eq!(unpacked(work.path()), 1, "a blank directory unpacks the binary's own");
    }

    /// The Docker backend exports images, so the executor the agents screen shows serves containers too.
    #[test]
    fn a_refused_or_absent_plugin_is_a_failure_of_the_scan_under_its_name_and_the_others_are_not() {
        let step = |state: &str, id: &str| -> PluginStep {
            let digest = "d".to_owned();
            match state {
                "absent" => {
                    PluginStep::Absent { plugin_id: id.into(), manifest_digest: digest, reason: "exited".into() }
                }
                "refused" => PluginStep::Refused {
                    plugin_id: id.into(),
                    manifest_digest: digest,
                    refusal: vectispire_protocol::Refusal::Unsigned,
                    reason: "unsigned".into(),
                },
                "na" => PluginStep::NotApplicable { plugin_id: id.into(), manifest_digest: digest, languages: vec![] },
                _ => PluginStep::Produced {
                    plugin_id: id.into(),
                    manifest_digest: digest,
                    tool_name: None,
                    tool_version: None,
                    findings: Findings::default(),
                    signature: None,
                },
            }
        };
        let mut artifacts = ScanArtifacts::default();
        record_plugins(
            vec![step("absent", "a"), step("refused", "b"), step("na", "c"), step("produced", "d")],
            &mut artifacts,
        );
        assert_eq!(artifacts.plugins.len(), 4, "every step is on the wire, in order");
        let failures: Vec<(&str, &str)> =
            artifacts.failures.iter().map(|failure| (failure.step.as_str(), failure.reason.as_str())).collect();
        assert_eq!(failures, [("plugin a", "exited"), ("plugin b", "unsigned")]);
    }

    #[test]
    fn the_docker_backend_says_it_exports_images() {
        let work = tempfile::tempdir().unwrap();
        assert!(runner(work.path(), None).exports_images());
    }

    #[test]
    fn a_blank_image_override_keeps_the_pinned_digest() {
        let images =
            Images::from_lookup(lookup(&[("VECTISPIRE_IMAGE_SYFT", "  "), ("VECTISPIRE_IMAGE_GRYPE", "r/g@sha256:1")]));
        assert_eq!(images.syft, vectispire_scanners::images::SYFT);
        assert_eq!(images.grype, "r/g@sha256:1");
    }

    /// The tree the scanners are started on carries none of their configuration files, in the sub-path or above it.
    #[test]
    fn the_tree_is_cleared_of_the_scanners_configuration_before_its_root_is_proven() {
        let clone = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(clone.path().join("infra")).unwrap();
        for name in [".semgrepignore", "infra/.checkov.yaml", "infra/.gitleaksignore"] {
            std::fs::write(clone.path().join(name), "planted\n").unwrap();
        }
        let root = prepare_tree(clone.path(), "infra", "main").unwrap();
        assert_eq!(root, clone.path().join("infra").canonicalize().unwrap());
        for name in [".semgrepignore", "infra/.checkov.yaml", "infra/.gitleaksignore"] {
            assert!(!clone.path().join(name).exists(), "{name} is still there for the scanners");
        }
        assert_eq!(prepare_tree(clone.path(), "missing", "main").unwrap_err().kind, FailureKind::Permanent);
    }

    #[test]
    fn a_sub_path_out_of_the_clone_or_absent_from_it_fails_the_scan_for_good() {
        let clone = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(clone.path().join("services/api")).unwrap();
        std::fs::write(clone.path().join("file"), "").unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), clone.path().join("out")).unwrap();

        assert!(scan_root(clone.path(), "services/api", "main").is_ok());
        assert!(scan_root(clone.path(), "", "main").is_ok());
        for (sub, said) in [
            ("missing", "The sub-path \"missing\" is not a directory of branch \"main\"."),
            ("file", "The sub-path \"file\" is not a directory of branch \"main\"."),
            ("out", "The sub-path \"out\" leads outside the repository."),
        ] {
            let failure = scan_root(clone.path(), sub, "main").unwrap_err();
            assert_eq!((failure.message.as_str(), failure.kind), (said, FailureKind::Permanent), "{sub}");
        }
    }

    #[tokio::test]
    async fn the_tree_is_read_in_process_as_the_java_runner_reads_it() {
        let tree = tempfile::tempdir().unwrap();
        std::fs::write(tree.path().join("package.json"), r#"{"version":"1.2.3"}"#).unwrap();
        std::fs::write(tree.path().join("server.js"), "app.get('/health', h)\n").unwrap();
        std::fs::write(tree.path().join("openapi.yaml"), "openapi: 3\npaths:\n  /spec:\n    get:\n").unwrap();
        let mut artifacts = ScanArtifacts::default();
        let census = read_in_process(tree.path().to_owned(), &mut artifacts).await;
        assert!(census.complete);
        assert_eq!(artifacts.project, Some(Project { kind: Some("npm".into()), version: Some("1.2.3".into()) }));
        let languages: Vec<_> = artifacts.languages.clone().unwrap().into_iter().collect();
        assert_eq!(languages, ["javascript", "json", "yaml"]);
        let body: serde_json::Value = serde_json::from_str(&artifacts.to_body().unwrap()).unwrap();
        let paths: Vec<_> =
            body["apiEndpoints"].as_array().unwrap().iter().map(|endpoint| endpoint["path"].clone()).collect();
        assert_eq!(paths.len(), 2, "{paths:?}");
        assert!(paths.contains(&serde_json::json!("/health")) && paths.contains(&serde_json::json!("/spec")));
        assert_eq!(body["apiContracts"][0]["contractPath"], "openapi.yaml");
        assert!(artifacts.failures.is_empty(), "{:?}", artifacts.failures);
        assert!(artifacts.observed_nothing(), "a version and an API inventory observe nothing (`observedNothing`)");
    }

    #[tokio::test]
    async fn a_tree_that_is_not_there_fails_the_discovery_and_records_no_language() {
        let tree = tempfile::tempdir().unwrap();
        let mut artifacts = ScanArtifacts::default();
        let census = read_in_process(tree.path().join("missing"), &mut artifacts).await;
        assert!(!census.complete);
        assert_eq!((artifacts.project.clone(), artifacts.languages.clone()), (None, None));
        assert!(artifacts.api_endpoints.is_none() && artifacts.api_contracts.is_none(), "absent, never empty");
        assert_eq!(artifacts.failures.len(), 1);
        assert_eq!(artifacts.failures[0].step, "api discovery");
        assert!(artifacts.failures[0].reason.ends_with(": no source tree to discover APIs in"));
    }
}
