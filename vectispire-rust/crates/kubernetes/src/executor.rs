//! Runs each [`ContainerRun`] as a pod, in a namespace of its own, on a cluster with no Docker (decision 0045) —
//! `KubernetesExecutor`.
//!
//! **The closed shape, as far as a pod expresses it.** No capability, no new privilege, a read-only root, the
//! workspace owner's uid, seccomp `RuntimeDefault`, memory and CPU limits, no token, a fresh pod deleted after its run;
//! the namespace's Pod Security `restricted` refuses anything wider whatever this asks. What a pod cannot express is
//! in 0045 §6, with its compensation.
//!
//! **Mounts are copied, not bound.** Each mount's content goes in over `exec` before the scanner starts; a writable
//! mount's new files come back after it ends ([`crate::archives`]).
//!
//! **Never empty.** Every way Kubernetes has of not running the scanner — an image that cannot be pulled, a pod nobody
//! schedules, a pod evicted, out of memory, the deadline, a read past its ceiling — is a failure naming the step
//! (0007). Nothing here answers a result the scanner did not produce.

use crate::api::{ExecResult, KubernetesApi};
use crate::channels::ExecChannels;
use crate::pods::{self, MountSource};
use crate::{KubernetesError, address, archives};
use rand_core::RngCore;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use vectispire_container::bounded_output::{BoundedOutput, CollectedOutput, OutputFile};
use vectispire_container::pull_credentials::MountedPullCredentials;
use vectispire_container::{
    BoxFuture, ContainerExecutor, ContainerResult, ContainerRun, ExportError, ExtendedError, ExtendedResult, Extras,
    Mount, REGISTRY_LOGIN_MOUNT, RegistryAccess, RunnerError, STDERR_BYTES, ScannerLimits, registry_of,
};

/// The static busybox the wrapper runs: musl, so it needs nothing of the scanner's image. Pinned by digest.
pub const HELPER_IMAGE: &str = "busybox@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092";

const POLL: Duration = Duration::from_millis(500);
/// **How long a new pod may take to come under its namespace's policies.** A CNI that enforces NetworkPolicy may
/// still do it a moment after the pod has its address: kube-router, k3s's, adds a pod's own chains when it hears of
/// the pod, and until then lets it through — measured at 0.3 to 0.7 s on an idle node, past a second on a loaded CI
/// runner. Waited for rather than slept through: the first refusal ends the wait, and a pod still reaching its target
/// past it is not cut off.
pub const ISOLATION_SETTLES: Duration = Duration::from_secs(30);
/// A metadata answer, a `df`: small.
const SMALL: u64 = 64 * 1024;
/// The slowest a copy through the API server's exec stream is assumed to run. A transfer is given the start timeout
/// plus its size at this rate: the matcher's 3 GB database took 21 s on a laptop's k3s, and a flat five minutes was
/// what failed it once the receiving container slowed under memory pressure.
pub const TRANSFER_FLOOR_BYTES_PER_SECOND: u64 = 8 * 1024 * 1024;
/// What one chunk of the copy in carries.
const COPY_CHUNK: usize = 64 * 1024;
/// What placement may set: where the pod goes, never what it may do.
const PLACEMENT: [&str; 3] = ["nodeSelector", "tolerations", "affinity"];

/// What a probe found: whether a scan pod is cut off from the address it tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    Enforced,
    NotEnforced,
}

/// **The matcher's database, kept once per generation where scan pods can mount it** (decision 0045 §7).
///
/// The database is some 3 GB, and copied into each matcher pod like any mount it would cross the API server at every
/// scan. A volume of the agent's cannot be shared: a claim belongs to one namespace, and scan pods live in another. So
/// the claim is in the scans' namespace, and each generation — a directory the database publishes once and never
/// changes — is copied onto it the first time a pod needs it, then mounted read-only by every matcher after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatcherCache {
    /// The ReadWriteOnce claim in the scans' namespace.
    pub claim: String,
    /// The agent's own `generations` directory: a read-only mount of one of its entries is served from the cache.
    pub generations: PathBuf,
    /// The agent's node: every pod mounting the claim goes there, since the claim attaches to one.
    pub node: String,
}

impl MatcherCache {
    pub fn new(claim: impl Into<String>, generations: &Path, node: impl Into<String>) -> MatcherCache {
        MatcherCache { claim: claim.into(), generations: absolute(generations), node: node.into() }
    }
}

/// The executor's settings, checked — `KubernetesExecutor.Settings`.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The scans' own namespace, labelled for Pod Security `restricted`.
    pub namespace: String,
    /// This agent's name, on every pod it starts — what it sweeps at start. A label value.
    pub agent: String,
    /// A **static** busybox, pinned by digest — copied into the scanner's pod for the wrapper.
    pub helper_image: String,
    /// `uid:gid` for a run that names none: the workspace's owner, the agent's own.
    pub default_user: String,
    /// How long a pod may take to be scheduled, pull its images and receive its workspace, before the scanner's own
    /// timeout starts.
    pub start_timeout: Duration,
    pub limits: ScannerLimits,
    /// `nodeSelector`, `tolerations` and `affinity`, and nothing else, copied into each pod's spec.
    pub placement: Map<String, Value>,
    pub cache: Option<MatcherCache>,
    /// The `address:port` every scan pod must be refused before its scanner starts — the isolation probe's target —
    /// or `None` where isolation is not required.
    pub cut_off_from: Option<String>,
    /// A Docker configuration directory — the pull secret the chart mounts — whose entry for a registry a tool reading
    /// that registry is handed, cosign verifying a plugin's signature; `None` where none is mounted, and the tool reads
    /// anonymously.
    pub registry_credentials: Option<PathBuf>,
}

impl Settings {
    /// Refuses a placement that sets anything but where the pod goes, and a probe target that is not an address.
    #[allow(clippy::too_many_arguments)] // Java's record, field for field.
    pub fn new(
        namespace: &str,
        agent: &str,
        helper_image: &str,
        default_user: &str,
        start_timeout: Duration,
        limits: ScannerLimits,
        placement: Map<String, Value>,
        cache: Option<MatcherCache>,
        cut_off_from: Option<String>,
    ) -> Result<Settings, String> {
        if let Some(field) = placement.keys().find(|field| !PLACEMENT.contains(&field.as_str())) {
            return Err(format!(
                "The scan pods' placement sets nodeSelector, tolerations and affinity, not \"{field}\"."
            ));
        }
        if let Some(target) = &cut_off_from {
            address::address(target)?;
        }
        Ok(Settings {
            namespace: namespace.to_owned(),
            agent: pods::label_value(agent),
            helper_image: helper_image.to_owned(),
            default_user: default_user.to_owned(),
            start_timeout,
            limits,
            placement,
            cache,
            cut_off_from,
            registry_credentials: None,
        })
    }

    /// These settings, a registry's tool handed `configuration`'s entry for it.
    pub fn with_registry_credentials(mut self, configuration: Option<PathBuf>) -> Settings {
        self.registry_credentials = configuration;
        self
    }

    fn output_bytes(&self) -> u64 {
        u64::try_from(self.limits.output_bytes).unwrap_or(u64::MAX)
    }
}

/// The executor.
#[derive(Debug, Clone)]
pub struct KubernetesExecutor {
    api: KubernetesApi,
    settings: Arc<Settings>,
    /// One seeding at a time: two matcher pods must not both copy the same generation onto the volume.
    seeding: Arc<tokio::sync::Mutex<()>>,
}

impl KubernetesExecutor {
    pub fn new(api: KubernetesApi, settings: Settings) -> KubernetesExecutor {
        KubernetesExecutor { api, settings: Arc::new(settings), seeding: Arc::new(tokio::sync::Mutex::new(())) }
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Can this agent's service account reach its namespace, and start a pod there? Asked before a scan is claimed.
    ///
    /// **Two calls, because the Role has two verbs that matter.** The listing proves the API server answers and the
    /// token reads the namespace; it says nothing about `create`, and a Role that lost it fails every scan at its first
    /// pod. The dry run asks for it without storing anything. **Only RBAC's own refusal counts against it**: a pod an
    /// admission policy or Pod Security turns away was still a request the Role allowed.
    pub async fn why_unavailable(&self) -> Option<String> {
        let namespace = &self.settings.namespace;
        let selector = format!("{}={}", pods::LABEL_AGENT, self.settings.agent);
        if let Err(unreachable) = self.api.pods(namespace, &selector).await {
            return Some(format!("The Kubernetes API did not list pods in {namespace}: {unreachable}"));
        }
        match self.api.create_pod_dry_run(namespace, &availability_probe(&self.settings)).await {
            Err(refused) if refused.status == 0 || forbidden_by_role(&refused) => {
                Some(format!("The Kubernetes API refused to create a pod in {namespace}: {refused}"))
            }
            _ => None,
        }
    }

    /// Deletes every pod this agent left: a crash between a pod's creation and its deletion.
    pub async fn sweep(&self) -> Result<(), KubernetesError> {
        let selector = format!("{}={}", pods::LABEL_AGENT, self.settings.agent);
        self.api.delete_pods(&self.settings.namespace, &selector).await
    }

    /// **Does the scans' namespace refuse a privileged pod?** (decision 0045 §3) Asked of the API server with a dry run
    /// of the widest pod there is, since the Role cannot read the namespace's labels. Only Pod Security's own refusal
    /// counts: a pod admitted, or refused for any other reason, says nothing about the ceiling (review of 2026-10-26,
    /// M1). An error for any other answer: an unknown.
    pub async fn pod_security(&self) -> Result<Isolation, KubernetesError> {
        match self.api.create_pod_dry_run(&self.settings.namespace, &pod_security_probe(&self.settings)).await {
            Ok(()) => Ok(Isolation::NotEnforced),
            Err(refused) if pod_security_refused(&refused) => Ok(Isolation::Enforced),
            Err(other) => Err(other),
        }
    }

    /// Runs a scan pod — offline, or `online` as the steps that need the network are — that tries to open a TCP
    /// connection to `host:port`, and says whether it could (decision 0045 §5).
    ///
    /// **A NetworkPolicy the CNI does not enforce is accepted and ignored**, and nothing on the API says so: the only
    /// proof that a scan pod is cut off is a scan pod that tried and failed. A loopback connection first, which must
    /// succeed: without it, an image whose `nc` is missing or broken would fail every connection and read as "blocked"
    /// (review of 2026-10-26, L1). An error when the probe did not run, or said something else: an unknown.
    pub async fn probe(&self, host: &str, port: u16, online: bool) -> Result<Isolation, RunnerError> {
        if host.is_empty() || !host.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':') || port == 0 {
            return Err(failed(
                "network probe",
                format!("The probe's target is an address and a port, not \"{host}:{port}\"."),
            ));
        }
        let mut probe =
            ContainerRun::new(&self.settings.helper_image, probe_command(host, port), Vec::new(), "network probe")
                .with_entrypoint(&[]);
        probe.timeout = Some(Duration::from_secs(120));
        probe.network = online;
        // Not gated as a scanner is: whether this pod is cut off is the question, not a precondition.
        let (result, _) = self.run_pod(&probe, None, false).await?;
        match vectispire_domain::java::strip(&result.stdout) {
            "BLOCKED" => Ok(Isolation::Enforced),
            "REACHED" => Ok(Isolation::NotEnforced),
            said => Err(failed(
                "network probe",
                format!("The probe said \"{said}\", which is neither: whether scan pods are cut off is unknown."),
            )),
        }
    }

    /// A run asking for a registry's login ([`Extras::login`]) is handed the mounted pull secret's entry for that
    /// registry, as the Docker executor hands its daemon's: one entry, in a directory of its own copied into the pod
    /// like a read-only mount, `DOCKER_CONFIG` naming it, removed after the run. Without it cosign read a private
    /// registry anonymously, and every plugin kept there was refused. What the tool prints, and any failure quoting
    /// it, is redacted of the entry's secrets.
    async fn run_extended(&self, request: &ContainerRun, extras: &Extras) -> Result<ExtendedResult, ExtendedError> {
        let label = request.label.as_str();
        let gated = self.settings.cut_off_from.is_some();
        let credentials = match &extras.login {
            None => None,
            Some(login) => MountedPullCredentials::of(self.settings.registry_credentials.as_deref(), &login.reference)
                // Its path, never its content.
                .map_err(|unreadable| extended_failure(label, unreadable.to_string()))?,
        };
        if extras.output.is_some() && request.user.is_none() {
            // The Docker executor's contract, kept here: its holder creates the directory owned by that user, and a
            // request one executor refuses must not run on the other.
            return Err(ExtendedError::Refused("A bounded output needs the user it belongs to.".to_owned()));
        }
        let output = extras.output.as_ref();
        let (Some(credentials), Some(login)) = (credentials, &extras.login) else {
            let (result, output) = self.run_pod(request, output, gated).await?;
            return Ok(ExtendedResult { result, output });
        };
        let written = credentials.write_under(&login.directory).map_err(|unwritable| {
            // The error names a path, never the credentials.
            extended_failure(label, format!("The registry credentials could not be handed to it: {unwritable}"))
        })?;
        let erasure = Erasure(Some(written.clone()));
        let mut with_login = request.clone();
        with_login.mounts.push(Mount::read_only(written.display().to_string(), REGISTRY_LOGIN_MOUNT));
        let outcome = self.run_pod(&with_login, output, gated).await;
        // After the pod, which held its copy: the credentials outlive the run by nothing.
        drop(erasure);
        match outcome {
            Ok((result, output)) => Ok(ExtendedResult {
                result: ContainerResult {
                    stdout: credentials.redact(&result.stdout),
                    stderr: credentials.redact(&result.stderr),
                    exit_code: result.exit_code,
                },
                output,
            }),
            Err(failure) => {
                // A registry quoting what it was sent must not carry it to the scan's failures.
                let said = failure.to_string();
                let redacted = credentials.redact(&said);
                Err(if redacted == said { ExtendedError::Runner(failure) } else { extended_failure(label, redacted) })
            }
        }
    }

    async fn run_pod(
        &self,
        request: &ContainerRun,
        output: Option<&BoundedOutput>,
        gated: bool,
    ) -> Result<(ContainerResult, Option<CollectedOutput>), RunnerError> {
        let label = request.label.as_str();
        let settings = &*self.settings;
        let timeout = request.timeout.unwrap_or(settings.limits.timeout);
        let (uid, gid) = owner(request.user.as_deref().unwrap_or(&settings.default_user), label)?;
        let mut sources = Vec::with_capacity(request.mounts.len());
        for mount in &request.mounts {
            let source = Path::new(&mount.source);
            if !source.exists() {
                return Err(failed(label, format!("Its mount {} does not exist.", mount.source)));
            }
            if self.cached_generation(mount.read_only, source) {
                sources.push(MountSource { cached: true, name: file_name(source) });
                continue;
            }
            let name = archives::name_of(source);
            if !mount.read_only && !name.is_empty() {
                return Err(failed(label, format!("A writable mount is a directory here: {}.", mount.source)));
            }
            sources.push(MountSource { cached: false, name });
        }
        let output_bytes = settings.output_bytes();
        let sizes: Vec<u64> = request.mounts.iter().map(|mount| bytes(Path::new(&mount.source))).collect();
        let (mut copied, mut moved) = (0u64, 0u64);
        for ((mount, source), size) in request.mounts.iter().zip(&sources).zip(&sizes) {
            copied = copied.saturating_add(if source.cached { 0 } else { *size });
            let writable = if mount.read_only { 0 } else { pods::ceiling(mount, output_bytes) };
            moved = moved.saturating_add(*size).saturating_add(writable);
        }

        let mut suffix = [0u8; 5];
        rand_core::OsRng.fill_bytes(&mut suffix);
        let name = pod_name(label, &suffix);
        let spec =
            pods::pod(&name, request, output, settings, uid, gid, &sources, copied, timeout, transfer_time(moved));
        if let Err(refused) = self.api.create_pod(&settings.namespace, &spec).await {
            return Err(failed(label, format!("Its pod could not be created: {refused}")));
        }
        let removal = Removal { api: self.api.clone(), namespace: settings.namespace.clone(), pod: Some(name.clone()) };
        let outcome = self.drive(&name, request, output, &sources, &sizes, timeout, gated).await;
        removal.now().await;
        match outcome {
            Ok(result) => Ok(result),
            Err(Failure::Kubernetes(failed_it)) => Err(failed(label, format!("Kubernetes failed it: {failed_it}"))),
            Err(Failure::Scanner(error)) => Err(error),
        }
    }

    /// The pod's life once created: the workspace in, the gate, the scanner, its output, its bounded output, its
    /// writes back.
    #[allow(clippy::too_many_arguments)] // What one run is, already worked out by `run_pod`: nothing to group.
    async fn drive(
        &self,
        pod: &str,
        request: &ContainerRun,
        output: Option<&BoundedOutput>,
        sources: &[MountSource],
        sizes: &[u64],
        timeout: Duration,
        gated: bool,
    ) -> Result<(ContainerResult, Option<CollectedOutput>), Failure> {
        let label = request.label.as_str();
        let settings = &*self.settings;
        self.await_receiving(pod, label).await?;
        for (index, ((mount, source), size)) in request.mounts.iter().zip(sources).zip(sizes).enumerate() {
            let path = Path::new(&mount.source);
            if source.cached {
                self.seed(pod, path, *size, label).await?;
            } else {
                self.copy_in(pod, index, path, *size, label).await?;
            }
        }
        if gated {
            self.await_cut_off(pod, label).await?;
        }
        self.exec(pod, pods::RECEIVE, &["touch", pods::RECEIVED], SMALL, label).await?;

        let terminated = self.await_scanner(pod, timeout, label).await?;
        if pods::killed(&terminated) {
            let limit = format!(
                "(its limit is {} MiB)",
                u64::try_from(settings.limits.memory).unwrap_or(0).checked_div(1024 * 1024).unwrap_or(0)
            );
            let said = if crate::json::text(crate::json::path(Some(&terminated), "reason")) == "OOMKilled" {
                format!("Scanner \"{label}\" ran out of memory {limit} and was stopped.")
            } else {
                format!(
                    "Scanner \"{label}\" was killed (exit {}, SIGKILL), most likely for running out of memory {limit} \
                     — the runtime does not always say so.",
                    pods::KILLED
                )
            };
            return Err(Failure::Scanner(failed(label, said)));
        }
        let exit_code = crate::json::int(crate::json::path(Some(&terminated), "exitCode"));

        let (stdout, stderr) = if request.entrypoint.is_some() {
            let output_bytes = settings.output_bytes();
            let out = self.exec(pod, pods::HOLDER, &["cat", pods::STDOUT], output_bytes, label).await?;
            if out.over_ceiling {
                return Err(Failure::Scanner(RunnerError::OutputTooLarge {
                    label: label.to_owned(),
                    limit: settings.limits.output_bytes,
                }));
            }
            let stderr_bytes = STDERR_BYTES.to_string();
            let err = self
                .exec(pod, pods::HOLDER, &["head", "-c", &stderr_bytes, pods::STDERR], STDERR_BYTES as u64, label)
                .await?;
            if out.exit_code != 0 || err.exit_code != 0 {
                // An output that could not be read back is absent, not empty (0007; review of 2026-10-26, L5).
                return Err(Failure::Scanner(failed(
                    label,
                    format!(
                        "Scanner \"{label}\"'s output could not be read back: {}",
                        excerpt(&format!("{}{}", out.stderr, err.stderr))
                    ),
                )));
            }
            (String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&err.stdout).into_owned())
        } else {
            // No entrypoint declared, so no wrapper: the tool wrote to its log, read as a diagnostic only. Its standard
            // output is not captured, and a caller parsing it reads an absent report.
            (String::new(), self.log(pod).await)
        };

        let collected = match output {
            Some(bounded) => Some(self.collect(pod, bounded, label).await?),
            None => None,
        };
        for (index, mount) in request.mounts.iter().enumerate() {
            if !mount.read_only {
                let ceiling = pods::ceiling(mount, settings.output_bytes());
                self.copy_back(pod, index, Path::new(&mount.source), ceiling, label).await?;
            }
        }
        Ok((ContainerResult { stdout, stderr, exit_code: i64::from(exit_code) }, collected))
    }

    /// The bounded output's file and what the kernel says of its directory, read from the holder — the same answer
    /// the Docker executor gives ([`CollectedOutput`]), so the plugins read it the same way. The size first: a file
    /// past the ceiling is refused before a byte of it is read.
    async fn collect(&self, pod: &str, bounded: &BoundedOutput, label: &str) -> Result<CollectedOutput, Failure> {
        let file = format!("{}/{}", bounded.target, bounded.file);
        let ceiling = bounded.bytes.min(self.settings.output_bytes());
        let probe = collection_probe(bounded);
        let answered = self.exec(pod, pods::HOLDER, &["sh", "-c", &probe], SMALL, label).await?;
        let answer = String::from_utf8_lossy(&answered.stdout).into_owned();
        let read = match probed(&answer, ceiling) {
            Ok(Some(settled)) => settled,
            Ok(None) => {
                let content = self.exec(pod, pods::HOLDER, &["cat", &file], ceiling, label).await?;
                if content.over_ceiling {
                    OutputFile::TooLarge(ceiling.saturating_add(1))
                } else if content.exit_code != 0 {
                    // A file that could not be read is absent, not empty (0007): Java reads `cat`'s nothing as the
                    // report, which the SARIF reader then refuses — same outcome, said here.
                    return Err(Failure::Scanner(failed(
                        label,
                        format!("Its output could not be read back: {}", excerpt(&content.stderr)),
                    )));
                } else {
                    OutputFile::Read(content.stdout)
                }
            }
            Err(unreadable) => {
                return Err(Failure::Scanner(failed(
                    label,
                    format!("Its output could not be read back: {unreadable}"),
                )));
            }
        };
        CollectedOutput::measured(bounded, &answer, read).ok_or_else(|| {
            Failure::Scanner(failed(
                label,
                "Its output directory could not be measured, so whether a write was refused is unknown; the report is \
                 not believed."
                    .to_owned(),
            ))
        })
    }

    fn transfer_timeout(&self, bytes: u64) -> Duration {
        self.settings.start_timeout.saturating_add(transfer_time(bytes))
    }

    /// A read-only mount of one of the agent's database generations, with a cache to serve it from.
    fn cached_generation(&self, read_only: bool, source: &Path) -> bool {
        let Some(cache) = &self.settings.cache else { return false };
        if !read_only {
            return false;
        }
        let absolute = absolute(source);
        absolute.parent() == Some(cache.generations.as_path())
            && std::fs::symlink_metadata(&absolute).is_ok_and(|metadata| metadata.is_dir())
            && generation_name(&file_name(&absolute))
    }

    /// Puts `generation` on the cache volume unless it is there already, through the pod's receiving container, then
    /// removes the generations the agent no longer holds.
    ///
    /// **Complete or absent.** It is received into a directory of its own, renamed into place, and only then marked
    /// `<name>.complete`; a generation without its mark — an agent that died mid-copy — is removed and copied again.
    /// Names are checked against what the database writes before they reach a shell.
    async fn seed(&self, pod: &str, generation: &Path, size: u64, label: &str) -> Result<(), Failure> {
        let name = file_name(generation);
        let root = format!("{}/{}", pods::CACHE, pods::GENERATIONS);
        let _seeding = self.seeding.lock().await;
        let complete = format!("{root}/{name}.complete");
        if self.exec(pod, pods::RECEIVE, &["test", "-f", &complete], SMALL, label).await?.exit_code != 0 {
            let partial = format!("{root}/.{name}.partial");
            let (sender, producer) = stream_archive(generation);
            let command = ["sh".to_owned(), "-c".to_owned(), seed_script(&root, &name, &partial)];
            let received = self
                .api
                .exec(
                    (&self.settings.namespace, pod, pods::RECEIVE),
                    &command,
                    Some(sender),
                    ExecChannels::new(SMALL),
                    self.transfer_timeout(size),
                )
                .await;
            let unreadable = producer.await.ok().and_then(Result::err);
            let received = received.map_err(Failure::Kubernetes)?;
            if unreadable.is_some() || received.exit_code != 0 {
                let why = unreadable.map_or_else(|| excerpt(&received.stderr), |error| error.to_string());
                return Err(Failure::Scanner(failed(
                    label,
                    format!("The matcher's database could not be put on its volume: {why}"),
                )));
            }
            let marked = self
                .exec(pod, pods::RECEIVE, &["sh", "-c", &complete_script(&root, &name, &partial)], SMALL, label)
                .await?;
            if marked.exit_code != 0 {
                return Err(Failure::Scanner(failed(
                    label,
                    "The matcher's database could not be marked complete on its volume.".to_owned(),
                )));
            }
        }
        self.prune(pod, &name, label).await
    }

    /// Removes from the volume every generation the agent no longer holds: the volume follows the agent's cache.
    async fn prune(&self, pod: &str, using: &str, label: &str) -> Result<(), Failure> {
        let Some(cache) = &self.settings.cache else { return Ok(()) };
        let mut held = BTreeSet::from([using.to_owned()]);
        let Ok(entries) = std::fs::read_dir(&cache.generations) else {
            // Nothing removed: a generation kept too long costs space, one removed too early a scan.
            return Ok(());
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if generation_name(&name) {
                held.insert(name);
            }
        }
        self.exec(pod, pods::RECEIVE, &["sh", "-c", &prune_script(&held)], SMALL, label).await?;
        Ok(())
    }

    /// **The scanner starts only once its own pod is refused the probe's target.** The probe at start proves the
    /// policies are enforced; it cannot prove they already cover a pod created since, and a CNI may let a new pod
    /// through for a moment ([`ISOLATION_SETTLES`]). Asked from the receiving container, which shares the pod's network
    /// and runs the helper image the probe already proved `nc` in; the scanner's container does not start before it.
    async fn await_cut_off(&self, pod: &str, label: &str) -> Result<(), Failure> {
        let target = self.settings.cut_off_from.clone().unwrap_or_default();
        let (host, port) = address::address(&target).map_err(|refused| Failure::Scanner(failed(label, refused)))?;
        let result = self.exec(pod, pods::RECEIVE, &["sh", "-c", &until_refused(&host, port, 2)], SMALL, label).await?;
        let said = String::from_utf8_lossy(&result.stdout).into_owned();
        let said = vectispire_domain::java::strip(&said);
        if result.exit_code != 0 || said != "BLOCKED" {
            return Err(Failure::Scanner(failed(
                label,
                format!(
                    "Its pod was not cut off from {target} within {}s of starting (it said \"{}\"), so the scanner was \
                     not started.",
                    ISOLATION_SETTLES.as_secs(),
                    excerpt(said)
                ),
            )));
        }
        Ok(())
    }

    async fn await_receiving(&self, pod: &str, label: &str) -> Result<(), Failure> {
        let deadline = Instant::now().checked_add(self.settings.start_timeout).unwrap_or_else(Instant::now);
        let mut last: Option<Value> = None;
        while Instant::now() < deadline {
            let state = self.api.pod(&self.settings.namespace, pod).await.map_err(Failure::Kubernetes)?;
            let Some(state) = state else {
                return Err(Failure::Scanner(failed(label, "Its pod was deleted before the scanner started.".into())));
            };
            if let Some(failure) = pods::failure(&state) {
                return Err(Failure::Scanner(failed(label, format!("Its pod could not run: {failure}"))));
            }
            if pods::receiving(&state) {
                return Ok(());
            }
            last = Some(state);
            tokio::time::sleep(POLL).await;
        }
        Err(Failure::Scanner(failed(
            label,
            format!(
                "Its pod was not ready to receive the workspace within {}s ({}).",
                self.settings.start_timeout.as_secs(),
                last.as_ref().map_or_else(|| "never read".to_owned(), pods::pending)
            ),
        )))
    }

    async fn await_scanner(&self, pod: &str, timeout: Duration, label: &str) -> Result<Value, Failure> {
        let deadline = Instant::now().checked_add(timeout).unwrap_or_else(Instant::now);
        while Instant::now() < deadline {
            let state = self.api.pod(&self.settings.namespace, pod).await.map_err(Failure::Kubernetes)?;
            let Some(state) = state else {
                return Err(Failure::Scanner(failed(label, "Its pod was deleted while the scanner ran.".into())));
            };
            if let Some(terminated) = pods::scanner_terminated(&state) {
                return Ok(terminated);
            }
            if let Some(failure) = pods::failure(&state) {
                return Err(Failure::Scanner(failed(label, format!("Its pod could not run: {failure}"))));
            }
            tokio::time::sleep(POLL).await;
        }
        // Deleted by the caller, which stops it: abandoning the wait alone would leave it running.
        Err(Failure::Scanner(RunnerError::TimedOut { label: label.to_owned(), seconds: timeout.as_secs() }))
    }

    async fn copy_in(&self, pod: &str, index: usize, source: &Path, size: u64, label: &str) -> Result<(), Failure> {
        let directory = format!("{}/m{index}", pods::WORK);
        let (sender, producer) = stream_archive(source);
        let command = ["sh".to_owned(), "-c".to_owned(), format!("mkdir -p {directory} && tar -x -C {directory}")];
        let result = self
            .api
            .exec(
                (&self.settings.namespace, pod, pods::RECEIVE),
                &command,
                Some(sender),
                ExecChannels::new(SMALL),
                self.transfer_timeout(size),
            )
            .await;
        let unreadable = producer.await.ok().and_then(Result::err);
        let result = result.map_err(Failure::Kubernetes)?;
        if let Some(unreadable) = unreadable {
            return Err(Failure::Scanner(failed(label, format!("Its workspace could not be read: {unreadable}"))));
        }
        if result.exit_code != 0 {
            return Err(Failure::Scanner(failed(
                label,
                format!(
                    "Its workspace could not be received (tar exited {}): {}",
                    result.exit_code,
                    excerpt(&result.stderr)
                ),
            )));
        }
        Ok(())
    }

    /// What the scanner wrote into a writable mount, and nothing else: see [`archives`].
    async fn copy_back(
        &self,
        pod: &str,
        index: usize,
        destination: &Path,
        ceiling: u64,
        label: &str,
    ) -> Result<(), Failure> {
        let not_back = |error: std::io::Error| {
            Failure::Scanner(failed(label, format!("What it wrote was not brought back: {error}")))
        };
        // Beside the mount, never in it: the scanner's files land there.
        let beside = destination.parent().map_or_else(std::env::temp_dir, Path::to_path_buf);
        let received = tempfile::Builder::new().prefix(".vectispire-written-").tempfile_in(beside).map_err(not_back)?;
        let sink = received.reopen().map_err(not_back)?;
        let command = ["sh".to_owned(), "-c".to_owned(), copy_back_script(&format!("{}/m{index}", pods::WORK))];
        let result = self
            .api
            .exec(
                (&self.settings.namespace, pod, pods::HOLDER),
                &command,
                None,
                ExecChannels::to_sink(Box::new(sink), ceiling),
                self.transfer_timeout(ceiling),
            )
            .await
            .map_err(Failure::Kubernetes)?;
        if result.over_ceiling {
            return Err(Failure::Scanner(failed(
                label,
                format!("It wrote more than {ceiling} bytes into its workspace."),
            )));
        }
        if result.exit_code != 0 {
            return Err(Failure::Scanner(failed(
                label,
                format!(
                    "What it wrote could not be read back (exit {}): {}",
                    result.exit_code,
                    excerpt(&result.stderr)
                ),
            )));
        }
        let length = received.as_file().metadata().map_err(not_back)?.len();
        if length > 0 {
            let file = received.reopen().map_err(not_back)?;
            archives::extract_written(std::io::BufReader::new(file), destination, ceiling).map_err(not_back)?;
        }
        Ok(())
    }

    async fn exec(
        &self,
        pod: &str,
        container: &str,
        command: &[&str],
        ceiling: u64,
        label: &str,
    ) -> Result<ExecResult, Failure> {
        let command: Vec<String> = command.iter().map(|part| (*part).to_owned()).collect();
        let result = self
            .api
            .exec(
                (&self.settings.namespace, pod, container),
                &command,
                None,
                ExecChannels::new(ceiling),
                self.settings.start_timeout,
            )
            .await
            .map_err(Failure::Kubernetes)?;
        if result.over_ceiling && ceiling == SMALL {
            let first = command.first().map(String::as_str).unwrap_or_default();
            return Err(Failure::Scanner(failed(label, format!("Its pod answered more than expected to {first}."))));
        }
        Ok(result)
    }

    async fn log(&self, pod: &str) -> String {
        match self.api.log(&self.settings.namespace, pod, pods::SCANNER, STDERR_BYTES as u64).await {
            Ok(log) => log,
            Err(unreadable) => format!("(its log could not be read: {unreadable})"),
        }
    }
}

impl ContainerExecutor for KubernetesExecutor {
    fn run<'a>(&'a self, run: &'a ContainerRun) -> BoxFuture<'a, Result<ContainerResult, RunnerError>> {
        Box::pin(async move {
            let (result, _) = self.run_pod(run, None, self.settings.cut_off_from.is_some()).await?;
            Ok(result)
        })
    }

    /// Not yet: an image target is copied into the workspace by a pinned copy step (0045 §8), which is not built. A
    /// failure, so the image's inventory is absent — never an empty one; and [`Self::exports_images`] says so first,
    /// so the claim hands this agent no image.
    fn export_image<'a>(
        &'a self,
        reference: &'a str,
        _platform: &'a str,
        _destination: &'a Path,
    ) -> BoxFuture<'a, Result<(), ExportError>> {
        Box::pin(async move {
            Err(ExportError::Unsupported(format!(
                "Image targets are not scanned by the Kubernetes executor yet: the copy step of decision 0045 §8 is \
                 not built. {reference} was not examined."
            )))
        })
    }

    fn why_unavailable(&self) -> BoxFuture<'_, Option<String>> {
        Box::pin(KubernetesExecutor::why_unavailable(self))
    }

    fn exports_images(&self) -> bool {
        false
    }

    fn scanner_timeout(&self) -> Duration {
        self.settings.limits.timeout
    }

    fn output_bytes(&self) -> u64 {
        self.settings.output_bytes()
    }

    /// A plugin's run: its bounded output an `emptyDir` in memory of its size, read back from the holder; cosign's
    /// registry login the mounted pull secret's entry ([`Settings::registry_credentials`]).
    fn run_with<'a>(
        &'a self,
        run: &'a ContainerRun,
        extras: &'a Extras,
    ) -> BoxFuture<'a, Result<ExtendedResult, ExtendedError>> {
        Box::pin(self.run_extended(run, extras))
    }

    /// Whether the mounted pull secret holds an entry for `reference`'s registry — never it. A secret that cannot be
    /// read holds none: the run that asks for it says why.
    fn registry_access_for(&self, reference: &str) -> RegistryAccess {
        let held =
            matches!(MountedPullCredentials::of(self.settings.registry_credentials.as_deref(), reference), Ok(Some(_)));
        RegistryAccess { registry: registry_of(reference), credentials_held: held }
    }
}

fn extended_failure(label: &str, message: String) -> ExtendedError {
    ExtendedError::Failed { label: label.to_owned(), message }
}

/// A registry login's directory, erased once the run is over — on drop too, so a future given up half-way leaves none.
struct Erasure(Option<PathBuf>);

impl Drop for Erasure {
    fn drop(&mut self) {
        vectispire_container::pull_credentials::erase(self.0.take().as_deref());
    }
}

/// What the holder runs once the tool has exited: `df` of the directory in bytes and in inodes, as the Docker
/// executor's holder prints them, then what the file is — a link and anything but a regular file told apart, and a
/// regular file's size, so that one past the ceiling is refused before a byte of it is read.
pub fn collection_probe(bounded: &BoundedOutput) -> String {
    let target = &bounded.target;
    format!(
        "df -P -k {target}; df -P -i {target}; f={target}/{}; if [ -L \"$f\" ]; then echo kind=other; elif [ ! -e \"$f\" \
         ]; then echo kind=missing; elif [ ! -f \"$f\" ]; then echo kind=other; else echo kind=file size=$(wc -c < \
         \"$f\"); fi",
        bounded.file
    )
}

/// The file as [`collection_probe`]'s answer settles it — missing, not a regular file, or too large — or `None` when it
/// is a regular file within `ceiling`, which is then read. A size that is not a number is an error, where Java's
/// `Long.parseLong` throws.
pub fn probed(answer: &str, ceiling: u64) -> Result<Option<OutputFile>, String> {
    if answer.contains("kind=missing") {
        return Ok(Some(OutputFile::Missing));
    }
    let Some((_, size)) = answer.split_once("kind=file size=") else { return Ok(Some(OutputFile::NotRegular)) };
    let size = vectispire_domain::java::read_long(vectispire_domain::java::strip(size))
        .ok_or_else(|| format!("its holder gave a size that is not a number: \"{}\".", excerpt(size)))?;
    Ok(match u64::try_from(size) {
        Ok(size) if size > ceiling => Some(OutputFile::TooLarge(size)),
        _ => None,
    })
}

/// How a pod's run ended badly: the API server's failure, which the run wraps in "Kubernetes failed it", or a failure
/// already worded for the step.
enum Failure {
    Kubernetes(KubernetesError),
    Scanner(RunnerError),
}

impl From<KubernetesError> for Failure {
    fn from(error: KubernetesError) -> Failure {
        Failure::Kubernetes(error)
    }
}

fn failed(label: &str, message: String) -> RunnerError {
    RunnerError::Failed { label: label.to_owned(), message }
}

/// A created pod, deleted when its run is over — and, should the future be dropped half-way (an agent stopping, a scan
/// abandoned), deleted by a task spawned on drop. The sweep at the next start removes what neither reached.
struct Removal {
    api: KubernetesApi,
    namespace: String,
    pod: Option<String>,
}

impl Removal {
    async fn now(mut self) {
        if let Some(pod) = self.pod.take() {
            // The run's own outcome is what matters here.
            let _ = self.api.delete_pod(&self.namespace, &pod).await;
        }
    }
}

impl Drop for Removal {
    fn drop(&mut self) {
        if let (Some(pod), Ok(runtime)) = (self.pod.take(), tokio::runtime::Handle::try_current()) {
            let (api, namespace) = (self.api.clone(), self.namespace.clone());
            runtime.spawn(async move {
                let _ = api.delete_pod(&namespace, &pod).await;
            });
        }
    }
}

/// `source` as a tar archive, written on a blocking thread into a channel the exec sends from. The producer's error,
/// if any, is the copy's: a source that could not be read is said as such, after the exec.
fn stream_archive(source: &Path) -> (mpsc::Receiver<Vec<u8>>, tokio::task::JoinHandle<std::io::Result<()>>) {
    let (sender, receiver) = mpsc::channel::<Vec<u8>>(16);
    let source = source.to_path_buf();
    let producer = tokio::task::spawn_blocking(move || {
        let mut writer = std::io::BufWriter::with_capacity(COPY_CHUNK, ChannelWriter { sender });
        archives::write(&source, &mut writer)?;
        std::io::Write::flush(&mut writer)
    });
    (receiver, producer)
}

/// A `Write` handing each buffer to the exec's sender: the copy in streams, it is never held whole.
struct ChannelWriter {
    sender: mpsc::Sender<Vec<u8>>,
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.sender
            .blocking_send(bytes.to_vec())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the pod stopped reading the copy"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What a mount holds, in bytes, links not followed: what its copy sends. Counted as nothing where it cannot be read:
/// the copy that follows reads the same tree and fails on it, by name.
fn bytes(source: &Path) -> u64 {
    let Ok(metadata) = std::fs::symlink_metadata(source) else { return 0 };
    if metadata.is_file() {
        return metadata.len();
    }
    if !metadata.is_dir() {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(source) else { return 0 };
    entries.flatten().fold(0u64, |total, entry| total.saturating_add(bytes(&entry.path())))
}

/// What moving `bytes` through the exec stream may take at the assumed floor.
pub fn transfer_time(bytes: u64) -> Duration {
    Duration::from_secs(bytes.checked_div(TRANSFER_FLOOR_BYTES_PER_SECOND).unwrap_or(0))
}

/// A generation's name, as the database writes it — `[0-9a-z][0-9a-z-]{0,63}`: nothing a shell or a path could misread.
fn generation_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes.first().is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
}

/// `toAbsolutePath().normalize()`: against the current directory, lexically.
fn absolute(path: &Path) -> PathBuf {
    let joined = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut normal = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    normal
}

/// `uid:gid`, numeric and not root: the namespace refuses root, and a name means nothing in a pod. `Long.parseLong`'s
/// reading, as the Java executor's.
pub fn owner(user: &str, label: &str) -> Result<(u64, u64), RunnerError> {
    let (uid, gid) = match user.split_once(':') {
        Some((uid, gid)) => (uid, Some(gid)),
        None => (user, None),
    };
    let named = || failed(label, format!("It runs as \"{user}\", and a scan pod runs as a numeric uid:gid."));
    let uid = vectispire_domain::java::read_long(uid).ok_or_else(named)?;
    let gid = match gid {
        Some(gid) => vectispire_domain::java::read_long(gid).ok_or_else(named)?,
        None => uid,
    };
    match (u64::try_from(uid), u64::try_from(gid)) {
        (Ok(uid), Ok(gid)) if uid > 0 => Ok((uid, gid)),
        _ => Err(failed(label, "It would run as root, which a scan pod never does.".to_owned())),
    }
}

/// `vs-<the label, as a name>-<the suffix in hex>`: a DNS label whatever the scanner is called.
pub fn pod_name(label: &str, suffix: &[u8]) -> String {
    let slug: String = pods::label_value(label)
        .chars()
        .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' { c } else { '-' })
        .take(40)
        .collect();
    let slug = slug.trim_matches('-');
    let hex: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("vs-{slug}-{hex}")
}

/// RBAC's refusal, as the API server words it — "cannot create resource" — and not an admission's, which is a 403 too.
pub fn forbidden_by_role(refused: &KubernetesError) -> bool {
    refused.status == 403 && refused.message.contains("cannot create resource")
}

/// Pod Security's own refusal, and no other: a 403 naming it.
pub fn pod_security_refused(refused: &KubernetesError) -> bool {
    refused.status == 403 && refused.message.contains("PodSecurity")
}

/// The pod [`KubernetesExecutor::why_unavailable`] asks a dry run of: the placement, no token, the helper image.
pub fn availability_probe(settings: &Settings) -> Value {
    let mut spec = settings.placement.clone();
    spec.insert("automountServiceAccountToken".into(), json!(false));
    spec.insert("containers".into(), json!([{"name": "probe", "image": settings.helper_image}]));
    json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "vs-availability-probe"}, "spec": spec})
}

/// The widest pod there is, with the scan pods' placement: what [`KubernetesExecutor::pod_security`] asks a dry run of.
///
/// Everything else a scan pod carries — its pool's placement, no token — so that the chart's admission policy, which
/// refuses a pod without them, has nothing to refuse: only Pod Security may answer, or the answer proves nothing about
/// it. On k3s 1.34 Pod Security answers first whatever the pod; these make the answer independent of the order.
pub fn pod_security_probe(settings: &Settings) -> Value {
    let mut spec = settings.placement.clone();
    spec.insert("automountServiceAccountToken".into(), json!(false));
    spec.insert("hostNetwork".into(), json!(true));
    spec.insert("hostPID".into(), json!(true));
    spec.insert("volumes".into(), json!([{"name": "host", "hostPath": {"path": "/"}}]));
    spec.insert(
        "containers".into(),
        json!([{
            "name": "probe",
            "image": settings.helper_image,
            "securityContext": {"privileged": true, "runAsUser": 0},
            "volumeMounts": [{"name": "host", "mountPath": "/host"}],
        }]),
    );
    json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "vs-pod-security-probe"}, "spec": spec})
}

/// Tries `host:port` once a second until the connection is refused, and says `BLOCKED`, or `REACHED` when it was still
/// answered after [`ISOLATION_SETTLES`]. `connect_seconds` bounds one attempt: a policy that drops rather than refuses
/// costs that much once.
pub fn until_refused(host: &str, port: u16, connect_seconds: u32) -> String {
    format!(
        "i=0; while nc -w {connect_seconds} {host} {port} </dev/null >/dev/null 2>&1; do i=$((i+1)); if [ $i -ge {} ]; \
         then echo REACHED; exit 0; fi; sleep 1; done; echo BLOCKED",
        ISOLATION_SETTLES.as_secs()
    )
}

/// The probe pod's command: the loopback control, then the target until refused.
pub fn probe_command(host: &str, port: u16) -> Vec<String> {
    vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!(
            "nc -l -p 7777 -s 127.0.0.1 >/dev/null 2>&1 & sleep 1; if ! nc -w 2 127.0.0.1 7777 </dev/null >/dev/null \
             2>&1; then echo NO-CONTROL; exit 0; fi; {}",
            until_refused(host, port, 5)
        ),
    ]
}

/// What the holder runs to send back a writable mount's new files. tar refuses an empty list, so nothing written sends
/// nothing. **A name with a line break is refused before the list is built**: the list is one name per line, and such
/// a name would make the holder archive a path the scanner chose (review of 2026-10-26, L4).
pub fn copy_back_script(directory: &str) -> String {
    format!(
        "cd {directory} && nl=$(printf '\\nx') && nl=${{nl%x}} && if [ -n \"$(find . -name \"*$nl*\")\" ]; then echo 'a \
         name with a line break' >&2; exit 3; fi && if [ -n \"$(find . -type f -mtime -1)\" ]; then find . -type f \
         -mtime -1 | tar -c -T -; fi"
    )
}

/// Receives a generation into its partial directory, whatever an earlier attempt left.
pub fn seed_script(root: &str, name: &str, partial: &str) -> String {
    format!("rm -rf {root}/{name} {partial} && mkdir -p {partial} && tar -x -C {partial}")
}

/// Renames a received generation into place, then marks it complete: in that order, so a mark means a whole one.
pub fn complete_script(root: &str, name: &str, partial: &str) -> String {
    format!("mv {partial} {root}/{name} && touch {root}/{name}.complete")
}

/// Keeps `held` and their marks, removes every other entry and every partial copy.
pub fn prune_script(held: &BTreeSet<String>) -> String {
    let mut script =
        format!("cd {}/{} && for entry in * .*.partial; do case \"$entry\" in", pods::CACHE, pods::GENERATIONS);
    for generation in held {
        script.push_str(&format!(" {generation}|{generation}.complete) ;;"));
    }
    script.push_str(" '*'|'.*.partial') ;; *) rm -rf \"$entry\" ;; esac; done");
    script
}

fn excerpt(text: &str) -> String {
    if text.chars().count() > 500 {
        format!("{}…", text.chars().take(500).collect::<String>())
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generation's name reaches a shell (the seeding and the pruning): only what the database writes is one.
    #[test]
    fn only_the_database_s_own_names_are_generations() {
        for name in ["1761400000000-aaaaaaaa", "a", "0-", &"a".repeat(64)] {
            assert!(generation_name(name), "{name}");
        }
        for name in ["", "-a", "A1", "a b", "a;rm", "a/b", ".a", &"a".repeat(65), "1761400000000-aaaaaaaa.complete"] {
            assert!(!generation_name(name), "{name}");
        }
    }

    /// A mount is served from the cache only when it is a read-only generation directory of the agent's own cache.
    #[test]
    fn only_a_read_only_generation_of_the_agent_s_cache_is_served_from_the_volume() {
        let root = tempfile::tempdir().unwrap();
        let generations = root.path().join("db/generations");
        std::fs::create_dir_all(generations.join("1761400000000-aaaaaaaa")).unwrap();
        std::fs::create_dir_all(generations.join("Not-A-Generation")).unwrap();
        std::fs::create_dir_all(root.path().join("elsewhere/1761400000000-aaaaaaaa")).unwrap();
        std::fs::write(generations.join("1761500000000-bbbbbbbb"), "a file").unwrap();
        let api = KubernetesApi::with_token(
            "https://127.0.0.1:1",
            vectispire_domain::secret::Secret::new("t"),
            &vectispire_tls::TlsTrust::BuiltIn,
        )
        .unwrap();
        let settings = |cache: Option<MatcherCache>| {
            Settings::new(
                "ns",
                "a",
                HELPER_IMAGE,
                "1000:1000",
                Duration::from_secs(1),
                ScannerLimits::default_for_this_host(),
                Map::new(),
                cache,
                None,
            )
            .unwrap()
        };
        let cached = KubernetesExecutor::new(api.clone(), settings(Some(MatcherCache::new("c", &generations, "n"))));
        let generation = generations.join("1761400000000-aaaaaaaa");
        assert!(cached.cached_generation(true, &generation));
        assert!(cached.cached_generation(true, &generations.join("x/../1761400000000-aaaaaaaa")), "normalized");
        assert!(!cached.cached_generation(false, &generation), "a writable mount is copied");
        assert!(!cached.cached_generation(true, &generations.join("Not-A-Generation")));
        assert!(!cached.cached_generation(true, &generations.join("1761500000000-bbbbbbbb")), "a file is not one");
        assert!(!cached.cached_generation(true, &root.path().join("elsewhere/1761400000000-aaaaaaaa")));
        let uncached = KubernetesExecutor::new(api, settings(None));
        assert!(!uncached.cached_generation(true, &generation), "no cache, every mount copied");
    }

    #[test]
    fn a_transfer_is_given_its_size_at_the_floor_on_top_of_the_start() {
        assert_eq!(transfer_time(3 * 1024 * 1024 * 1024), Duration::from_secs(384));
        assert_eq!(transfer_time(TRANSFER_FLOOR_BYTES_PER_SECOND - 1), Duration::ZERO);
    }
}
