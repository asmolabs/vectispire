//! One claimed scan, run — `ScanRunner` on the Java side, which the agent and the built-in worker share.
//!
//! **Each step is independent of the others.** One scanner failing does not sink the scan: its result
//! stays absent — "not looked at", which protects that type's backlog (decision 0007) — and the step
//! is recorded as a failure with what happened. Only the clone and the sub-path are blocking: with no
//! tree there is nothing to analyse, and carrying on would produce empty lists that resolve everything.
//!
//! **What this build does not run yet, it says.** The language census, the project manifest and the
//! API discovery are not ported (`README.md`, "Remaining work"): the census and the manifest are
//! ordinary absences — "unknown", no finding resolved — and the discovery is a step like the others,
//! so it is recorded as one that did not run rather than left silently absent. A plugin step is
//! recorded absent, under its plugin's name, as the Java runner records a plugin that could not run.
//! An image target is handed back as a transient failure, so it returns to the queue for an agent
//! that can export images.

use crate::serve::{Execute, ExecutionFailure};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vectispire_container::{ContainerRunner, ScannerLimits};
use vectispire_domain::FailureKind;
use vectispire_git::{CloneRequest, HostKeyPolicy, HttpsCredential, WithoutKey};
use vectispire_protocol::{AgentClient, Findings, PluginStep, ScanArtifacts, ScanTask, Step, Target};
use vectispire_scanners::dependencies::{self, StepError};
use vectispire_scanners::rules::{self, RulePlacement, StoredFile};
use vectispire_scanners::vulnerability_database::VulnerabilityDatabase;
use vectispire_scanners::{container_paths, iac, jackson, sast, secrets};
use vectispire_tls::TlsTrust;

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

/// What every scan of this process shares.
pub struct ScanRunner {
    containers: Arc<ContainerRunner>,
    images: Images,
    database: VulnerabilityDatabase<ContainerRunner>,
    placement: RulePlacement,
    /// Kept for as long as the process runs: its drop removes the materialised tree.
    _bundled: rules::MaterialisedRules,
    client: Arc<AgentClient>,
    places: Places,
    trust: TlsTrust,
}

impl std::fmt::Debug for ScanRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ScanRunner").field("images", &self.images).field("places", &self.places).finish()
    }
}

/// The step names and reasons of `ScanRunner`, word for word: they reach the scan's page.
const SECRETS_ABSENT: &str = "the search for hardcoded secrets did not complete.";
const IAC_ABSENT: &str = "the infrastructure manifest check did not complete.";
const SAST_ABSENT: &str = "the source analysis did not run, or covered too few files to be worth reading.";
/// Not a Java sentence: this build's own, for the step it does not run yet.
const API_DISCOVERY_NOT_PORTED: &str =
    "this agent (the Rust port, in progress) does not run the API discovery yet; the inventory is left as it was.";
const PLUGIN_NOT_PORTED: &str = "this agent (the Rust port, in progress) does not run plugins yet.";
const IMAGE_NOT_PORTED: &str =
    "This build of the agent (the Rust port, in progress) does not scan container images yet; another agent can.";

impl ScanRunner {
    /// `vulnerability_root`: `VECTISPIRE_VULNERABILITY_DB_DIR`, blank for a directory beside the
    /// workspaces, as on the Java agent.
    pub fn new(
        client: Arc<AgentClient>,
        images: Images,
        places: Places,
        vulnerability_root: Option<PathBuf>,
        trust: TlsTrust,
    ) -> Result<ScanRunner, String> {
        let limits = ScannerLimits::default_for_this_host();
        let containers = Arc::new(ContainerRunner::connect(None, limits).map_err(|error| error.to_string())?);
        let root = vulnerability_root.unwrap_or_else(|| places.work.join("vectispire-vulnerability-db"));
        let database =
            VulnerabilityDatabase::with_defaults(containers.clone(), images.grype.clone(), &root, limits.timeout);
        // Unpacked from the binary, as the Java agent unpacks them from its jar: no rules directory
        // ships beside it, and one read from the current directory would be whatever is there.
        let bundled = rules::materialise_in(&places.work)
            .map_err(|error| format!("the bundled rules could not be unpacked: {error}"))?;
        let placement = RulePlacement::new(bundled.tree());
        Ok(ScanRunner { containers, images, database, placement, _bundled: bundled, client, places, trust })
    }

    async fn run(&self, task: ScanTask) -> Result<ScanArtifacts, ExecutionFailure> {
        let started = Instant::now();
        let repository = match &task.target {
            Target::Repository(repository) => repository.clone(),
            Target::Image(_) => {
                return Err(ExecutionFailure { message: IMAGE_NOT_PORTED.to_owned(), kind: FailureKind::Transient });
            }
        };
        let workspace = Workspace::create(&self.places.work)?;
        let mut artifacts = ScanArtifacts::default();

        self.clone_into(&repository, &workspace.source).await?;
        let sub_path = vectispire_domain::sub_path::normalize(repository.sub_path.as_deref())
            .map_err(|problem| permanent(format!("The repository's sub-path is refused: {problem}")))?;
        let branch = repository.branch.clone().unwrap_or_default();
        scan_root(&workspace.source, &sub_path, &branch)?;
        let sub = (!sub_path.is_empty()).then_some(sub_path.as_str());

        artifacts.failed("api discovery", API_DISCOVERY_NOT_PORTED);

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
            match secrets::scan(&self.containers, &workspace.root, sub, &self.images.gitleaks).await {
                Ok(Some(found)) => artifacts.secrets = findings(&found),
                Ok(None) => artifacts.failed("secrets", SECRETS_ABSENT),
                Err(error) => artifacts.failed("secrets", error.to_string()),
            }
        }
        if task.runs(Step::Iac) {
            match iac::scan(&self.containers, &workspace.root, sub, &self.images.checkov).await {
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

        for plugin in &task.plugins {
            artifacts.plugins.push(PluginStep::Absent {
                plugin_id: plugin.id.clone(),
                manifest_digest: plugin.digest.clone(),
                reason: PLUGIN_NOT_PORTED.to_owned(),
            });
            artifacts.failed(format!("plugin {}", plugin.id), PLUGIN_NOT_PORTED);
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
            // What `local` mode has always promised: no key in the task, the host's own git access.
            without_key: WithoutKey::HostSsh,
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
        let fetched: Option<Result<Vec<StoredFile>, String>> = match hash {
            None => None,
            Some(hash) => Some(self.client.rule_set(hash).await.map_err(|error| error.to_string()).map(|files| {
                files
                    .into_iter()
                    .map(|file| StoredFile {
                        path: file.path,
                        original_name: file.original_name.unwrap_or_default(),
                        content: file.content,
                    })
                    .collect()
            })),
        };
        let provider = |_: &str| -> Result<Vec<StoredFile>, String> {
            fetched.clone().unwrap_or_else(|| Err("no rule set was fetched".to_owned()))
        };
        self.placement
            .place_rule_set(&workspace.rules, hash, Some(&provider), RulePlacement::environment_directory().as_deref())
            .map_err(|error| error.to_string())?;
        sast::scan(&self.containers, &workspace.root, sub, &self.images.semgrep)
            .await
            .map_err(|error| error.to_string())
    }
}

impl Execute for ScanRunner {
    fn execute(
        &self,
        task: ScanTask,
    ) -> impl std::future::Future<Output = Result<ScanArtifacts, ExecutionFailure>> + Send {
        self.run(task)
    }
}

/// A step's findings as the protocol carries them, each written as the Java agent's mapper writes it.
fn findings<T: serde::Serialize>(found: &[T]) -> Option<Findings> {
    // A finding that does not serialize cannot happen for these types; were it to, the step reads as
    // absent rather than as a shorter list.
    Findings::from_documents(found.iter().map(jackson::to_wire_string)).ok()
}

fn raw(document: &serde_json::Value) -> Option<Box<serde_json::value::RawValue>> {
    serde_json::value::RawValue::from_string(jackson::to_wire_string(document)).ok()
}

fn permanent(message: String) -> ExecutionFailure {
    ExecutionFailure { message, kind: FailureKind::Permanent }
}

fn transient(message: String) -> ExecutionFailure {
    ExecutionFailure { message, kind: FailureKind::Transient }
}

/// The directory the scan examines, proven to lie inside the clone and to be there — `scanRoot` and
/// `SourceFiles.within`. A directory of the repository may itself be a link out of it.
fn scan_root(source: &Path, sub_path: &str, branch: &str) -> Result<PathBuf, ExecutionFailure> {
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
struct Workspace {
    root: PathBuf,
    source: PathBuf,
    rules: PathBuf,
    _directory: tempfile::TempDir,
}

impl Workspace {
    fn create(work: &Path) -> Result<Workspace, ExecutionFailure> {
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

    #[test]
    fn a_blank_image_override_keeps_the_pinned_digest() {
        let images =
            Images::from_lookup(lookup(&[("VECTISPIRE_IMAGE_SYFT", "  "), ("VECTISPIRE_IMAGE_GRYPE", "r/g@sha256:1")]));
        assert_eq!(images.syft, vectispire_scanners::images::SYFT);
        assert_eq!(images.grype, "r/g@sha256:1");
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
}
