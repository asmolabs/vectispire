//! A run with a bounded output or a registry login — the half of `ContainerRunner.run` that [`ContainerRunner::run`]
//! leaves out, beside it so that what every scanner already runs does not change.
//!
//! **A bounded output** ([`BoundedOutput`]): a holder container keeps a size-limited tmpfs volume mounted, the tool
//! reaches it through `VolumesFrom` with `fsize` capped at the directory's size (a sparse file of any apparent size
//! would otherwise be archived back at that size), the file is read from the holder once the tool has exited, then
//! the holder is stopped and its `df` read. **A registry login** ([`RegistryLogin`]): what this executor's pulls send
//! the reference's registry, written for the run alone into a directory of the workspace, 0700, mounted read-only at
//! [`REGISTRY_LOGIN_MOUNT`] with `DOCKER_CONFIG` naming it, and erased once the container is gone. Nobody outside
//! this crate holds the credentials, so nobody can log them; what the tool prints is redacted of them.
//!
//! The create requests are held to what the Java runner sends by `reference/plugins/creates/`.

use crate::bounded_output::{BoundedOutput, CollectedOutput, OutputFile, archive_budget, read_archive};
use crate::pull_credentials::{self, AuthConfig, RegistryAccess};
use crate::runner::{Removal, daemon};
use crate::{
    ContainerResult, ContainerRun, ContainerRunner, Mount, RunnerError, SCANNER_LABEL, ScannerLimits, create_body,
};
use bollard::models::{
    ContainerCreateBody, Mount as DaemonMount, MountTypeEnum, MountVolumeOptions, MountVolumeOptionsDriverConfig,
    ResourcesUlimits,
};
use bollard::query_parameters::{
    DownloadFromContainerOptionsBuilder, LogsOptionsBuilder, RemoveContainerOptionsBuilder, StopContainerOptionsBuilder,
};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where a registry login is mounted, read-only, and what `DOCKER_CONFIG` names in the tool's environment.
pub const REGISTRY_LOGIN_MOUNT: &str = "/trust/registry";

/// How long a holder outlives its tool's timeout if nothing removes it — a crash of this process.
const HOLDER_GRACE: Duration = Duration::from_secs(10 * 60);

/// What the holder's `df` may print, and its error stream: a few lines.
const MEASURE_BYTES: usize = 64 * 1024;

/// The pull credentials handed to the tool for one registry — `ContainerRun.RegistryLogin`. Named, never carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryLogin {
    /// The image whose registry's credentials are handed over.
    pub reference: String,
    /// Where the file is written for the run — a directory of the workspace no tool reads.
    pub directory: PathBuf,
}

/// What a run may carry beyond [`ContainerRun`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extras {
    pub output: Option<BoundedOutput>,
    pub login: Option<RegistryLogin>,
}

/// A run's result, and what its bounded output held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedResult {
    pub result: ContainerResult,
    /// `None` for a run without a bounded output.
    pub output: Option<CollectedOutput>,
}

/// Why a run with extras produced nothing: the runner's own reasons, and the Java runner's sentences for the rest.
#[derive(Debug, thiserror::Error)]
pub enum ExtendedError {
    #[error(transparent)]
    Runner(#[from] RunnerError),
    /// A step of the run's own — `ScannerFailureException.of(label, message)`: the sentence as is.
    #[error("{message}")]
    Failed { label: String, message: String },
    /// A request this runner refuses before anything runs — Java's `IllegalArgumentException`.
    #[error("{0}")]
    Refused(String),
}

impl ContainerRunner {
    /// The Docker runner a scan uses, its pulls' credentials read once as docker-java reads them for the Java runner:
    /// `DOCKER_CONFIG`, else `.docker` under `home`. One that cannot be read stops the start, rather than every private
    /// pull — and every plugin signature kept in a private registry — failing as "anonymous" later.
    pub fn for_scans(home: &std::path::Path, limits: crate::ScannerLimits) -> Result<ContainerRunner, String> {
        let docker_config = std::env::var("DOCKER_CONFIG")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map_or_else(|| home.join(".docker"), std::path::PathBuf::from);
        let credentials = pull_credentials::DockerConfig::load(&docker_config).map_err(|error| error.to_string())?;
        Ok(ContainerRunner::connect(None, limits).map_err(|error| error.to_string())?.with_docker_config(credentials))
    }

    /// This runner, its pulls and its registry logins sending what `config` holds — read once, as docker-java reads
    /// the Java runner's configuration when its client is built.
    pub fn with_docker_config(mut self, config: pull_credentials::DockerConfig) -> ContainerRunner {
        self.credentials = config;
        self
    }

    /// The ceiling on what a scanner may hand back — its standard output, and a plugin's report file.
    pub fn output_bytes(&self) -> u64 {
        u64::try_from(self.limits.output_bytes).unwrap_or(u64::MAX)
    }

    /// `registryAccessFor`: the registry as the pulls key it, and whether credentials are held for it — never them.
    pub fn registry_access_for(&self, reference: &str) -> RegistryAccess {
        RegistryAccess {
            registry: pull_credentials::registry_of(reference),
            credentials_held: self.credentials.credentials_for(reference).is_some(),
        }
    }

    /// `ContainerRunner.run` with a bounded output and/or a registry login: pulled if absent, the login written, the
    /// holder started, the tool created, started, waited for, its output and its directory read back — and the
    /// tool, the holder with its volume, and the login removed whatever happens, the future dropped included.
    pub async fn run_with(&self, run: &ContainerRun, extras: &Extras) -> Result<ExtendedResult, ExtendedError> {
        let limits = self.limits().await;
        let timeout = run.timeout.unwrap_or(limits.timeout);
        let owner = match (&extras.output, &run.user) {
            (Some(_), None) => {
                // Created owned by this uid:gid, 0700: without one the directory would be root's, and a tool that is
                // not root could not write its report.
                return Err(ExtendedError::Refused("A bounded output needs the user it belongs to.".to_owned()));
            }
            (Some(_), Some(user)) => Some(numeric_owner(user)?),
            (None, _) => None,
        };
        self.ensure_present(&run.image).await?;

        let mut cleanup = Cleanup { docker: self.docker.clone(), holder: None, login: None };
        let mut sent: Option<&AuthConfig> = None;
        let mut login_directory: Option<PathBuf> = None;
        if let Some(login) = &extras.login
            && let Some(auth) = self.credentials.credentials_for(&login.reference)
        {
            let registry = pull_credentials::registry_of(&login.reference);
            let written = pull_credentials::write(auth, &registry, &login.directory).map_err(|error| {
                // The error names a path, never the credentials.
                failed(run, format!("The registry credentials could not be handed to it: {error}"))
            })?;
            cleanup.login = Some(written.clone());
            login_directory = Some(written);
            sent = Some(auth);
        }

        let holder = match (&extras.output, owner) {
            (Some(bounded), Some(owner)) => {
                self.ensure_present(&bounded.holder_image).await?;
                let body =
                    holder_body(bounded, run.user.as_deref().unwrap_or_default(), &owner, &run.label, timeout, &limits);
                let created = self
                    .docker
                    .create_container(None::<bollard::query_parameters::CreateContainerOptions>, body)
                    .await
                    .map_err(|error| failed(run, format!("Its output directory could not be created: {error}")))?;
                cleanup.holder = Some(created.id.clone());
                if let Err(error) = self
                    .docker
                    .start_container(&created.id, None::<bollard::query_parameters::StartContainerOptions>)
                    .await
                {
                    return Err(failed(run, format!("Its output directory could not be created: {error}")));
                }
                Some(created.id)
            }
            _ => None,
        };

        let body = tool_body(run, &limits, extras.output.as_ref().zip(holder.as_deref()), login_directory.as_deref());
        let created = self
            .docker
            .create_container(None::<bollard::query_parameters::CreateContainerOptions>, body)
            .await
            .map_err(|error| daemon(run, error))?;
        let container = Removal { docker: self.docker.clone(), id: Some(created.id) };
        let outcome = self
            .run_and_collect(run, container.id(), timeout, &limits, extras.output.as_ref().zip(holder.as_deref()))
            .await;
        // The tool first, then its holder with its volume — the other order would leave the volume in use and its
        // removal refused — then the login, which the container held open.
        container.now().await;
        cleanup.now().await;
        let (result, output) = outcome?;
        let redact = |text: &str| sent.map_or_else(|| text.to_owned(), |auth| auth.redact(text));
        Ok(ExtendedResult {
            result: ContainerResult {
                stdout: redact(&result.stdout),
                stderr: redact(&result.stderr),
                exit_code: result.exit_code,
            },
            output,
        })
    }

    async fn run_and_collect(
        &self,
        run: &ContainerRun,
        id: &str,
        timeout: Duration,
        limits: &ScannerLimits,
        bounded: Option<(&BoundedOutput, &str)>,
    ) -> Result<(ContainerResult, Option<CollectedOutput>), ExtendedError> {
        let result = self.run_created(run, id, timeout, limits.output_bytes).await?;
        let collected = match bounded {
            None => None,
            Some((bounded, holder)) => Some(self.collect(holder, bounded, &run.label, limits).await?),
        };
        Ok((result, collected))
    }

    /// Reads the file back from the holder, then stops the holder and reads what the kernel said — in that order:
    /// stopping the holder unmounts the tmpfs, and what was in it is gone.
    async fn collect(
        &self,
        holder: &str,
        bounded: &BoundedOutput,
        label: &str,
        limits: &ScannerLimits,
    ) -> Result<CollectedOutput, ExtendedError> {
        // The smaller of the two ceilings: the directory's own and what a scanner may hand back.
        let ceiling = bounded.bytes.min(u64::try_from(limits.output_bytes).unwrap_or(u64::MAX));
        let path = format!("{}/{}", bounded.target, bounded.file);
        let options = DownloadFromContainerOptionsBuilder::new().path(&path).build();
        let mut archive = self.docker.download_from_container(holder, Some(options));
        let budget = archive_budget(ceiling);
        let mut bytes: Vec<u8> = Vec::new();
        let mut missing = false;
        while let Some(chunk) = archive.next().await {
            match chunk {
                Ok(chunk) => {
                    let room = usize::try_from(budget.saturating_sub(u64::try_from(bytes.len()).unwrap_or(u64::MAX)))
                        .unwrap_or(usize::MAX);
                    bytes.extend(chunk.iter().take(room));
                    if room <= chunk.len() {
                        // Enough for the header to have spoken: the rest is drained by nobody.
                        break;
                    }
                }
                Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
                    missing = true;
                    break;
                }
                Err(error) => {
                    return Err(failed_label(label, format!("Its output could not be read back: {error}")));
                }
            }
        }
        drop(archive);
        let file = if missing {
            OutputFile::Missing
        } else {
            read_archive(&bytes, &bounded.file, ceiling)
                .map_err(|error| failed_label(label, format!("Its output could not be read back: {error}")))?
        };

        // Measured below or not at all; a holder that is gone printed nothing, and says so there.
        let stop = StopContainerOptionsBuilder::new().t(10).build();
        let _ = self.docker.stop_container(holder, Some(stop)).await;
        let options = LogsOptionsBuilder::new().stdout(true).stderr(true).tail("all").build();
        let mut logs = self.docker.logs(holder, Some(options));
        let mut printed = Vec::new();
        while let Some(chunk) = logs.next().await {
            if let Ok(
                bollard::container::LogOutput::StdOut { message } | bollard::container::LogOutput::Console { message },
            ) = chunk
            {
                let room = MEASURE_BYTES.saturating_sub(printed.len());
                printed.extend(message.iter().take(room));
            }
        }
        CollectedOutput::measured(bounded, &String::from_utf8_lossy(&printed), file).ok_or_else(|| {
            failed_label(
                label,
                "Its output directory could not be measured, so whether a write was refused is unknown; the report \
                 is not believed.",
            )
        })
    }
}

/// `uid:gid`, both numeric — what the volume's `uid=` and `gid=` options take.
fn numeric_owner(user: &str) -> Result<(String, String), ExtendedError> {
    match user.split_once(':') {
        Some((uid, gid))
            if !uid.is_empty()
                && !gid.is_empty()
                && uid.bytes().all(|b| b.is_ascii_digit())
                && gid.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Ok((uid.to_owned(), gid.to_owned()))
        }
        _ => Err(ExtendedError::Refused(format!("A bounded output belongs to a numeric uid:gid, not \"{user}\"."))),
    }
}

fn failed(run: &ContainerRun, message: String) -> ExtendedError {
    failed_label(&run.label, message)
}

fn failed_label(label: &str, message: impl Into<String>) -> ExtendedError {
    ExtendedError::Failed { label: label.to_owned(), message: message.into() }
}

/// The holder's create request — `startHolder`: it sleeps until stopped, then prints `df` of the directory in bytes
/// and in inodes and exits; it expires on its own after the tool's timeout and a grace.
pub fn holder_body(
    bounded: &BoundedOutput,
    user: &str,
    owner: &(String, String),
    label: &str,
    timeout: Duration,
    limits: &ScannerLimits,
) -> ContainerCreateBody {
    let holder_label = format!("{label} (output)");
    let report = format!("df -P -k {target}; df -P -i {target}", target = bounded.target);
    let seconds = timeout.saturating_add(HOLDER_GRACE).as_secs();
    let mut run = ContainerRun::new(
        bounded.holder_image.clone(),
        vec!["sh".into(), "-c".into(), format!("trap '{report}; exit 0' TERM; sleep {seconds} & wait")],
        Vec::new(),
        holder_label.clone(),
    );
    run.user = Some(user.to_owned());
    let mut body = create_body(&run, limits);
    let volume = DaemonMount {
        target: Some(bounded.target.clone()),
        typ: Some(MountTypeEnum::VOLUME),
        volume_options: Some(MountVolumeOptions {
            // Labelled like the containers, so that a sweep can find a volume a crash left behind.
            labels: Some(HashMap::from([(SCANNER_LABEL.to_owned(), holder_label)])),
            driver_config: Some(MountVolumeOptionsDriverConfig {
                name: Some("local".to_owned()),
                options: Some(HashMap::from([
                    ("type".to_owned(), "tmpfs".to_owned()),
                    ("device".to_owned(), "tmpfs".to_owned()),
                    (
                        "o".to_owned(),
                        format!(
                            "size={},nr_inodes={},uid={},gid={},mode=0700,noexec,nosuid,nodev",
                            bounded.bytes, bounded.inodes, owner.0, owner.1
                        ),
                    ),
                ])),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    if let Some(host) = body.host_config.as_mut() {
        host.mounts = Some(vec![volume]);
    }
    body
}

/// The tool's create request: the closed shape, the login's mount and variable, and the holder's volume with no
/// file larger than the directory.
pub fn tool_body(
    run: &ContainerRun,
    limits: &ScannerLimits,
    bounded: Option<(&BoundedOutput, &str)>,
    login: Option<&Path>,
) -> ContainerCreateBody {
    let mut run = run.clone();
    if let Some(directory) = login {
        run.mounts.push(Mount::read_only(directory.display().to_string(), REGISTRY_LOGIN_MOUNT));
    }
    let mut body = create_body(&run, limits);
    if login.is_some()
        && let Some(env) = body.env.as_mut()
    {
        env.push(format!("DOCKER_CONFIG={REGISTRY_LOGIN_MOUNT}"));
    }
    if let (Some((bounded, holder)), Some(host)) = (bounded, body.host_config.as_mut()) {
        let size = i64::try_from(bounded.bytes).unwrap_or(i64::MAX);
        host.volumes_from = Some(vec![format!("{holder}:rw")]);
        // **No file larger than the directory**, sparse ones included: tmpfs keeps a sparse file of any apparent
        // size in a few pages, and the daemon archives the apparent size. The kernel sends SIGXFSZ past it (153).
        host.ulimits =
            Some(vec![ResourcesUlimits { name: Some("fsize".to_owned()), soft: Some(size), hard: Some(size) }]);
    }
    body
}

/// What is removed once the tool is gone: the holder with its volume, and the login's directory — on drop too, so a
/// future given up half-way leaves neither.
struct Cleanup {
    docker: bollard::Docker,
    holder: Option<String>,
    login: Option<PathBuf>,
}

impl Cleanup {
    async fn now(mut self) {
        if let Some(holder) = self.holder.take() {
            remove_with_volumes(&self.docker, &holder).await;
        }
        pull_credentials::erase(self.login.take().as_deref());
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        pull_credentials::erase(self.login.take().as_deref());
        if let (Some(holder), Ok(runtime)) = (self.holder.take(), tokio::runtime::Handle::try_current()) {
            let docker = self.docker.clone();
            runtime.spawn(async move { remove_with_volumes(&docker, &holder).await });
        }
    }
}

async fn remove_with_volumes(docker: &bollard::Docker, id: &str) {
    let options = RemoveContainerOptionsBuilder::new().force(true).v(true).build();
    let _ = docker.remove_container(id, Some(options)).await;
}
