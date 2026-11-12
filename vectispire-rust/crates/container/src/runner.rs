//! Running one scanner container to completion — `ContainerRunner.run`.

use crate::{ContainerRun, ScannerLimits, create_body};
use bollard::Docker;
use bollard::query_parameters::{
    CreateImageOptionsBuilder, LogsOptionsBuilder, RemoveContainerOptionsBuilder, StopContainerOptionsBuilder,
};
use futures_util::StreamExt;
use tokio::sync::OnceCell;

/// What standard error keeps: enough for the tool's own explanation, not a second unbounded stream.
const STDERR_BYTES: usize = 1024 * 1024;

/// How long one call to the daemon may take, the run's own wait aside.
const DAEMON_CALL_TIMEOUT_SECONDS: u64 = 120;

/// Why a run produced no result — with the Java runner's sentences, which reach the scan's error.
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("Scanner \"{label}\" exceeded {seconds}s and was stopped.")]
    TimedOut { label: String, seconds: u64 },
    #[error("Scanner \"{label}\" wrote more than {limit} bytes of output; it was stopped and its output discarded.")]
    OutputTooLarge { label: String, limit: usize },
    #[error(
        "The scanner image {image} is not on this host and could not be fetched: {cause} Pre-pull it, or point the \
         corresponding image setting at a registry this machine can reach."
    )]
    ImageUnavailable { image: String, cause: String },
    #[error("The Docker daemon refused scanner \"{label}\": {cause}")]
    Daemon { label: String, cause: String },
    #[error("No Docker daemon could be reached at {address}: {cause}")]
    Unreachable { address: String, cause: String },
}

/// What a run printed, and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i64,
}

/// The daemon — through the socket proxy in every shipped composition — and the limits runs get.
#[derive(Debug)]
pub struct ContainerRunner {
    docker: Docker,
    limits: ScannerLimits,
    /// The CPU quota the daemon accepts, asked once, on the first run: asking at start would turn "no
    /// Docker today" into "the agent does not start".
    clamped: OnceCell<ScannerLimits>,
}

impl ContainerRunner {
    /// The daemon `DOCKER_HOST` names — `tcp://` for the socket proxy, `unix://` or a path for a
    /// socket — or the local socket.
    ///
    /// **One request per connection**, as on the Java side: the socket proxy closes idle connections,
    /// and a pooled one reused after that failed image scans with "broken pipe". bollard's HTTP and
    /// socket transports keep no idle connection (`pool_max_idle_per_host(0)`).
    pub fn connect(docker_host: Option<&str>, limits: ScannerLimits) -> Result<ContainerRunner, RunnerError> {
        let address = docker_host
            .map(str::to_owned)
            .or_else(|| std::env::var("DOCKER_HOST").ok().filter(|value| !value.trim().is_empty()))
            .unwrap_or_else(|| "unix:///var/run/docker.sock".to_owned());
        let unreachable = |error: bollard::errors::Error| RunnerError::Unreachable {
            address: address.clone(),
            cause: error.to_string(),
        };
        let docker = if address.starts_with("tcp://") || address.starts_with("http://") {
            Docker::connect_with_http(&address, DAEMON_CALL_TIMEOUT_SECONDS, bollard::API_DEFAULT_VERSION)
        } else {
            Docker::connect_with_socket(
                address.strip_prefix("unix://").unwrap_or(&address),
                DAEMON_CALL_TIMEOUT_SECONDS,
                bollard::API_DEFAULT_VERSION,
            )
        }
        .map_err(unreachable)?;
        Ok(ContainerRunner { docker, limits, clamped: OnceCell::new() })
    }

    /// Whether the daemon answers — asked before claiming a scan, so that an agent without Docker
    /// does not take work it cannot do.
    pub async fn is_available(&self) -> bool {
        self.docker.ping().await.is_ok()
    }

    async fn limits(&self) -> ScannerLimits {
        *self
            .clamped
            .get_or_init(|| async {
                match self.docker.info().await {
                    Ok(info) => self.limits.clamped_to(info.ncpu.unwrap_or(0)),
                    // The create that follows reports the real problem; this is not a second way to.
                    Err(_) => self.limits,
                }
            })
            .await
    }

    /// Runs `run` to completion: pulled if absent, created, started, waited for, its output read, and
    /// removed — whatever happens, including the caller giving up on the future.
    pub async fn run(&self, run: &ContainerRun) -> Result<ContainerResult, RunnerError> {
        let limits = self.limits().await;
        let timeout = run.timeout.unwrap_or(limits.timeout);
        self.ensure_image_present(run).await?;
        let created = self
            .docker
            .create_container(None::<bollard::query_parameters::CreateContainerOptions>, create_body(run, &limits))
            .await
            .map_err(|error| daemon(run, error))?;
        let container = Removal { docker: self.docker.clone(), id: Some(created.id) };
        let id = container.id().to_owned();
        let outcome = self.run_created(run, &id, timeout, limits.output_bytes).await;
        container.now().await;
        outcome
    }

    async fn run_created(
        &self,
        run: &ContainerRun,
        id: &str,
        timeout: std::time::Duration,
        output_bytes: usize,
    ) -> Result<ContainerResult, RunnerError> {
        self.docker
            .start_container(id, None::<bollard::query_parameters::StartContainerOptions>)
            .await
            .map_err(|error| daemon(run, error))?;
        let mut wait = self.docker.wait_container(id, None::<bollard::query_parameters::WaitContainerOptions>);
        let exit_code = match tokio::time::timeout(timeout, wait.next()).await {
            Err(_) => {
                let stop = StopContainerOptionsBuilder::new().t(5).build();
                let _ = self.docker.stop_container(id, Some(stop)).await;
                return Err(RunnerError::TimedOut { label: run.label.clone(), seconds: timeout.as_secs() });
            }
            Ok(Some(Ok(response))) => response.status_code,
            // bollard reports a non-zero exit as an error carrying the code.
            Ok(Some(Err(bollard::errors::Error::DockerContainerWaitError { code, .. }))) => code,
            Ok(Some(Err(error))) => return Err(daemon(run, error)),
            Ok(None) => {
                return Err(RunnerError::Daemon { label: run.label.clone(), cause: "no exit status".to_owned() });
            }
        };

        // Read after the container has finished, never attached before it starts: a stream attached
        // too early ends on output that does not exist yet, which reads as "printed nothing", hence
        // "analysed, found nothing".
        let options = LogsOptionsBuilder::new().stdout(true).stderr(true).tail("all").build();
        let mut logs = self.docker.logs(id, Some(options));
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        while let Some(chunk) = logs.next().await {
            match chunk.map_err(|error| daemon(run, error))? {
                bollard::container::LogOutput::StdOut { message }
                | bollard::container::LogOutput::Console { message } => {
                    if stdout.len() + message.len() > output_bytes {
                        // Failed, not truncated: a report cut short is not a smaller report.
                        return Err(RunnerError::OutputTooLarge { label: run.label.clone(), limit: output_bytes });
                    }
                    stdout.extend_from_slice(&message);
                }
                bollard::container::LogOutput::StdErr { message } => {
                    let room = STDERR_BYTES.saturating_sub(stderr.len());
                    stderr.extend_from_slice(&message[..message.len().min(room)]);
                }
                bollard::container::LogOutput::StdIn { .. } => {}
            }
        }
        Ok(ContainerResult {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code,
        })
    }

    /// Pulls the image if the host lacks it: the create call never pulls, and nothing else will.
    async fn ensure_image_present(&self, run: &ContainerRun) -> Result<(), RunnerError> {
        if self.docker.inspect_image(&run.image).await.is_ok() {
            return Ok(());
        }
        let options = CreateImageOptionsBuilder::new().from_image(&run.image).build();
        let mut pull = self.docker.create_image(Some(options), None, None);
        while let Some(progress) = pull.next().await {
            if let Err(error) = progress {
                return Err(RunnerError::ImageUnavailable { image: run.image.clone(), cause: error.to_string() });
            }
        }
        Ok(())
    }
}

fn daemon(run: &ContainerRun, error: bollard::errors::Error) -> RunnerError {
    RunnerError::Daemon { label: run.label.clone(), cause: error.to_string() }
}

/// A created container, removed when its run is over — and, should the future be dropped half-way
/// (an agent shutting down, a scan cancelled), removed by a task spawned on drop. A forgotten
/// container holds its workspace, hence the whole clone, until the disk is full.
struct Removal {
    docker: Docker,
    id: Option<String>,
}

impl Removal {
    fn id(&self) -> &str {
        self.id.as_deref().unwrap_or_default()
    }

    async fn now(mut self) {
        if let Some(id) = self.id.take() {
            remove(&self.docker, &id).await;
        }
    }
}

impl Drop for Removal {
    fn drop(&mut self) {
        if let (Some(id), Ok(runtime)) = (self.id.take(), tokio::runtime::Handle::try_current()) {
            let docker = self.docker.clone();
            runtime.spawn(async move { remove(&docker, &id).await });
        }
    }
}

async fn remove(docker: &Docker, id: &str) {
    let options = RemoveContainerOptionsBuilder::new().force(true).v(false).build();
    // Nothing to do about a container already gone, and nothing worth masking the run's error for.
    let _ = docker.remove_container(id, Some(options)).await;
}
