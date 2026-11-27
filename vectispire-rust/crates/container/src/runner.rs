//! Running one scanner container to completion — `ContainerRunner.run`.

use crate::{ContainerRun, ScannerLimits, create_body, image_archive};
use bollard::Docker;
use bollard::query_parameters::{
    CreateImageOptionsBuilder, LogsOptionsBuilder, RemoveContainerOptionsBuilder, StopContainerOptionsBuilder,
};
use futures_util::StreamExt;
use tokio::sync::OnceCell;

/// What standard error keeps: enough for the tool's own explanation, not a second unbounded stream.
pub const STDERR_BYTES: usize = 1024 * 1024;

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
    /// Another executor's failure, in its own words — `ScannerFailureException.of(label, message)`: the Kubernetes
    /// executor's pod that could not be created, scheduled, pulled, cut off or read back (decision 0045 §9).
    #[error("{message}")]
    Failed { label: String, message: String },
}

/// Why an image could not be exported for its inventory — the step's failure, which reaches the scan's page.
///
/// Java's are docker-java's own messages for the pull and `could not export <reference>` for the save; the daemon's
/// cause is kept here in both, since it is the only thing that tells a typo from a registry that refused.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("The image {reference} could not be pulled: {cause}")]
    Pull { reference: String, cause: String },
    #[error("could not export {reference}: {cause}")]
    Save { reference: String, cause: String },
    /// The platform asked for, malformed, or not the one the archive holds — `ImagePlatform`'s sentences
    /// ([`crate::image_archive`]).
    #[error("{0}")]
    Platform(String),
    /// An executor that does not export images, in its own words — the Kubernetes one (decision 0045 §8, not built).
    #[error("{0}")]
    Unsupported(String),
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
    pub(crate) docker: Docker,
    pub(crate) limits: ScannerLimits,
    /// The CPU quota the daemon accepts, asked once, on the first run: asking at start would turn "no
    /// Docker today" into "the agent does not start".
    clamped: OnceCell<ScannerLimits>,
    /// What this executor's pulls send a registry — read once, from its Docker configuration
    /// ([`ContainerRunner::with_docker_config`]); none until then, and every pull anonymous.
    pub(crate) credentials: crate::pull_credentials::DockerConfig,
    /// Where the daemon is, as [`ContainerRunner::connect`] resolved it: for the one request bollard cannot make
    /// (the save of [`ContainerRunner::export_image`]).
    address: String,
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
        Ok(ContainerRunner { docker, limits, clamped: OnceCell::new(), credentials: Default::default(), address })
    }

    /// Whether the daemon answers — asked before claiming a scan, so that an agent without Docker
    /// does not take work it cannot do.
    pub async fn is_available(&self) -> bool {
        self.why_unavailable().await.is_none()
    }

    /// Why the daemon cannot run anything now, in its own words — `None` when it answers a ping. What a worker
    /// announces as its executor's state (decision 0045), worded as the Java executor words it.
    pub async fn why_unavailable(&self) -> Option<String> {
        self.docker.ping().await.err().map(|error| format!("The Docker daemon did not answer a ping: {error}"))
    }

    /// How long a scanner may run before it is stopped — `ContainerExecutor.scannerTimeout`.
    pub fn scanner_timeout(&self) -> std::time::Duration {
        self.limits.timeout
    }

    pub(crate) async fn limits(&self) -> ScannerLimits {
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

    pub(crate) async fn run_created(
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

    /// Pulls `reference` for `platform` and writes it to `destination` as an archive — `ContainerRunner.exportImage`.
    ///
    /// **This is what replaces the socket mounted into the cataloguer**: only Vectispire talks to the daemon, and
    /// the scanner is handed a file. The platform is **mandatory on the pull**: without it the daemon answers with
    /// the host's own architecture, and the inventory is of a variant nobody asked to audit. The pull always runs,
    /// as Java's does, rather than trusting a local copy that may be another platform's.
    ///
    /// **And on the save**, which the pull does not decide: on Docker's containerd image store a save without one
    /// exported the host's variant whatever the pull fetched (measured 2026-11-15 and 2026-11-27, Docker 29.1 on
    /// arm64). The save names it (API 1.48), and the archive is checked against it whatever the daemon — an image of
    /// another platform, or an archive that cannot be read, fails the step and is removed ([`crate::image_archive`]).
    ///
    /// Written to a fresh file (`create_new`): the destination is in the scan's own 0700 workspace, and a file
    /// already there is not this export's to overwrite.
    pub async fn export_image(
        &self,
        reference: &str,
        platform: &str,
        destination: &std::path::Path,
    ) -> Result<(), ExportError> {
        let asked = image_archive::requested(platform).map_err(ExportError::Platform)?;
        // None only where the task named no platform, which Java passes on as `null`: the daemon's own then.
        let options = match asked {
            None => CreateImageOptionsBuilder::new().from_image(reference).build(),
            Some(_) => CreateImageOptionsBuilder::new().from_image(reference).platform(platform).build(),
        };
        let mut pull = self.docker.create_image(Some(options), None, None);
        while let Some(progress) = pull.next().await {
            progress
                .map_err(|error| ExportError::Pull { reference: reference.to_owned(), cause: error.to_string() })?;
        }
        let could_not_export = |cause: String| ExportError::Save { reference: reference.to_owned(), cause };
        let mut archive = self.save(reference, asked.as_ref()).await.map_err(could_not_export)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|error| could_not_export(error.to_string()))?;
        while let Some(frame) = http_body_util::BodyExt::frame(&mut archive).await {
            let frame = frame.map_err(|error| could_not_export(error.to_string()))?;
            if let Ok(chunk) = frame.into_data() {
                std::io::Write::write_all(&mut file, &chunk).map_err(|error| could_not_export(error.to_string()))?;
            }
        }
        // A short write the kernel has not reported yet would be a truncated archive the cataloguer reads as less.
        file.sync_all().map_err(|error| could_not_export(error.to_string()))?;
        let Some(asked) = asked else { return Ok(()) };
        let refusal = image_archive::refusal(reference, platform, &asked, |name, limit| {
            image_archive::entry(destination, name, limit)
        });
        match refusal {
            None => Ok(()),
            Some(refusal) => {
                // Not left for the workspace removal: nothing may pick up an archive that was refused.
                let _ = std::fs::remove_file(destination);
                Err(ExportError::Platform(refusal))
            }
        }
    }

    /// `GET /images/get?names=…&platform=…`, by hand: bollard 0.19's save takes no platform. Unversioned, as bollard's
    /// own requests reach the daemon, so it reads them at its own API version — one from 1.48 on honours the
    /// platform, an older one ignores it and [`image_archive::refusal`] has the last word. One connection for this one
    /// request, as for every call here: the socket proxy closes idle ones. A refusal is the daemon's `message`.
    async fn save(
        &self,
        reference: &str,
        platform: Option<&image_archive::Platform>,
    ) -> Result<hyper::body::Incoming, String> {
        use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
        let mut path = format!("/images/get?names={}", utf8_percent_encode(reference, NON_ALPHANUMERIC));
        if let Some(platform) = platform {
            path.push_str("&platform=");
            path.push_str(&utf8_percent_encode(&platform.save_query(), NON_ALPHANUMERIC).to_string());
        }
        let request = http::Request::get(path)
            .header(http::header::HOST, "docker")
            .header(http::header::CONNECTION, "close")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .map_err(|error| error.to_string())?;
        let answer = tokio::time::timeout(std::time::Duration::from_secs(DAEMON_CALL_TIMEOUT_SECONDS), async {
            let mut sender = daemon_connection(&self.address).await?;
            sender.send_request(request).await.map_err(|error| error.to_string())
        })
        .await
        .map_err(|_| format!("the daemon did not answer within {DAEMON_CALL_TIMEOUT_SECONDS}s"))??;
        let status = answer.status();
        if status == http::StatusCode::OK {
            return Ok(answer.into_body());
        }
        let body = http_body_util::BodyExt::collect(http_body_util::Limited::new(answer.into_body(), 64 * 1024)).await;
        let message = body
            .ok()
            .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body.to_bytes()).ok())
            .and_then(|document| document.get("message").and_then(serde_json::Value::as_str).map(str::to_owned));
        Err(message.unwrap_or_else(|| format!("the daemon answered {}", status.as_u16())))
    }

    /// Pulls the image if the host lacks it: the create call never pulls, and nothing else will.
    ///
    /// The pull sends what this executor's Docker configuration holds for the image's registry, as docker-java's
    /// pull sends it for the Java runner — nothing when it holds nothing usable.
    async fn ensure_image_present(&self, run: &ContainerRun) -> Result<(), RunnerError> {
        self.ensure_present(&run.image).await
    }

    pub(crate) async fn ensure_present(&self, image: &str) -> Result<(), RunnerError> {
        if self.docker.inspect_image(image).await.is_ok() {
            return Ok(());
        }
        let options = CreateImageOptionsBuilder::new().from_image(image).build();
        let credentials = self.credentials.credentials_for(image).map(|auth| bollard::auth::DockerCredentials {
            username: auth.username.clone(),
            password: auth.password.clone(),
            identitytoken: auth.identity_token.clone(),
            registrytoken: auth.registry_token.clone(),
            serveraddress: Some(crate::pull_credentials::registry_of(image)),
            ..Default::default()
        });
        let mut pull = self.docker.create_image(Some(options), None, credentials);
        while let Some(progress) = pull.next().await {
            if let Err(error) = progress {
                return Err(RunnerError::ImageUnavailable { image: image.to_owned(), cause: error.to_string() });
            }
        }
        Ok(())
    }
}

/// An HTTP/1.1 connection to the daemon at `address` — `tcp://` or `http://` for the socket proxy, `unix://` or a
/// path for a socket, as [`ContainerRunner::connect`] reads it — driven in the background until its one exchange ends.
async fn daemon_connection(
    address: &str,
) -> Result<hyper::client::conn::http1::SendRequest<http_body_util::Empty<bytes::Bytes>>, String> {
    let unreachable = |error: std::io::Error| format!("No Docker daemon could be reached at {address}: {error}");
    match address.strip_prefix("tcp://").or_else(|| address.strip_prefix("http://")) {
        Some(authority) => {
            let stream = tokio::net::TcpStream::connect(authority.trim_end_matches('/')).await.map_err(unreachable)?;
            handshake(stream).await
        }
        None => {
            let stream = tokio::net::UnixStream::connect(address.strip_prefix("unix://").unwrap_or(address))
                .await
                .map_err(unreachable)?;
            handshake(stream).await
        }
    }
}

async fn handshake<S>(
    stream: S,
) -> Result<hyper::client::conn::http1::SendRequest<http_body_util::Empty<bytes::Bytes>>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
        .await
        .map_err(|error| error.to_string())?;
    // Its failure, if any, is the body's: the archive's reader sees it as an error, never as an end.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

pub(crate) fn daemon(run: &ContainerRun, error: bollard::errors::Error) -> RunnerError {
    RunnerError::Daemon { label: run.label.clone(), cause: error.to_string() }
}

/// A created container, removed when its run is over — and, should the future be dropped half-way
/// (an agent shutting down, a scan cancelled), removed by a task spawned on drop. A forgotten
/// container holds its workspace, hence the whole clone, until the disk is full.
pub(crate) struct Removal {
    pub(crate) docker: Docker,
    pub(crate) id: Option<String>,
}

impl Removal {
    pub(crate) fn id(&self) -> &str {
        self.id.as_deref().unwrap_or_default()
    }

    pub(crate) async fn now(mut self) {
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
