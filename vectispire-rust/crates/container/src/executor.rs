//! The seam of decision 0045 — `ContainerExecutor`: what a scan needs to run its scanners, one [`ContainerRun`] at a
//! time in the closed shape it describes, and an image exported for the cataloguer to read.
//!
//! [`ContainerRunner`] runs each request as a Docker container; on a cluster without Docker, the agent runs each one
//! as a pod in a namespace of its own (`vectispire-kubernetes`, which only the agent links: the control plane holds
//! the encryption key, and a credential that starts pods beside it would let a compromise of it run arbitrary images
//! in the cluster with the key in hand). Every scanner and the vulnerability database take an [`Executor`], so the
//! backend is chosen once, where the agent is composed, and nothing that reads a scanner's output knows which ran it.
//!
//! **The contract is the closed shape, not Docker.** An implementation runs the request with no capability, no new
//! privilege, a read-only root, as the user the request names, with no network unless the request asks for it,
//! within the limits and the timeout, in a fresh container removed after the run; and it fails — never an empty
//! result — when it cannot (decision 0007).

use crate::{ContainerResult, ContainerRun, ContainerRunner, ExportError, RunnerError};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// A future an executor hands back, boxed so that the seam can be a trait object.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What runs the scanners — `ContainerExecutor`.
pub trait ContainerExecutor: Send + Sync + std::fmt::Debug {
    /// Runs one request in the closed shape and returns what it wrote, or fails naming the step.
    fn run<'a>(&'a self, run: &'a ContainerRun) -> BoxFuture<'a, Result<ContainerResult, RunnerError>>;

    /// Writes `reference`, for `platform`, to `destination` as an archive the cataloguer reads offline.
    fn export_image<'a>(
        &'a self,
        reference: &'a str,
        platform: &'a str,
        destination: &'a Path,
    ) -> BoxFuture<'a, Result<(), ExportError>>;

    /// Why it cannot run anything now, in its own words, or `None` when it can. Asked as often as the agent polls,
    /// so as cheap as the backend allows: a ping, a listing.
    fn why_unavailable(&self) -> BoxFuture<'_, Option<String>>;

    /// Whether [`ContainerExecutor::export_image`] works on this backend, and so whether a worker using it can scan
    /// a container image at all: the claim reads what the agent announces, so a scan it would fail is never handed
    /// to it.
    fn exports_images(&self) -> bool {
        true
    }

    /// How long a scanner may run before it is stopped.
    fn scanner_timeout(&self) -> Duration;
}

impl ContainerExecutor for ContainerRunner {
    fn run<'a>(&'a self, run: &'a ContainerRun) -> BoxFuture<'a, Result<ContainerResult, RunnerError>> {
        Box::pin(ContainerRunner::run(self, run))
    }

    fn export_image<'a>(
        &'a self,
        reference: &'a str,
        platform: &'a str,
        destination: &'a Path,
    ) -> BoxFuture<'a, Result<(), ExportError>> {
        Box::pin(ContainerRunner::export_image(self, reference, platform, destination))
    }

    fn why_unavailable(&self) -> BoxFuture<'_, Option<String>> {
        Box::pin(ContainerRunner::why_unavailable(self))
    }

    fn scanner_timeout(&self) -> Duration {
        ContainerRunner::scanner_timeout(self)
    }
}

/// The executor every scan of this process shares, whichever backend it is.
#[derive(Debug, Clone)]
pub struct Executor(Arc<dyn ContainerExecutor>);

impl Executor {
    pub fn new(executor: impl ContainerExecutor + 'static) -> Executor {
        Executor(Arc::new(executor))
    }

    pub async fn run(&self, run: &ContainerRun) -> Result<ContainerResult, RunnerError> {
        self.0.run(run).await
    }

    pub async fn export_image(&self, reference: &str, platform: &str, destination: &Path) -> Result<(), ExportError> {
        self.0.export_image(reference, platform, destination).await
    }

    pub async fn why_unavailable(&self) -> Option<String> {
        self.0.why_unavailable().await
    }

    pub fn exports_images(&self) -> bool {
        self.0.exports_images()
    }

    pub fn scanner_timeout(&self) -> Duration {
        self.0.scanner_timeout()
    }
}
