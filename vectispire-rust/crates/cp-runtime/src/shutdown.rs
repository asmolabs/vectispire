//! Graceful shutdown — what `server.shutdown: graceful` does, which is Spring Boot's default.
//!
//! On `SIGTERM` or `SIGINT`: readiness goes out of service at once so that a load balancer stops sending,
//! the service is told to stop accepting and to finish what it holds, and the process waits for it — at
//! most [`TIMEOUT_PER_SHUTDOWN_PHASE`], Spring's `spring.lifecycle.timeout-per-shutdown-phase`, thirty
//! seconds. An agent's long poll holds its request up to thirty seconds, which is why the figure matters.

use std::time::Duration;

use tokio::sync::watch;

/// `spring.lifecycle.timeout-per-shutdown-phase`'s default.
pub const TIMEOUT_PER_SHUTDOWN_PHASE: Duration = Duration::from_secs(30);

/// The sender of the stop, held by whoever decides.
#[derive(Debug)]
pub struct Shutdown {
    sender: watch::Sender<bool>,
}

/// What a service watches: it resolves when the process has been told to stop.
#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    receiver: watch::Receiver<bool>,
}

impl Shutdown {
    pub fn new() -> (Shutdown, ShutdownSignal) {
        let (sender, receiver) = watch::channel(false);
        (Shutdown { sender }, ShutdownSignal { receiver })
    }

    pub fn trigger(&self) {
        let _ = self.sender.send(true);
    }
}

impl ShutdownSignal {
    /// Resolves once the stop has been given — at once if it already has.
    pub async fn triggered(&mut self) {
        let _ = self.receiver.wait_for(|stopped| *stopped).await;
    }

    pub fn is_triggered(&self) -> bool {
        *self.receiver.borrow()
    }
}

/// Resolves on `SIGTERM` or `SIGINT`.
pub async fn termination() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    Ok(())
}
