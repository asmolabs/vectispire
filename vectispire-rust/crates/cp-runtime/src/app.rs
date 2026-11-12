//! The binary's skeleton: a service that serves until it is told to stop, and a stop that is graceful.
//!
//! `App::serve` is the interface the HTTP stack (`cp-http`) plugs into — a [`Service`] that watches a
//! [`ShutdownSignal`] — and what it guarantees is the order: readiness out of service first, then the
//! signal to the service, then a bounded wait.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::actuator::{Actuator, BuildInfo, Health};
use crate::metrics::Metrics;
use crate::settings::Settings;
use crate::shutdown::{Shutdown, ShutdownSignal, TIMEOUT_PER_SHUTDOWN_PHASE, termination};

/// Something that serves until told to stop — the HTTP stack, the scheduler.
pub trait Service: Send + 'static {
    fn serve(self, shutdown: ShutdownSignal) -> impl Future<Output = Result<(), String>> + Send;
}

/// Everything a service of the control plane shares.
#[derive(Debug)]
pub struct App {
    pub settings: Settings,
    pub health: Arc<Health>,
    pub metrics: Arc<Metrics>,
    pub actuator: Arc<Actuator>,
}

impl App {
    /// An application named `application` (the `application` tag of every series).
    pub fn new(settings: Settings, application: &str, build: BuildInfo) -> App {
        let health = Arc::new(Health::default());
        let metrics = Arc::new(Metrics::new(application));
        let actuator = Arc::new(Actuator { health: health.clone(), metrics: metrics.clone(), build });
        App { settings, health, metrics, actuator }
    }

    /// Serves until `SIGTERM` or `SIGINT`, then stops gracefully.
    pub async fn serve<S: Service>(&self, service: S) -> Result<(), String> {
        let signal = async {
            if let Err(error) = termination().await {
                // A process that cannot be signalled would never stop gracefully: stop now, loudly.
                tracing::error!("The termination signals could not be installed: {error}");
            }
        };
        self.serve_until(service, TIMEOUT_PER_SHUTDOWN_PHASE, signal).await
    }

    /// Serves until `stop` resolves (or the service ends), then stops gracefully within `grace`.
    pub async fn serve_until<S: Service>(
        &self,
        service: S,
        grace: Duration,
        stop: impl Future<Output = ()>,
    ) -> Result<(), String> {
        let (shutdown, signal) = Shutdown::new();
        let mut task = tokio::spawn(service.serve(signal));
        tokio::select! {
            ended = &mut task => return ended.map_err(|panicked| format!("The service stopped abnormally: {panicked}"))?,
            () = stop => {}
        }
        // Readiness first: a load balancer must stop sending before the requests in flight are done.
        self.health.refuse_traffic();
        tracing::info!("Commencing graceful shutdown. Waiting for active requests to complete");
        shutdown.trigger();
        match tokio::time::timeout(grace, &mut task).await {
            Ok(ended) => {
                tracing::info!("Graceful shutdown complete");
                ended.map_err(|panicked| format!("The service stopped abnormally: {panicked}"))?
            }
            Err(_) => {
                task.abort();
                Err(format!("The service did not stop within {} s; it was abandoned.", grace.as_secs()))
            }
        }
    }
}
