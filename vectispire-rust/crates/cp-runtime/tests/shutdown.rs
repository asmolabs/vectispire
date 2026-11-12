//! The order of a graceful stop, with a service of the test's own.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use vectispire_cp_runtime::actuator::BuildInfo;
use vectispire_cp_runtime::property::Environment;
use vectispire_cp_runtime::settings::Settings;
use vectispire_cp_runtime::shutdown::ShutdownSignal;
use vectispire_cp_runtime::{App, Service};

fn app() -> App {
    let (settings, _) = Settings::load(&Environment::of([], [])).unwrap();
    App::new(
        settings,
        "vectispire",
        BuildInfo {
            group: "g".to_owned(),
            artifact: "a".to_owned(),
            name: "n".to_owned(),
            version: "0".to_owned(),
            time: None,
        },
    )
}

/// Serves until told to stop, then takes `winding_down` to finish what it holds.
struct Slow {
    winding_down: Duration,
    finished: Arc<AtomicBool>,
}

impl Service for Slow {
    async fn serve(self, mut shutdown: ShutdownSignal) -> Result<(), String> {
        shutdown.triggered().await;
        tokio::time::sleep(self.winding_down).await;
        self.finished.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn readiness_goes_out_of_service_first_and_the_service_is_waited_for() {
    let app = app();
    let finished = Arc::new(AtomicBool::new(false));
    let service = Slow { winding_down: Duration::from_millis(200), finished: finished.clone() };
    let ready_during = Arc::new(std::sync::Mutex::new(None));
    // The stop comes at 50 ms; the service then takes 200 ms to wind down. A probe at 150 ms is mid-wind-down.
    let stop = tokio::time::sleep(Duration::from_millis(50));
    let probe = tokio::spawn({
        let actuator = app.actuator.clone();
        let seen = ready_during.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            *seen.lock().unwrap() =
                actuator.answer("/actuator/health/readiness", "", "http://h").map(|answer| answer.status);
        }
    });
    app.serve_until(service, Duration::from_secs(5), stop).await.unwrap();
    probe.await.unwrap();
    assert!(finished.load(Ordering::SeqCst), "the service was waited for, not cut off");
    assert_eq!(*ready_during.lock().unwrap(), Some(503), "while it wound down, readiness said out of service");
}

#[tokio::test]
async fn a_service_that_does_not_stop_in_time_is_abandoned_and_the_stop_says_so() {
    let app = app();
    let finished = Arc::new(AtomicBool::new(false));
    let service = Slow { winding_down: Duration::from_secs(30), finished: finished.clone() };
    let failure = app.serve_until(service, Duration::from_millis(200), async {}).await.unwrap_err();
    assert_eq!(failure, "The service did not stop within 0 s; it was abandoned.");
    assert!(!finished.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_service_that_ends_by_itself_ends_the_run_with_its_own_result() {
    struct Done(Result<(), String>);
    impl Service for Done {
        async fn serve(self, _shutdown: ShutdownSignal) -> Result<(), String> {
            self.0
        }
    }
    assert_eq!(app().serve_until(Done(Ok(())), Duration::from_secs(1), std::future::pending()).await, Ok(()));
    assert_eq!(
        app().serve_until(Done(Err("it broke".to_owned())), Duration::from_secs(1), std::future::pending()).await,
        Err("it broke".to_owned())
    );
}
