//! The control plane, as far as the port has got: it reads its configuration under the Java names, refuses
//! to start on what the Java one refuses to start on, logs as it does, and stops gracefully. **The HTTP
//! stack and the database are not wired yet** — the service below says so and waits to be stopped.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use vectispire_cp_outbound::guard::OutboundUrlGuard;
use vectispire_cp_outbound::reserved;
use vectispire_cp_runtime::actuator::BuildInfo;
use vectispire_cp_runtime::settings::{ReportLine, Settings};
use vectispire_cp_runtime::shutdown::ShutdownSignal;
use vectispire_cp_runtime::telemetry::{self, LogFormat};
use vectispire_cp_runtime::{App, Service};

const USAGE: &str = "Usage: vectispire-control-plane [--check-config | --version | --help]

  (no argument)   serve — the HTTP stack and the database are not wired yet
  --check-config  read the configuration, refuse what the Java control plane refuses, print every
                  setting and where its value came from (a secret as (set) or (not set)), and exit
  --version       print the version
";

/// Everything a start refuses on, read once — what `OutboundGuardConfiguration` and the property binding
/// refuse on in the Java control plane, before any request is served.
fn start_checks() -> Result<(Settings, Vec<ReportLine>, OutboundUrlGuard), String> {
    let (settings, report) = Settings::from_process().map_err(|error| error.to_string())?;
    let environment = &settings.environment;
    let mut reserved_endpoints = Vec::new();
    for reading in [
        reserved::of_docker_host(environment.docker_host.as_deref()),
        reserved::of_datasource(Some(&settings.datasource.url)),
        reserved::of_kubernetes_service(
            environment.kubernetes_service_host.as_deref(),
            environment.kubernetes_service_port.as_deref(),
        ),
    ] {
        reserved_endpoints.extend(reading.map_err(|error| error.to_string())?);
    }
    Ok((settings, report, OutboundUrlGuard::new(reserved_endpoints)))
}

/// What stands where the HTTP stack will: it serves nothing, and stops when told to.
struct NotWired;

impl Service for NotWired {
    async fn serve(self, mut shutdown: ShutdownSignal) -> Result<(), String> {
        tracing::warn!("The HTTP stack and the database are not wired yet: this process serves nothing");
        shutdown.triggered().await;
        Ok(())
    }
}

/// What the command line says on stdout. A closed pipe (`| head`) is not a failure of the command, so the
/// write's result is dropped on purpose; the print macros are denied workspace-wide (`Cargo.toml`) and a
/// binary that answers a flag is the one place that needs a way to speak.
fn out(text: &str) {
    drop(std::io::stdout().lock().write_all(text.as_bytes()));
}

/// The same on stderr, for what a refused start says before the logs exist.
fn err(text: &str) {
    drop(std::io::stderr().lock().write_all(text.as_bytes()));
}

#[tokio::main]
async fn main() -> ExitCode {
    let argument = std::env::args().nth(1);
    match argument.as_deref() {
        Some("--version") => {
            out(&format!("vectispire-control-plane {}\n", env!("CARGO_PKG_VERSION")));
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            out(USAGE);
            ExitCode::SUCCESS
        }
        Some("--check-config") => match start_checks() {
            Ok((_, report, _)) => {
                for line in report {
                    out(&format!("{} = {}  [{}]\n", line.key, line.shown, line.origin));
                }
                ExitCode::SUCCESS
            }
            Err(problem) => {
                err(&format!("{problem}\n"));
                ExitCode::FAILURE
            }
        },
        None => serve().await,
        Some(other) => {
            err(&format!("Unknown argument {other:?}\n\n{USAGE}\n"));
            ExitCode::from(2)
        }
    }
}

async fn serve() -> ExitCode {
    let format = match LogFormat::from_variable(std::env::var("VECTISPIRE_LOG_FORMAT").ok().as_deref()) {
        Ok(format) => format,
        Err(problem) => {
            err(&format!("{problem}\n"));
            return ExitCode::FAILURE;
        }
    };
    if let Err(problem) = telemetry::init(format, "vectispire") {
        err(&format!("The logs could not be set up: {problem}\n"));
        return ExitCode::FAILURE;
    }
    let (settings, _, _guard) = match start_checks() {
        Ok(checked) => checked,
        Err(problem) => {
            tracing::error!("{problem}");
            return ExitCode::FAILURE;
        }
    };
    let build = BuildInfo {
        group: "vectispire".to_owned(),
        artifact: "vectispire-core".to_owned(),
        name: "vectispire-core".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        time: None,
    };
    let app = App::new(settings, "vectispire", build);
    tracing::info!("Started vectispire {} on port {}", env!("CARGO_PKG_VERSION"), app.settings.server_port);
    match app.serve(NotWired).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => {
            tracing::error!("{problem}");
            ExitCode::FAILURE
        }
    }
}
