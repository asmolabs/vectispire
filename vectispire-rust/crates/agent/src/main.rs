//! The remote agent — the Rust port of `vectispire-agent`, **in progress and not shipped**.
//!
//! Today it announces itself, signs and announces its sealing key, and holds the long poll — which is
//! what the measurements of the port's Phase 0 needed (`README.md`). **It does not run scans yet**: a
//! scan it is handed is reported back as a transient failure, so it returns to the queue for an agent
//! that can. Never point it at a control plane whose scans matter.

mod check;
mod config;

use config::Config;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vectispire_crypto::{ResultSigner, SealingKeyPair};
use vectispire_domain::FailureKind;
use vectispire_protocol::{AgentClient, CredentialsMode, Description, ProtocolError, SealingKeyOutcome};
use vectispire_tls::TlsTrust;

fn main() -> ExitCode {
    logging();
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "the agent's runtime could not start");
            return ExitCode::FAILURE;
        }
    };
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("check") {
        return runtime.block_on(check::run(&arguments[1..]));
    }
    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Plain lines by default, one JSON object per line with `VECTISPIRE_LOG_FORMAT=json`; the level from
/// `VECTISPIRE_LOG_LEVEL` (`info` by default), or `RUST_LOG` for a per-crate filter.
fn logging() {
    let filter = std::env::var("RUST_LOG")
        .ok()
        .or_else(|| std::env::var("VECTISPIRE_LOG_LEVEL").ok())
        .unwrap_or_else(|| "info".to_owned());
    let filter =
        tracing_subscriber::EnvFilter::try_new(filter).unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    if std::env::var("VECTISPIRE_LOG_FORMAT").is_ok_and(|format| format.eq_ignore_ascii_case("json")) {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// Why the agent stopped for good.
#[derive(Debug, thiserror::Error)]
enum Fatal {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Trust(#[from] vectispire_tls::TrustError),
    #[error("{0}")]
    SigningKey(String),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

async fn run() -> Result<(), Fatal> {
    let config = Config::from_environment()?;
    let trust = TlsTrust::from_environment()?;
    if !config.url.starts_with("https://") {
        // Warned and not refused, as on the Java agent: a deployment behind a reverse proxy
        // legitimately sees HTTP, and a delegated credential only ever travels sealed.
        tracing::warn!("Unencrypted link to {}: the API key and the results travel in the clear.", config.url);
    }
    let signer = match &config.signing_key {
        None => {
            tracing::info!(
                "No result-signing key configured — results are accepted on this agent's API key alone. Pin one from the \
                 agents administration screen to change that."
            );
            None
        }
        Some(seed) => Some(ResultSigner::from_base64_seed(seed.expose()).map_err(|_| {
            Fatal::SigningKey(
                "VECTISPIRE_AGENT_SIGNING_KEY is not 32 bytes of base64. Leave it blank for an agent whose results are not \
                 attested."
                    .to_owned(),
            )
        })?),
    };
    // Regenerated on every start, never written: a restarted agent is a new recipient, and there is
    // nothing to recover from the disk of a compromised scanning machine.
    let sealing = SealingKeyPair::generate();
    let generation = SystemTime::now().duration_since(UNIX_EPOCH).map_or(1, |elapsed| elapsed.as_millis() as i64);
    let client = AgentClient::new(&config.url, config.token.clone(), &trust, signer, sealing, generation)?;

    let description = Description {
        contract_version: vectispire_domain::contract::VERSION,
        hostname: hostname(),
        platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        scanner_engine: "docker".to_owned(),
        sealing_public_key: client.sealing_public_key(),
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
    };
    let identity = announce(&client, &description, config.retry_delay).await?;
    tracing::info!(
        "Agent \"{}\" announced — contract {}, credentials {}.",
        identity.name.as_deref().unwrap_or_default(),
        identity.contract_version.as_deref().unwrap_or_default(),
        identity.credentials_mode.as_deref().unwrap_or_default()
    );
    if CredentialsMode::by_wire_name(identity.credentials_mode.as_deref())
        .is_some_and(CredentialsMode::delivers_credentials)
    {
        log_sealing_outcome(client.announce_sealing_key().await);
    }

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => {
                tracing::info!("Agent stopped.");
                return Ok(());
            }
            claim = client.claim(config.claim_wait) => match claim {
                Ok(claim) => {
                    if let Some(task) = claim.task {
                        tracing::warn!(scan = task.scan_id, "Handed a scan this build cannot run yet; giving it back.");
                        let reason = "This build of the agent (the Rust port, in progress) does not run scans yet.";
                        if let Err(error) = client.report_failure(&task, reason, FailureKind::Transient).await {
                            tracing::warn!("The scan could not be handed back: {error}");
                        }
                    }
                }
                Err(error @ (ProtocolError::Unauthorized(_) | ProtocolError::ContractMismatch(_))) => return Err(error.into()),
                Err(error) => {
                    tracing::warn!("{error}; retrying in {}s.", config.retry_delay.as_secs());
                    tokio::time::sleep(config.retry_delay).await;
                }
            }
        }
    }
}

/// The hello, retried while the control plane cannot be reached — never while it refuses.
async fn announce(
    client: &AgentClient,
    description: &Description,
    retry: Duration,
) -> Result<vectispire_protocol::Identity, Fatal> {
    loop {
        match client.hello(description).await {
            Ok(identity) => return Ok(identity),
            Err(ProtocolError::Unreachable(cause)) => {
                tracing::warn!("The control plane is unreachable: {cause}; retrying in {}s.", retry.as_secs());
                tokio::time::sleep(retry).await;
            }
            Err(refused) => return Err(refused.into()),
        }
    }
}

/// The Java agent's sentence for each outcome: the one place an operator learns why delegated
/// credentials are withheld.
fn log_sealing_outcome(outcome: Result<SealingKeyOutcome, ProtocolError>) {
    match outcome {
        Ok(SealingKeyOutcome::Accepted) => {
            tracing::info!(
                "Sealing key verified by the control plane: delegated credentials are sealed for this process alone."
            )
        }
        Ok(SealingKeyOutcome::NotSupported) => tracing::info!(
            "The control plane predates signed sealing keys; it seals for the key in the hello. Upgrade it to take a \
             TLS-terminating proxy out of the trust boundary."
        ),
        Ok(SealingKeyOutcome::NotPinned) => tracing::warn!(
            "No signing key is pinned for this agent on the control plane, so it hands this agent no delegated credential. \
             Pin one from the agents administration screen and set its private half as VECTISPIRE_AGENT_SIGNING_KEY."
        ),
        Ok(SealingKeyOutcome::Refused) => tracing::error!(
            "The control plane refused this agent's sealing key: VECTISPIRE_AGENT_SIGNING_KEY is not the key pinned for \
             it. No delegated credential will be handed to it."
        ),
        Ok(SealingKeyOutcome::Stale) => tracing::error!(
            "The control plane holds a newer sealing key than this process made: this host's clock is behind. Correct \
             it, or have an administrator reset this agent's sealing key."
        ),
        Ok(SealingKeyOutcome::Unsignable) => tracing::warn!(
            "This agent receives delegated credentials but has no VECTISPIRE_AGENT_SIGNING_KEY to sign its sealing key \
             with: a current control plane hands it none. Pin a key from the agents administration screen and \
             configure its private half."
        ),
        Err(error) => {
            tracing::warn!(
                "The sealing key could not be announced ({error}); delegated credentials are withheld until it is."
            )
        }
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|name| !name.is_empty())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|name| name.trim().to_owned()))
        .unwrap_or_else(|| "unknown".to_owned())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = terminate.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
