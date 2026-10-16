//! `vectispire-agent check …` — what an operator runs on a new agent host before trusting it with
//! scans: whether the Docker daemon (or the socket proxy) answers, and whether a repository clones
//! from this machine with the credential it will be given.
//!
//! - `check docker` — the daemon `DOCKER_HOST` names answers.
//! - `check clone <url> [branch]` — a clone into `VECTISPIRE_WORK_DIR`, removed after; the key from
//!   `VECTISPIRE_CHECK_SSH_KEY_FILE`, the token from `VECTISPIRE_CHECK_HTTPS_TOKEN_FILE` (files, so
//!   that neither lands in a shell history), host keys recorded in `$VECTISPIRE_WORK_DIR/known_hosts`.
//!
//! The same code as a scan runs, so a check that passes is a clone that will pass.

use std::process::ExitCode;
use std::time::Duration;
use vectispire_container::{ContainerRunner, ScannerLimits};
use vectispire_domain::secret::Secret;
use vectispire_git::{CloneRequest, HostKeyPolicy, HttpsCredential, WithoutKey};
use vectispire_tls::TlsTrust;

pub async fn run(arguments: &[String]) -> ExitCode {
    let outcome = match arguments.first().map(String::as_str) {
        Some("docker") => docker().await,
        Some("clone") if arguments.len() >= 2 => {
            clone(&arguments[1], arguments.get(2).map_or("main", String::as_str)).await
        }
        _ => Err("usage: vectispire-agent check docker | check clone <url> [branch]".to_owned()),
    };
    match outcome {
        Ok(said) => {
            tracing::info!("{said}");
            ExitCode::SUCCESS
        }
        Err(refused) => {
            tracing::error!("{refused}");
            ExitCode::FAILURE
        }
    }
}

async fn docker() -> Result<String, String> {
    let runner =
        ContainerRunner::connect(None, ScannerLimits::default_for_this_host()).map_err(|error| error.to_string())?;
    if runner.is_available().await {
        Ok("The Docker daemon answers.".to_owned())
    } else {
        Err("The Docker daemon does not answer at DOCKER_HOST (or the local socket).".to_owned())
    }
}

async fn clone(url: &str, branch: &str) -> Result<String, String> {
    let work =
        std::env::var_os("VECTISPIRE_WORK_DIR").ok_or("VECTISPIRE_WORK_DIR is required: the clone goes there.")?;
    let work = std::path::PathBuf::from(work);
    let read = |variable: &str| -> Result<Option<Secret>, String> {
        match std::env::var_os(variable) {
            None => Ok(None),
            Some(path) => std::fs::read_to_string(&path)
                .map(|text| Some(Secret::new(text.trim_end_matches('\n').to_owned() + "\n")))
                .map_err(|error| format!("{variable}: {error}")),
        }
    };
    let key = read("VECTISPIRE_CHECK_SSH_KEY_FILE")?;
    let token = read("VECTISPIRE_CHECK_HTTPS_TOKEN_FILE")?;
    let host = vectispire_domain::repository_url::host(url).unwrap_or_default().to_lowercase();
    let into = work.join(format!("check-{}", std::process::id()));
    let request = CloneRequest {
        url: url.to_owned(),
        branch: branch.to_owned(),
        into: into.clone(),
        private_key: key,
        timeout: Duration::from_secs(300),
        host_keys: HostKeyPolicy::AcceptNew(work.join("known_hosts")),
        without_key: WithoutKey::None,
        https: token.map(|token| HttpsCredential { host, username: None, token: Secret::new(token.expose().trim()) }),
        trust: TlsTrust::from_environment().map_err(|error| error.to_string())?,
    };
    let outcome = tokio::task::spawn_blocking(move || vectispire_git::clone(&request))
        .await
        .map_err(|error| error.to_string())?;
    let _ = std::fs::remove_dir_all(&into);
    outcome.map(|()| format!("{} cloned: branch {branch}.", vectispire_domain::repository_url::redact(url))).map_err(
        |error| {
            // The transport's own text beside the sentence: what an operator asks for first, and the
            // only way to see what a forge answered. Credentials are masked in both.
            let detail = if error.detail.is_empty() { String::new() } else { format!(" [{}]", error.detail) };
            format!("{} ({}, {}){detail}", error.message, error.kind.wire_name(), error.kind.failure_kind().wire_name())
        },
    )
}
