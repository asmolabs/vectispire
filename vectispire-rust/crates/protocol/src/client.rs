//! The HTTP calls — `AgentHttp` and `AgentProtocol`.
//!
//! **Every route of the agent protocol, and nothing else.** No database access, and that is a
//! security property rather than a detail: an agent with a connection would also need the encryption
//! key, the means to decrypt every deployment key Vectispire holds (decision 0003). It knows the
//! control plane only through these calls, authenticated by an API key bearing the `agent` scope, and
//! it opens no port.

use crate::artifacts::ScanArtifacts;
use crate::concurrency;
use crate::wire::{AssignedTask, Description, Identity, PluginRef, StoredFile, Target};
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;
use uuid::Uuid;
use vectispire_crypto::{ResultSigner, SIGNATURE_HEADER, SealContext, SealingKeyPair};
use vectispire_domain::FailureKind;
use vectispire_domain::failure::Classified;
use vectispire_domain::secret::Secret;
use vectispire_tls::TlsTrust;

/// The header the control plane states this agent's current concurrency limit in.
pub const CONCURRENCY_HEADER: &str = concurrency::HEADER;

/// A call the control plane refused or could not be reached for — with the Java agent's sentences.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Its fix is a deployment, not a configuration change.
    #[error("{0}")]
    ContractMismatch(String),
    /// The API key — or a report's attestation — was refused. Not a retry's to fix.
    #[error("{0}")]
    Unauthorized(String),
    /// A claimed scan whose task cannot be used — a sealed credential that will not open, a clear one
    /// where a sealed one was due. The scan is this agent's all the same, so it is the caller's to
    /// report, as received.
    #[error("{message}")]
    UnusableTask { assigned: Box<AssignedTask>, message: String },
    #[error("{0}")]
    Refused(String),
    #[error("The control plane is unreachable: {0}")]
    Unreachable(String),
}

impl ProtocolError {
    /// Whether looping cannot fix it: a refused key, a contract gap.
    pub fn is_fatal(&self) -> bool {
        matches!(self, ProtocolError::Unauthorized(_) | ProtocolError::ContractMismatch(_))
    }
}

impl Classified for ProtocolError {
    /// **Permanent for an unusable task**: the credential this agent was handed will not open for it,
    /// and taking the scan again would hand it the same one (the owner's decision of 2026-09-28).
    fn failure_kind(&self) -> FailureKind {
        match self {
            ProtocolError::UnusableTask { .. } => FailureKind::Permanent,
            _ => FailureKind::Transient,
        }
    }
}

/// What became of the sealing-key announcement — `SealingKeyOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealingKeyOutcome {
    Accepted,
    /// An older control plane, with no such route: it seals for the key in the hello.
    NotSupported,
    /// No signing key is pinned for this agent: it hands this agent no delegated credential.
    NotPinned,
    /// The signature does not verify against the pinned key.
    Refused,
    /// The control plane holds a newer generation: this host's clock is behind.
    Stale,
    /// This agent has no signing key to sign with, or no hello answered yet.
    Unsignable,
}

/// What became of a report that a claimed scan could not run — `FailureReported`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReported {
    /// Recorded: the scan is back in the queue, with the attempt counted.
    Retried,
    /// Recorded: the scan failed for good — permanent, or its last attempt.
    Failed,
    /// Not this agent's at that attempt any more (409): the lease lapsed first, or it was reported.
    NotYours,
    /// The control plane predates the report (404, or no attempt on the claim): the lease will lapse.
    NotSupported,
}

/// A long poll's answer: a scan or none, and the limit stated with it either way.
#[derive(Debug, Clone)]
pub struct Claim {
    pub task: Option<AssignedTask>,
    /// `None` when the control plane sent none — an older one, which never applied a limit either.
    pub max_concurrent: Option<u32>,
}

/// The agent's client of its control plane.
#[derive(Debug)]
pub struct AgentClient {
    base: String,
    token: Secret,
    http: reqwest::Client,
    signer: Option<ResultSigner>,
    sealing: SealingKeyPair,
    /// When the sealing pair was made, in epoch milliseconds: the control plane keeps the newest.
    generation: i64,
    agent_id: Mutex<Option<Uuid>>,
    /// The last announcement's outcome; a withheld credential announces again only after an
    /// acceptance — a refused key announced on every claim would fill the audit log.
    sealing_outcome: Mutex<SealingKeyOutcome>,
    /// Keyed by hash, therefore never to invalidate: a hash names a content, never a state.
    rule_sets: Mutex<HashMap<String, Vec<StoredFile>>>,
    /// Keyed by id and digest, for the same reason; only a manifest whose digest is the one asked for
    /// is kept, so a bad answer is not cached.
    plugins: Mutex<HashMap<PluginRef, serde_json::Value>>,
}

struct Answer {
    status: u16,
    body: serde_json::Value,
    concurrency: Option<u32>,
}

impl Answer {
    /// The problem document's `detail`, a plain `message`, or `fallback` — `messageOr`.
    fn message_or(&self, fallback: &str) -> String {
        for field in ["detail", "message"] {
            if let Some(text) = self.body.get(field).and_then(serde_json::Value::as_str).filter(|text| !text.is_empty())
            {
                return text.to_owned();
            }
        }
        fallback.to_owned()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One path segment, percent-encoded. The Java agent concatenates the hash and the plugin's id and
/// digest as they come; here a `/` or a `..` in one of them cannot reach another route.
fn segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    if encoded == "." || encoded == ".." { encoded.replace('.', "%2E") } else { encoded }
}

const ATTESTATION_REFUSED: &str = "The control plane refused this result's attestation. The key in \
     vectispire.agent.signing-key does not match the one pinned for this agent.";
const REPORT_ATTESTATION_REFUSED: &str = "The control plane refused this report's attestation. The key in \
     vectispire.agent.signing-key does not match the one pinned for this agent.";

impl AgentClient {
    /// A client of the control plane at `url` (trailing slashes ignored), with the agent's API key.
    pub fn new(
        url: &str,
        token: Secret,
        trust: &TlsTrust,
        signer: Option<ResultSigner>,
        sealing: SealingKeyPair,
        generation: i64,
    ) -> Result<AgentClient, ProtocolError> {
        let http = trust
            .client()
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(|error| ProtocolError::Unreachable(error.to_string()))?;
        Ok(AgentClient {
            base: url.trim().trim_end_matches('/').to_owned(),
            token,
            http,
            signer,
            sealing,
            generation,
            agent_id: Mutex::new(None),
            sealing_outcome: Mutex::new(SealingKeyOutcome::Unsignable),
            rule_sets: Mutex::new(HashMap::new()),
            plugins: Mutex::new(HashMap::new()),
        })
    }

    /// The public half of this process's sealing key, as announced.
    pub fn sealing_public_key(&self) -> String {
        self.sealing.public_key()
    }

    /// The secrets this client holds — what a failure reason is scrubbed of, beside the task's own.
    pub fn api_key(&self) -> &Secret {
        &self.token
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<String>,
        timeout: Duration,
        headers: &[(&str, String)],
    ) -> Result<Answer, ProtocolError> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .timeout(timeout)
            .bearer_auth(self.token.expose())
            .header(reqwest::header::ACCEPT, "application/json");
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        if let Some(body) = body {
            request = request.header(reqwest::header::CONTENT_TYPE, "application/json").body(body);
        }
        let response =
            request.send().await.map_err(|error| ProtocolError::Unreachable(error.without_url().to_string()))?;
        let status = response.status().as_u16();
        let concurrency =
            concurrency::parse(response.headers().get(CONCURRENCY_HEADER).and_then(|value| value.to_str().ok()));
        let text =
            response.text().await.map_err(|error| ProtocolError::Unreachable(error.without_url().to_string()))?;
        let body = if text.trim().is_empty() {
            serde_json::Value::Null
        } else {
            // An unreadable answer is information — a proxy's HTML page, say: its first 500 chars.
            serde_json::from_str(&text)
                .unwrap_or_else(|_| serde_json::json!({ "message": text.chars().take(500).collect::<String>() }))
        };
        Ok(Answer { status, body, concurrency })
    }

    fn refuse_if_unauthorized(answer: &Answer) -> Result<(), ProtocolError> {
        if answer.status == 401 || answer.status == 403 {
            return Err(ProtocolError::Unauthorized(answer.message_or("API key refused.")));
        }
        Ok(())
    }

    fn refuse_if_failed(answer: &Answer, what: &str) -> Result<(), ProtocolError> {
        if answer.status >= 400 {
            return Err(ProtocolError::Refused(answer.message_or(&format!("{what} (HTTP {}).", answer.status))));
        }
        Ok(())
    }

    /// The announcement, and an operator's first diagnostic: if it answers, the URL, the key, the
    /// scope and the agent's row are all right.
    pub async fn hello(&self, description: &Description) -> Result<Identity, ProtocolError> {
        let body = serde_json::to_string(description).map_err(|error| ProtocolError::Refused(error.to_string()))?;
        let answer =
            self.call(reqwest::Method::POST, "/api/v1/agent/hello", Some(body), Duration::from_secs(30), &[]).await?;
        if answer.status == 409 {
            return Err(ProtocolError::ContractMismatch(answer.message_or("Incompatible contract.")));
        }
        Self::refuse_if_unauthorized(&answer)?;
        Self::refuse_if_failed(&answer, "Announcement refused")?;
        let identity: Identity = serde_json::from_value(answer.body)
            .map_err(|error| ProtocolError::Refused(format!("Announcement unreadable: {error}")))?;
        // Unreadable is none: an agent that cannot sign its key still runs what needs no credential.
        *lock(&self.agent_id) = identity.id.as_deref().and_then(|id| Uuid::parse_str(id.trim()).ok());
        Ok(identity)
    }

    /// This process's sealing key, signed with the key an administrator pinned for this agent — after
    /// the hello, because the signature covers the agent's id and the hello is where it is learnt.
    ///
    /// Never an error for an answer the control plane gives on purpose: every outcome leaves the agent
    /// running, and the caller logs what the operator has to do.
    pub async fn announce_sealing_key(&self) -> Result<SealingKeyOutcome, ProtocolError> {
        let outcome = self.announce().await;
        if let Ok(outcome) = outcome {
            *lock(&self.sealing_outcome) = outcome;
        }
        outcome
    }

    async fn announce(&self) -> Result<SealingKeyOutcome, ProtocolError> {
        let id = *lock(&self.agent_id);
        let (Some(signer), Some(id)) = (&self.signer, id) else {
            return Ok(SealingKeyOutcome::Unsignable);
        };
        let public_key = self.sealing.public_key();
        let Ok(signature) = signer.sign_sealing_key(id, self.generation, &public_key) else {
            return Ok(SealingKeyOutcome::Unsignable);
        };
        let body =
            serde_json::json!({ "public_key": public_key, "generation": self.generation, "signature": signature });
        let answer = self
            .call(
                reqwest::Method::POST,
                "/api/v1/agent/sealing-key",
                Some(body.to_string()),
                Duration::from_secs(30),
                &[],
            )
            .await?;
        Ok(match answer.status {
            200 | 204 => SealingKeyOutcome::Accepted,
            404 => SealingKeyOutcome::NotSupported,
            412 => SealingKeyOutcome::NotPinned,
            403 => SealingKeyOutcome::Refused,
            409 => SealingKeyOutcome::Stale,
            401 => {
                return Err(ProtocolError::Unauthorized(answer.message_or("API key refused.")));
            }
            _ => {
                Self::refuse_if_failed(&answer, "Sealing key announcement refused")?;
                // A 2xx this protocol does not use: taken as accepted, like the 204 it stands for.
                SealingKeyOutcome::Accepted
            }
        })
    }

    /// A task, or none after the server's long wait — 204 meaning none — and the limit the answer
    /// states either way.
    pub async fn claim(&self, wait: Duration) -> Result<Claim, ProtocolError> {
        let path = format!("/api/v1/agent/jobs?wait={}", wait.as_secs());
        // Longer than the wait asked for: the server bounds it, and cutting flush would time out every
        // poll just before its answer.
        let answer = self.call(reqwest::Method::GET, &path, None, wait + Duration::from_secs(30), &[]).await?;
        if answer.status == 204 {
            return Ok(Claim { task: None, max_concurrent: answer.concurrency });
        }
        Self::refuse_if_unauthorized(&answer)?;
        if answer.status == 412 {
            // A delegated credential withheld: the control plane holds no sealing key it believes for
            // this agent. After an acceptance it means the key was forgotten since — an administrator's
            // reset, a signing key pinned anew — so the agent announces once more, and the next claim
            // takes the scan, which went back to the queue.
            if *lock(&self.sealing_outcome) == SealingKeyOutcome::Accepted {
                // Left as it was on any other answer, so the next withheld credential tries again; the
                // control plane's own message is the one worth reporting.
                if let Err(refused @ ProtocolError::Unauthorized(_)) = self.announce_sealing_key().await {
                    return Err(refused);
                }
            }
            return Err(ProtocolError::Refused(answer.message_or(
                "A delegated credential was withheld: the control plane holds no verified sealing key for this agent.",
            )));
        }
        Self::refuse_if_failed(&answer, "Claim refused")?;
        let received: AssignedTask = serde_json::from_value(answer.body)
            .map_err(|error| ProtocolError::Refused(format!("Claim unreadable: {error}")))?;
        let task = self.unseal(received)?;
        Ok(Claim { task: Some(task), max_concurrent: answer.concurrency })
    }

    /// Opens a task's credentials, when they arrived sealed — or refuses the task, by name.
    ///
    /// An envelope nobody opens is a string that looks like a key: it would be written to a file,
    /// handed to git, and the failure would look like a repository or a permission problem.
    fn unseal(&self, mut assigned: AssignedTask) -> Result<AssignedTask, ProtocolError> {
        let Target::Repository(repository) = &assigned.task.target else {
            return Ok(assigned);
        };
        let unusable = |message: String| ProtocolError::UnusableTask { assigned: Box::new(assigned.clone()), message };
        let key = match &repository.private_key {
            None => None,
            Some(value) => Some(self.open(value, "deployment key", &SealContext::deployment_key()).map_err(unusable)?),
        };
        // Opened under the host and user name it arrived with, which are the ones the clone binds it
        // to: a proxy that rewrote either gets an envelope that no longer opens, not a token sent to
        // its server.
        let token = match &repository.https {
            Some(https) => match &https.token {
                Some(value) => Some(
                    self.open(
                        value,
                        "HTTPS token",
                        &SealContext::https_token(https.host.as_deref(), https.username.as_deref()),
                    )
                    .map_err(unusable)?,
                ),
                None => None,
            },
            None => None,
        };
        if let Target::Repository(repository) = &mut assigned.task.target {
            repository.private_key = key;
            if let Some(https) = &mut repository.https {
                https.token = token;
            }
        }
        Ok(assigned)
    }

    /// One credential of a task, opened if it arrived sealed — `AgentProtocol.open`.
    ///
    /// **A clear credential after announcing a sealing key is a downgrade, not a choice**: the control
    /// plane seals for any agent that announced a key, so a clear one means the announcement did not
    /// arrive — what a TLS-terminating proxy stripping it from the hello looks like from here. This agent
    /// always announces one.
    fn open(&self, value: &Secret, what: &str, context: &SealContext) -> Result<Secret, String> {
        let text = value.expose();
        if text.trim().is_empty() {
            return Ok(value.clone());
        }
        if text.starts_with("sealed:v1:") {
            return Err(format!(
                "A {what} arrived sealed in the format of a control plane older than this agent, which does not bind \
                 it to its destination. Refusing it: update the control plane."
            ));
        }
        if !text.starts_with(vectispire_crypto::SEALED_PREFIX) {
            return Err(format!(
                "A {what} arrived unsealed although this agent announced a sealing key: the announcement was removed \
                 on the way. Refusing it rather than using it."
            ));
        }
        self.sealing.open(text, context).map(Secret::new).ok_or_else(|| {
            format!(
                "The sealed {what} could not be opened: it is not addressed to this process, or it or what it is \
                 bound to was altered on the way."
            )
        })
    }

    /// A Semgrep rule set's content, cached by hash for the life of the process.
    ///
    /// No fallback to the bundled rules on a refusal: the caller places this inside the SAST step,
    /// whose failure leaves the artifact absent. Scanning with fewer rules would hand back a shorter
    /// list, which reads as "analysed, those issues are gone".
    pub async fn rule_set(&self, hash: &str) -> Result<Vec<StoredFile>, ProtocolError> {
        if let Some(files) = lock(&self.rule_sets).get(hash) {
            return Ok(files.clone());
        }
        let path = format!("/api/v1/agent/rules/{}", segment(hash));
        let answer = self.call(reqwest::Method::GET, &path, None, Duration::from_secs(120), &[]).await?;
        Self::refuse_if_failed(&answer, &format!("Rule set {hash} refused"))?;
        let files: Vec<StoredFile> =
            serde_json::from_value(answer.body.get("files").cloned().unwrap_or(serde_json::Value::Null))
                .map_err(|error| ProtocolError::Refused(format!("Rule set {hash} unreadable: {error}")))?;
        lock(&self.rule_sets).insert(hash.to_owned(), files.clone());
        Ok(files)
    }

    /// A plugin's manifest, by the id and digest the task named, as the control plane wrote it.
    ///
    /// `digest_of` computes a manifest's digest — the plugins stream's, which owns the manifest's
    /// meaning. Only a manifest that hashes to the digest asked for is cached; one that does not is
    /// returned all the same, for the runner to refuse with its own reason. A refusal (a 404 among them)
    /// leaves the plugin absent, never replaced by something else.
    pub async fn plugin(
        &self,
        reference: &PluginRef,
        digest_of: impl Fn(&serde_json::Value) -> Option<String>,
    ) -> Result<serde_json::Value, ProtocolError> {
        if let Some(manifest) = lock(&self.plugins).get(reference) {
            return Ok(manifest.clone());
        }
        let path = format!("/api/v1/agent/plugins/{}/{}", segment(&reference.id), segment(&reference.digest));
        let answer = self.call(reqwest::Method::GET, &path, None, Duration::from_secs(30), &[]).await?;
        Self::refuse_if_failed(&answer, &format!("Plugin {} refused", reference.id))?;
        let manifest = answer.body;
        if digest_of(&manifest).as_deref() == Some(reference.digest.as_str()) {
            lock(&self.plugins).insert(reference.clone(), manifest.clone());
        }
        Ok(manifest)
    }

    /// The sign of life of an agent still working: `false` when the lease was taken over, and the agent
    /// must then give up, or its result would overwrite its successor's.
    pub async fn heartbeat(&self, scan_id: i64) -> Result<bool, ProtocolError> {
        let path = format!("/api/v1/agent/jobs/{scan_id}/heartbeat");
        let answer = self.call(reqwest::Method::POST, &path, None, Duration::from_secs(15), &[]).await?;
        if answer.status == 409 {
            return Ok(false);
        }
        Self::refuse_if_failed(&answer, "Heartbeat refused")?;
        Ok(true)
    }

    /// Hands back the result, **signed over the exact bytes sent**; `false` when the lease was taken
    /// over in the meantime.
    ///
    /// An agent with no signing key sends no signature, and a control plane with no key pinned for it
    /// accepts that — the upgrade path in both directions.
    pub async fn submit(&self, scan_id: i64, artifacts: &ScanArtifacts) -> Result<bool, ProtocolError> {
        let body = artifacts
            .to_body()
            .map_err(|error| ProtocolError::Refused(format!("The result could not be serialized: {error}")))?;
        let mut headers = Vec::new();
        if let Some(signer) = &self.signer {
            headers.push((SIGNATURE_HEADER, signer.sign_result(scan_id, body.as_bytes())));
        }
        let path = format!("/api/v1/agent/jobs/{scan_id}/result");
        // A SBOM weighs several megabytes: the timeout has to cover the upload, not only the answer.
        let answer = self.call(reqwest::Method::POST, &path, Some(body), Duration::from_secs(120), &headers).await?;
        match answer.status {
            // Distinct, because the fix is distinct and neither retrying nor rescanning is it.
            403 => Err(ProtocolError::Unauthorized(answer.message_or(ATTESTATION_REFUSED))),
            409 => Ok(false),
            _ => {
                Self::refuse_if_failed(&answer, "Result refused")?;
                Ok(true)
            }
        }
    }

    /// Says why a claimed scan produced no result, **signed over the exact bytes sent**, under a context
    /// of its own; an outcome, not an error, for every answer about the scan.
    ///
    /// `reason` is already scrubbed ([`crate::failure_reason::scrub`]); `kind` says whether another
    /// attempt could pass, which only this side can tell.
    pub async fn report_failure(
        &self,
        assigned: &AssignedTask,
        reason: &str,
        kind: FailureKind,
    ) -> Result<FailureReported, ProtocolError> {
        let Some(attempt) = assigned.attempt else {
            // A claim without an attempt comes from a control plane without the route.
            return Ok(FailureReported::NotSupported);
        };
        let body = serde_json::json!({ "attempt": attempt, "reason": reason, "kind": kind.wire_name() }).to_string();
        let mut headers = Vec::new();
        if let Some(signer) = &self.signer {
            headers.push((SIGNATURE_HEADER, signer.sign_failure(assigned.scan_id, body.as_bytes())));
        }
        let path = format!("/api/v1/agent/jobs/{}/failure", assigned.scan_id);
        let answer = self.call(reqwest::Method::POST, &path, Some(body), Duration::from_secs(30), &headers).await?;
        match answer.status {
            404 => Ok(FailureReported::NotSupported),
            409 => Ok(FailureReported::NotYours),
            403 => Err(ProtocolError::Unauthorized(answer.message_or(REPORT_ATTESTATION_REFUSED))),
            _ => {
                Self::refuse_if_unauthorized(&answer)?;
                Self::refuse_if_failed(&answer, "Failure report refused")?;
                Ok(if answer.body.get("retried").and_then(serde_json::Value::as_bool).unwrap_or(false) {
                    FailureReported::Retried
                } else {
                    FailureReported::Failed
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_segment_cannot_reach_another_route() {
        assert_eq!(segment("ab12"), "ab12");
        assert_eq!(segment("../x"), "..%2Fx");
        assert_eq!(segment(".."), "%2E%2E");
        assert_eq!(segment("a b?c#d"), "a%20b%3Fc%23d");
    }
}
