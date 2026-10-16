//! The HTTP calls — `AgentHttp` and `AgentProtocol`.

use crate::wire::{AssignedTask, Description, Identity};
use std::time::Duration;
use uuid::Uuid;
use vectispire_crypto::{ResultSigner, SIGNATURE_HEADER, SealingKeyPair};
use vectispire_domain::FailureKind;
use vectispire_domain::secret::Secret;
use vectispire_tls::TlsTrust;

/// The header the control plane states this agent's current concurrency limit in.
pub const CONCURRENCY_HEADER: &str = "X-Vectispire-Max-Concurrent";

/// A call the control plane refused or could not be reached for — with the Java agent's sentences.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Its fix is a deployment, not a configuration change.
    #[error("{0}")]
    ContractMismatch(String),
    /// The API key — or a report's attestation — was refused.
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Refused(String),
    #[error("The control plane is unreachable: {0}")]
    Unreachable(String),
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
    /// This agent has no signing key to sign with.
    Unsignable,
}

/// A long poll's answer: a scan or none, and the limit stated with it either way.
#[derive(Debug, Clone, PartialEq)]
pub struct Claim {
    pub task: Option<AssignedTask>,
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
    agent_id: std::sync::Mutex<Option<Uuid>>,
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
            .connect_timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| ProtocolError::Unreachable(error.to_string()))?;
        Ok(AgentClient {
            base: url.trim().trim_end_matches('/').to_owned(),
            token,
            http,
            signer,
            sealing,
            generation,
            agent_id: std::sync::Mutex::new(None),
        })
    }

    /// The public half of this process's sealing key, as announced.
    pub fn sealing_public_key(&self) -> String {
        self.sealing.public_key()
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
        let concurrency = response
            .headers()
            .get(CONCURRENCY_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|limit| *limit > 0);
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
        let id = identity.id.as_deref().and_then(|id| Uuid::parse_str(id.trim()).ok());
        *self.agent_id.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = id;
        Ok(identity)
    }

    /// This process's sealing key, signed with the key an administrator pinned for this agent — after
    /// the hello, because the signature covers the agent's id and the hello is where it is learnt.
    pub async fn announce_sealing_key(&self) -> Result<SealingKeyOutcome, ProtocolError> {
        let id = *self.agent_id.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
                SealingKeyOutcome::Accepted
            }
        })
    }

    /// A task, or none after the server's long wait — 204 meaning none.
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
            return Err(ProtocolError::Refused(answer.message_or(
                "A delegated credential was withheld: the control plane holds no verified sealing key for this agent.",
            )));
        }
        Self::refuse_if_failed(&answer, "Claim refused")?;
        let task: AssignedTask = serde_json::from_value(answer.body)
            .map_err(|error| ProtocolError::Refused(format!("Claim unreadable: {error}")))?;
        Ok(Claim { task: Some(task), max_concurrent: answer.concurrency })
    }

    /// Says why a claimed scan produced no result, signed over the exact bytes sent; `true` when the
    /// control plane put it back in the queue.
    pub async fn report_failure(
        &self,
        assigned: &AssignedTask,
        reason: &str,
        kind: FailureKind,
    ) -> Result<bool, ProtocolError> {
        let Some(attempt) = assigned.attempt else {
            return Ok(false);
        };
        let body = serde_json::json!({ "attempt": attempt, "reason": reason, "kind": kind.wire_name() }).to_string();
        let mut headers = Vec::new();
        if let Some(signer) = &self.signer {
            headers.push((SIGNATURE_HEADER, signer.sign_failure(assigned.scan_id, body.as_bytes())));
        }
        let path = format!("/api/v1/agent/jobs/{}/failure", assigned.scan_id);
        let answer = self.call(reqwest::Method::POST, &path, Some(body), Duration::from_secs(30), &headers).await?;
        match answer.status {
            404 | 409 => Ok(false),
            403 => Err(ProtocolError::Unauthorized(answer.message_or(
                "The control plane refused this report's attestation. The key in vectispire.agent.signing-key does not \
                 match the one pinned for this agent.",
            ))),
            _ => {
                Self::refuse_if_unauthorized(&answer)?;
                Self::refuse_if_failed(&answer, "Failure report refused")?;
                Ok(answer.body.get("retried").and_then(serde_json::Value::as_bool).unwrap_or(false))
            }
        }
    }
}
