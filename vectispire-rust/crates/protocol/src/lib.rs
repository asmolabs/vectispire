//! The agent's side of the agent protocol — `AgentProtocol` and `AgentHttp`.
//!
//! **The control plane is the authority on this protocol; this crate follows it.** The routes and
//! bodies are in the published `openapi.json` (the `agent` paths and `ScanArtifacts`), and the
//! contract number is compared for strict equality at hello. A field written in another case or
//! another order of significance is a second protocol, not a second agent.
//!
//! Every route the agent calls is here: hello, the signed sealing-key announcement, the long-poll
//! claim (with the credentials it carries opened), the rule sets and plugin manifests a task names,
//! heartbeats, the signed result and the signed failure report. What decides *when* to call them —
//! slots, heartbeats, giving up a lost lease, a graceful stop — is the agent's loop
//! (`crates/agent/src/serve.rs`).

mod artifacts;
mod client;
pub mod concurrency;
pub mod failure_reason;
mod wire;

pub use artifacts::{Failure, Findings, PluginStep, Project, Refusal, ScanArtifacts, Signature, java_duration};
pub use client::{AgentClient, CONCURRENCY_HEADER, Claim, FailureReported, ProtocolError, SealingKeyOutcome};
pub use wire::{
    AssignedTask, CredentialsMode, Description, HttpsCredential, Identity, Image, ImageReference, PluginRef,
    Repository, ScanTask, Step, StoredFile, Target,
};
