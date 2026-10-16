//! The agent's side of the agent protocol — `AgentProtocol` and `AgentHttp`.
//!
//! **The control plane is the authority on this protocol; this crate follows it.** The routes and
//! bodies are in the published `openapi.json` (the `agent` paths and `ScanArtifacts`), and the
//! contract number is compared for strict equality at hello. A field written in another case or
//! another order of significance is a second protocol, not a second agent.
//!
//! In this crate today: hello, the signed sealing-key announcement, the long-poll claim and the signed
//! failure report — what an agent needs to announce itself and hold a poll. The other routes (rules,
//! plugin manifests, heartbeats, results) are the protocol stream of the port (`README.md`).

mod client;
mod wire;

pub use client::{AgentClient, Claim, ProtocolError, SealingKeyOutcome};
pub use wire::{AssignedTask, CredentialsMode, Description, Identity};
