//! The bodies, as the control plane writes and reads them.

use serde::{Deserialize, Serialize};

/// What the agent says about itself at hello — `HelloRequest`, in its snake case.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Description {
    pub contract_version: &'static str,
    pub hostname: String,
    pub platform: String,
    pub scanner_engine: String,
    /// Unsigned, for a control plane older than decision 0031; a current one believes only the
    /// signed announcement that follows the hello.
    pub sealing_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// What the control plane answers at hello — `HelloResponse`, in its camel case.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub id: Option<String>,
    pub name: Option<String>,
    pub contract_version: Option<String>,
    #[serde(default)]
    pub max_concurrent: i32,
    pub credentials_mode: Option<String>,
}

/// How the agent's clones are credentialed — `CredentialsMode`, by its lower-case wire name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialsMode {
    /// The agent's own git access. The default and the recommendation.
    Local,
    /// The control plane seals each repository's key or token to this process.
    Delegated,
}

impl CredentialsMode {
    pub fn by_wire_name(value: Option<&str>) -> Option<CredentialsMode> {
        match value? {
            "local" => Some(CredentialsMode::Local),
            "delegated" => Some(CredentialsMode::Delegated),
            _ => None,
        }
    }

    /// Whether a key may be decrypted for this agent at all.
    pub fn delivers_credentials(self) -> bool {
        self == CredentialsMode::Delegated
    }
}

/// A claimed scan — `AssignedTask`. The task itself stays JSON here until the protocol stream types it
/// from `openapi.json`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AssignedTask {
    pub scan_id: i64,
    pub attempt: Option<i32>,
    pub task: serde_json::Value,
}
