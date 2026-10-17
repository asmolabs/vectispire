//! Sessions and credentials (Phase 1, task 1.2): who a bearer token, an API key, an agent's key or the SCIM token
//! stands for — `AuthService`'s sessions, `ApiKeyAuthService`, `AgentKeys` and the bearer filter's decisions.
//!
//! [`CredentialService`] implements `cp-http`'s [`Credentials`](vectispire_cp_http::credentials::Credentials), so the
//! chain's bearer layer resolves real principals. What the chain's [`Principal`](vectispire_cp_http::Principal) does
//! not carry — the account's id, the session's hash, an integration key's restriction — is in [`Resolved`], which the
//! routes ask for through [`CredentialService::authenticate_session`] and [`CredentialService::authenticate_key`].
//!
//! **Sessions survive the switch to Rust.** The store holds the SHA-256 of each token, computed alike on both sides,
//! and an API key's hash is the same Argon2id PHC string; `tests/across_the_switch.rs` proves it against the Java
//! control plane on one database, both ways.

pub use crate::internal::credentials::api_keys::{
    DEFAULT_SCOPES, IssueRefusal, KEY_PREFIX, PREFIX_LENGTH, has_scope, normalize_lifetime, normalize_scopes,
    restriction_of, scope_from_wire_name,
};
pub use crate::internal::credentials::sessions::{
    HANDOFF_LIFETIME, SessionPolicy, SessionState, bearer_token, handoff_hash_of, hash_of, is_session_token_shape,
    should_record_activity, state_of,
};
pub use crate::internal::credentials::{
    AccountView, AgentDirectory, AgentRef, Clock, CredentialService, Integration, IssueError, IssuedIntegrationKey,
    IssuedSession, IssuerSees, KeyRequest, KeyView, Resolved, ScimToken, SessionView, StoreError, SystemClock,
    attribution,
};

/// The Argon2id PHC string an API key's — and a password's — stored hash is. `PasswordHasher`.
pub mod phc {
    pub use crate::internal::credentials::phc::{
        ITERATIONS, MEMORY_KIB, PARALLELISM, hash, hash_with, needs_rehash, verify,
    };
}

/// Key minting, for the agents module's declaration of an agent and for tests.
pub mod keys {
    pub use crate::internal::credentials::api_keys::{IssuedKey, generate, lookup_prefix};
    pub use crate::internal::credentials::sessions::IssuedToken;
    pub use crate::internal::credentials::sessions::issue as issue_session_token;
}
