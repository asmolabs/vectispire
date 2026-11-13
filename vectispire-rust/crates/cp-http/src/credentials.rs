//! What the chain asks of the rest of the control plane, as traits it is handed.
//!
//! **Nothing here reads a table.** A session's hash, an API key's prefix and hash, the SCIM token and the audit log
//! are Phase 1's (`cp-access`, `cp-audit`); this crate decides what the answers *let a request reach*. The doubles at
//! the bottom are what its tests (and Phase 1's route tests) are built on.

use crate::principal::Principal;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use subtle::ConstantTimeEq;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolves a bearer token into the principal it stands for. Each lookup is the Java service's: a session by
/// the SHA-256 of its token, an integration or agent key by prefix and hash, the SCIM token against the configuration.
pub trait Credentials: Send + Sync + std::fmt::Debug {
    /// A session token — `AuthService.resolve`. The session's account must be active; one whose account is gone is
    /// revoked and resolves to nothing.
    fn session<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Principal>>;

    /// An API key, integration or agent — `ApiKeyAuthService.resolve`.
    fn api_key<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Principal>>;

    /// The same lookup, able to say it could not be made: a key is verified as a password is, under the bound on
    /// password derivations, and with no permit free **nothing was compared** — the key was neither accepted nor
    /// refused. Java's bearer filter answers that 503 with `Retry-After`; reading it as no credential would answer 401
    /// to a valid key under load. By default, [`Credentials::api_key`]'s answer, never busy.
    fn api_key_lookup<'a>(&'a self, token: &'a str) -> BoxFuture<'a, KeyLookup> {
        Box::pin(async move {
            match self.api_key(token).await {
                Some(principal) => KeyLookup::Found(principal),
                None => KeyLookup::Absent,
            }
        })
    }

    /// Whether `token` is the SCIM token **and SCIM is switched on**. Compared in constant time
    /// ([`secret_equals`]); a token left in the environment of an installation that switched SCIM off does not match.
    fn scim<'a>(&'a self, token: &'a str) -> BoxFuture<'a, bool>;
}

/// What an API key's lookup came to ([`Credentials::api_key_lookup`]).
#[derive(Debug, Clone)]
pub enum KeyLookup {
    Found(Principal),
    Absent,
    /// No derivation permit came free: the sentence and the wait, in seconds, the 503 says.
    Busy {
        detail: String,
        retry_after_seconds: u64,
    },
}

/// The metrics scrape token in force — `ScrapeTokenProperties.token()`: the file's when one is named, **read at each
/// call** so a rotated secret takes effect without a restart, else the value's. `Ok(None)`: no scraper is configured,
/// and the Prometheus page answers an administrator's session only. `Err`: the file named cannot be read.
pub trait ScrapeToken: Send + Sync + std::fmt::Debug {
    fn token(&self) -> Result<Option<vectispire_domain::secret::Secret>, String>;
}

/// Constant-time equality of two secrets of any length — the comparison for every token, key hash and MAC.
pub fn secret_equals(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// A refusal worth an audit entry. Written by the chain; stored by `cp-audit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessDenied {
    pub path: String,
    pub detail: String,
    pub who: Option<String>,
    pub address: String,
    pub user_agent: Option<String>,
}

/// The audit entries the chain writes itself.
pub trait Audit: Send + Sync + std::fmt::Debug {
    /// `ACCESS_DENIED`: a credential that resolved and may not call the route.
    fn access_denied(&self, entry: AccessDenied);

    /// `ACCESS_DENIED` with the `BEARER_TOKEN_THROTTLED` event: an address spent its allowance of refused tokens.
    fn bearer_throttled(&self, entry: AccessDenied);
}

/// The limit counted across instances in the database (`RateWindows`) — the tracker webhook's second budget.
pub trait SharedWindow: Send + Sync + std::fmt::Debug {
    /// Whether one more hit by `subject` is admitted; if not, how long until it would be.
    fn hit<'a>(
        &'a self,
        subject: &'a str,
        ceiling: u64,
        window: std::time::Duration,
    ) -> BoxFuture<'a, Result<(), std::time::Duration>>;
}

/// Credentials from a fixed table — tests.
#[derive(Debug, Default)]
pub struct StaticCredentials {
    sessions: HashMap<String, Principal>,
    keys: HashMap<String, Principal>,
    scim: Option<String>,
}

impl StaticCredentials {
    pub fn session(mut self, token: &str, principal: Principal) -> Self {
        self.sessions.insert(token.to_owned(), principal);
        self
    }

    pub fn key(mut self, token: &str, principal: Principal) -> Self {
        self.keys.insert(token.to_owned(), principal);
        self
    }

    pub fn scim_token(mut self, token: &str) -> Self {
        self.scim = Some(token.to_owned());
        self
    }
}

impl Credentials for StaticCredentials {
    fn session<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Principal>> {
        Box::pin(async move { self.sessions.get(token).cloned() })
    }

    fn api_key<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Principal>> {
        Box::pin(async move { self.keys.get(token).cloned() })
    }

    fn scim<'a>(&'a self, token: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async move { self.scim.as_deref().is_some_and(|expected| secret_equals(token, expected)) })
    }
}

/// An audit that remembers what it was told — tests.
#[derive(Debug, Default)]
pub struct RecordingAudit {
    pub denied: Mutex<Vec<AccessDenied>>,
    pub throttled: Mutex<Vec<AccessDenied>>,
}

impl Audit for RecordingAudit {
    fn access_denied(&self, entry: AccessDenied) {
        self.denied.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(entry);
    }

    fn bearer_throttled(&self, entry: AccessDenied) {
        self.throttled.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_compare_equal_only_when_they_are_the_same_bytes() {
        assert!(secret_equals("abc", "abc"));
        assert!(!secret_equals("abc", "abd"));
        assert!(!secret_equals("abc", "abcd"));
        assert!(!secret_equals("", "a"));
        assert!(secret_equals("", ""));
    }
}
