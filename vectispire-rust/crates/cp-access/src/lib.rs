//! The control plane's access module, `core.access` (plan, Phase 1).
//!
//! Task 1.1 — accounts and passwords — is what is here: the account rows and views ([`accounts`]), the rules that
//! keep an administrator from locking everybody out ([`account_rules`]), and Argon2id as `PasswordHasher` writes
//! it ([`passwords`]). Sessions and keys (1.2), MFA and throttles (1.3), single sign-on (1.4), authorization
//! (1.5) and the audit log (1.6) plug into the traits [`accounts`] declares.

#![forbid(unsafe_code)]

pub mod account_rules;
pub mod accounts;
pub mod passwords;

mod persistence;

pub use persistence::{SessionsAndKeys, SqlAccountStore};
