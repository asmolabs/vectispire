//! The credential tables — `t_session`, `t_api_key`, and the columns of `t_user` a credential needs to know whether
//! its account may still act. `SessionRepository`, `ApiKeyRepository` and the reads of `UserRepository` the
//! authentication services make, one statement per engine.
//!
//! **Runtime-checked, for now.** The fixed queries here are `sqlx::query` on static strings, proved against both
//! engines by `tests/credentials_on_both_engines.rs` rather than by `sqlx::query!` at compile time: the offline cache
//! machinery (`crates/cp-db/scripts/sqlx-prepare.sh`) is written for `cp-db`'s own directory, and generalising it to
//! every module crate is its own change. Each statement is spelt once per engine, as the checked ones are.

pub(crate) mod accounts;
pub(crate) mod api_keys;
pub(crate) mod sessions;

/// A storage failure, kept opaque: what failed is logged where it is caught, and nothing about it reaches a response.
#[derive(Debug, thiserror::Error)]
#[error("the credential store failed: {0}")]
pub struct StoreError(#[from] sqlx::Error);

/// A UUID stored as `char(36)` that is not one: a row this side did not write.
pub(crate) fn uuid_of(text: &str) -> Result<uuid::Uuid, StoreError> {
    uuid::Uuid::try_parse(text).map_err(|error| StoreError(sqlx::Error::Decode(Box::new(error))))
}
