//! The credential tables — `t_session`, `t_api_key`, and the columns of `t_user` a credential needs to know whether
//! its account may still act. `SessionRepository`, `ApiKeyRepository` and the reads of `UserRepository` the
//! authentication services make, one statement per engine.
//!
//! **Checked at compile time, as `cp-db`'s are.** Every statement is `sqlx::query!` / `query_as!`, described by a
//! real server of its engine and kept in this crate's `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh`, which
//! prepares every crate it lists), so a renamed column or a result read as the wrong type does not build. Each
//! statement starts with its engine's tag: the cache file is named after the SQL text alone.
//!
//! **Each engine's arm is behind its feature** (`mysql-queries`, `postgres-queries`, both on by default): the cache
//! script compiles one engine's statements at a time against that engine, and the other's arm then falls to
//! [`StoreError::not_built`]. Every build that ships has both.

pub(crate) mod accounts;
pub(crate) mod api_keys;
pub(crate) mod sessions;

/// A storage failure, kept opaque: what failed is logged where it is caught, and nothing about it reaches a response.
#[derive(Debug, thiserror::Error)]
#[error("the credential store failed: {0}")]
pub struct StoreError(#[from] sqlx::Error);

impl StoreError {
    /// The database's engine has no statements in this build — only while the cache script prepares the other one.
    #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
    pub(crate) fn not_built() -> StoreError {
        StoreError(sqlx::Error::Configuration("this engine's queries are not built into this binary".into()))
    }
}

/// A UUID stored as `char(36)` that is not one: a row this side did not write.
pub(crate) fn uuid_of(text: &str) -> Result<uuid::Uuid, StoreError> {
    uuid::Uuid::try_parse(text).map_err(|error| StoreError(sqlx::Error::Decode(Box::new(error))))
}
