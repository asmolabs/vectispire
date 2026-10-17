//! Every statement the module runs — the grants and the approver count. Nothing above this names a query API: a
//! service hands a criterion down and gets rows, or a [`StoreError`], back.
//!
//! Each engine's statements are a feature (`mysql-queries`, `postgres-queries`, both on by default), as in
//! `vectispire-cp-db`: the offline cache is generated one engine at a time, against a server of that engine.

pub(crate) mod accounts;
pub(crate) mod grants;

/// A statement the database refused or could not answer. The driver's error stays inside, as the cause.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the database did not answer: {0}")]
    Database(#[from] sqlx::Error),
    /// This build carries no statement for the engine in hand. Only the cache script builds one engine's statements
    /// alone; an error, never a panic and never an empty answer, should such a build ever be run.
    #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
    #[error("this build carries no statement for this engine")]
    EngineNotBuilt,
}
