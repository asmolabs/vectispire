//! Persistence for `t_agent`.

pub mod agents;

use vectispire_cp_db::{Db, Mode, Tx};

/// A database failure, kept in this layer: the services see a [`StoreError`].
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[allow(dead_code)]
    #[error("this build holds no statements for {0}")]
    EngineNotCompiled(&'static str),
}

/// What a service sees of a failed statement.
#[derive(Debug, thiserror::Error)]
#[error("the agents' table did not answer: {0}")]
pub struct StoreError(#[source] pub Box<dyn std::error::Error + Send + Sync>);

impl From<DbError> for StoreError {
    fn from(error: DbError) -> StoreError {
        StoreError(Box::new(error))
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> StoreError {
        StoreError(Box::new(DbError::Sql(error)))
    }
}

#[allow(dead_code)]
pub async fn read(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(Mode::ReadOnly).await?)
}

#[allow(dead_code)]
pub async fn write(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(Mode::ReadWrite).await?)
}
