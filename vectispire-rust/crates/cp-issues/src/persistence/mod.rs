//! Persistence layer for the issues crate.

pub mod checked;
pub mod entities;
pub mod filters;
pub mod repository;

pub use filters::{IssueFilters, Lifetime};
pub use repository::*;

// The repository on both engines (persistence/suite.rs): in the crate, so that it reaches `persistence` without
// opening it, and needs Docker as every engine suite does.
#[cfg(test)]
mod suite;

/// A read-only transaction on `db`. The services take theirs here so that the driver's error is converted where
/// the driver is allowed to be named.
pub async fn read(db: &vectispire_cp_db::Db) -> Result<vectispire_cp_db::Tx, StoreError> {
    Ok(db.begin(vectispire_cp_db::Mode::ReadOnly).await?)
}

/// A read-write transaction on `db`.
pub async fn write(db: &vectispire_cp_db::Db) -> Result<vectispire_cp_db::Tx, StoreError> {
    Ok(db.begin(vectispire_cp_db::Mode::ReadWrite).await?)
}

/// Commits `tx`.
pub async fn commit(tx: vectispire_cp_db::Tx) -> Result<(), StoreError> {
    Ok(tx.commit().await?)
}
