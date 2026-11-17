//! The module's tables on either engine — `ChecklistTemplateRepository`, `ChecklistTemplateVersionRepository`,
//! `ChecklistItemRepository`, `ChecklistRepository`, `ChecklistAnswerRepository`, `ChecklistEvidenceRepository`,
//! `ChecklistFileRepository`, `ChecklistMeasurementRepository`, `ChecklistDocumentRepository` and
//! `ChecklistContactRepository` — as checked statements, one per engine, kept in `.sqlx/` by
//! `crates/cp-db/scripts/sqlx-prepare.sh`.
//!
//! **Every statement runs on a transaction** (`&mut Tx`): the services open a read-only one for a read and a
//! read-write one for a write, which is the grain Spring's `TransactionTemplate` and the repositories' own
//! `@Transactional` gave the Java side. A reading of several tables inside one read-only transaction sees one
//! snapshot, which a read outside any transaction on the Java side did not always — never less consistent.
//!
//! **The tables were written with no foreign key** (decision 0027: a key would be written three times), so nothing
//! follows a deleted project into them: [`purge_project`] deletes its rows, children first.

use time::OffsetDateTime;
use vectispire_cp_db::Tx;
use vectispire_cp_db::types::UtcInstant;

mod checklists;
mod contacts;
mod templates;

pub(crate) use checklists::*;
pub(crate) use contacts::*;
pub(crate) use templates::*;

/// A statement the database refused or could not answer, or a row that does not read back.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the database did not answer: {0}")]
    Database(#[from] sqlx::Error),
    /// An identity the engine handed back that no `i64` holds — never seen, refused rather than wrapped.
    #[error("the database handed back an identifier out of range: {0}")]
    Identifier(u64),
    /// This build carries no statement for the engine in hand. Only the cache script builds one engine's statements
    /// alone; an error, never a panic and never an empty answer, should such a build ever be run.
    #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
    #[error("this build carries no statement for this engine")]
    EngineNotBuilt,
}

/// One statement per engine on the caller's transaction: `$tx` is bound to the engine's `Transaction` in each arm.
macro_rules! engines {
    ($tx:expr, |$m:ident| $mysql:expr, |$p:ident| $postgres:expr $(,)?) => {
        match $tx {
            #[cfg(feature = "mysql-queries")]
            vectispire_cp_db::Tx::MySql($m) => $mysql,
            #[cfg(feature = "postgres-queries")]
            vectispire_cp_db::Tx::PostgreSql($p) => $postgres,
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            #[allow(unreachable_patterns)]
            _ => Err($crate::persistence::StoreError::EngineNotBuilt),
        }
    };
}
pub(crate) use engines;

/// `last_insert_id`, as the `bigint` identity it is.
#[cfg(feature = "mysql-queries")]
pub(crate) fn inserted(done: &sqlx::mysql::MySqlQueryResult) -> Result<i64, StoreError> {
    i64::try_from(done.last_insert_id()).map_err(|_| StoreError::Identifier(done.last_insert_id()))
}

/// `delete … where project_id = ?` in every table that names a project, children first — `ChecklistPurge`, in the
/// transaction that deletes the project. The answers, proofs and measurements are found through their checklists'
/// rows, which must still be there when those statements run; the files and documents by their own column.
pub async fn purge_project(tx: &mut Tx, project_id: i64) -> Result<(), StoreError> {
    delete_answers_of_project(tx, project_id).await?;
    delete_evidence_of_project(tx, project_id).await?;
    delete_measurements_of_project(tx, project_id).await?;
    delete_files_of_project(tx, project_id).await?;
    delete_documents_of_project(tx, project_id).await?;
    // Kept, a link would name an account for a project identifier the engine may hand out again.
    delete_contacts_of_project(tx, project_id).await?;
    delete_checklists_of_project(tx, project_id).await?;
    Ok(())
}

/// An instant as a column stores it — what a row's instants are, for the services that read them.
pub(crate) use vectispire_cp_db::types::UtcInstant as StoredInstant;

/// A transaction of its own: read-only for a read, read-write for a write.
pub(crate) async fn begin(db: &vectispire_cp_db::Db, writes: bool) -> Result<Tx, StoreError> {
    let mode = if writes { vectispire_cp_db::Mode::ReadWrite } else { vectispire_cp_db::Mode::ReadOnly };
    Ok(db.begin(mode).await?)
}

pub(crate) async fn commit(tx: Tx) -> Result<(), StoreError> {
    Ok(tx.commit().await?)
}

pub(crate) async fn rollback(tx: Tx) -> Result<(), StoreError> {
    Ok(tx.rollback().await?)
}

/// An instant a column stores.
pub(crate) fn at(instant: OffsetDateTime) -> UtcInstant {
    UtcInstant(instant)
}
