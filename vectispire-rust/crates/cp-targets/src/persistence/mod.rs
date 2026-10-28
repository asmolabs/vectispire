//! The six tables `targets` owns — `t_solution`, `t_project`, `t_repository`, `t_container`, `t_git_token`,
//! `t_ssh_key` — and every statement on them: the repositories of `core.targets.persistence`.
//!
//! **Checked statements, `sqlx::query!`, one module per engine**, described by a migrated server of the engine while
//! compiling and kept in this crate's `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh check cp-targets`). Every
//! statement carries its engine's tag, because the cache file is named after the SQL text alone.
//!
//! **A list of identifiers is one parameter on both engines**: `= any($1)` over an array on PostgreSQL, and on MySQL a
//! `json_table` over a JSON array — MySQL has no array parameter, and an `in (?, ?, …)` as long as the list would be
//! a statement nobody can check. Java bound one parameter per identifier, a thousand per statement, because the
//! PostgreSQL driver refuses past 65,535; one parameter has no such ceiling, and the batches are kept anyway so that
//! a statement's size stays what Java's was.
//!
//! **A row is written whole, as Hibernate's `save` writes it** — every column but `project_id`, which the entity maps
//! read-only: a project is filed by its one targeted update, never by a save that would write back a stale value.
//!
//! **Secrets stay ciphertext here.** `t_git_token.token` and `t_ssh_key.private_key` are read and written as the
//! `Encryption` service hands them over; the row types do not print them.

#[cfg(feature = "mysql-queries")]
mod mysql;
#[cfg(feature = "postgres-queries")]
mod postgres;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::{Db, Mode, Tx};

/// How many identifiers one statement carries — Java's `LOOKUP_BATCH` and `PROJECT_BATCH`.
pub const LOOKUP_BATCH: usize = 1_000;

/// A database failure, kept in this layer: the services see a [`StoreError`].
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    /// The engine's statements were compiled out — only the one-engine build of the cache script lacks some.
    #[cfg_attr(all(feature = "mysql-queries", feature = "postgres-queries"), allow(dead_code))]
    #[error("this build holds no statements for {0}")]
    EngineNotCompiled(&'static str),
}

/// What a service sees of a failed statement: that it failed, and whether it was a unique key refusing the row.
#[derive(Debug, thiserror::Error)]
#[error("the targets' tables did not answer: {0}")]
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

macro_rules! on {
    ($target:expr, $enum:ident, |$handle:ident| $mysql:expr, $postgres:expr) => {
        match $target {
            #[cfg(feature = "mysql-queries")]
            $enum::MySql($handle) => $mysql,
            #[cfg(not(feature = "mysql-queries"))]
            $enum::MySql(_) => Err(DbError::EngineNotCompiled("MySQL")),
            #[cfg(feature = "postgres-queries")]
            $enum::PostgreSql($handle) => $postgres,
            #[cfg(not(feature = "postgres-queries"))]
            $enum::PostgreSql(_) => Err(DbError::EngineNotCompiled("PostgreSQL")),
        }
    };
}

/// A row of `t_repository`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RepositoryRow {
    pub id: i64,
    pub url: String,
    pub branch: String,
    pub sub_path: Option<String>,
    pub name: Option<String>,
    pub scan_interval_minutes: Option<i32>,
    pub scan_cron: Option<String>,
    pub scan_manual_only: bool,
    pub required_agent_label: Option<String>,
    pub last_scheduled_scan_at: Option<OffsetDateTime>,
    pub ssh_key_id: Option<Uuid>,
    pub https_token_id: Option<Uuid>,
    /// A bearer capability (`posture`'s badge): carried for the save that must write it back, never shown.
    pub badge_token: Option<String>,
    pub tier: String,
    pub in_certified_scope: bool,
    pub project_id: Option<i64>,
    pub url_identity: Option<String>,
    pub identity_guard: Option<String>,
}

/// A row of `t_container`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ContainerRow {
    pub id: i64,
    pub registry: Option<String>,
    pub image_name: String,
    pub tag: String,
    pub scan_interval_minutes: Option<i32>,
    pub scan_cron: Option<String>,
    pub scan_manual_only: bool,
    pub required_agent_label: Option<String>,
    pub last_scheduled_scan_at: Option<OffsetDateTime>,
    pub tier: String,
    pub in_certified_scope: bool,
    pub project_id: Option<i64>,
}

/// A row of `t_solution`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SolutionRow {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
}

/// A row of `t_project`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProjectRow {
    pub id: i64,
    pub solution_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
}

/// A row of `t_git_token`: `token` is the ciphertext, bound to `id` by its context.
#[derive(Clone, PartialEq, Eq)]
pub struct GitTokenRow {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub username: Option<String>,
    pub token: String,
    pub created_at: OffsetDateTime,
}

impl std::fmt::Debug for GitTokenRow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitTokenRow")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("host", &self.host)
            .field("token", &"<ciphertext>")
            .finish_non_exhaustive()
    }
}

/// A row of `t_ssh_key`: `private_key` is the ciphertext, bound to `id` by its context.
#[derive(Clone, PartialEq, Eq)]
pub struct SshKeyRow {
    pub id: Uuid,
    pub name: String,
    pub private_key: String,
    pub public_key: Option<String>,
    pub created_at: OffsetDateTime,
}

impl std::fmt::Debug for SshKeyRow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshKeyRow")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("private_key", &"<ciphertext>")
            .finish_non_exhaustive()
    }
}

/// A list of identifiers as MySQL's one parameter reads it: a JSON array.
#[cfg_attr(not(feature = "mysql-queries"), allow(dead_code))]
fn json_ids(ids: &[i64]) -> String {
    let joined: Vec<String> = ids.iter().map(i64::to_string).collect();
    format!("[{}]", joined.join(","))
}

/// A list of strings as MySQL's one parameter reads it.
#[cfg_attr(not(feature = "mysql-queries"), allow(dead_code))]
fn json_strings(values: &[String]) -> String {
    serde_json::Value::from(values.to_vec()).to_string()
}

// ── repositories ─────────────────────────────────────────────────────────────────────────

/// Every repository, by identifier.
pub async fn repositories(tx: &mut Tx) -> Result<Vec<RepositoryRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::repositories(t).await, postgres::repositories(t).await)?)
}

pub async fn repository(tx: &mut Tx, id: i64) -> Result<Option<RepositoryRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::repository(t, id).await, postgres::repository(t, id).await)?)
}

/// The repositories with these identifiers that exist, a thousand per statement, by identifier within each.
pub async fn repositories_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<Vec<RepositoryRow>, StoreError> {
    let mut found = Vec::new();
    for chunk in ids.chunks(LOOKUP_BATCH) {
        found.extend(on!(
            &mut *tx,
            Tx,
            |t| mysql::repositories_by_ids(t, &json_ids(chunk)).await,
            postgres::repositories_by_ids(t, chunk).await
        )?);
    }
    Ok(found)
}

pub async fn repositories_of_project(tx: &mut Tx, project_id: i64) -> Result<Vec<RepositoryRow>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::repositories_of_project(t, project_id).await,
        postgres::repositories_of_project(t, project_id).await
    )?)
}

pub async fn repository_by_guard(tx: &mut Tx, guard: &str) -> Result<Option<RepositoryRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::repository_by_guard(t, guard).await, postgres::repository_by_guard(t, guard).await)?)
}

/// `findByIdentityGuardIsNullOrderByIdAsc`.
pub async fn unguarded_repositories(tx: &mut Tx) -> Result<Vec<RepositoryRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::unguarded_repositories(t).await, postgres::unguarded_repositories(t).await)?)
}

pub async fn repository_by_badge(tx: &mut Tx, token: &str) -> Result<Option<RepositoryRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::repository_by_badge(t, token).await, postgres::repository_by_badge(t, token).await)?)
}

/// Inserts every column but `id` and `project_id`; answers the identifier the engine gave.
pub async fn insert_repository(tx: &mut Tx, row: &RepositoryRow) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::insert_repository(t, row).await, postgres::insert_repository(t, row).await)?)
}

/// Writes every column but `id` and `project_id` back — Hibernate's update of a loaded entity.
pub async fn update_repository(tx: &mut Tx, row: &RepositoryRow) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::update_repository(t, row).await, postgres::update_repository(t, row).await)?)
}

pub async fn delete_repository(tx: &mut Tx, id: i64) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::delete_repository(t, id).await, postgres::delete_repository(t, id).await)?)
}

/// `stampScheduled`: a targeted update, never a save of a row read at the top of the tick.
pub async fn stamp_repository(tx: &mut Tx, id: i64, at: OffsetDateTime) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::stamp_repository(t, id, at).await, postgres::stamp_repository(t, id, at).await)?)
}

pub async fn count_by_ssh_key(tx: &mut Tx, key: Uuid) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::count_by_ssh_key(t, key).await, postgres::count_by_ssh_key(t, key).await)?)
}

pub async fn count_by_https_token(tx: &mut Tx, token: Uuid) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::count_by_https_token(t, token).await, postgres::count_by_https_token(t, token).await)?)
}

/// How many repositories use each SSH key that some repository uses.
pub async fn usage_by_ssh_key(tx: &mut Tx) -> Result<Vec<(Uuid, i64)>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::usage_by_ssh_key(t).await, postgres::usage_by_ssh_key(t).await)?)
}

/// How many repositories use each HTTPS token that some repository uses.
pub async fn usage_by_https_token(tx: &mut Tx) -> Result<Vec<(Uuid, i64)>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::usage_by_https_token(t).await, postgres::usage_by_https_token(t).await)?)
}

/// The repositories filed in these projects, a thousand projects per statement.
pub async fn repository_ids_in_projects(tx: &mut Tx, projects: &[i64]) -> Result<Vec<i64>, StoreError> {
    let mut found = Vec::new();
    for chunk in projects.chunks(LOOKUP_BATCH) {
        found.extend(on!(
            &mut *tx,
            Tx,
            |t| mysql::repository_ids_in_projects(t, &json_ids(chunk)).await,
            postgres::repository_ids_in_projects(t, chunk).await
        )?);
    }
    Ok(found)
}

pub async fn repository_ids_of_solution(tx: &mut Tx, solution_id: i64) -> Result<Vec<i64>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::repository_ids_of_solution(t, solution_id).await,
        postgres::repository_ids_of_solution(t, solution_id).await
    )?)
}

/// `assignProject`: the column's one writer.
pub async fn assign_repository(tx: &mut Tx, id: i64, project_id: Option<i64>) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::assign_repository(t, id, project_id).await,
        postgres::assign_repository(t, id, project_id).await
    )?)
}

pub async fn detach_repositories(tx: &mut Tx, project_id: i64) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::detach_repositories(t, project_id).await,
        postgres::detach_repositories(t, project_id).await
    )?)
}

/// `(id, url_identity)` of the repositories filing these identities, a thousand per statement.
pub async fn repositories_by_identity(tx: &mut Tx, identities: &[String]) -> Result<Vec<(i64, String)>, StoreError> {
    let mut found = Vec::new();
    for chunk in identities.chunks(LOOKUP_BATCH) {
        found.extend(on!(
            &mut *tx,
            Tx,
            |t| mysql::repositories_by_identity(t, &json_strings(chunk)).await,
            postgres::repositories_by_identity(t, chunk).await
        )?);
    }
    Ok(found)
}

/// `(id, url)` of the repositories the keying has not reached.
pub async fn unidentified_repositories(tx: &mut Tx) -> Result<Vec<(i64, String)>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::unidentified_repositories(t).await, postgres::unidentified_repositories(t).await)?)
}

/// What the identity keying writes, conditional on the row still naming what was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keying<'a> {
    pub id: i64,
    pub url: &'a str,
    pub branch: &'a str,
    pub sub_path: &'a str,
    pub url_identity: &'a str,
    pub guard: Option<&'a str>,
}

/// `key`: written only while the row holds no guard and still names what was read — two instances keying together
/// write one value, and the second finds nothing to do.
pub async fn key_repository(tx: &mut Tx, keying: &Keying<'_>) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::key_repository(t, keying).await, postgres::key_repository(t, keying).await)?)
}

// ── containers ───────────────────────────────────────────────────────────────────────────

pub async fn containers(tx: &mut Tx) -> Result<Vec<ContainerRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::containers(t).await, postgres::containers(t).await)?)
}

pub async fn container(tx: &mut Tx, id: i64) -> Result<Option<ContainerRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::container(t, id).await, postgres::container(t, id).await)?)
}

pub async fn containers_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<Vec<ContainerRow>, StoreError> {
    let mut found = Vec::new();
    for chunk in ids.chunks(LOOKUP_BATCH) {
        found.extend(on!(
            &mut *tx,
            Tx,
            |t| mysql::containers_by_ids(t, &json_ids(chunk)).await,
            postgres::containers_by_ids(t, chunk).await
        )?);
    }
    Ok(found)
}

pub async fn containers_of_project(tx: &mut Tx, project_id: i64) -> Result<Vec<ContainerRow>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::containers_of_project(t, project_id).await,
        postgres::containers_of_project(t, project_id).await
    )?)
}

pub async fn insert_container(tx: &mut Tx, row: &ContainerRow) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::insert_container(t, row).await, postgres::insert_container(t, row).await)?)
}

pub async fn update_container(tx: &mut Tx, row: &ContainerRow) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::update_container(t, row).await, postgres::update_container(t, row).await)?)
}

pub async fn delete_container(tx: &mut Tx, id: i64) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::delete_container(t, id).await, postgres::delete_container(t, id).await)?)
}

pub async fn stamp_container(tx: &mut Tx, id: i64, at: OffsetDateTime) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::stamp_container(t, id, at).await, postgres::stamp_container(t, id, at).await)?)
}

pub async fn container_ids_in_projects(tx: &mut Tx, projects: &[i64]) -> Result<Vec<i64>, StoreError> {
    let mut found = Vec::new();
    for chunk in projects.chunks(LOOKUP_BATCH) {
        found.extend(on!(
            &mut *tx,
            Tx,
            |t| mysql::container_ids_in_projects(t, &json_ids(chunk)).await,
            postgres::container_ids_in_projects(t, chunk).await
        )?);
    }
    Ok(found)
}

pub async fn container_ids_of_solution(tx: &mut Tx, solution_id: i64) -> Result<Vec<i64>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::container_ids_of_solution(t, solution_id).await,
        postgres::container_ids_of_solution(t, solution_id).await
    )?)
}

pub async fn assign_container(tx: &mut Tx, id: i64, project_id: Option<i64>) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::assign_container(t, id, project_id).await,
        postgres::assign_container(t, id, project_id).await
    )?)
}

pub async fn detach_containers(tx: &mut Tx, project_id: i64) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::detach_containers(t, project_id).await,
        postgres::detach_containers(t, project_id).await
    )?)
}

// ── solutions and projects ───────────────────────────────────────────────────────────────

pub async fn solutions(tx: &mut Tx) -> Result<Vec<SolutionRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::solutions(t).await, postgres::solutions(t).await)?)
}

pub async fn solution(tx: &mut Tx, id: i64) -> Result<Option<SolutionRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::solution(t, id).await, postgres::solution(t, id).await)?)
}

pub async fn solutions_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<Vec<SolutionRow>, StoreError> {
    let mut found = Vec::new();
    for chunk in ids.chunks(LOOKUP_BATCH) {
        found.extend(on!(
            &mut *tx,
            Tx,
            |t| mysql::solutions_by_ids(t, &json_ids(chunk)).await,
            postgres::solutions_by_ids(t, chunk).await
        )?);
    }
    Ok(found)
}

/// `findByNameIgnoreCase`: `upper(name) = upper(?)`, as Hibernate derives it — the same folding on both engines,
/// where the unique index folds case on MySQL and not on PostgreSQL.
pub async fn solution_named(tx: &mut Tx, name: &str) -> Result<Option<SolutionRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::solution_named(t, name).await, postgres::solution_named(t, name).await)?)
}

pub async fn insert_solution(tx: &mut Tx, row: &SolutionRow) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::insert_solution(t, row).await, postgres::insert_solution(t, row).await)?)
}

pub async fn update_solution(tx: &mut Tx, row: &SolutionRow) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::update_solution(t, row).await, postgres::update_solution(t, row).await)?)
}

pub async fn delete_solution(tx: &mut Tx, id: i64) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::delete_solution(t, id).await, postgres::delete_solution(t, id).await)?)
}

pub async fn projects(tx: &mut Tx) -> Result<Vec<ProjectRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::projects(t).await, postgres::projects(t).await)?)
}

pub async fn project(tx: &mut Tx, id: i64) -> Result<Option<ProjectRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::project(t, id).await, postgres::project(t, id).await)?)
}

pub async fn projects_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<Vec<ProjectRow>, StoreError> {
    let mut found = Vec::new();
    for chunk in ids.chunks(LOOKUP_BATCH) {
        found.extend(on!(
            &mut *tx,
            Tx,
            |t| mysql::projects_by_ids(t, &json_ids(chunk)).await,
            postgres::projects_by_ids(t, chunk).await
        )?);
    }
    Ok(found)
}

/// `findBySolutionIdAndNameIgnoreCase`.
pub async fn project_named(tx: &mut Tx, solution_id: i64, name: &str) -> Result<Option<ProjectRow>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::project_named(t, solution_id, name).await,
        postgres::project_named(t, solution_id, name).await
    )?)
}

pub async fn count_projects_of_solution(tx: &mut Tx, solution_id: i64) -> Result<i64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::count_projects_of_solution(t, solution_id).await,
        postgres::count_projects_of_solution(t, solution_id).await
    )?)
}

pub async fn projects_of_solution(tx: &mut Tx, solution_id: i64) -> Result<Vec<ProjectRow>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::projects_of_solution(t, solution_id).await,
        postgres::projects_of_solution(t, solution_id).await
    )?)
}

pub async fn insert_project(tx: &mut Tx, row: &ProjectRow) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::insert_project(t, row).await, postgres::insert_project(t, row).await)?)
}

pub async fn update_project(tx: &mut Tx, row: &ProjectRow) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::update_project(t, row).await, postgres::update_project(t, row).await)?)
}

pub async fn delete_project(tx: &mut Tx, id: i64) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::delete_project(t, id).await, postgres::delete_project(t, id).await)?)
}

// ── clone credentials ────────────────────────────────────────────────────────────────────

/// `findAllByOrderByCreatedAtDesc`.
pub async fn git_tokens(tx: &mut Tx) -> Result<Vec<GitTokenRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::git_tokens(t).await, postgres::git_tokens(t).await)?)
}

pub async fn git_token(tx: &mut Tx, id: Uuid) -> Result<Option<GitTokenRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::git_token(t, id).await, postgres::git_token(t, id).await)?)
}

pub async fn insert_git_token(tx: &mut Tx, row: &GitTokenRow) -> Result<(), StoreError> {
    Ok(on!(tx, Tx, |t| mysql::insert_git_token(t, row).await, postgres::insert_git_token(t, row).await)?)
}

pub async fn delete_git_token(tx: &mut Tx, id: Uuid) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::delete_git_token(t, id).await, postgres::delete_git_token(t, id).await)?)
}

pub async fn ssh_keys(tx: &mut Tx) -> Result<Vec<SshKeyRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::ssh_keys(t).await, postgres::ssh_keys(t).await)?)
}

pub async fn ssh_key(tx: &mut Tx, id: Uuid) -> Result<Option<SshKeyRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::ssh_key(t, id).await, postgres::ssh_key(t, id).await)?)
}

pub async fn insert_ssh_key(tx: &mut Tx, row: &SshKeyRow) -> Result<(), StoreError> {
    Ok(on!(tx, Tx, |t| mysql::insert_ssh_key(t, row).await, postgres::insert_ssh_key(t, row).await)?)
}

pub async fn delete_ssh_key(tx: &mut Tx, id: Uuid) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::delete_ssh_key(t, id).await, postgres::delete_ssh_key(t, id).await)?)
}

// ── the visible reads ────────────────────────────────────────────────────────────────────

/// The repositories `visibility` permits, by identifier — **narrowed in the statement**, through cp-db's
/// `VisibleSelect`, which cannot be built without the visibility (AGENTS.md: the visibility is applied in the query).
pub async fn visible_repositories(
    db: &Db,
    visibility: &vectispire_cp_db::Visibility,
) -> Result<Vec<RepositoryRow>, StoreError> {
    use vectispire_cp_db::VisibleSelect;
    use vectispire_cp_db::query::Repositories;
    let rows: Vec<visible::Repository> =
        VisibleSelect::<Repositories>::columns(visibility, visible::REPOSITORY_COLUMNS)
            .order_by("id", sea_query::Order::Asc)
            .fetch_all(db)
            .await?;
    Ok(rows.into_iter().map(RepositoryRow::from).collect())
}

/// The images `visibility` permits, by identifier, narrowed in the statement.
pub async fn visible_containers(
    db: &Db,
    visibility: &vectispire_cp_db::Visibility,
) -> Result<Vec<ContainerRow>, StoreError> {
    use vectispire_cp_db::VisibleSelect;
    use vectispire_cp_db::query::Containers;
    let rows: Vec<visible::Container> = VisibleSelect::<Containers>::columns(visibility, visible::CONTAINER_COLUMNS)
        .order_by("id", sea_query::Order::Asc)
        .fetch_all(db)
        .await?;
    Ok(rows.into_iter().map(ContainerRow::from).collect())
}

/// A read-only transaction on `db`, for a service's reads.
pub async fn read(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(Mode::ReadOnly).await?)
}

/// A read-write transaction on `db`.
pub async fn write(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(Mode::ReadWrite).await?)
}

/// The rows a `VisibleSelect` reads, decoded alike on both engines.
mod visible {
    use vectispire_cp_db::types::{TextUuid, UtcInstant};

    pub const REPOSITORY_COLUMNS: &[&str] = &[
        "id",
        "url",
        "branch",
        "sub_path",
        "name",
        "scan_interval_minutes",
        "scan_cron",
        "scan_manual_only",
        "required_agent_label",
        "last_scheduled_scan_at",
        "ssh_key_id",
        "https_token_id",
        "badge_token",
        "tier",
        "in_certified_scope",
        "project_id",
        "url_identity",
        "identity_guard",
    ];

    pub const CONTAINER_COLUMNS: &[&str] = &[
        "id",
        "registry",
        "image_name",
        "tag",
        "scan_interval_minutes",
        "scan_cron",
        "scan_manual_only",
        "required_agent_label",
        "last_scheduled_scan_at",
        "tier",
        "in_certified_scope",
        "project_id",
    ];

    #[derive(sqlx::FromRow, Debug)]
    pub struct Repository {
        id: i64,
        url: String,
        branch: String,
        sub_path: Option<String>,
        name: Option<String>,
        scan_interval_minutes: Option<i32>,
        scan_cron: Option<String>,
        scan_manual_only: bool,
        required_agent_label: Option<String>,
        last_scheduled_scan_at: Option<UtcInstant>,
        ssh_key_id: Option<TextUuid>,
        https_token_id: Option<TextUuid>,
        badge_token: Option<String>,
        tier: String,
        in_certified_scope: bool,
        project_id: Option<i64>,
        url_identity: Option<String>,
        identity_guard: Option<String>,
    }

    impl From<Repository> for super::RepositoryRow {
        fn from(row: Repository) -> super::RepositoryRow {
            super::RepositoryRow {
                id: row.id,
                url: row.url,
                branch: row.branch,
                sub_path: row.sub_path,
                name: row.name,
                scan_interval_minutes: row.scan_interval_minutes,
                scan_cron: row.scan_cron,
                scan_manual_only: row.scan_manual_only,
                required_agent_label: row.required_agent_label,
                last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
                ssh_key_id: row.ssh_key_id.map(|id| id.0),
                https_token_id: row.https_token_id.map(|id| id.0),
                badge_token: row.badge_token,
                tier: row.tier,
                in_certified_scope: row.in_certified_scope,
                project_id: row.project_id,
                url_identity: row.url_identity,
                identity_guard: row.identity_guard,
            }
        }
    }

    #[derive(sqlx::FromRow, Debug)]
    pub struct Container {
        id: i64,
        registry: Option<String>,
        image_name: String,
        tag: String,
        scan_interval_minutes: Option<i32>,
        scan_cron: Option<String>,
        scan_manual_only: bool,
        required_agent_label: Option<String>,
        last_scheduled_scan_at: Option<UtcInstant>,
        tier: String,
        in_certified_scope: bool,
        project_id: Option<i64>,
    }

    impl From<Container> for super::ContainerRow {
        fn from(row: Container) -> super::ContainerRow {
            super::ContainerRow {
                id: row.id,
                registry: row.registry,
                image_name: row.image_name,
                tag: row.tag,
                scan_interval_minutes: row.scan_interval_minutes,
                scan_cron: row.scan_cron,
                scan_manual_only: row.scan_manual_only,
                required_agent_label: row.required_agent_label,
                last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
                tier: row.tier,
                in_certified_scope: row.in_certified_scope,
                project_id: row.project_id,
            }
        }
    }
}
