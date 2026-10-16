//! The control plane's schema migrations, run the way Flyway 12.4 runs them for the Java control plane.
//!
//! **The history table decides everything.** An installation the Java control plane migrated must
//! continue under Rust, and — while both exist — go back, so this crate reads the same files
//! (`vectispire-core`'s `db/migration`, embedded at build time), computes Flyway's checksum, and reads
//! and writes `flyway_schema_history` row for row as Flyway does, under Flyway's own lock. The plan's
//! §3.3 (`docs/analysis/en/2026-10-16_rust_control_plane_port_plan.en.md`) says why no existing crate
//! could: each keeps its own table and its own checksum.
//!
//! What a start does, in Flyway's order:
//!
//! 1. resolve the files for the engine (`common`, then its own directory), with its placeholders;
//! 2. **validate** the history against them, and refuse to go further on any problem (`validate.rs`);
//! 3. refuse a schema that holds objects but no history table — Flyway's "non-empty schema" rule,
//!    since `baselineOnMigrate` is off;
//! 4. create the history table if it is missing, under the lock;
//! 5. apply the pending migrations **one at a time, each under the lock**, re-reading the history
//!    inside it, so that a second instance — Java or Rust — that started at the same moment waits and
//!    then finds nothing left to do.
//!
//! `clean`, `baseline`, `repair`, repeatable migrations and `outOfOrder` are not implemented: the
//! control plane's configuration uses none of them, and each would need its own port.

mod checksum;
mod dialect;
mod embedded;
pub mod history;
pub mod layout;
mod set;
mod sql;
mod validate;
mod version;

use std::collections::BTreeMap;
use std::time::Instant;

use sqlx::mysql::MySqlPool;
use sqlx::postgres::PgPool;

pub use checksum::{of as checksum_of, of_text as checksum_of_text};
pub use dialect::{Engine, placeholders_for, replace as replace_placeholders};
pub use history::Applied;
pub use set::{COMMON, File, MigrationSet, Resolved, parse_name};
pub use sql::statements;
pub use validate::{Problem, Validation, validate as validate_history};
pub use version::Version;

/// Why a migration run stopped. A message an operator reads is Flyway's sentence where Flyway has one.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{script} is not UTF-8: a migration this project ships is never anything else, so the file is damaged")]
    NotUtf8 { script: String },
    #[error("{message}")]
    PlaceholderOverride { message: String },
    #[error("No value provided for placeholder: ${{{name}}} in {script}.  Check your configuration!")]
    UnknownPlaceholder { script: String, name: String },
    #[error("Found more than one migration with version {version}\nOffenders:\n-> {}", offenders.join("\n-> "))]
    DuplicateVersion { version: String, offenders: Vec<String> },
    #[error("{script}: a {kind} migration — this runner applies versioned SQL migrations only")]
    UnsupportedMigration { script: String, kind: String },
    #[error("{script} could not be cut into statements: {reason}")]
    Unparsable { script: String, reason: String },
    #[error(
        "{script} holds a statement PostgreSQL runs only outside a transaction ({statement}); this runner applies \
         every migration in one"
    )]
    NonTransactional { script: String, statement: String },
    #[error("{}", .0.message())]
    Validation(Box<Validation>),
    #[error(
        "Found non-empty schema(s) {schema} but no schema history table. Use baseline() or set baselineOnMigrate to true \
         to initialize the schema history table."
    )]
    NonEmptySchema { schema: String },
    #[error("Schema {schema} contains a failed migration to version {version} !")]
    FailedMigrationPresent { schema: String, version: String },
    #[error("Migration of schema {schema} to version \"{version} - {description}\" failed! {outcome}\n{cause}")]
    MigrationFailed {
        schema: String,
        version: String,
        description: String,
        outcome: &'static str,
        cause: Box<sqlx::Error>,
    },
    #[error("Unable to determine the current schema: the connection names no database")]
    NoCurrentSchema,
    #[error(
        "Number of retries exceeded while attempting to acquire PostgreSQL advisory lock. Configure the number of \
         retries with the 'lockRetryCount' configuration option"
    )]
    LockTimeout,
    #[error("the migration layout is broken:\n{}", .0.join("\n"))]
    Layout(Vec<String>),
    #[error(transparent)]
    Database(#[from] Box<sqlx::Error>),
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        Error::Database(Box::new(error))
    }
}

/// A pool of either engine — what the control plane's database layer hands this crate.
///
/// **It needs two connections at once**, as Flyway does: one holds the lock and writes the history,
/// the other runs the migration. A pool capped at one connection would wait for itself.
#[derive(Debug, Clone)]
pub enum Database {
    MySql(MySqlPool),
    PostgreSql(PgPool),
}

impl Database {
    pub fn engine(&self) -> Engine {
        match self {
            Database::MySql(_) => Engine::MySql,
            Database::PostgreSql(_) => Engine::PostgreSql,
        }
    }

    async fn connection(&self) -> Result<history::Conn, Error> {
        Ok(match self {
            Database::MySql(pool) => history::Conn::MySql(pool.acquire().await?.detach()),
            Database::PostgreSql(pool) => history::Conn::PostgreSql(pool.acquire().await?.detach()),
        })
    }
}

/// How a run is configured: the files and any placeholder the deployment adds.
#[derive(Debug, Clone)]
pub struct Options {
    pub set: MigrationSet,
    /// `spring.flyway.placeholders.*`; one that redefines a column type is refused.
    pub placeholders: BTreeMap<String, String>,
}

impl Default for Options {
    fn default() -> Self {
        Options { set: MigrationSet::embedded(), placeholders: BTreeMap::new() }
    }
}

/// What a run did.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub schema: String,
    /// The versions applied by this run, in order.
    pub applied: Vec<String>,
    /// Applied versions newer than any file: a newer build migrated this database, and this one runs
    /// on it, as Flyway's `*:future` allows.
    pub future: Vec<String>,
}

/// Validates the database's history against the files without changing anything: what the control
/// plane's start does before it serves, and what a dry run reports.
pub async fn validate(database: &Database, options: &Options) -> Result<Validation, Error> {
    let resolved = resolve(database.engine(), options)?;
    let mut conn = database.connection().await?;
    let schema = conn.current_schema().await?;
    let applied = if conn.table_exists(&schema).await? { conn.applied(&schema).await? } else { Vec::new() };
    let _ = conn.close().await;
    Ok(validate::validate(&resolved, &applied))
}

/// Validates, then applies every pending migration — Flyway's `migrate` with the control plane's
/// configuration. The control plane does not answer HTTP until this has returned `Ok`.
pub async fn run(database: &Database, options: &Options) -> Result<Report, Error> {
    let engine = database.engine();
    let resolved = resolve(engine, options)?;

    let mut lock = database.connection().await?;
    let schema = lock.current_schema().await?;
    let installed_by = lock.installed_by().await?;

    let exists = lock.table_exists(&schema).await?;
    let applied = if exists { lock.applied(&schema).await? } else { Vec::new() };
    let validation = validate::validate(&resolved, &applied);
    if !validation.is_valid() {
        return Err(Error::Validation(Box::new(validation)));
    }
    let future = validation.future.clone();

    if !exists {
        // `Flyway.migrate`: with `baselineOnMigrate` off, objects without a history are refused — they
        // were not made by these migrations, and applying V1 over them would fail half-way or worse.
        if !lock.schema_is_empty(&schema).await? && !lock.table_exists(&schema).await? {
            return Err(Error::NonEmptySchema { schema: quote_schema(engine, &schema) });
        }
        create_history(&mut lock, &schema).await?;
    }

    let mut migrator = database.connection().await?;
    let mut report = Report { schema: schema.clone(), applied: Vec::new(), future };
    loop {
        lock.lock(&schema).await?;
        let step = apply_next(&mut lock, &mut migrator, engine, &schema, &installed_by, &resolved).await;
        // On PostgreSQL the lock is the transaction that writes the row: committed only if the step held.
        let released = lock.unlock(&schema, step.is_ok()).await;
        match step {
            Ok(Some(version)) => {
                released?;
                report.applied.push(version);
            }
            Ok(None) => {
                released?;
                break;
            }
            Err(error) => return Err(error),
        }
    }
    let _ = migrator.close().await;
    let _ = lock.close().await;
    if report.applied.is_empty() {
        tracing::info!(schema = %report.schema, "Schema {} is up to date. No migration necessary.", report.schema);
    } else {
        tracing::info!(
            schema = %report.schema,
            count = report.applied.len(),
            "Successfully applied {} migration(s) to schema {}, now at version v{}",
            report.applied.len(),
            report.schema,
            report.applied.last().map_or("", String::as_str)
        );
    }
    Ok(report)
}

fn resolve(engine: Engine, options: &Options) -> Result<Vec<Resolved>, Error> {
    let layout = layout::check(&options.set);
    if !layout.is_empty() {
        return Err(Error::Layout(layout));
    }
    let placeholders = dialect::placeholders_for(engine, &options.placeholders)?;
    let mut resolved = options.set.resolve(engine)?;
    for migration in &mut resolved {
        migration.sql = dialect::replace(&migration.script, &migration.sql, &placeholders)?;
        // Cut now, so that a file that cannot be cut stops the start before anything is applied.
        sql::statements(engine, &migration.script, &migration.sql)?;
    }
    Ok(resolved)
}

/// `JdbcTableSchemaHistory.create`: under the lock, and only if no other instance created it meanwhile.
async fn create_history(lock: &mut history::Conn, schema: &str) -> Result<(), Error> {
    let engine = lock.engine();
    lock.lock(schema).await?;
    let outcome = async {
        if lock.table_exists(schema).await? {
            return Ok(());
        }
        tracing::info!("Creating Schema History table {} ...", history::qualified(engine, schema));
        // On PostgreSQL the lock's transaction is open: the table is created in it, and visible to the
        // other instance when it ends — after which that instance finds it and creates nothing.
        for statement in history::create_statements(engine, schema) {
            lock.execute_raw(&statement).await?;
        }
        Ok::<(), Error>(())
    }
    .await;
    lock.unlock(schema, outcome.is_ok()).await?;
    outcome
}

/// One turn of `DbMigrate.migrateGroup` with `group=false`, the lock held: re-reads the history,
/// refuses a failed row, applies the first pending migration and records it. `None` when nothing is
/// left.
async fn apply_next(
    lock: &mut history::Conn,
    migrator: &mut history::Conn,
    engine: Engine,
    schema: &str,
    installed_by: &str,
    resolved: &[Resolved],
) -> Result<Option<String>, Error> {
    let applied = lock.applied(schema).await?;
    let validation = validate::validate(resolved, &applied);
    if let Some(failed) = applied.iter().find(|row| !row.success) {
        return Err(Error::FailedMigrationPresent {
            schema: quote_schema(engine, schema),
            version: failed.version.clone().unwrap_or_default(),
        });
    }
    let Some(next) = validation.pending.first() else { return Ok(None) };

    let statements = sql::statements(engine, &next.script, &next.sql)?;
    tracing::info!(
        "Migrating schema {} to version \"{} - {}\"",
        quote_schema(engine, schema),
        next.version,
        next.description
    );
    let started = Instant::now();
    let outcome: Result<(), sqlx::Error> = async {
        migrator.begin().await?;
        for statement in &statements {
            migrator.execute_raw(statement).await?;
        }
        migrator.commit().await
    }
    .await;
    let elapsed = i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX);

    if let Err(cause) = outcome {
        let _ = migrator.rollback().await;
        let outcome = match engine {
            // PostgreSQL's DDL is transactional: the migration left nothing behind, and no row is written.
            Engine::PostgreSql => "Changes successfully rolled back.",
            // MySQL committed every DDL statement as it ran: the row says so, and the next start refuses.
            Engine::MySql => {
                lock.record(
                    schema,
                    &next.version,
                    &next.description,
                    &next.script,
                    next.checksum,
                    installed_by,
                    elapsed,
                    false,
                )
                .await?;
                "Please restore backups and roll back database and code!"
            }
        };
        return Err(Error::MigrationFailed {
            schema: quote_schema(engine, schema),
            version: next.version.to_string(),
            description: next.description.clone(),
            outcome,
            cause: Box::new(cause),
        });
    }
    lock.record(schema, &next.version, &next.description, &next.script, next.checksum, installed_by, elapsed, true)
        .await?;
    Ok(Some(next.version.to_string()))
}

fn quote_schema(engine: Engine, schema: &str) -> String {
    match engine {
        Engine::MySql => format!("`{schema}`"),
        Engine::PostgreSql => format!("\"{schema}\""),
    }
}
