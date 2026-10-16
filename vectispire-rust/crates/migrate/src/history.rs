//! `flyway_schema_history`, read and written the way Flyway 12.4 reads and writes it, and the lock
//! Flyway takes around each migration.
//!
//! **Every statement here is Flyway's own**, from `MySQLDatabase`, `PostgreSQLDatabase`,
//! `JdbcTableSchemaHistory`, `MySQLNamedLockTemplate` and `PostgreSQLAdvisoryLockTemplate`: the same
//! table definition, the same insert, the same `installed_by`, the same lock under the same key. The
//! key is what makes a Java and a Rust instance starting together exclude each other; it is derived
//! from the quoted table name exactly as Flyway derives it (`Table.toString().hashCode()`).

use std::time::Duration;

use sqlx::mysql::MySqlConnection;
use sqlx::postgres::PgConnection;
use sqlx::{Connection as _, Row as _};

use crate::Error;
use crate::dialect::Engine;
use crate::version::Version;

/// Flyway's default table name, which the Java configuration keeps.
pub const TABLE: &str = "flyway_schema_history";

/// A row of `flyway_schema_history`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub installed_rank: i32,
    /// `None` for the rows that carry no version (repeatable migrations, the schema marker).
    pub version: Option<String>,
    pub description: String,
    /// `SQL` for every migration this project has; `SCHEMA`, `BASELINE`, `DELETE`… are Flyway's own.
    pub kind: String,
    pub script: String,
    pub checksum: Option<i32>,
    pub installed_by: String,
    pub execution_time: i32,
    pub success: bool,
}

impl Applied {
    pub fn parsed_version(&self) -> Option<Version> {
        self.version.as_deref().and_then(Version::parse)
    }
}

/// The table, quoted and qualified with its schema as Flyway's `Table.toString()` prints it.
pub fn qualified(engine: Engine, schema: &str) -> String {
    match engine {
        Engine::MySql => format!("`{}`.`{TABLE}`", schema.replace('`', "``")),
        Engine::PostgreSql => format!("\"{}\".\"{TABLE}\"", schema.replace('"', "\"\"")),
    }
}

/// `java.lang.String.hashCode()`: the UTF-16 code units, `31 * h + c`, wrapping.
pub fn java_hash_code(text: &str) -> i32 {
    text.encode_utf16().fold(0i32, |hash, unit| hash.wrapping_mul(31).wrapping_add(i32::from(unit)))
}

/// MySQL's named lock: `"Flyway-" + table.toString().hashCode()`.
pub fn mysql_lock_name(schema: &str) -> String {
    format!("Flyway-{}", java_hash_code(&qualified(Engine::MySql, schema)))
}

/// PostgreSQL's advisory lock: "Flyway" in ASCII, plus the table's hash code.
pub fn postgres_lock_number(schema: &str) -> i64 {
    const MAGIC: i64 = (0x46 << 40) + (0x6C << 32) + (0x79 << 24) + (0x77 << 16) + (0x61 << 8) + 0x79;
    MAGIC + i64::from(java_hash_code(&qualified(Engine::PostgreSql, schema)))
}

/// The table's definition, statement by statement, as `getRawCreateScript(table, false)` writes it.
pub fn create_statements(engine: Engine, schema: &str) -> Vec<String> {
    let table = qualified(engine, schema);
    match engine {
        Engine::MySql => vec![
            format!(
                "CREATE TABLE {table} (\n    `installed_rank` INT NOT NULL,\n    `version` VARCHAR(50),\n    \
                 `description` VARCHAR(200) NOT NULL,\n    `type` VARCHAR(20) NOT NULL,\n    `script` VARCHAR(1000) NOT NULL,\n    \
                 `checksum` INT,\n    `installed_by` VARCHAR(100) NOT NULL,\n    \
                 `installed_on` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,\n    `execution_time` INT NOT NULL,\n    \
                 `success` BOOL NOT NULL,\n    CONSTRAINT `{TABLE}_pk` PRIMARY KEY (`installed_rank`)\n)"
            ),
            format!("CREATE INDEX `{TABLE}_s_idx` ON {table} (`success`)"),
        ],
        Engine::PostgreSql => vec![
            format!(
                "CREATE TABLE {table} (\n    \"installed_rank\" INT NOT NULL,\n    \"version\" VARCHAR(50),\n    \
                 \"description\" VARCHAR(200) NOT NULL,\n    \"type\" VARCHAR(20) NOT NULL,\n    \"script\" VARCHAR(1000) NOT NULL,\n    \
                 \"checksum\" INTEGER,\n    \"installed_by\" VARCHAR(100) NOT NULL,\n    \
                 \"installed_on\" TIMESTAMP NOT NULL DEFAULT now(),\n    \"execution_time\" INTEGER NOT NULL,\n    \
                 \"success\" BOOLEAN NOT NULL\n)"
            ),
            format!("ALTER TABLE {table} ADD CONSTRAINT \"{TABLE}_pk\" PRIMARY KEY (\"installed_rank\")"),
            format!("CREATE INDEX \"{TABLE}_s_idx\" ON {table} (\"success\")"),
        ],
    }
}

fn quote(engine: Engine, column: &str) -> String {
    match engine {
        Engine::MySql => format!("`{column}`"),
        Engine::PostgreSql => format!("\"{column}\""),
    }
}

fn select(engine: Engine, schema: &str) -> String {
    let columns = [
        "installed_rank",
        "version",
        "description",
        "type",
        "script",
        "checksum",
        "installed_on",
        "installed_by",
        "execution_time",
        "success",
    ]
    .map(|column| quote(engine, column))
    .join(",");
    format!(
        "SELECT {columns} FROM {} WHERE {} > ? ORDER BY {}",
        qualified(engine, schema),
        quote(engine, "installed_rank"),
        quote(engine, "installed_rank")
    )
}

fn insert(engine: Engine, schema: &str) -> String {
    let columns = [
        "installed_rank",
        "version",
        "description",
        "type",
        "script",
        "checksum",
        "installed_by",
        "execution_time",
        "success",
    ]
    .map(|column| quote(engine, column))
    .join(", ");
    let values = match engine {
        Engine::MySql => "?, ?, ?, ?, ?, ?, ?, ?, ?".to_owned(),
        Engine::PostgreSql => "$1, $2, $3, $4, $5, $6, $7, $8, $9".to_owned(),
    };
    format!("INSERT INTO {} ({columns}) VALUES ({values})", qualified(engine, schema))
}

/// `AbbreviationUtils.abbreviateDescription`: 200 characters at most, the last three `...`.
pub fn abbreviate_description(description: &str) -> String {
    abbreviate(description, 200, |kept| format!("{kept}..."), true)
}

/// `AbbreviationUtils.abbreviateScript`: 1000 characters at most, the first three `...`.
pub fn abbreviate_script(script: &str) -> String {
    abbreviate(script, 1000, |kept| format!("...{kept}"), false)
}

fn abbreviate(text: &str, limit: usize, mark: impl Fn(&str) -> String, keep_start: bool) -> String {
    let units: Vec<u16> = text.encode_utf16().collect();
    if units.len() <= limit {
        return text.to_owned();
    }
    let kept = if keep_start { &units[..limit - 3] } else { &units[3..limit] };
    mark(&String::from_utf16_lossy(kept))
}

/// One connection, of either engine.
#[derive(Debug)]
pub enum Conn {
    MySql(MySqlConnection),
    PostgreSql(PgConnection),
}

impl Conn {
    pub fn engine(&self) -> Engine {
        match self {
            Conn::MySql(_) => Engine::MySql,
            Conn::PostgreSql(_) => Engine::PostgreSql,
        }
    }

    /// The schema the history table lives in: `DATABASE()` on MySQL, `current_schema()` on PostgreSQL.
    pub async fn current_schema(&mut self) -> Result<String, Error> {
        let schema: Option<String> = match self {
            Conn::MySql(conn) => sqlx::query_scalar("SELECT DATABASE()").fetch_one(conn).await?,
            Conn::PostgreSql(conn) => sqlx::query_scalar("SELECT current_schema()").fetch_one(conn).await?,
        };
        schema.filter(|name| !name.is_empty()).ok_or(Error::NoCurrentSchema)
    }

    /// `getInstalledBy()` with no `installedBy` configured: the database user, as each engine names it.
    pub async fn installed_by(&mut self) -> Result<String, Error> {
        Ok(match self {
            Conn::MySql(conn) => sqlx::query_scalar("SELECT SUBSTRING_INDEX(USER(),'@',1)").fetch_one(conn).await?,
            Conn::PostgreSql(conn) => sqlx::query_scalar("SELECT current_user").fetch_one(conn).await?,
        })
    }

    pub async fn table_exists(&mut self, schema: &str) -> Result<bool, Error> {
        Ok(match self {
            Conn::MySql(conn) => {
                let found: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = ?",
                )
                .bind(schema)
                .bind(TABLE)
                .fetch_one(conn)
                .await?;
                found > 0
            }
            Conn::PostgreSql(conn) => {
                sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                     WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind = 'r')",
                )
                .bind(schema)
                .bind(TABLE)
                .fetch_one(conn)
                .await?
            }
        })
    }

    /// `Schema.empty()`: no table, view, constraint, trigger, routine or event (MySQL); no relation,
    /// type or function outside an extension (PostgreSQL).
    pub async fn schema_is_empty(&mut self, schema: &str) -> Result<bool, Error> {
        Ok(match self {
            Conn::MySql(conn) => {
                let found: i64 = sqlx::query_scalar(
                    "SELECT CAST(COALESCE(SUM(found), 0) AS SIGNED) FROM (\
                     (SELECT 1 as found FROM information_schema.tables WHERE table_schema=?) UNION ALL \
                     (SELECT 1 as found FROM information_schema.views WHERE table_schema=? LIMIT 1) UNION ALL \
                     (SELECT 1 as found FROM information_schema.table_constraints WHERE table_schema=? LIMIT 1) UNION ALL \
                     (SELECT 1 as found FROM information_schema.triggers WHERE event_object_schema=?  LIMIT 1) UNION ALL \
                     (SELECT 1 as found FROM information_schema.routines WHERE routine_schema=? LIMIT 1) UNION ALL \
                     (SELECT 1 as found FROM information_schema.events WHERE event_schema=? LIMIT 1)\
                     ) as all_found",
                )
                .bind(schema)
                .bind(schema)
                .bind(schema)
                .bind(schema)
                .bind(schema)
                .bind(schema)
                .fetch_one(conn)
                .await?;
                found == 0
            }
            Conn::PostgreSql(conn) => {
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS (\n\
                     SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                     LEFT JOIN pg_catalog.pg_depend d ON d.objid = c.oid AND d.deptype = 'e' \
                     WHERE n.nspname = $1 AND d.objid IS NULL AND c.relkind IN ('r', 'v', 'S', 't')\n\
                     UNION ALL SELECT t.oid FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace \
                     LEFT JOIN pg_catalog.pg_depend d ON d.objid = t.oid AND d.deptype = 'e' \
                     WHERE n.nspname = $1 AND d.objid IS NULL AND t.typcategory NOT IN ('A', 'C')\n\
                     UNION ALL SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
                     LEFT JOIN pg_catalog.pg_depend d ON d.objid = p.oid AND d.deptype = 'e' \
                     WHERE n.nspname = $1 AND d.objid IS NULL)",
                )
                .bind(schema)
                .fetch_one(conn)
                .await?;
                !exists
            }
        })
    }

    /// Every row, by `installed_rank`.
    pub async fn applied(&mut self, schema: &str) -> Result<Vec<Applied>, Error> {
        let engine = self.engine();
        let sql = select(engine, schema);
        let rows: Vec<Applied> = match self {
            Conn::MySql(conn) => sqlx::query(&sql)
                .bind(-1i32)
                .fetch_all(conn)
                .await?
                .iter()
                .map(|row| -> Result<Applied, sqlx::Error> {
                    Ok(Applied {
                        installed_rank: row.try_get("installed_rank")?,
                        version: row.try_get("version")?,
                        description: row.try_get("description")?,
                        kind: row.try_get("type")?,
                        script: row.try_get("script")?,
                        checksum: row.try_get("checksum")?,
                        installed_by: row.try_get("installed_by")?,
                        execution_time: row.try_get("execution_time")?,
                        success: row.try_get("success")?,
                    })
                })
                .collect::<Result<_, _>>()?,
            Conn::PostgreSql(conn) => sqlx::query(&sql.replace('?', "$1"))
                .bind(-1i32)
                .fetch_all(conn)
                .await?
                .iter()
                .map(|row| -> Result<Applied, sqlx::Error> {
                    Ok(Applied {
                        installed_rank: row.try_get("installed_rank")?,
                        version: row.try_get("version")?,
                        description: row.try_get("description")?,
                        kind: row.try_get("type")?,
                        script: row.try_get("script")?,
                        checksum: row.try_get("checksum")?,
                        installed_by: row.try_get("installed_by")?,
                        execution_time: row.try_get("execution_time")?,
                        success: row.try_get("success")?,
                    })
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(rows)
    }

    /// `doAddAppliedMigration`, with the rank `calculateInstalledRank` gives: one past the last row's.
    #[allow(clippy::too_many_arguments)]
    pub async fn record(
        &mut self,
        schema: &str,
        version: &Version,
        description: &str,
        script: &str,
        checksum: i32,
        installed_by: &str,
        execution_time: i32,
        success: bool,
    ) -> Result<(), Error> {
        let rank = self.applied(schema).await?.last().map_or(1, |last| last.installed_rank + 1);
        let sql = insert(self.engine(), schema);
        let description = abbreviate_description(description);
        let script = abbreviate_script(script);
        let version = version.to_string();
        match self {
            Conn::MySql(conn) => {
                sqlx::query(&sql)
                    .bind(rank)
                    .bind(&version)
                    .bind(&description)
                    .bind("SQL")
                    .bind(&script)
                    .bind(checksum)
                    .bind(installed_by)
                    .bind(execution_time)
                    .bind(success)
                    .execute(conn)
                    .await?;
            }
            Conn::PostgreSql(conn) => {
                sqlx::query(&sql)
                    .bind(rank)
                    .bind(&version)
                    .bind(&description)
                    .bind("SQL")
                    .bind(&script)
                    .bind(checksum)
                    .bind(installed_by)
                    .bind(execution_time)
                    .bind(success)
                    .execute(conn)
                    .await?;
            }
        }
        Ok(())
    }

    /// Runs one statement as written, through the text protocol: `PREPARE`, `DELIMITER`-built
    /// procedures and multi-statement bodies are not things a prepared statement may carry.
    pub async fn execute_raw(&mut self, statement: &str) -> Result<(), sqlx::Error> {
        match self {
            Conn::MySql(conn) => sqlx::raw_sql(statement).execute(conn).await.map(drop),
            Conn::PostgreSql(conn) => sqlx::raw_sql(statement).execute(conn).await.map(drop),
        }
    }

    pub async fn begin(&mut self) -> Result<(), sqlx::Error> {
        self.execute_raw(match self.engine() {
            Engine::MySql => "START TRANSACTION",
            Engine::PostgreSql => "BEGIN",
        })
        .await
    }

    pub async fn commit(&mut self) -> Result<(), sqlx::Error> {
        self.execute_raw("COMMIT").await
    }

    pub async fn rollback(&mut self) -> Result<(), sqlx::Error> {
        self.execute_raw("ROLLBACK").await
    }

    /// Takes Flyway's lock on this connection. On PostgreSQL it is a transaction-level advisory lock,
    /// as Flyway 12 takes it by default (`flyway.postgresql.transactional.lock`): a transaction is opened
    /// here and the lock ends with it, at [`Conn::unlock`]. On MySQL it is a named lock held by the
    /// session.
    pub async fn lock(&mut self, schema: &str) -> Result<(), Error> {
        match self {
            Conn::MySql(conn) => {
                // `MySQLNamedLockTemplate.lock`: GET_LOCK with a 10-second wait, again every 100 ms, forever.
                let name = mysql_lock_name(schema);
                loop {
                    let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?,10)").bind(&name).fetch_one(&mut *conn).await?;
                    if got == Some(1) {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            Conn::PostgreSql(conn) => {
                // `PostgreSQLAdvisoryLockTemplate` with `RetryStrategy`'s defaults: 50 tries a second apart.
                let number = postgres_lock_number(schema);
                sqlx::raw_sql("BEGIN").execute(&mut *conn).await?;
                for _ in 0..=50 {
                    let got: bool = sqlx::query_scalar(&format!("SELECT pg_try_advisory_xact_lock({number})"))
                        .fetch_one(&mut *conn)
                        .await?;
                    if got {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                let _ = sqlx::raw_sql("ROLLBACK").execute(&mut *conn).await;
                Err(Error::LockTimeout)
            }
        }
    }

    /// Releases the lock [`Conn::lock`] took: commits PostgreSQL's transaction, releases MySQL's name.
    pub async fn unlock(&mut self, schema: &str, commit: bool) -> Result<(), Error> {
        match self {
            Conn::MySql(conn) => {
                sqlx::query("SELECT RELEASE_LOCK(?)").bind(mysql_lock_name(schema)).execute(conn).await?;
            }
            Conn::PostgreSql(conn) => {
                sqlx::raw_sql(if commit { "COMMIT" } else { "ROLLBACK" }).execute(conn).await?;
            }
        }
        Ok(())
    }

    pub async fn close(self) -> Result<(), sqlx::Error> {
        match self {
            Conn::MySql(conn) => conn.close().await,
            Conn::PostgreSql(conn) => conn.close().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_is_java_s() {
        // Values printed by `"…".hashCode()` in jshell.
        assert_eq!(java_hash_code(""), 0);
        assert_eq!(java_hash_code("a"), 97);
        assert_eq!(java_hash_code("hello"), 99_162_322);
        assert_eq!(java_hash_code("flyway_schema_history"), 1_610_714_361);
        assert_eq!(java_hash_code("`vectispire`.`flyway_schema_history`"), -986_636_733);
        assert_eq!(java_hash_code("\"public\".\"flyway_schema_history\""), 2_125_624_436);
        assert_eq!(mysql_lock_name("vectispire"), "Flyway--986636733");
    }

    #[test]
    fn the_table_is_quoted_as_flyway_prints_it() {
        assert_eq!(qualified(Engine::MySql, "vectispire"), "`vectispire`.`flyway_schema_history`");
        assert_eq!(qualified(Engine::PostgreSql, "public"), "\"public\".\"flyway_schema_history\"");
    }

    #[test]
    fn long_texts_are_abbreviated_as_flyway_abbreviates_them() {
        let long = "x".repeat(250);
        assert_eq!(abbreviate_description(&long).chars().count(), 200);
        assert!(abbreviate_description(&long).ends_with("..."));
        assert_eq!(abbreviate_description("short"), "short");
        let script = format!("ab{}", "y".repeat(1200));
        let abbreviated = abbreviate_script(&script);
        assert_eq!(abbreviated.chars().count(), 1000);
        assert!(abbreviated.starts_with("...y"));
    }
}
