//! The schema check that stands where `ddl-auto: validate` stood: what the code declares against what
//! the migrations built, on whichever engine it runs.
//!
//! **The schema has one authority, the migrations.** Nothing here creates or alters a column; a
//! disagreement fails the start, as Hibernate's validation fails the context, and the fix is a
//! migration or a declaration — never a reconciliation at run time (AGENTS.md, "`ddl-auto` stays
//! `validate`").
//!
//! **Stricter than Hibernate on purpose.** Hibernate checks that a column exists with a compatible
//! type; this also checks nullability and the length of `varchar`/`char`, because those are what a
//! write trips on — a `NOT NULL` the code thinks optional fails an insert, a `varchar(64)` the code
//! thinks 255 fails one on MySQL's strict mode and on PostgreSQL alike. Columns the schema has and the
//! declaration does not name are not refused: Hibernate ignores them too, and a migration adding a
//! column must not break a control plane that has not learnt to read it yet.

use std::collections::BTreeMap;
use std::fmt;

use sqlx::FromRow;

use crate::db::Db;
use crate::engine::Engine;

/// What a column holds, in the vocabulary of the migrations rather than of either engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    /// `${id}`: `bigint auto_increment` / `bigint generated always as identity`. A few PostgreSQL
    /// columns from before the placeholders are a `nextval` default instead, which inserts the same way.
    Identity,
    BigInt,
    Int,
    Varchar(u32),
    /// `char(n)` / `character(n)` — the UUID ids are `Char(36)`.
    Char(u32),
    /// `longtext` or `text` on MySQL — which, matters: `text` holds 64 KiB — and `text` on PostgreSQL.
    Text(MySqlText),
    /// `${bool}` is `bit(1)`; older tables have `tinyint(1)`. Both read and write as `bool`.
    Bool,
    /// `${ts}`: `datetime(6)` / `timestamp with time zone`, microseconds, UTC.
    Timestamp,
    /// Spelled before the placeholders: MySQL `timestamp`, **to the second** (a written microsecond is
    /// rounded away, as it is for the Java side) — and on PostgreSQL either `timestamp with time zone`
    /// or `timestamp without time zone` holding UTC. Read it with [`crate::types::UtcInstant`].
    LegacyTimestamp {
        postgres_zoned: bool,
    },
    /// `${double}`: `double` / `double precision`.
    Double,
    /// `${bytes}`: `longblob` / `bytea`.
    Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MySqlText {
    Long,
    Regular,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    pub name: &'static str,
    pub ty: ColumnType,
    pub nullable: bool,
}

/// A table as a module's persistence declares it.
#[derive(Debug, Clone, Copy)]
pub struct Table {
    pub name: &'static str,
    pub columns: &'static [Column],
}

pub const fn column(name: &'static str, ty: ColumnType) -> Column {
    Column { name, ty, nullable: false }
}

pub const fn nullable(name: &'static str, ty: ColumnType) -> Column {
    Column { name, ty, nullable: true }
}

/// A table as a SeaORM entity declares it — [`crate::orm::entity_table`] reads it off the entity, so the check
/// judges the declaration the statements are built from, and not a list kept beside it.
#[derive(Debug, Clone)]
pub struct EntityTable {
    pub name: &'static str,
    pub columns: Vec<Column>,
}

/// One way the schema disagrees with a declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    MissingTable { table: &'static str },
    MissingColumn { table: &'static str, column: &'static str },
    Type { table: &'static str, column: &'static str, declared: ColumnType, found: String },
    Nullability { table: &'static str, column: &'static str, declared_nullable: bool },
}

impl fmt::Display for Mismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mismatch::MissingTable { table } => write!(formatter, "{table}: no such table"),
            Mismatch::MissingColumn { table, column } => write!(formatter, "{table}.{column}: no such column"),
            Mismatch::Type { table, column, declared, found } => {
                write!(formatter, "{table}.{column}: declared {declared:?}, the schema has {found}")
            }
            Mismatch::Nullability { table, column, declared_nullable: true } => {
                write!(formatter, "{table}.{column}: declared nullable, the schema has NOT NULL")
            }
            Mismatch::Nullability { table, column, declared_nullable: false } => {
                write!(formatter, "{table}.{column}: declared NOT NULL, the schema allows null")
            }
        }
    }
}

/// Every disagreement found, not only the first — one start should say everything that is wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParityError {
    #[error("the schema could not be read: {0}")]
    Unreadable(String),
    #[error("the {engine} schema disagrees with the declarations:\n  {}", .mismatches.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n  "))]
    Mismatches { engine: Engine, mismatches: Vec<Mismatch> },
}

/// A column as the engine reports it, normalised to what the comparison needs.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
struct Found {
    table_name: String,
    column_name: String,
    /// MySQL `column_type` (`varchar(64)`, `bit(1)`) or PostgreSQL `data_type` (`character varying`).
    spelled: String,
    length: Option<i64>,
    precision: Option<i64>,
    nullable: bool,
    generated: bool,
}

/// Compares `tables` with the schema `db` reaches.
pub async fn check(db: &Db, tables: &[Table]) -> Result<(), ParityError> {
    let found = read(db).await.map_err(|error| ParityError::Unreadable(error.to_string()))?;
    let mismatches = compare(db.engine(), tables, &found);
    if mismatches.is_empty() { Ok(()) } else { Err(ParityError::Mismatches { engine: db.engine(), mismatches }) }
}

/// Compares the entities' tables with the schema `db` reaches — what `check` does for a declared [`Table`].
pub async fn check_entities(db: &Db, tables: &[EntityTable]) -> Result<(), ParityError> {
    let declared: Vec<Table> = tables.iter().map(|table| Table { name: table.name, columns: &[] }).collect();
    let found = read(db).await.map_err(|error| ParityError::Unreadable(error.to_string()))?;
    let mismatches: Vec<Mismatch> = declared
        .iter()
        .zip(tables)
        .flat_map(|(table, entity)| compare_columns(db.engine(), table.name, &entity.columns, &found))
        .collect();
    if mismatches.is_empty() { Ok(()) } else { Err(ParityError::Mismatches { engine: db.engine(), mismatches }) }
}

async fn read(db: &Db) -> Result<BTreeMap<(String, String), Found>, sqlx::Error> {
    // The current schema only — `database()` / `current_schema()` — so a server shared with other
    // databases cannot make a missing table look present.
    let rows: Vec<Found> = match db {
        Db::MySql(pool) => {
            sqlx::query_as(
                "select table_name as table_name, column_name as column_name, column_type as spelled, \
                 cast(character_maximum_length as signed) as length, cast(datetime_precision as signed) as `precision`, \
                 is_nullable = 'YES' as nullable, extra like '%auto_increment%' as `generated` \
                 from information_schema.columns where table_schema = database()",
            )
            .fetch_all(pool)
            .await?
        }
        Db::PostgreSql(pool) => {
            sqlx::query_as(
                "select table_name::text as table_name, column_name::text as column_name, data_type::text as spelled, \
                 character_maximum_length::bigint as length, datetime_precision::bigint as precision, \
                 is_nullable = 'YES' as nullable, \
                 (is_identity = 'YES' or coalesce(column_default, '') like 'nextval(%') as generated \
                 from information_schema.columns where table_schema = current_schema()",
            )
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows.into_iter().map(|row| ((row.table_name.clone(), row.column_name.clone()), row)).collect())
}

fn compare(engine: Engine, tables: &[Table], found: &BTreeMap<(String, String), Found>) -> Vec<Mismatch> {
    tables.iter().flat_map(|table| compare_columns(engine, table.name, table.columns, found)).collect()
}

fn compare_columns(
    engine: Engine,
    table: &'static str,
    columns: &[Column],
    found: &BTreeMap<(String, String), Found>,
) -> Vec<Mismatch> {
    let mut mismatches = Vec::new();
    if !found.keys().any(|(name, _)| name == table) {
        mismatches.push(Mismatch::MissingTable { table });
        return mismatches;
    }
    for column in columns {
        let Some(actual) = found.get(&(table.to_owned(), column.name.to_owned())) else {
            mismatches.push(Mismatch::MissingColumn { table, column: column.name });
            continue;
        };
        if !matches_type(engine, column.ty, actual) {
            mismatches.push(Mismatch::Type {
                table,
                column: column.name,
                declared: column.ty,
                found: describe(actual),
            });
        }
        if column.nullable != actual.nullable {
            mismatches.push(Mismatch::Nullability { table, column: column.name, declared_nullable: column.nullable });
        }
    }
    mismatches
}

fn describe(found: &Found) -> String {
    // PostgreSQL reports a length apart from the type's name; MySQL's `column_type` already holds it.
    match found.length {
        Some(length) if found.spelled.starts_with("character") => format!("{}({length})", found.spelled),
        _ => found.spelled.clone(),
    }
}

fn matches_type(engine: Engine, declared: ColumnType, found: &Found) -> bool {
    let spelled = found.spelled.as_str();
    let length = |n: u32| found.length == Some(i64::from(n));
    match (engine, declared) {
        (Engine::MySql, ColumnType::Identity) => spelled == "bigint" && found.generated,
        (Engine::MySql, ColumnType::BigInt) => spelled == "bigint" && !found.generated,
        (Engine::MySql, ColumnType::Int) => spelled == "int",
        (Engine::MySql, ColumnType::Varchar(n)) => spelled == format!("varchar({n})"),
        (Engine::MySql, ColumnType::Char(n)) => spelled == format!("char({n})"),
        (Engine::MySql, ColumnType::Text(MySqlText::Long)) => spelled == "longtext",
        (Engine::MySql, ColumnType::Text(MySqlText::Regular)) => spelled == "text",
        (Engine::MySql, ColumnType::Bool) => spelled == "bit(1)" || spelled == "tinyint(1)",
        (Engine::MySql, ColumnType::Timestamp) => spelled == "datetime(6)",
        (Engine::MySql, ColumnType::LegacyTimestamp { .. }) => spelled == "timestamp",
        (Engine::MySql, ColumnType::Double) => spelled == "double",
        (Engine::MySql, ColumnType::Bytes) => spelled == "longblob",

        (Engine::PostgreSql, ColumnType::Identity) => spelled == "bigint" && found.generated,
        (Engine::PostgreSql, ColumnType::BigInt) => spelled == "bigint" && !found.generated,
        (Engine::PostgreSql, ColumnType::Int) => spelled == "integer",
        (Engine::PostgreSql, ColumnType::Varchar(n)) => spelled == "character varying" && length(n),
        (Engine::PostgreSql, ColumnType::Char(n)) => spelled == "character" && length(n),
        (Engine::PostgreSql, ColumnType::Text(_)) => spelled == "text",
        (Engine::PostgreSql, ColumnType::Bool) => spelled == "boolean",
        (Engine::PostgreSql, ColumnType::Timestamp) => {
            spelled == "timestamp with time zone" && found.precision == Some(6)
        }
        (Engine::PostgreSql, ColumnType::LegacyTimestamp { postgres_zoned: true }) => {
            spelled == "timestamp with time zone"
        }
        (Engine::PostgreSql, ColumnType::LegacyTimestamp { postgres_zoned: false }) => {
            spelled == "timestamp without time zone"
        }
        (Engine::PostgreSql, ColumnType::Double) => spelled == "double precision",
        (Engine::PostgreSql, ColumnType::Bytes) => spelled == "bytea",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ColumnType::*;

    fn found(
        table: &str,
        column: &str,
        spelled: &str,
        length: Option<i64>,
        nullable: bool,
        generated: bool,
    ) -> ((String, String), Found) {
        (
            (table.to_owned(), column.to_owned()),
            Found {
                table_name: table.to_owned(),
                column_name: column.to_owned(),
                spelled: spelled.to_owned(),
                length,
                precision: None,
                nullable,
                generated,
            },
        )
    }

    const USERS: Table = Table {
        name: "t_user",
        columns: &[
            column("id", Identity),
            column("username", Varchar(255)),
            nullable("totp_secret", Text(MySqlText::Regular)),
        ],
    };

    #[test]
    fn a_schema_that_agrees_says_nothing() {
        let schema = BTreeMap::from([
            found("t_user", "id", "bigint", None, false, true),
            found("t_user", "username", "varchar(255)", Some(255), false, false),
            found("t_user", "totp_secret", "text", Some(65_535), true, false),
            found("t_user", "added_later", "int", None, true, false),
        ]);
        assert_eq!(compare(Engine::MySql, &[USERS], &schema), vec![]);
    }

    #[test]
    fn every_disagreement_is_reported_at_once() {
        let schema = BTreeMap::from([
            found("t_user", "id", "bigint", None, false, false),
            found("t_user", "username", "varchar(64)", Some(64), true, false),
        ]);
        let mismatches = compare(Engine::MySql, &[USERS, Table { name: "t_gone", columns: &[] }], &schema);
        let said: Vec<String> = mismatches.iter().map(ToString::to_string).collect();
        assert_eq!(
            said,
            [
                "t_user.id: declared Identity, the schema has bigint",
                "t_user.username: declared Varchar(255), the schema has varchar(64)",
                "t_user.username: declared NOT NULL, the schema allows null",
                "t_user.totp_secret: no such column",
                "t_gone: no such table",
            ]
        );
    }

    #[test]
    fn a_text_of_64_kib_is_not_a_long_text() {
        let schema = BTreeMap::from([found("t_x", "body", "text", Some(65_535), false, false)]);
        const BODY: &[Column] = &[column("body", Text(MySqlText::Long))];
        let table = Table { name: "t_x", columns: BODY };
        assert_eq!(compare(Engine::MySql, &[table], &schema).len(), 1);
        assert_eq!(
            compare(Engine::PostgreSql, &[table], &BTreeMap::from([found("t_x", "body", "text", None, false, false)])),
            vec![]
        );
    }
}
