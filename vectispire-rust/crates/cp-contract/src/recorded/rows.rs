//! Every table, read and written as the recorder reads them (`RowSnapshots.java`), on MySQL and PostgreSQL.
//!
//! **The recorder read MySQL through JDBC**: a `bit(1)` or `tinyint(1)` is a boolean, a `datetime` a
//! `LocalDateTime` printed by its `toString` (`2026-10-18T10:15` when the seconds are zero), a blob
//! `«bytes:<length>:<16 hex of its SHA-256>»`, a JSON column its text. Each value is selected here as text in SQL
//! and turned into what JDBC's object would have printed, so that a row of either engine compares with the
//! recording — and every statement is built at run time from the schema the server reports, which is why none of
//! them can be a checked `query!`.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::{AssertSqlSafe, Row};
use vectispire_cp_db::{Db, Engine};

use crate::json::Json;
use crate::recorded::placeholders::{Bindings, Context, Unseedable, renders_alike};

/// Why the database did not do what the replay asked.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct RowsError(pub String);

fn failed(what: &str, error: impl std::fmt::Display) -> RowsError {
    RowsError(format!("{what}: {error}"))
}

/// What a column holds, as far as reading it back is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Integer,
    Boolean,
    Text,
    DateTime,
    Date,
    Time,
    Bytes,
    /// A PostgreSQL large object (`oid`), the blob of `MigrationDialect`'s `${blob}`.
    LargeObject,
    Number,
}

#[derive(Clone, Debug)]
pub struct Column {
    pub name: String,
    pub kind: Kind,
    /// PostgreSQL's type name, which a bound text is cast to.
    pub cast: String,
    /// `timestamptz` on PostgreSQL: read in UTC, as the recorder's `LocalDateTime` of MySQL's `timestamp`.
    pub zoned: bool,
}

#[derive(Clone, Debug)]
pub struct Table {
    pub name: String,
    pub columns: Vec<Column>,
    /// The primary key's columns, by position; empty when the table has none — its whole row is then its key.
    pub key: Vec<usize>,
    /// The identity column and, on PostgreSQL, its sequence.
    pub identity: Option<(String, Option<String>)>,
    /// PostgreSQL's `generated always as identity`: an explicit id needs `overriding system value`.
    pub always: bool,
    pub base: Option<i64>,
}

impl Table {
    /// The recorder's `numericKey`: rows keep the order they were created in.
    #[must_use]
    pub fn numeric_key(&self) -> bool {
        self.identity.is_some() && self.key.len() == 1
    }

    /// A row as the recorder shows it: `{column: value}` in declared order.
    #[must_use]
    pub fn object(&self, row: &[Json]) -> Json {
        as_object(self, row)
    }

    fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|column| column.name == name)
    }
}

/// The schema the server reports: the tables the recorder reads, `flyway_schema_history` left out.
#[derive(Clone, Debug)]
pub struct Schema {
    pub engine: Engine,
    pub tables: Vec<Table>,
}

async fn texts(db: &Db, sql: &str) -> Result<Vec<Vec<Option<String>>>, RowsError> {
    let statement = AssertSqlSafe(sql.to_owned());
    match db {
        Db::MySql(pool) => {
            let rows = sqlx::query(statement).fetch_all(pool).await.map_err(|error| failed(sql, error))?;
            rows.iter()
                .map(|row| {
                    (0..row.len())
                        .map(|index| row.try_get::<Option<String>, _>(index).map_err(|error| failed(sql, error)))
                        .collect()
                })
                .collect()
        }
        Db::PostgreSql(pool) => {
            let rows = sqlx::query(statement).fetch_all(pool).await.map_err(|error| failed(sql, error))?;
            rows.iter()
                .map(|row| {
                    (0..row.len())
                        .map(|index| row.try_get::<Option<String>, _>(index).map_err(|error| failed(sql, error)))
                        .collect()
                })
                .collect()
        }
    }
}

fn cell(row: &[Option<String>], index: usize) -> String {
    row.get(index).cloned().flatten().unwrap_or_default()
}

impl Schema {
    /// Reads the tables, their columns in declared order, their keys and identities. `bases` are the recording's.
    pub async fn read(db: &Db, bases: &[(String, i64)]) -> Result<Schema, RowsError> {
        let engine = db.engine();
        let (columns_sql, keys_sql) = match engine {
            Engine::MySql => (
                "select cast(lower(table_name) as char), cast(lower(column_name) as char), cast(lower(data_type) as char), \
                 cast(lower(column_type) as char), cast(lower(extra) as char), '' from information_schema.columns \
                 where table_schema = database() order by table_name, ordinal_position",
                "select cast(lower(table_name) as char), cast(lower(column_name) as char) from information_schema.key_column_usage \
                 where table_schema = database() and constraint_name = 'PRIMARY' order by table_name, ordinal_position",
            ),
            Engine::PostgreSql => (
                "select c.table_name::text, c.column_name::text, c.data_type::text, c.udt_name::text, \
                 case when c.is_identity = 'YES' then 'identity ' || lower(coalesce(c.identity_generation, '')) \
                      when c.column_default like 'nextval(%' then 'serial' else '' end, \
                 coalesce(pg_get_serial_sequence(quote_ident(c.table_name), c.column_name), '') \
                 from information_schema.columns c join information_schema.tables t \
                   on t.table_schema = c.table_schema and t.table_name = c.table_name and t.table_type = 'BASE TABLE' \
                 where c.table_schema = current_schema() order by c.table_name, c.ordinal_position",
                "select kcu.table_name::text, kcu.column_name::text from information_schema.table_constraints tc \
                 join information_schema.key_column_usage kcu on tc.constraint_name = kcu.constraint_name \
                   and tc.table_schema = kcu.table_schema and tc.table_name = kcu.table_name \
                 where tc.constraint_type = 'PRIMARY KEY' and tc.table_schema = current_schema() \
                 order by kcu.table_name, kcu.ordinal_position",
            ),
        };
        let mut tables: BTreeMap<String, Table> = BTreeMap::new();
        for row in texts(db, columns_sql).await? {
            let table = cell(&row, 0);
            if table == "flyway_schema_history" {
                continue;
            }
            let (name, data_type, full_type, extra, sequence) =
                (cell(&row, 1), cell(&row, 2), cell(&row, 3), cell(&row, 4), cell(&row, 5));
            let kind = kind_of(engine, &data_type, &full_type);
            let entry = tables.entry(table.clone()).or_insert_with(|| Table {
                name: table.clone(),
                columns: Vec::new(),
                key: Vec::new(),
                identity: None,
                always: false,
                base: bases.iter().find(|(named, _)| *named == table).map(|(_, base)| *base),
            });
            if extra.contains("auto_increment") || extra.starts_with("identity") || extra == "serial" {
                entry.identity = Some((name.clone(), (!sequence.is_empty()).then_some(sequence)));
                entry.always |= extra.contains("always");
            }
            entry.columns.push(Column {
                name,
                kind,
                cast: full_type.clone(),
                zoned: engine == Engine::PostgreSql && full_type == "timestamptz",
            });
        }
        for row in texts(db, keys_sql).await? {
            let (table, column) = (cell(&row, 0), cell(&row, 1));
            if let Some(entry) = tables.get_mut(&table)
                && let Some(position) = entry.columns.iter().position(|known| known.name == column)
            {
                entry.key.push(position);
            }
        }
        Ok(Schema { engine, tables: tables.into_values().collect() })
    }

    #[must_use]
    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables.iter().find(|table| table.name == name)
    }
}

fn kind_of(engine: Engine, data_type: &str, full_type: &str) -> Kind {
    match engine {
        Engine::MySql => match data_type {
            "bit" => Kind::Boolean,
            "tinyint" if full_type.starts_with("tinyint(1)") => Kind::Boolean,
            "tinyint" | "smallint" | "mediumint" | "int" | "integer" | "bigint" => Kind::Integer,
            "datetime" | "timestamp" => Kind::DateTime,
            "date" => Kind::Date,
            "time" => Kind::Time,
            "blob" | "tinyblob" | "mediumblob" | "longblob" | "binary" | "varbinary" => Kind::Bytes,
            "decimal" | "numeric" | "double" | "float" | "real" => Kind::Number,
            _ => Kind::Text,
        },
        Engine::PostgreSql => match full_type {
            "bool" => Kind::Boolean,
            "int2" | "int4" | "int8" => Kind::Integer,
            "timestamp" | "timestamptz" => Kind::DateTime,
            "date" => Kind::Date,
            "time" | "timetz" => Kind::Time,
            "bytea" => Kind::Bytes,
            "oid" => Kind::LargeObject,
            "numeric" | "float4" | "float8" => Kind::Number,
            _ => Kind::Text,
        },
    }
}

/// How a column is selected: as text, in a form that turns into what JDBC printed.
fn select_expression(engine: Engine, column: &Column) -> String {
    let name = quoted(engine, &column.name);
    match (engine, column.kind) {
        (Engine::MySql, Kind::Boolean) => format!("cast({name} + 0 as char)"),
        (Engine::MySql, Kind::DateTime) => format!("date_format({name}, '%Y-%m-%d %H:%i:%s.%f')"),
        (Engine::MySql, Kind::Bytes) => format!("concat(length({name}), ':', left(sha2({name}, 256), 16))"),
        (Engine::MySql, _) => format!("cast({name} as char)"),
        (Engine::PostgreSql, Kind::DateTime) if column.zoned => {
            format!("to_char({name} at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS.US')")
        }
        (Engine::PostgreSql, Kind::DateTime) => format!("to_char({name}, 'YYYY-MM-DD HH24:MI:SS.US')"),
        (Engine::PostgreSql, Kind::Bytes) => {
            format!("octet_length({name})::text || ':' || left(encode(sha256({name}), 'hex'), 16)")
        }
        (Engine::PostgreSql, Kind::LargeObject) => {
            format!("octet_length(lo_get({name}))::text || ':' || left(encode(sha256(lo_get({name})), 'hex'), 16)")
        }
        (Engine::PostgreSql, _) => format!("{name}::text"),
    }
}

fn quoted(engine: Engine, name: &str) -> String {
    match engine {
        Engine::MySql => format!("`{name}`"),
        Engine::PostgreSql => format!("\"{name}\""),
    }
}

/// `LocalDateTime.toString` / `LocalTime.toString` from `HH:MM:SS.ffffff`: the seconds only when they or the
/// fraction are not zero, the fraction in groups of three.
fn java_time(text: &str) -> String {
    let (clock, fraction) = text.split_once('.').unwrap_or((text, ""));
    let mut parts = clock.split(':');
    let (hours, minutes, seconds) =
        (parts.next().unwrap_or("00"), parts.next().unwrap_or("00"), parts.next().unwrap_or("00"));
    let fraction = fraction.trim_end_matches('0');
    let grouped = match fraction.chars().count() {
        0 => String::new(),
        1..=3 => format!(".{fraction:0<3}"),
        4..=6 => format!(".{fraction:0<6}"),
        _ => format!(".{fraction:0<9}"),
    };
    if seconds == "00" && grouped.is_empty() {
        format!("{hours}:{minutes}")
    } else {
        format!("{hours}:{minutes}:{seconds}{grouped}")
    }
}

/// A value as the recorder wrote it.
fn rendered(column: &Column, text: Option<String>) -> Json {
    let Some(text) = text else {
        return Json::Null;
    };
    match column.kind {
        Kind::Integer | Kind::Number => Json::Num(text),
        Kind::Boolean => Json::Bool(text == "1" || text == "true" || text == "t"),
        Kind::DateTime => {
            let (date, time) = text.split_once(' ').unwrap_or((&text, "00:00:00"));
            Json::Str(format!("{date}T{}", java_time(time)))
        }
        Kind::Time => Json::Str(java_time(&text)),
        Kind::Bytes | Kind::LargeObject => {
            let (length, digest) = text.split_once(':').unwrap_or(("?", ""));
            Json::Str(format!("«bytes:{length}:{digest}»"))
        }
        Kind::Text | Kind::Date => Json::Str(text),
    }
}

/// One table's rows, each in column order.
pub type Rows = Vec<Vec<Json>>;

/// Every table at one instant.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub tables: BTreeMap<String, Rows>,
}

/// More rows than the recorder reads: `RowSnapshots.ROW_CEILING`.
pub const ROW_CEILING: usize = 5_000;

/// Reads every table.
pub async fn snapshot(db: &Db, schema: &Schema) -> Result<Snapshot, RowsError> {
    let mut out = Snapshot::default();
    for table in &schema.tables {
        let expressions: Vec<String> =
            table.columns.iter().map(|column| select_expression(schema.engine, column)).collect();
        let sql = format!(
            "select {} from {} limit {}",
            expressions.join(", "),
            quoted(schema.engine, &table.name),
            ROW_CEILING.saturating_add(1)
        );
        let rows = texts(db, &sql)
            .await?
            .into_iter()
            .map(|row| table.columns.iter().zip(row).map(|(column, text)| rendered(column, text)).collect())
            .collect();
        out.tables.insert(table.name.clone(), rows);
    }
    Ok(out)
}

fn key_of(table: &Table, row: &[Json]) -> Vec<String> {
    if table.key.is_empty() {
        return row.iter().map(Json::to_text).collect();
    }
    table.key.iter().map(|index| row.get(*index).map_or_else(String::new, Json::to_text)).collect()
}

fn as_object(table: &Table, row: &[Json]) -> Json {
    Json::Obj(table.columns.iter().zip(row).map(|(column, value)| (column.name.clone(), value.clone())).collect())
}

/// Ranks repeated rows of a table without a key, as the recorder does (`#1`, `#2`).
fn keyed(table: &Table, rows: &Rows) -> BTreeMap<Vec<String>, Vec<Json>> {
    let mut out = BTreeMap::new();
    for row in rows {
        let mut key = key_of(table, row);
        if table.key.is_empty() {
            let mut rank = 1_u32;
            loop {
                let mut candidate = key.clone();
                candidate.push(format!("#{rank}"));
                if !out.contains_key(&candidate) {
                    key = candidate;
                    break;
                }
                rank = rank.saturating_add(1);
            }
        }
        out.insert(key, row.clone());
    }
    out
}

fn numeric(key: &[String]) -> Vec<i128> {
    key.iter().map(|part| part.parse().unwrap_or(0)).collect()
}

/// `RowSnapshots.diff`, with `dropUnchangedUpdates`: what changed from `before` to `after`, table by table, as the
/// recording shows it — before placeholders. `today` places the recorder's date window.
#[must_use]
pub fn diff(schema: &Schema, before: &Snapshot, after: &Snapshot, today: time::Date) -> Json {
    let mut tables = Vec::new();
    for table in &schema.tables {
        let (Some(was), Some(is)) = (before.tables.get(&table.name), after.tables.get(&table.name)) else {
            continue;
        };
        if was.len() > ROW_CEILING || is.len() > ROW_CEILING {
            tables.push((table.name.clone(), Json::Obj(vec![("overCeiling".to_owned(), Json::Bool(true))])));
            continue;
        }
        let (old, new) = (keyed(table, was), keyed(table, is));
        let mut keys: Vec<&Vec<String>> = old.keys().chain(new.keys()).collect::<BTreeSet<_>>().into_iter().collect();
        if table.numeric_key() {
            keys.sort_by_key(|key| numeric(key));
        }
        let (mut inserted, mut updated, mut deleted) = (Vec::new(), Vec::new(), Vec::new());
        for key in keys {
            match (old.get(key), new.get(key)) {
                (None, Some(row)) => inserted.push(as_object(table, row)),
                (Some(row), None) => deleted.push(as_object(table, row)),
                (Some(from), Some(to)) if from != to => {
                    let changed: Vec<(String, Json)> = table
                        .columns
                        .iter()
                        .zip(from.iter().zip(to))
                        .filter(|(column, (from, to))| {
                            from != to && !renders_alike(today, &column.name, &from.to_text(), &to.to_text())
                        })
                        .map(|(column, (from, to))| {
                            (
                                column.name.clone(),
                                Json::Obj(vec![("from".to_owned(), from.clone()), ("to".to_owned(), to.clone())]),
                            )
                        })
                        .collect();
                    if !changed.is_empty() {
                        let key_columns: Vec<(String, Json)> = table
                            .key
                            .iter()
                            .filter_map(|index| {
                                Some((table.columns.get(*index)?.name.clone(), to.get(*index)?.clone()))
                            })
                            .collect();
                        updated.push(Json::Obj(vec![
                            ("key".to_owned(), Json::Obj(key_columns)),
                            ("changed".to_owned(), Json::Obj(changed)),
                        ]));
                    }
                }
                _ => {}
            }
        }
        let mut changes = Vec::new();
        for (name, list) in [("inserted", inserted), ("updated", updated), ("deleted", deleted)] {
            if !list.is_empty() {
                changes.push((name.to_owned(), Json::Arr(list)));
            }
        }
        if !changes.is_empty() {
            tables.push((table.name.clone(), Json::Obj(changes)));
        }
    }
    Json::Obj(tables)
}

/// A value bound to a statement.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Bound {
    Null,
    Text(String),
    Integer(i64),
    /// A blob, in hex: `unhex` / `decode` in the statement.
    Hex(String),
}

/// One statement of a seed.
#[derive(Clone, Debug)]
struct Statement {
    sql: String,
    values: Vec<Bound>,
}

/// A seed — or the effect of a request the replay plays in Java's place — turned into statements.
#[derive(Debug, Default)]
pub struct Writes {
    deletes: Vec<Statement>,
    inserts: Vec<Statement>,
    updates: Vec<Statement>,
    /// Tables an explicit id went into: PostgreSQL's sequence does not move by itself.
    identities_written: BTreeSet<String>,
}

impl Writes {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.deletes.is_empty() && self.inserts.is_empty() && self.updates.is_empty()
    }
}

/// A recorded value made concrete for its column.
fn concrete(engine: Engine, column: &Column, value: &Json, bindings: &mut Bindings<'_>) -> Result<Bound, Unseedable> {
    let text = match value {
        Json::Null => return Ok(Bound::Null),
        Json::Bool(flag) => {
            return Ok(match engine {
                // `'1'` into a `bit(1)` is a binary string, too long for the column: MySQL takes the number.
                Engine::MySql => Bound::Integer(i64::from(*flag)),
                Engine::PostgreSql => Bound::Text(flag.to_string()),
            });
        }
        Json::Num(text) => text.clone(),
        Json::Str(template) => bindings.concrete(template, &column.name, Context::Row)?,
        Json::Arr(_) | Json::Obj(_) => {
            return Err(Unseedable(format!("`{}` holds a structure, not a column's value", column.name)));
        }
    };
    if text == "«clob:unreadable»" {
        return Err(Unseedable(format!("`{}` is a text the recorder could not read", column.name)));
    }
    Ok(match column.kind {
        // The recording keeps a blob's length and digest only. Zeros of that length stand in: a row played in Java's
        // place keeps its size, and a served route that reads the content answers differently from Java — shown,
        // never hidden — while one that carries the row along is unaffected.
        Kind::Bytes | Kind::LargeObject => {
            let length = text
                .strip_prefix("«bytes:")
                .and_then(|rest| rest.split(':').next())
                .and_then(|length| length.parse::<usize>().ok())
                .ok_or_else(|| Unseedable(format!("`{}` = {text:?} is not a recorded blob", column.name)))?;
            Bound::Hex("00".repeat(length))
        }
        Kind::Boolean if engine == Engine::MySql => Bound::Integer(i64::from(text == "true" || text == "1")),
        Kind::Integer if engine == Engine::MySql => Bound::Integer(
            text.parse().map_err(|_| Unseedable(format!("`{}` = {text:?} is not an integer", column.name)))?,
        ),
        // `2020-01-01T00:00`, as `LocalDateTime` printed it: both engines read `2020-01-01 00:00`.
        Kind::DateTime => Bound::Text(text.replacen('T', " ", 1)),
        _ => Bound::Text(text),
    })
}

fn placeholder_sql(engine: Engine, column: &Column, position: usize) -> String {
    match (engine, column.kind) {
        (Engine::MySql, Kind::Bytes) => "unhex(?)".to_owned(),
        (Engine::MySql, _) => "?".to_owned(),
        (Engine::PostgreSql, Kind::Bytes) => format!("decode(${position}::text, 'hex')"),
        (Engine::PostgreSql, Kind::LargeObject) => format!("lo_from_bytea(0, decode(${position}::text, 'hex'))"),
        (Engine::PostgreSql, _) => format!("${position}::{}", column.cast),
    }
}

fn row_fields(row: &Json) -> Result<&[(String, Json)], Unseedable> {
    row.as_object().ok_or_else(|| Unseedable("a recorded row is not an object".to_owned()))
}

impl Writes {
    /// The statements for `changes` (`{table: {inserted, updated, deleted}}`), placeholders made concrete through
    /// `bindings`. Refused whole when one value cannot be chosen: a half-applied seed would be a state Java never had.
    pub fn plan(schema: &Schema, changes: &Json, bindings: &mut Bindings<'_>) -> Result<Writes, Unseedable> {
        let mut writes = Writes::default();
        let engine = schema.engine;
        for (name, change) in changes.as_object().unwrap_or(&[]) {
            let table =
                schema.table(name).ok_or_else(|| Unseedable(format!("{name} is not a table of this schema")))?;
            if matches!(change.get("overCeiling"), Some(Json::Bool(true))) {
                return Err(Unseedable(format!("{name} held more rows than the recorder reads")));
            }
            for row in in_chain_order(change.get("inserted").and_then(Json::as_array).unwrap_or(&[])) {
                let mut columns = Vec::new();
                let mut marks = Vec::new();
                let mut values = Vec::new();
                for (column_name, value) in row_fields(row)? {
                    let column = table
                        .column(column_name)
                        .ok_or_else(|| Unseedable(format!("{name}.{column_name} is not a column of this schema")))?;
                    values.push(concrete(engine, column, value, bindings)?);
                    columns.push(quoted(engine, column_name));
                    marks.push(placeholder_sql(engine, column, values.len()));
                    if table.identity.as_ref().is_some_and(|(identity, _)| identity == column_name) {
                        writes.identities_written.insert(name.clone());
                    }
                }
                let overriding =
                    if engine == Engine::PostgreSql && table.always { " overriding system value" } else { "" };
                writes.inserts.push(Statement {
                    sql: format!(
                        "insert into {} ({}){overriding} values ({})",
                        quoted(engine, name),
                        columns.join(", "),
                        marks.join(", ")
                    ),
                    values,
                });
            }
            for update in change.get("updated").and_then(Json::as_array).unwrap_or(&[]) {
                let mut values = Vec::new();
                let mut sets = Vec::new();
                for (column_name, change) in update.get("changed").and_then(Json::as_object).unwrap_or(&[]) {
                    let column = table
                        .column(column_name)
                        .ok_or_else(|| Unseedable(format!("{name}.{column_name} is not a column of this schema")))?;
                    let to = change.get("to").ok_or_else(|| Unseedable(format!("{name}.{column_name}: no `to`")))?;
                    values.push(concrete(engine, column, to, bindings)?);
                    sets.push(format!(
                        "{} = {}",
                        quoted(engine, column_name),
                        placeholder_sql(engine, column, values.len())
                    ));
                }
                let key =
                    update.get("key").ok_or_else(|| Unseedable(format!("an update of {name} without its key")))?;
                let condition = condition(engine, table, row_fields(key)?, &mut values, bindings)?;
                if !sets.is_empty() {
                    writes.updates.push(Statement {
                        sql: format!("update {} set {} where {condition}", quoted(engine, name), sets.join(", ")),
                        values,
                    });
                }
            }
            for row in change.get("deleted").and_then(Json::as_array).unwrap_or(&[]) {
                let fields = row_fields(row)?;
                let key: Vec<(String, Json)> = if table.key.is_empty() {
                    fields.to_vec()
                } else {
                    table
                        .key
                        .iter()
                        .filter_map(|index| table.columns.get(*index))
                        .filter_map(|column| fields.iter().find(|(name, _)| *name == column.name).cloned())
                        .collect()
                };
                let mut values = Vec::new();
                let condition = condition(engine, table, &key, &mut values, bindings)?;
                writes
                    .deletes
                    .push(Statement { sql: format!("delete from {} where {condition}", quoted(engine, name)), values });
            }
        }
        Ok(writes)
    }
}

/// Rows linked by `previous_hash` → `entry_hash` (the audit chain), in the order of the chain; any other rows as
/// recorded. The recorder lists a table keyed by a UUID in the order of its masked content, not the order the rows
/// were written in, and the seeded clock follows the list: written as listed, the newest entry by time would not be
/// the chain's head, and the server's next entry would link to the wrong one.
fn in_chain_order(rows: &[Json]) -> Vec<&Json> {
    let text = |row: &Json, column: &str| row.get(column).and_then(Json::as_str).map(str::to_owned);
    if rows.len() < 2 || rows.iter().any(|row| row.get("entry_hash").is_none() || row.get("previous_hash").is_none()) {
        return rows.iter().collect();
    }
    let hashes: BTreeSet<String> = rows.iter().filter_map(|row| text(row, "entry_hash")).collect();
    let mut ordered: Vec<&Json> = Vec::new();
    // The first is the one whose predecessor is not in the batch; each next one names the last as its predecessor.
    let mut current = rows.iter().find(|row| text(row, "previous_hash").is_none_or(|link| !hashes.contains(&link)));
    while let Some(row) = current {
        if ordered.iter().any(|seen| std::ptr::eq(*seen, row)) {
            break;
        }
        ordered.push(row);
        let previous = text(row, "entry_hash");
        current = rows.iter().find(|next| previous.is_some() && text(next, "previous_hash") == previous);
    }
    // A batch that is not one chain is written as recorded: nothing is dropped.
    if ordered.len() != rows.len() {
        return rows.iter().collect();
    }
    ordered
}

fn condition(
    engine: Engine,
    table: &Table,
    key: &[(String, Json)],
    values: &mut Vec<Bound>,
    bindings: &mut Bindings<'_>,
) -> Result<String, Unseedable> {
    if key.is_empty() {
        return Err(Unseedable(format!("a row of {} named by no key", table.name)));
    }
    let mut parts = Vec::new();
    for (column_name, value) in key {
        let column = table
            .column(column_name)
            .ok_or_else(|| Unseedable(format!("{}.{column_name} is not a column of this schema", table.name)))?;
        values.push(concrete(engine, column, value, bindings)?);
        let mark = placeholder_sql(engine, column, values.len());
        // Null-safe: a table without a key is matched on every column, nulls included.
        parts.push(match engine {
            Engine::MySql => format!("{} <=> {mark}", quoted(engine, column_name)),
            Engine::PostgreSql => format!("{} is not distinct from {mark}", quoted(engine, column_name)),
        });
    }
    Ok(parts.join(" and "))
}

/// Runs `writes` in one transaction, the foreign keys unchecked while it runs (a seed lists tables by name, not in
/// the order their keys need), then moves PostgreSQL's sequences past the ids written.
pub async fn apply(db: &Db, schema: &Schema, writes: &Writes) -> Result<(), RowsError> {
    let statements: Vec<&Statement> = writes.deletes.iter().chain(&writes.inserts).chain(&writes.updates).collect();
    match db {
        Db::MySql(pool) => {
            let mut connection = pool.acquire().await.map_err(|error| failed("a connection", error))?;
            sqlx::raw_sql("set foreign_key_checks = 0")
                .execute(&mut *connection)
                .await
                .map_err(|error| failed("foreign keys off", error))?;
            let mut outcome = Ok(());
            for statement in statements {
                let mut query = sqlx::query(AssertSqlSafe(statement.sql.clone()));
                for value in &statement.values {
                    query = match value {
                        Bound::Null => query.bind(None::<String>),
                        Bound::Text(text) | Bound::Hex(text) => query.bind(text.clone()),
                        Bound::Integer(number) => query.bind(*number),
                    };
                }
                if let Err(error) = query.execute(&mut *connection).await {
                    outcome = Err(failed(&statement.sql, error));
                    break;
                }
            }
            // Back on before the connection returns to the pool, whatever happened: the server's own statements
            // run on these connections and must have their keys checked.
            sqlx::raw_sql("set foreign_key_checks = 1")
                .execute(&mut *connection)
                .await
                .map_err(|error| failed("foreign keys on", error))?;
            outcome
        }
        Db::PostgreSql(pool) => {
            let mut transaction = pool.begin().await.map_err(|error| failed("a transaction", error))?;
            sqlx::raw_sql("set local session_replication_role = replica")
                .execute(&mut *transaction)
                .await
                .map_err(|error| failed("foreign keys off", error))?;
            for statement in statements {
                let mut query = sqlx::query(AssertSqlSafe(statement.sql.clone()));
                for value in &statement.values {
                    query = match value {
                        Bound::Null => query.bind(None::<String>),
                        Bound::Text(text) | Bound::Hex(text) => query.bind(text.clone()),
                        Bound::Integer(number) => query.bind(number.to_string()),
                    };
                }
                query.execute(&mut *transaction).await.map_err(|error| failed(&statement.sql, error))?;
            }
            for name in &writes.identities_written {
                if let Some(Table { identity: Some((column, Some(sequence))), .. }) = schema.table(name) {
                    // MySQL's counter moves past an explicit id by itself; a PostgreSQL sequence does not, and the
                    // server's next row would take an id the seed already holds.
                    let sql = format!(
                        "select setval('{sequence}', m) from (select max(\"{column}\") as m from \"{name}\") x, \
                         (select last_value, is_called from {sequence}) s \
                         where x.m is not null and x.m >= s.last_value + case when s.is_called then 1 else 0 end"
                    );
                    sqlx::raw_sql(AssertSqlSafe(sql.clone()))
                        .execute(&mut *transaction)
                        .await
                        .map_err(|error| failed(&sql, error))?;
                }
            }
            transaction.commit().await.map_err(|error| failed("the seed's commit", error))
        }
    }
}

/// Each identity table's next id, as the server holds it now — a test's ranks count from there.
pub async fn next_identities(db: &Db, schema: &Schema) -> Result<BTreeMap<String, i64>, RowsError> {
    let mut out = BTreeMap::new();
    match db {
        Db::MySql(pool) => {
            let mut connection = pool.acquire().await.map_err(|error| failed("a connection", error))?;
            // The statistics are cached for a day by default: the counter read would be yesterday's.
            sqlx::raw_sql("set session information_schema_stats_expiry = 0")
                .execute(&mut *connection)
                .await
                .map_err(|error| failed("the statistics' expiry", error))?;
            let rows = sqlx::query(
                "select cast(lower(table_name) as char), cast(auto_increment as char) from information_schema.tables \
                 where table_schema = database() and auto_increment is not null",
            )
            .fetch_all(&mut *connection)
            .await
            .map_err(|error| failed("the identity counters", error))?;
            for row in rows {
                let table: String = row.try_get(0).map_err(|error| failed("a counter's table", error))?;
                let next: Option<String> = row.try_get(1).map_err(|error| failed("a counter", error))?;
                if let Some(next) = next.and_then(|next| next.parse().ok()) {
                    out.insert(table, next);
                }
            }
        }
        Db::PostgreSql(_) => {
            let parts: Vec<String> = schema
                .tables
                .iter()
                .filter_map(|table| match &table.identity {
                    Some((_, Some(sequence))) => Some(format!(
                        "select '{}', (last_value + case when is_called then 1 else 0 end)::text from {sequence}",
                        table.name
                    )),
                    _ => None,
                })
                .collect();
            if !parts.is_empty() {
                for row in texts(db, &parts.join(" union all ")).await? {
                    if let Ok(next) = cell(&row, 1).parse() {
                        out.insert(cell(&row, 0), next);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Moves a counter: the recorder's `placeIdentities`, for a table whose counter is outside its range.
pub async fn place_identity(db: &Db, table: &Table, next: i64) -> Result<(), RowsError> {
    let sql = match (db, &table.identity) {
        (Db::MySql(_), Some(_)) => format!("alter table `{}` auto_increment = {next}", table.name),
        (Db::PostgreSql(_), Some((_, Some(sequence)))) => format!("select setval('{sequence}', {next}, false)"),
        _ => return Ok(()),
    };
    execute(db, &sql).await
}

async fn execute(db: &Db, sql: &str) -> Result<(), RowsError> {
    let statement = AssertSqlSafe(sql.to_owned());
    match db {
        Db::MySql(pool) => sqlx::raw_sql(statement).execute(pool).await.map(drop),
        Db::PostgreSql(pool) => sqlx::raw_sql(statement).execute(pool).await.map(drop),
    }
    .map_err(|error| failed(sql, error))
}

/// Empties every table, then puts back `kept`'s rows of the tables `restore` names — what a test starts from once
/// the harness has emptied the rest (the manifest's `baseline`).
pub async fn reset(db: &Db, schema: &Schema, kept: &Snapshot, restore: &BTreeSet<String>) -> Result<(), RowsError> {
    match db {
        Db::MySql(pool) => {
            let mut connection = pool.acquire().await.map_err(|error| failed("a connection", error))?;
            sqlx::raw_sql("set foreign_key_checks = 0")
                .execute(&mut *connection)
                .await
                .map_err(|error| failed("foreign keys off", error))?;
            let mut outcome = Ok(());
            for table in &schema.tables {
                let sql = format!("delete from `{}`", table.name);
                if let Err(error) = sqlx::raw_sql(AssertSqlSafe(sql.clone())).execute(&mut *connection).await {
                    outcome = Err(failed(&sql, error));
                    break;
                }
            }
            sqlx::raw_sql("set foreign_key_checks = 1")
                .execute(&mut *connection)
                .await
                .map_err(|error| failed("foreign keys on", error))?;
            outcome?;
        }
        Db::PostgreSql(_) => {
            let names: Vec<String> = schema.tables.iter().map(|table| format!("\"{}\"", table.name)).collect();
            // Without `restart identity`: identities only grow, as they do in production and in the recording.
            execute(db, &format!("truncate {}", names.join(", "))).await?;
        }
    }
    let mut writes = Writes::default();
    for name in restore {
        let (Some(table), Some(rows)) = (schema.table(name), kept.tables.get(name)) else {
            continue;
        };
        for row in rows {
            let mut columns = Vec::new();
            let mut marks = Vec::new();
            let mut values = Vec::new();
            for (column, value) in table.columns.iter().zip(row) {
                values.push(match value {
                    Json::Null => Bound::Null,
                    Json::Bool(flag) if schema.engine == Engine::MySql => Bound::Integer(i64::from(*flag)),
                    Json::Bool(flag) => Bound::Text(flag.to_string()),
                    Json::Num(text) | Json::Str(text) if column.kind == Kind::DateTime => {
                        Bound::Text(text.replacen('T', " ", 1))
                    }
                    Json::Num(text) | Json::Str(text) => Bound::Text(text.clone()),
                    Json::Arr(_) | Json::Obj(_) => Bound::Null,
                });
                columns.push(quoted(schema.engine, &column.name));
                marks.push(placeholder_sql(schema.engine, column, values.len()));
            }
            let overriding =
                if schema.engine == Engine::PostgreSql && table.always { " overriding system value" } else { "" };
            writes.inserts.push(Statement {
                sql: format!(
                    "insert into {} ({}){overriding} values ({})",
                    quoted(schema.engine, name),
                    columns.join(", "),
                    marks.join(", ")
                ),
                values,
            });
        }
    }
    apply(db, schema, &writes).await
}

#[cfg(test)]
mod tests {
    use super::java_time;

    #[test]
    fn times_print_as_java_prints_them() {
        assert_eq!(java_time("10:15:00.000000"), "10:15");
        assert_eq!(java_time("10:15:30.000000"), "10:15:30");
        assert_eq!(java_time("10:15:00.120000"), "10:15:00.120");
        assert_eq!(java_time("10:15:30.123400"), "10:15:30.123400");
        assert_eq!(java_time("10:15:30"), "10:15:30");
    }
}
