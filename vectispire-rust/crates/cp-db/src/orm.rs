//! SeaORM's entities and statements, run on the port's own [`Tx`] — the spike of 2026-10-26.
//!
//! **SeaORM builds, this module runs.** A module's repository describes its tables as SeaORM entities and writes
//! its statements with them (`Entity::find().filter(Column::Id.is_in(ids))`); the statement is rendered here for the
//! transaction's engine by `sea-query-sqlx`, executed with sqlx **on the connection the [`Tx`] holds**, and its rows
//! decoded by SeaORM's `FromQueryResult`. SeaORM's own `DatabaseConnection` and `DatabaseTransaction` are never
//! made: a unit of work that mixes a compile-checked `sqlx::query!` and an entity call is one transaction because
//! there is only one connection to run them on, not because two transaction objects were kept in step.
//!
//! **Checked by [`crate::parity`], not by the compiler.** An entity is a declaration, as a JPA entity is; that it
//! agrees with the schema the migrations built is what [`entity_table`] hands to `parity::check_entities`, on both
//! engines, in the module's suite.
//!
//! **A target's rows are read for a reader through [`Visible`]**, which cannot be built without a [`Visibility`] and
//! writes it as `VisibleSelect` does — the same condition, from the same function.

use std::marker::PhantomData;

use sea_orm::sea_query::{
    Condition, Expr, IntoCondition, MysqlQueryBuilder, Order, PostgresQueryBuilder, SelectStatement, SimpleExpr,
};
use sea_orm::{
    ColumnTrait, ColumnType, EntityTrait, FromQueryResult, IdenStatic, Iterable, PrimaryKeyToColumn, PrimaryKeyTrait,
    QueryFilter, QueryOrder, QueryResult, QuerySelect, QueryTrait, Select,
};
use sea_query_sqlx::SqlxBinder;
use sqlx::AssertSqlSafe;

use crate::parity::{Column, ColumnType as Declared, MySqlText};
use crate::query::{TargetTable, visible};
use crate::tx::Tx;
use crate::visibility::Visibility;

/// Renders `statement` for `tx`'s engine and runs it there, its rows decoded as `M`.
///
/// Sound to assert: the text is sea-query's rendering of identifiers the entities declare; every value a caller
/// supplied is in the bound values.
pub async fn fetch_all<M, S>(tx: &mut Tx, statement: &S) -> Result<Vec<M>, sqlx::Error>
where
    M: FromQueryResult,
    S: SqlxBinder,
{
    match tx {
        Tx::MySql(conn) => {
            let (sql, values) = statement.build_sqlx(MysqlQueryBuilder);
            let rows = sqlx::query_with(AssertSqlSafe(sql), values).fetch_all(&mut **conn).await?;
            rows.into_iter().map(|row| decode(QueryResult::from(row))).collect()
        }
        Tx::PostgreSql(conn) => {
            let (sql, values) = statement.build_sqlx(PostgresQueryBuilder);
            let rows = sqlx::query_with(AssertSqlSafe(sql), values).fetch_all(&mut **conn).await?;
            rows.into_iter().map(|row| decode(QueryResult::from(row))).collect()
        }
    }
}

/// At most one row.
pub async fn fetch_optional<M, S>(tx: &mut Tx, statement: &S) -> Result<Option<M>, sqlx::Error>
where
    M: FromQueryResult,
    S: SqlxBinder,
{
    match tx {
        Tx::MySql(conn) => {
            let (sql, values) = statement.build_sqlx(MysqlQueryBuilder);
            let row = sqlx::query_with(AssertSqlSafe(sql), values).fetch_optional(&mut **conn).await?;
            row.map(|row| decode(QueryResult::from(row))).transpose()
        }
        Tx::PostgreSql(conn) => {
            let (sql, values) = statement.build_sqlx(PostgresQueryBuilder);
            let row = sqlx::query_with(AssertSqlSafe(sql), values).fetch_optional(&mut **conn).await?;
            row.map(|row| decode(QueryResult::from(row))).transpose()
        }
    }
}

/// The single `i64` a count answers — [`Visible::count`], or any `SELECT count(…)`.
pub async fn fetch_count<S: SqlxBinder>(tx: &mut Tx, statement: &S) -> Result<i64, sqlx::Error> {
    match tx {
        Tx::MySql(conn) => {
            let (sql, values) = statement.build_sqlx(MysqlQueryBuilder);
            sqlx::query_scalar_with(AssertSqlSafe(sql), values).fetch_one(&mut **conn).await
        }
        Tx::PostgreSql(conn) => {
            let (sql, values) = statement.build_sqlx(PostgresQueryBuilder);
            sqlx::query_scalar_with(AssertSqlSafe(sql), values).fetch_one(&mut **conn).await
        }
    }
}

/// An `INSERT`, `UPDATE` or `DELETE`: the rows it touched, as the engine counts them (found rows on MySQL, as
/// Connector/J asks for).
pub async fn execute<S: SqlxBinder>(tx: &mut Tx, statement: &S) -> Result<u64, sqlx::Error> {
    Ok(match tx {
        Tx::MySql(conn) => {
            let (sql, values) = statement.build_sqlx(MysqlQueryBuilder);
            sqlx::query_with(AssertSqlSafe(sql), values).execute(&mut **conn).await?.rows_affected()
        }
        Tx::PostgreSql(conn) => {
            let (sql, values) = statement.build_sqlx(PostgresQueryBuilder);
            sqlx::query_with(AssertSqlSafe(sql), values).execute(&mut **conn).await?.rows_affected()
        }
    })
}

/// An `INSERT` of one row into a table whose key the engine generates: the key.
///
/// MySQL has no `RETURNING`; the key is the statement's `last_insert_id`. PostgreSQL answers it, so the statement
/// is given a `RETURNING` of the key column here.
pub async fn insert_returning_id<E: EntityTrait>(
    tx: &mut Tx,
    mut statement: sea_orm::sea_query::InsertStatement,
) -> Result<i64, sqlx::Error> {
    match tx {
        Tx::MySql(conn) => {
            let (sql, values) = statement.build_sqlx(MysqlQueryBuilder);
            let done = sqlx::query_with(AssertSqlSafe(sql), values).execute(&mut **conn).await?;
            i64::try_from(done.last_insert_id())
                .map_err(|_| sqlx::Error::Protocol("a generated key beyond i64".to_owned()))
        }
        Tx::PostgreSql(conn) => {
            let key = E::PrimaryKey::iter()
                .next()
                .ok_or_else(|| sqlx::Error::Protocol(format!("{} declares no key", E::default().table_name())))?;
            statement.returning_col(key.into_column());
            let (sql, values) = statement.build_sqlx(PostgresQueryBuilder);
            sqlx::query_scalar_with(AssertSqlSafe(sql), values).fetch_one(&mut **conn).await
        }
    }
}

fn decode<M: FromQueryResult>(row: QueryResult) -> Result<M, sqlx::Error> {
    M::from_query_result(&row, "").map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

/// An entity whose every row belongs to a target, and which table of [`crate::query`]'s sealed list it is.
///
/// Implementing it is how a module says "a reader's query on these rows goes through [`Visible`]"; the targets'
/// columns are the table's, read from the list beside the rule, never from the module.
pub trait TargetEntity: EntityTrait {
    type Table: TargetTable;
}

/// A `SELECT` on a target's rows for a reader: [`VisibleSelect`](crate::VisibleSelect)'s guarantee, for an entity.
///
/// Built only from a [`Visibility`]; conditions are only **added**. The SeaORM `Select` is never handed out —
/// `QuerySelect::query()` would give a `&mut SelectStatement`, and `and_or_where(Or(…))` on it would put back a row
/// the visibility excluded.
#[derive(Debug, Clone)]
pub struct Visible<E: TargetEntity> {
    select: Select<E>,
    entity: PhantomData<E>,
}

impl<E: TargetEntity> Visible<E> {
    /// `SELECT <every column> FROM <E> WHERE <visibility>`.
    pub fn find(visibility: &Visibility) -> Visible<E> {
        let mut select = E::find();
        if let Some(condition) = visible::<E::Table>(visibility) {
            select = select.filter(condition);
        }
        Visible { select, entity: PhantomData }
    }

    /// Narrows the rows further — `AND`, whatever `condition` holds inside.
    pub fn filter(mut self, condition: impl IntoCondition) -> Visible<E> {
        self.select = self.select.filter(Condition::all().add(condition.into_condition()));
        self
    }

    pub fn order_by(mut self, column: E::Column, order: Order) -> Visible<E> {
        self.select = self.select.order_by(column, order);
        self
    }

    pub fn order_by_expr(mut self, expression: SimpleExpr, order: Order) -> Visible<E> {
        self.select = self.select.order_by(expression, order);
        self
    }

    pub fn limit(mut self, limit: u64) -> Visible<E> {
        self.select = self.select.limit(limit);
        self
    }

    pub fn offset(mut self, offset: u64) -> Visible<E> {
        self.select = self.select.offset(offset);
        self
    }

    /// The rows, every column.
    pub fn statement(&self) -> &SelectStatement {
        self.select.as_query()
    }

    /// `SELECT count(*)` of the same rows.
    pub fn count(&self) -> SelectStatement {
        let mut count = self.select.clone().into_query();
        count.clear_selects().clear_order_by().expr(Expr::cust("count(*)"));
        count.reset_limit().reset_offset();
        count
    }

    /// `SELECT <columns>, count(*) … GROUP BY <columns>` of the same rows.
    pub fn grouped_count(&self, columns: &[E::Column]) -> SelectStatement {
        let mut grouped = self.select.clone().into_query();
        grouped.clear_selects().clear_order_by();
        grouped.reset_limit().reset_offset();
        for column in columns {
            grouped.column(*column).add_group_by([Expr::col(*column)]);
        }
        grouped.expr_as(Expr::cust("count(*)"), sea_orm::sea_query::Alias::new("c"));
        grouped
    }
}

/// `E`'s columns in [`crate::parity`]'s vocabulary, for `parity::check_entities`.
///
/// What SeaORM's types cannot say is refused here rather than guessed: a `Text` is MySQL's 64 KiB `text`, and an
/// entity whose column is a `longtext` declares `column_type = "custom(\"longtext\")"`.
pub fn entity_table<E: EntityTrait>() -> Result<crate::parity::EntityTable, String> {
    let name = E::default().table_name();
    let keys: Vec<&'static str> = E::PrimaryKey::iter().map(|key| key.into_column().as_str()).collect();
    let mut columns = Vec::new();
    for column in E::Column::iter() {
        let definition = column.def();
        let column_name = column.as_str();
        let generated = keys.contains(&column_name) && <E::PrimaryKey as PrimaryKeyTrait>::auto_increment();
        let ty = match definition.get_column_type() {
            ColumnType::BigInteger if generated => Declared::Identity,
            ColumnType::BigInteger => Declared::BigInt,
            ColumnType::Integer => Declared::Int,
            ColumnType::String(sea_orm::sea_query::StringLen::N(length)) => Declared::Varchar(*length),
            ColumnType::Char(Some(length)) => Declared::Char(*length),
            ColumnType::Text => Declared::Text(MySqlText::Regular),
            ColumnType::Custom(custom) if custom.to_string() == "longtext" => Declared::Text(MySqlText::Long),
            ColumnType::Boolean => Declared::Bool,
            ColumnType::TimestampWithTimeZone => Declared::Timestamp,
            ColumnType::Double => Declared::Double,
            ColumnType::Blob | ColumnType::VarBinary(_) => Declared::Bytes,
            other => {
                return Err(format!("{name}.{column_name}: {other:?} has no counterpart in the schema's vocabulary"));
            }
        };
        columns.push(Column { name: column_name, ty, nullable: definition.is_null() });
    }
    Ok(crate::parity::EntityTable { name, columns })
}
