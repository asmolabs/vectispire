//! Dynamic queries on a target's rows, which cannot be built without a [`Visibility`].
//!
//! **The guarantee is in the types.** A table whose rows belong to a target is a [`TargetTable`] — a
//! marker that is *not* a `sea_query::Iden`, so `Query::select().from(Issues)` does not compile — and
//! the only way to put it in a `FROM` is [`VisibleSelect`], whose constructors take the `Visibility`
//! and write it into the `WHERE` before anything else can. "A route naming a target must resolve a
//! Visibility and pass it to the query" (AGENTS.md) becomes a compile error when it is forgotten,
//! instead of a review finding — twenty-three routes passed every test while serving other accounts'
//! rows. `tests/ui/` holds the programs that must not compile.
//!
//! What types cannot see — a table name written as a string in raw SQL — is `cp-arch-tests`' to refuse.

use std::marker::PhantomData;

use sea_query::{
    Alias, Condition, Expr, ExprTrait, IntoCondition, MysqlQueryBuilder, Order, PostgresQueryBuilder, Query,
    SelectStatement,
};
use sea_query_sqlx::{SqlxBinder, SqlxValues};
use sqlx::mysql::MySqlRow;
use sqlx::postgres::PgRow;
use sqlx::{AssertSqlSafe, FromRow};

use crate::db::Db;
use crate::engine::Engine;
use crate::visibility::Visibility;

/// How a table's row names its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetColumns {
    /// A row of a repository or of an image, never both by intent: **when a row names both, it is the
    /// repository's** — the rule 0.11.1 made uniform after a scan of an image built from a repository
    /// was shown to a reader of the image only (`IssueSpecifications.visible`). So an image's grant
    /// matches only rows whose repository column is empty.
    Either { repository: &'static str, container: &'static str },
    /// The row is a repository's — `t_repository` itself (`id`), or a table only repositories have.
    Repository(&'static str),
    /// The row is an image's.
    Container(&'static str),
}

mod sealed {
    pub trait Sealed {}
}

/// A table whose every row belongs to a target. Sealed: the list is here, beside the rule that reads it.
pub trait TargetTable: sealed::Sealed {
    const TABLE: &'static str;
    const TARGET: TargetColumns;
}

macro_rules! target_tables {
    ($($(#[$meta:meta])* $name:ident = $table:literal, $target:expr;)*) => {
        $(
            $(#[$meta])*
            #[derive(Debug, Clone, Copy)]
            pub struct $name;
            impl sealed::Sealed for $name {}
            impl TargetTable for $name {
                const TABLE: &'static str = $table;
                const TARGET: TargetColumns = $target;
            }
        )*
    };
}

target_tables! {
    /// The backlog.
    Issues = "t_issue", TargetColumns::Either { repository: "repo_id", container: "container_id" };
    Scans = "t_scan", TargetColumns::Either { repository: "repo_id", container: "container_id" };
    Components = "t_component", TargetColumns::Either { repository: "repo_id", container: "container_id" };
    GateVerdicts = "t_gate_verdict", TargetColumns::Either { repository: "repo_id", container: "container_id" };
    Repositories = "t_repository", TargetColumns::Repository("id");
    Containers = "t_container", TargetColumns::Container("id");
}

/// How many identifiers one `IN` list carries — `IssueSpecifications.IN_LIST_BATCH`.
pub const IN_LIST_BATCH: usize = 1_000;

/// The visibility as a condition on `T`'s rows.
///
/// **The identifiers are written into the statement, not bound**, in lists of [`IN_LIST_BATCH`] joined
/// by `OR`: bound, one parameter per repository, a page and its count failed on PostgreSQL past 65,535
/// parameters — the driver's ceiling, measured by `ProjectBacklogIntegrationTest`. They are `i64`s,
/// formatted by Rust, so there is nothing to inject; the cost is a statement text that differs per
/// reader, as on the Java side.
///
/// `None` for [`Visibility::Everything`]: no restriction, and no `WHERE` written for it.
pub(crate) fn visible<T: TargetTable>(visibility: &Visibility) -> Option<Condition> {
    let Visibility::Only(targets) = visibility else {
        return None;
    };
    let (repositories, containers) = Visibility::split(targets);
    let mut either = Condition::any();
    match T::TARGET {
        TargetColumns::Either { repository, container } => {
            if !repositories.is_empty() {
                either = either.add(in_literals(repository, &repositories));
            }
            if !containers.is_empty() {
                either = either.add(
                    Condition::all()
                        .add(Expr::col(Alias::new(repository)).is_null())
                        .add(in_literals(container, &containers)),
                );
            }
        }
        TargetColumns::Repository(column) => {
            if !repositories.is_empty() {
                either = either.add(in_literals(column, &repositories));
            }
        }
        TargetColumns::Container(column) => {
            if !containers.is_empty() {
                either = either.add(in_literals(column, &containers));
            }
        }
    }
    if either.is_empty() {
        // Nothing granted on this table's kind of target: no row, never every row.
        return Some(Condition::all().add(Expr::cust("1 = 0")));
    }
    Some(Condition::all().add(either))
}

/// The rows of these targets — a project's or a solution's (`IssueSpecifications.within`): [`visible`]'s condition,
/// for the same reason, and no row at all for no target.
pub fn rows_of<T: TargetTable>(targets: &std::collections::BTreeSet<crate::visibility::ScanTarget>) -> Condition {
    visible::<T>(&Visibility::Only(targets.clone())).unwrap_or_else(|| Condition::all().add(Expr::cust("1 = 0")))
}

fn in_literals(column: &'static str, ids: &[i64]) -> Condition {
    ids.chunks(IN_LIST_BATCH).fold(Condition::any(), |any, chunk| {
        any.add(Expr::col(Alias::new(column)).is_in(chunk.iter().map(|id| Expr::cust(id.to_string()))))
    })
}

/// A `SELECT` on a target's rows, restricted to what the reader may see from the moment it exists.
///
/// Conditions are only ever **added** (`AND`); there is no `or_where`, which would put a row the
/// visibility excluded back.
#[derive(Debug, Clone)]
pub struct VisibleSelect<T: TargetTable> {
    statement: SelectStatement,
    table: PhantomData<T>,
}

impl<T: TargetTable> VisibleSelect<T> {
    /// `SELECT <columns> FROM <T> WHERE <visibility>`.
    pub fn columns(visibility: &Visibility, columns: &[&'static str]) -> VisibleSelect<T> {
        let mut statement = Query::select();
        statement.columns(columns.iter().map(|column| Alias::new(*column))).from(Alias::new(T::TABLE));
        VisibleSelect::restricted(statement, visibility)
    }

    /// `SELECT count(*) FROM <T> WHERE <visibility>`.
    pub fn count(visibility: &Visibility) -> VisibleSelect<T> {
        let mut statement = Query::select();
        statement.expr(Expr::cust("count(*)")).from(Alias::new(T::TABLE));
        VisibleSelect::restricted(statement, visibility)
    }

    fn restricted(mut statement: SelectStatement, visibility: &Visibility) -> VisibleSelect<T> {
        if let Some(condition) = visible::<T>(visibility) {
            statement.cond_where(condition);
        }
        VisibleSelect { statement, table: PhantomData }
    }

    /// Narrows the rows further — `AND`, whatever `condition` holds inside.
    pub fn and_where(mut self, condition: impl IntoCondition) -> VisibleSelect<T> {
        self.statement.cond_where(Condition::all().add(condition.into_condition()));
        self
    }

    pub fn order_by(mut self, column: &'static str, order: Order) -> VisibleSelect<T> {
        self.statement.order_by(Alias::new(column), order);
        self
    }

    pub fn limit(mut self, limit: u64) -> VisibleSelect<T> {
        self.statement.limit(limit);
        self
    }

    pub fn offset(mut self, offset: u64) -> VisibleSelect<T> {
        self.statement.offset(offset);
        self
    }

    /// The statement in `engine`'s SQL, with its bound values.
    pub fn build(&self, engine: Engine) -> (String, SqlxValues) {
        match engine {
            Engine::MySql => self.statement.build_sqlx(MysqlQueryBuilder),
            Engine::PostgreSql => self.statement.build_sqlx(PostgresQueryBuilder),
        }
    }

    pub async fn fetch_all<R>(&self, db: &Db) -> Result<Vec<R>, sqlx::Error>
    where
        R: for<'r> FromRow<'r, MySqlRow> + for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        let (sql, values) = self.build(db.engine());
        // Sound: the text is sea-query's rendering of identifiers this module declares and of `i64`s;
        // every value a caller supplied is in `values`, bound.
        match db {
            Db::MySql(pool) => sqlx::query_as_with(AssertSqlSafe(sql), values).fetch_all(pool).await,
            Db::PostgreSql(pool) => sqlx::query_as_with(AssertSqlSafe(sql), values).fetch_all(pool).await,
        }
    }

    /// The single `i64` a [`VisibleSelect::count`] answers.
    pub async fn fetch_count(&self, db: &Db) -> Result<i64, sqlx::Error> {
        let (sql, values) = self.build(db.engine());
        match db {
            Db::MySql(pool) => sqlx::query_scalar_with(AssertSqlSafe(sql), values).fetch_one(pool).await,
            Db::PostgreSql(pool) => sqlx::query_scalar_with(AssertSqlSafe(sql), values).fetch_one(pool).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::visibility::ScanTarget::{Container, Repository};

    fn sql<T: TargetTable>(select: &VisibleSelect<T>, engine: Engine) -> String {
        select.build(engine).0
    }

    #[test]
    fn everything_adds_no_restriction() {
        let select = VisibleSelect::<Issues>::count(&Visibility::everything());
        assert_eq!(sql(&select, Engine::PostgreSql), r#"SELECT count(*) FROM "t_issue""#);
    }

    #[test]
    fn an_image_grant_matches_only_rows_without_a_repository() {
        let select = VisibleSelect::<Issues>::count(&Visibility::only([Repository(3), Container(9)]));
        assert_eq!(
            sql(&select, Engine::MySql),
            "SELECT count(*) FROM `t_issue` WHERE `repo_id` IN (3) OR (`repo_id` IS NULL AND `container_id` IN (9))"
        );
    }

    #[test]
    fn nothing_granted_matches_no_row() {
        for visibility in [Visibility::only([]), Visibility::only([Container(1)])] {
            let select = VisibleSelect::<Repositories>::count(&visibility);
            assert_eq!(sql(&select, Engine::PostgreSql), r#"SELECT count(*) FROM "t_repository" WHERE 1 = 0"#);
        }
    }

    #[test]
    fn a_long_grant_is_written_in_lists_of_a_thousand() {
        let visibility = Visibility::only((1..=2_500).map(Repository));
        let text = sql(&VisibleSelect::<Repositories>::count(&visibility), Engine::PostgreSql);
        assert_eq!(text.matches(" IN (").count(), 3);
        assert!(text.contains("2500)"));
        assert_eq!(
            VisibleSelect::<Repositories>::count(&visibility).build(Engine::PostgreSql).1.0.0.len(),
            0,
            "no identifier is bound"
        );
    }

    #[test]
    fn an_added_alternative_cannot_widen_what_is_visible() {
        let select = VisibleSelect::<Issues>::count(&Visibility::only([Repository(3)])).and_where(
            Condition::any()
                .add(Expr::col(Alias::new("state")).eq("open"))
                .add(Expr::col(Alias::new("state")).eq("reopened")),
        );
        let (text, values) = select.build(Engine::PostgreSql);
        assert_eq!(text, r#"SELECT count(*) FROM "t_issue" WHERE "repo_id" IN (3) AND ("state" = $1 OR "state" = $2)"#);
        assert_eq!(values.0.0.len(), 2, "what a caller supplies is bound");
    }
}
