//! The two engines the control plane runs on, and nothing else.

/// MySQL or PostgreSQL — chosen by the database URL and by nothing else, as `spring.datasource.url`
/// chooses it on the Java side (decision 0034).
///
/// **Two variants, matched exhaustively everywhere.** A third engine is a decision with its own
/// migrations directory (decision 0027), so adding a variant here must fail to compile at every place
/// that spells something per engine — which a `_ =>` arm would hide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Engine {
    MySql,
    PostgreSql,
}

impl Engine {
    /// Both, in the order the campaign runs them — for a test that must cover each.
    pub const ALL: [Engine; 2] = [Engine::MySql, Engine::PostgreSql];

    /// The vendor directory of its own migrations: `db/migration/{vendor}`, as `MigrationDialect`
    /// spells it — Flyway's `{vendor}` placeholder answers `mysql` and `postgresql`, not `postgres`.
    pub fn vendor(self) -> &'static str {
        match self {
            Engine::MySql => "mysql",
            Engine::PostgreSql => "postgresql",
        }
    }
}

impl std::fmt::Display for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Engine::MySql => "MySQL",
            Engine::PostgreSql => "PostgreSQL",
        })
    }
}
