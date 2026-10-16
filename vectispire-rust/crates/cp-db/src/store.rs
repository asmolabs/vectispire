//! The checked fixed queries — `sqlx::query!` against the schema, once per engine.
//!
//! **What stands in for Hibernate validating 319 `@Query` methods at start.** The macro asks a real
//! database to describe each statement while compiling: a column that does not exist, a parameter of
//! the wrong type or a result read as the wrong Rust type does not build. The answer is kept in
//! `.sqlx/`, so a build needs no database (`SQLX_OFFLINE=true`), and CI proves the cache is complete
//! and not stale (`crates/cp-db/scripts/sqlx-prepare.sh check`).
//!
//! **Two engines, one cache directory, one rule: every statement starts with its engine's tag**
//! (`/* mysql */`, `/* postgres */`). The cache file is named after a hash of the SQL text alone, so
//! the same statement on both engines — a query with no parameter is spelled alike — would name one
//! file twice, and the second generation would overwrite the first with the other engine's types.
//! `cp-arch-tests` reads every `query!` string and refuses an untagged one.
//!
//! These two modules are the pattern and the proof for the 319 that follow, not a module's queries: a
//! module's persistence declares its own, in its own crate.

/// A row of `t_epss_score`.
#[derive(Debug, Clone, PartialEq)]
pub struct EpssScore {
    pub cve_id: String,
    pub score: f64,
    pub percentile: f64,
}

#[cfg(feature = "mysql-queries")]
pub mod mysql {
    use super::EpssScore;
    use sqlx::MySqlPool;

    pub async fn epss_score(pool: &MySqlPool, generation: i64, cve_id: &str) -> sqlx::Result<Option<EpssScore>> {
        let row = sqlx::query!(
            "/* mysql */ select cve_id, score, percentile from t_epss_score where generation = ? and cve_id = ?",
            generation,
            cve_id
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| EpssScore { cve_id: row.cve_id, score: row.score, percentile: row.percentile }))
    }

    pub async fn upsert_epss_score(pool: &MySqlPool, generation: i64, score: &EpssScore) -> sqlx::Result<()> {
        sqlx::query!(
            "/* mysql */ insert into t_epss_score (generation, cve_id, score, percentile) values (?, ?, ?, ?) \
             on duplicate key update score = values(score), percentile = values(percentile)",
            generation,
            score.cve_id,
            score.score,
            score.percentile
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}

#[cfg(feature = "postgres-queries")]
pub mod postgres {
    use super::EpssScore;
    use sqlx::PgPool;

    pub async fn epss_score(pool: &PgPool, generation: i64, cve_id: &str) -> sqlx::Result<Option<EpssScore>> {
        let row = sqlx::query!(
            "/* postgres */ select cve_id, score, percentile from t_epss_score where generation = $1 and cve_id = $2",
            generation,
            cve_id
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| EpssScore { cve_id: row.cve_id, score: row.score, percentile: row.percentile }))
    }

    pub async fn upsert_epss_score(pool: &PgPool, generation: i64, score: &EpssScore) -> sqlx::Result<()> {
        sqlx::query!(
            "/* postgres */ insert into t_epss_score (generation, cve_id, score, percentile) values ($1, $2, $3, $4) \
             on conflict (generation, cve_id) do update set score = excluded.score, percentile = excluded.percentile",
            generation,
            score.cve_id,
            score.score,
            score.percentile
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}
