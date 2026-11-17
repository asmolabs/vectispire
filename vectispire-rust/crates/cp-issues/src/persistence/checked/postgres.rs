//! The fixed statements on PostgreSQL (`super`'s note).

use sqlx::PgConnection;

use crate::persistence::repository::{NewTriageEvent, StoreError};

pub async fn insert_triage_event(conn: &mut PgConnection, event: &NewTriageEvent) -> Result<(), StoreError> {
    sqlx::query!(
        "/* postgres */ insert into t_issue_triage_event (issue_id, from_status, to_status, justification, comment, actor, origin, occurred_at, expires_at, requested_status, scan_id, previous_resolved_at) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        event.issue_id,
        event.from_status,
        event.to_status,
        event.justification,
        event.comment,
        event.actor,
        event.origin,
        event.occurred_at,
        event.expires_at,
        event.requested_status,
        event.scan_id,
        event.previous_resolved_at,
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn count_by_state_and_repository(
    conn: &mut PgConnection,
    state: &str,
    repo_id: i64,
) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(id) as "count!" from t_issue where state = $1 and repo_id = $2"#,
        state,
        repo_id
    )
    .fetch_one(conn)
    .await?)
}

pub async fn count_decisions_for_repository(
    conn: &mut PgConnection,
    repo_id: i64,
    not_a_decision: &str,
) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(e.id) as "count!" from t_issue_triage_event e join t_issue i on e.issue_id = i.id where i.repo_id = $1 and e.origin <> $2"#,
        repo_id,
        not_a_decision
    )
    .fetch_one(conn)
    .await?)
}

/// When V68 was applied, as Flyway stored it: a `timestamp` without a zone, the server's — read as UTC by the caller,
/// with a day's margin (`ReopeningsRecord`).
pub async fn reopening_migration_installed_on(
    conn: &mut PgConnection,
) -> Result<Vec<time::OffsetDateTime>, StoreError> {
    let stored = sqlx::query_scalar!(
        r#"/* postgres */ select installed_on as "installed_on!: time::PrimitiveDateTime" from flyway_schema_history where version = '68' and success = true"#
    )
    .fetch_all(conn)
    .await?;
    Ok(stored.into_iter().map(time::PrimitiveDateTime::assume_utc).collect())
}

/// Named as `cp-arch-tests`' `sql-known.toml` names it: the sweep reads targets' tables, a listed exception.
pub struct IssueRepository;

impl IssueRepository {
    pub async fn find_orphaned_ids(conn: &mut PgConnection) -> Result<Vec<i64>, StoreError> {
        Ok(sqlx::query_scalar!(
            "/* postgres */ select i.id from t_issue i where (i.container_id is not null and i.container_id not in (select c.id from t_container c)) or (i.repo_id is not null and i.repo_id not in (select r.id from t_repository r))"
        )
        .fetch_all(conn)
        .await?)
    }
}
