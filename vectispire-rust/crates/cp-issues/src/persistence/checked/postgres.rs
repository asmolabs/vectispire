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

pub async fn count_unsettled_within(
    conn: &mut PgConnection,
    scope: super::UnsettledScope<'_>,
    repositories: &[i64],
    [first, second, third]: [&str; 3],
) -> Result<Vec<(i64, Option<String>, String, i64)>, StoreError> {
    let rows = match scope {
        super::UnsettledScope::Type(kind) => sqlx::query!(
            r#"/* postgres */ select i.repo_id as "repo_id!", i.severity, i.state, count(i.id) as "count!" from t_issue i where i.repo_id = any($1) and i.type = $2 and i.triage_status not in ($3, $4, $5) group by i.repo_id, i.severity, i.state"#,
            repositories,
            kind,
            first,
            second,
            third
        )
        .fetch_all(conn)
        .await?
        .into_iter()
        .map(|row| (row.repo_id, row.severity, row.state, row.count))
        .collect(),
        super::UnsettledScope::Tool(tool) => sqlx::query!(
            r#"/* postgres */ select i.repo_id as "repo_id!", i.severity, i.state, count(i.id) as "count!" from t_issue i where i.repo_id = any($1) and i.tool = $2 and i.triage_status not in ($3, $4, $5) group by i.repo_id, i.severity, i.state"#,
            repositories,
            tool,
            first,
            second,
            third
        )
        .fetch_all(conn)
        .await?
        .into_iter()
        .map(|row| (row.repo_id, row.severity, row.state, row.count))
        .collect(),
    };
    // `repo_id!`: the filter on it has already left out an image's issue, whose column is null.
    Ok(rows)
}

// ------------------------------------------------------------------ tickets (`super`'s note on each)

pub async fn attach_ticket(
    conn: &mut PgConnection,
    id: i64,
    reference: &str,
    url: Option<&str>,
) -> Result<u64, StoreError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_issue set ticket_ref = $1, ticket_url = $2, revision = revision + 1, ticket_claimed_by = null, ticket_claim_until = null where id = $3 and ticket_ref is null",
        reference,
        url,
        id
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn claim_ticket(
    conn: &mut PgConnection,
    id: i64,
    holder: &str,
    until: time::OffsetDateTime,
    at: time::OffsetDateTime,
) -> Result<u64, StoreError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_issue set ticket_claimed_by = $1, ticket_claim_until = $2 where id = $3 and ticket_ref is null and (ticket_claim_until is null or ticket_claim_until <= $4)",
        holder,
        until,
        id,
        at
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn release_ticket_claim(conn: &mut PgConnection, id: i64, holder: &str) -> Result<u64, StoreError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_issue set ticket_claimed_by = null, ticket_claim_until = null where id = $1 and ticket_claimed_by = $2",
        id,
        holder
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn mark_ticket_closed(
    conn: &mut PgConnection,
    id: i64,
    closed: &str,
    reference: &str,
) -> Result<u64, StoreError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_issue set ticket_ref = $1, revision = revision + 1 where id = $2 and ticket_ref = $3",
        closed,
        id,
        reference
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn attach_ticket_by(
    conn: &mut PgConnection,
    id: i64,
    reference: &str,
    url: Option<&str>,
    by: &str,
) -> Result<u64, StoreError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_issue set ticket_ref = $1, ticket_url = $2, ticket_attached_by = $3, revision = revision + 1 where id = $4",
        reference,
        url,
        by,
        id
    )
    .execute(conn)
    .await?
    .rows_affected())
}
