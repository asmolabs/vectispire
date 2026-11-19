//! The fixed statements on MySQL (`super`'s note).

use sqlx::MySqlConnection;
use vectispire_cp_db::types::UtcInstant;

use crate::persistence::repository::{NewTriageEvent, StoreError};

pub async fn insert_triage_event(conn: &mut MySqlConnection, event: &NewTriageEvent) -> Result<(), StoreError> {
    sqlx::query!(
        "/* mysql */ insert into t_issue_triage_event (issue_id, from_status, to_status, justification, comment, actor, origin, occurred_at, expires_at, requested_status, scan_id, previous_resolved_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        event.issue_id,
        event.from_status,
        event.to_status,
        event.justification,
        event.comment,
        event.actor,
        event.origin,
        UtcInstant(event.occurred_at),
        event.expires_at.map(UtcInstant),
        event.requested_status,
        event.scan_id,
        event.previous_resolved_at.map(UtcInstant),
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn count_by_state_and_repository(
    conn: &mut MySqlConnection,
    state: &str,
    repo_id: i64,
) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_issue where state = ? and repo_id = ?"#,
        state,
        repo_id
    )
    .fetch_one(conn)
    .await?)
}

pub async fn count_decisions_for_repository(
    conn: &mut MySqlConnection,
    repo_id: i64,
    not_a_decision: &str,
) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(e.id) as "count!: i64" from t_issue_triage_event e join t_issue i on e.issue_id = i.id where i.repo_id = ? and e.origin <> ?"#,
        repo_id,
        not_a_decision
    )
    .fetch_one(conn)
    .await?)
}

/// Named as `cp-arch-tests`' `sql-known.toml` names it: the sweep reads targets' tables, a listed exception.
pub struct IssueRepository;

impl IssueRepository {
    pub async fn find_orphaned_ids(conn: &mut MySqlConnection) -> Result<Vec<i64>, StoreError> {
        Ok(sqlx::query_scalar!(
            "/* mysql */ select i.id from t_issue i where (i.container_id is not null and i.container_id not in (select c.id from t_container c)) or (i.repo_id is not null and i.repo_id not in (select r.id from t_repository r))"
        )
        .fetch_all(conn)
        .await?)
    }
}

/// When V68 — the migration that began recording reopenings — was applied, as Flyway stored it: a `timestamp`, in the
/// session's zone, which the caller reads with a day's margin (`ReopeningsRecord`).
pub async fn reopening_migration_installed_on(
    conn: &mut MySqlConnection,
) -> Result<Vec<time::OffsetDateTime>, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select installed_on as "installed_on!: time::OffsetDateTime" from flyway_schema_history where version = '68' and success = true"#
    )
    .fetch_all(conn)
    .await?)
}

pub async fn count_unsettled_within(
    conn: &mut MySqlConnection,
    scope: super::UnsettledScope<'_>,
    repositories: &str,
    [first, second, third]: [&str; 3],
) -> Result<Vec<(i64, Option<String>, String, i64)>, StoreError> {
    let rows = match scope {
        super::UnsettledScope::Type(kind) => sqlx::query!(
            r#"/* mysql */ select i.repo_id as "repo_id!", i.severity, i.state, count(i.id) as "count!: i64" from t_issue i where i.repo_id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) and i.type = ? and i.triage_status not in (?, ?, ?) group by i.repo_id, i.severity, i.state"#,
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
            r#"/* mysql */ select i.repo_id as "repo_id!", i.severity, i.state, count(i.id) as "count!: i64" from t_issue i where i.repo_id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) and i.tool = ? and i.triage_status not in (?, ?, ?) group by i.repo_id, i.severity, i.state"#,
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
    conn: &mut MySqlConnection,
    id: i64,
    reference: &str,
    url: Option<&str>,
) -> Result<u64, StoreError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_issue set ticket_ref = ?, ticket_url = ?, revision = revision + 1, ticket_claimed_by = null, ticket_claim_until = null where id = ? and ticket_ref is null",
        reference,
        url,
        id
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn claim_ticket(
    conn: &mut MySqlConnection,
    id: i64,
    holder: &str,
    until: time::OffsetDateTime,
    at: time::OffsetDateTime,
) -> Result<u64, StoreError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_issue set ticket_claimed_by = ?, ticket_claim_until = ? where id = ? and ticket_ref is null and (ticket_claim_until is null or ticket_claim_until <= ?)",
        holder,
        UtcInstant(until),
        id,
        UtcInstant(at)
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn release_ticket_claim(conn: &mut MySqlConnection, id: i64, holder: &str) -> Result<u64, StoreError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_issue set ticket_claimed_by = null, ticket_claim_until = null where id = ? and ticket_claimed_by = ?",
        id,
        holder
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn mark_ticket_closed(
    conn: &mut MySqlConnection,
    id: i64,
    closed: &str,
    reference: &str,
) -> Result<u64, StoreError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_issue set ticket_ref = ?, revision = revision + 1 where id = ? and ticket_ref = ?",
        closed,
        id,
        reference
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn attach_ticket_by(
    conn: &mut MySqlConnection,
    id: i64,
    reference: &str,
    url: Option<&str>,
    by: &str,
) -> Result<u64, StoreError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_issue set ticket_ref = ?, ticket_url = ?, ticket_attached_by = ?, revision = revision + 1 where id = ?",
        reference,
        url,
        by,
        id
    )
    .execute(conn)
    .await?
    .rows_affected())
}
