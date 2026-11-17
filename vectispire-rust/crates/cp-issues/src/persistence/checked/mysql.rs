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
