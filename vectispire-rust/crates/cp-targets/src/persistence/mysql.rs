//! The targets' statements on MySQL, checked against a migrated server while compiling (`super`'s note).
//! MySQL describes no parameter type, so the binds are checked at run time by the engine suite, on this engine. A list
//! is one JSON array read by `json_table` — MySQL has no array parameter.

use sqlx::MySqlConnection;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::types::{TextUuid, UtcInstant};

use super::{ContainerRow, DbError, GitTokenRow, Keying, ProjectRow, RepositoryRow, SolutionRow, SshKeyRow};

pub async fn repositories(conn: &mut MySqlConnection) -> Result<Vec<RepositoryRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, url, branch, sub_path, name, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", ssh_key_id as "ssh_key_id: TextUuid", https_token_id as "https_token_id: TextUuid", badge_token, tier, in_certified_scope as "in_certified_scope: bool", project_id, url_identity, identity_guard from t_repository order by id"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| RepositoryRow {
            id: row.id,
            url: row.url,
            branch: row.branch,
            sub_path: row.sub_path,
            name: row.name,
            scan_interval_minutes: row.scan_interval_minutes,
            scan_cron: row.scan_cron,
            scan_manual_only: row.scan_manual_only,
            required_agent_label: row.required_agent_label,
            last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
            ssh_key_id: row.ssh_key_id.map(|id| id.0),
            https_token_id: row.https_token_id.map(|id| id.0),
            badge_token: row.badge_token,
            tier: row.tier,
            in_certified_scope: row.in_certified_scope,
            project_id: row.project_id,
            url_identity: row.url_identity,
            identity_guard: row.identity_guard,
        })
        .collect())
}

pub async fn repository(conn: &mut MySqlConnection, id: i64) -> Result<Option<RepositoryRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id, url, branch, sub_path, name, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", ssh_key_id as "ssh_key_id: TextUuid", https_token_id as "https_token_id: TextUuid", badge_token, tier, in_certified_scope as "in_certified_scope: bool", project_id, url_identity, identity_guard from t_repository where id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| RepositoryRow {
        id: row.id,
        url: row.url,
        branch: row.branch,
        sub_path: row.sub_path,
        name: row.name,
        scan_interval_minutes: row.scan_interval_minutes,
        scan_cron: row.scan_cron,
        scan_manual_only: row.scan_manual_only,
        required_agent_label: row.required_agent_label,
        last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
        ssh_key_id: row.ssh_key_id.map(|id| id.0),
        https_token_id: row.https_token_id.map(|id| id.0),
        badge_token: row.badge_token,
        tier: row.tier,
        in_certified_scope: row.in_certified_scope,
        project_id: row.project_id,
        url_identity: row.url_identity,
        identity_guard: row.identity_guard,
    }))
}

pub async fn repositories_by_ids(conn: &mut MySqlConnection, ids: &str) -> Result<Vec<RepositoryRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, url, branch, sub_path, name, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", ssh_key_id as "ssh_key_id: TextUuid", https_token_id as "https_token_id: TextUuid", badge_token, tier, in_certified_scope as "in_certified_scope: bool", project_id, url_identity, identity_guard from t_repository where id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) order by id"#,
        ids
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| RepositoryRow {
            id: row.id,
            url: row.url,
            branch: row.branch,
            sub_path: row.sub_path,
            name: row.name,
            scan_interval_minutes: row.scan_interval_minutes,
            scan_cron: row.scan_cron,
            scan_manual_only: row.scan_manual_only,
            required_agent_label: row.required_agent_label,
            last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
            ssh_key_id: row.ssh_key_id.map(|id| id.0),
            https_token_id: row.https_token_id.map(|id| id.0),
            badge_token: row.badge_token,
            tier: row.tier,
            in_certified_scope: row.in_certified_scope,
            project_id: row.project_id,
            url_identity: row.url_identity,
            identity_guard: row.identity_guard,
        })
        .collect())
}

pub async fn repositories_of_project(
    conn: &mut MySqlConnection,
    project_id: i64,
) -> Result<Vec<RepositoryRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, url, branch, sub_path, name, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", ssh_key_id as "ssh_key_id: TextUuid", https_token_id as "https_token_id: TextUuid", badge_token, tier, in_certified_scope as "in_certified_scope: bool", project_id, url_identity, identity_guard from t_repository where project_id = ? order by id"#,
        project_id
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| RepositoryRow {
            id: row.id,
            url: row.url,
            branch: row.branch,
            sub_path: row.sub_path,
            name: row.name,
            scan_interval_minutes: row.scan_interval_minutes,
            scan_cron: row.scan_cron,
            scan_manual_only: row.scan_manual_only,
            required_agent_label: row.required_agent_label,
            last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
            ssh_key_id: row.ssh_key_id.map(|id| id.0),
            https_token_id: row.https_token_id.map(|id| id.0),
            badge_token: row.badge_token,
            tier: row.tier,
            in_certified_scope: row.in_certified_scope,
            project_id: row.project_id,
            url_identity: row.url_identity,
            identity_guard: row.identity_guard,
        })
        .collect())
}

pub async fn repository_by_guard(conn: &mut MySqlConnection, guard: &str) -> Result<Option<RepositoryRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id, url, branch, sub_path, name, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", ssh_key_id as "ssh_key_id: TextUuid", https_token_id as "https_token_id: TextUuid", badge_token, tier, in_certified_scope as "in_certified_scope: bool", project_id, url_identity, identity_guard from t_repository where identity_guard = ?"#,
        guard
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| RepositoryRow {
        id: row.id,
        url: row.url,
        branch: row.branch,
        sub_path: row.sub_path,
        name: row.name,
        scan_interval_minutes: row.scan_interval_minutes,
        scan_cron: row.scan_cron,
        scan_manual_only: row.scan_manual_only,
        required_agent_label: row.required_agent_label,
        last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
        ssh_key_id: row.ssh_key_id.map(|id| id.0),
        https_token_id: row.https_token_id.map(|id| id.0),
        badge_token: row.badge_token,
        tier: row.tier,
        in_certified_scope: row.in_certified_scope,
        project_id: row.project_id,
        url_identity: row.url_identity,
        identity_guard: row.identity_guard,
    }))
}

pub async fn unguarded_repositories(conn: &mut MySqlConnection) -> Result<Vec<RepositoryRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, url, branch, sub_path, name, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", ssh_key_id as "ssh_key_id: TextUuid", https_token_id as "https_token_id: TextUuid", badge_token, tier, in_certified_scope as "in_certified_scope: bool", project_id, url_identity, identity_guard from t_repository where identity_guard is null order by id asc"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| RepositoryRow {
            id: row.id,
            url: row.url,
            branch: row.branch,
            sub_path: row.sub_path,
            name: row.name,
            scan_interval_minutes: row.scan_interval_minutes,
            scan_cron: row.scan_cron,
            scan_manual_only: row.scan_manual_only,
            required_agent_label: row.required_agent_label,
            last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
            ssh_key_id: row.ssh_key_id.map(|id| id.0),
            https_token_id: row.https_token_id.map(|id| id.0),
            badge_token: row.badge_token,
            tier: row.tier,
            in_certified_scope: row.in_certified_scope,
            project_id: row.project_id,
            url_identity: row.url_identity,
            identity_guard: row.identity_guard,
        })
        .collect())
}

pub async fn repository_by_badge(conn: &mut MySqlConnection, token: &str) -> Result<Option<RepositoryRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id, url, branch, sub_path, name, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", ssh_key_id as "ssh_key_id: TextUuid", https_token_id as "https_token_id: TextUuid", badge_token, tier, in_certified_scope as "in_certified_scope: bool", project_id, url_identity, identity_guard from t_repository where badge_token = ?"#,
        token
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| RepositoryRow {
        id: row.id,
        url: row.url,
        branch: row.branch,
        sub_path: row.sub_path,
        name: row.name,
        scan_interval_minutes: row.scan_interval_minutes,
        scan_cron: row.scan_cron,
        scan_manual_only: row.scan_manual_only,
        required_agent_label: row.required_agent_label,
        last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
        ssh_key_id: row.ssh_key_id.map(|id| id.0),
        https_token_id: row.https_token_id.map(|id| id.0),
        badge_token: row.badge_token,
        tier: row.tier,
        in_certified_scope: row.in_certified_scope,
        project_id: row.project_id,
        url_identity: row.url_identity,
        identity_guard: row.identity_guard,
    }))
}

pub async fn insert_repository(conn: &mut MySqlConnection, row: &RepositoryRow) -> Result<i64, DbError> {
    let done = sqlx::query!(
        r#"/* mysql */ insert into t_repository (url, branch, sub_path, name, scan_interval_minutes, scan_cron, scan_manual_only, required_agent_label, last_scheduled_scan_at, ssh_key_id, https_token_id, badge_token, tier, in_certified_scope, url_identity, identity_guard) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        &row.url,
        &row.branch,
        row.sub_path.as_deref(),
        row.name.as_deref(),
        row.scan_interval_minutes,
        row.scan_cron.as_deref(),
        row.scan_manual_only,
        row.required_agent_label.as_deref(),
        row.last_scheduled_scan_at.map(UtcInstant),
        row.ssh_key_id.map(TextUuid),
        row.https_token_id.map(TextUuid),
        row.badge_token.as_deref(),
        &row.tier,
        row.in_certified_scope,
        row.url_identity.as_deref(),
        row.identity_guard.as_deref()
    )
    .execute(conn)
    .await?;
    // MySQL's last insert id is unsigned; an `auto_increment` on a signed `bigint` never exceeds `i64::MAX`.
    Ok(i64::try_from(done.last_insert_id()).unwrap_or(i64::MAX))
}

pub async fn update_repository(conn: &mut MySqlConnection, row: &RepositoryRow) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_repository set url = ?, branch = ?, sub_path = ?, name = ?, scan_interval_minutes = ?, scan_cron = ?, scan_manual_only = ?, required_agent_label = ?, last_scheduled_scan_at = ?, ssh_key_id = ?, https_token_id = ?, badge_token = ?, tier = ?, in_certified_scope = ?, url_identity = ?, identity_guard = ? where id = ?"#,
        &row.url,
        &row.branch,
        row.sub_path.as_deref(),
        row.name.as_deref(),
        row.scan_interval_minutes,
        row.scan_cron.as_deref(),
        row.scan_manual_only,
        row.required_agent_label.as_deref(),
        row.last_scheduled_scan_at.map(UtcInstant),
        row.ssh_key_id.map(TextUuid),
        row.https_token_id.map(TextUuid),
        row.badge_token.as_deref(),
        &row.tier,
        row.in_certified_scope,
        row.url_identity.as_deref(),
        row.identity_guard.as_deref(),
        row.id
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn delete_repository(conn: &mut MySqlConnection, id: i64) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ delete from t_repository where id = ?"#, id).execute(conn).await?.rows_affected())
}

pub async fn stamp_repository(conn: &mut MySqlConnection, id: i64, at: OffsetDateTime) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_repository set last_scheduled_scan_at = ? where id = ?"#,
        UtcInstant(at),
        id
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn count_by_ssh_key(conn: &mut MySqlConnection, key: Uuid) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_repository where ssh_key_id = ?"#,
        TextUuid(key)
    )
    .fetch_one(conn)
    .await?)
}

pub async fn count_by_https_token(conn: &mut MySqlConnection, token: Uuid) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_repository where https_token_id = ?"#,
        TextUuid(token)
    )
    .fetch_one(conn)
    .await?)
}

pub async fn usage_by_ssh_key(conn: &mut MySqlConnection) -> Result<Vec<(Uuid, i64)>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select ssh_key_id as "key!: TextUuid", count(id) as "count!: i64" from t_repository where ssh_key_id is not null group by ssh_key_id"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.key.0, row.count)).collect())
}

pub async fn usage_by_https_token(conn: &mut MySqlConnection) -> Result<Vec<(Uuid, i64)>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select https_token_id as "key!: TextUuid", count(id) as "count!: i64" from t_repository where https_token_id is not null group by https_token_id"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.key.0, row.count)).collect())
}

pub async fn repository_ids_in_projects(conn: &mut MySqlConnection, ids: &str) -> Result<Vec<i64>, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select id from t_repository where project_id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) order by id"#,
        ids
    )
    .fetch_all(conn)
    .await?)
}

pub async fn repository_ids_of_solution(conn: &mut MySqlConnection, solution_id: i64) -> Result<Vec<i64>, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select id from t_repository where project_id in (select p.id from t_project p where p.solution_id = ?) order by id"#,
        solution_id
    )
    .fetch_all(conn)
    .await?)
}

pub async fn assign_repository(conn: &mut MySqlConnection, id: i64, project_id: Option<i64>) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ update t_repository set project_id = ? where id = ?"#, project_id, id)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn detach_repositories(conn: &mut MySqlConnection, project_id: i64) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ update t_repository set project_id = null where project_id = ?"#, project_id)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn repositories_by_identity(
    conn: &mut MySqlConnection,
    identities: &str,
) -> Result<Vec<(i64, String)>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, url_identity as "identity!" from t_repository where url_identity in (select j.v from json_table(?, '$[*]' columns (v varchar(255) path '$')) as j) order by id"#,
        identities
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.id, row.identity)).collect())
}

pub async fn unidentified_repositories(conn: &mut MySqlConnection) -> Result<Vec<(i64, String)>, DbError> {
    let rows = sqlx::query!(r#"/* mysql */ select id, url from t_repository where url_identity is null order by id"#)
        .fetch_all(conn)
        .await?;
    Ok(rows.into_iter().map(|row| (row.id, row.url)).collect())
}

pub async fn key_repository(conn: &mut MySqlConnection, keying: &Keying<'_>) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_repository set url_identity = ?, identity_guard = ? where id = ? and identity_guard is null and url = ? and branch = ? and coalesce(sub_path, '') = ?"#,
        keying.url_identity,
        keying.guard,
        keying.id,
        keying.url,
        keying.branch,
        keying.sub_path
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn containers(conn: &mut MySqlConnection) -> Result<Vec<ContainerRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, registry, image_name, tag, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", tier, in_certified_scope as "in_certified_scope: bool", project_id from t_container order by id"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ContainerRow {
            id: row.id,
            registry: row.registry,
            image_name: row.image_name,
            tag: row.tag,
            scan_interval_minutes: row.scan_interval_minutes,
            scan_cron: row.scan_cron,
            scan_manual_only: row.scan_manual_only,
            required_agent_label: row.required_agent_label,
            last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
            tier: row.tier,
            in_certified_scope: row.in_certified_scope,
            project_id: row.project_id,
        })
        .collect())
}

pub async fn container(conn: &mut MySqlConnection, id: i64) -> Result<Option<ContainerRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id, registry, image_name, tag, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", tier, in_certified_scope as "in_certified_scope: bool", project_id from t_container where id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| ContainerRow {
        id: row.id,
        registry: row.registry,
        image_name: row.image_name,
        tag: row.tag,
        scan_interval_minutes: row.scan_interval_minutes,
        scan_cron: row.scan_cron,
        scan_manual_only: row.scan_manual_only,
        required_agent_label: row.required_agent_label,
        last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
        tier: row.tier,
        in_certified_scope: row.in_certified_scope,
        project_id: row.project_id,
    }))
}

pub async fn containers_by_ids(conn: &mut MySqlConnection, ids: &str) -> Result<Vec<ContainerRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, registry, image_name, tag, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", tier, in_certified_scope as "in_certified_scope: bool", project_id from t_container where id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) order by id"#,
        ids
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ContainerRow {
            id: row.id,
            registry: row.registry,
            image_name: row.image_name,
            tag: row.tag,
            scan_interval_minutes: row.scan_interval_minutes,
            scan_cron: row.scan_cron,
            scan_manual_only: row.scan_manual_only,
            required_agent_label: row.required_agent_label,
            last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
            tier: row.tier,
            in_certified_scope: row.in_certified_scope,
            project_id: row.project_id,
        })
        .collect())
}

pub async fn containers_of_project(conn: &mut MySqlConnection, project_id: i64) -> Result<Vec<ContainerRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, registry, image_name, tag, scan_interval_minutes, scan_cron, scan_manual_only as "scan_manual_only: bool", required_agent_label, last_scheduled_scan_at as "last_scheduled_scan_at: UtcInstant", tier, in_certified_scope as "in_certified_scope: bool", project_id from t_container where project_id = ? order by id"#,
        project_id
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ContainerRow {
            id: row.id,
            registry: row.registry,
            image_name: row.image_name,
            tag: row.tag,
            scan_interval_minutes: row.scan_interval_minutes,
            scan_cron: row.scan_cron,
            scan_manual_only: row.scan_manual_only,
            required_agent_label: row.required_agent_label,
            last_scheduled_scan_at: row.last_scheduled_scan_at.map(|at| at.0),
            tier: row.tier,
            in_certified_scope: row.in_certified_scope,
            project_id: row.project_id,
        })
        .collect())
}

pub async fn insert_container(conn: &mut MySqlConnection, row: &ContainerRow) -> Result<i64, DbError> {
    let done = sqlx::query!(
        r#"/* mysql */ insert into t_container (registry, image_name, tag, scan_interval_minutes, scan_cron, scan_manual_only, required_agent_label, last_scheduled_scan_at, tier, in_certified_scope) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        row.registry.as_deref(),
        &row.image_name,
        &row.tag,
        row.scan_interval_minutes,
        row.scan_cron.as_deref(),
        row.scan_manual_only,
        row.required_agent_label.as_deref(),
        row.last_scheduled_scan_at.map(UtcInstant),
        &row.tier,
        row.in_certified_scope
    )
    .execute(conn)
    .await?;
    // MySQL's last insert id is unsigned; an `auto_increment` on a signed `bigint` never exceeds `i64::MAX`.
    Ok(i64::try_from(done.last_insert_id()).unwrap_or(i64::MAX))
}

pub async fn update_container(conn: &mut MySqlConnection, row: &ContainerRow) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_container set registry = ?, image_name = ?, tag = ?, scan_interval_minutes = ?, scan_cron = ?, scan_manual_only = ?, required_agent_label = ?, last_scheduled_scan_at = ?, tier = ?, in_certified_scope = ? where id = ?"#,
        row.registry.as_deref(),
        &row.image_name,
        &row.tag,
        row.scan_interval_minutes,
        row.scan_cron.as_deref(),
        row.scan_manual_only,
        row.required_agent_label.as_deref(),
        row.last_scheduled_scan_at.map(UtcInstant),
        &row.tier,
        row.in_certified_scope,
        row.id
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn delete_container(conn: &mut MySqlConnection, id: i64) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ delete from t_container where id = ?"#, id).execute(conn).await?.rows_affected())
}

pub async fn stamp_container(conn: &mut MySqlConnection, id: i64, at: OffsetDateTime) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_container set last_scheduled_scan_at = ? where id = ?"#,
        UtcInstant(at),
        id
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn container_ids_in_projects(conn: &mut MySqlConnection, ids: &str) -> Result<Vec<i64>, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select id from t_container where project_id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) order by id"#,
        ids
    )
    .fetch_all(conn)
    .await?)
}

pub async fn container_ids_of_solution(conn: &mut MySqlConnection, solution_id: i64) -> Result<Vec<i64>, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select id from t_container where project_id in (select p.id from t_project p where p.solution_id = ?) order by id"#,
        solution_id
    )
    .fetch_all(conn)
    .await?)
}

pub async fn assign_container(conn: &mut MySqlConnection, id: i64, project_id: Option<i64>) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ update t_container set project_id = ? where id = ?"#, project_id, id)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn detach_containers(conn: &mut MySqlConnection, project_id: i64) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ update t_container set project_id = null where project_id = ?"#, project_id)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn solutions(conn: &mut MySqlConnection) -> Result<Vec<SolutionRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, name, description, created_at as "created_at: UtcInstant" from t_solution order by id"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| SolutionRow {
            id: row.id,
            name: row.name,
            description: row.description,
            created_at: row.created_at.0,
        })
        .collect())
}

pub async fn solution(conn: &mut MySqlConnection, id: i64) -> Result<Option<SolutionRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id, name, description, created_at as "created_at: UtcInstant" from t_solution where id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| SolutionRow {
        id: row.id,
        name: row.name,
        description: row.description,
        created_at: row.created_at.0,
    }))
}

pub async fn solutions_by_ids(conn: &mut MySqlConnection, ids: &str) -> Result<Vec<SolutionRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, name, description, created_at as "created_at: UtcInstant" from t_solution where id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) order by id"#,
        ids
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| SolutionRow {
            id: row.id,
            name: row.name,
            description: row.description,
            created_at: row.created_at.0,
        })
        .collect())
}

pub async fn solution_named(conn: &mut MySqlConnection, name: &str) -> Result<Option<SolutionRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id, name, description, created_at as "created_at: UtcInstant" from t_solution where upper(name) = upper(?) order by id"#,
        name
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| SolutionRow {
        id: row.id,
        name: row.name,
        description: row.description,
        created_at: row.created_at.0,
    }))
}

pub async fn insert_solution(conn: &mut MySqlConnection, row: &SolutionRow) -> Result<i64, DbError> {
    let done = sqlx::query!(
        r#"/* mysql */ insert into t_solution (name, description, created_at) values (?, ?, ?)"#,
        &row.name,
        row.description.as_deref(),
        UtcInstant(row.created_at)
    )
    .execute(conn)
    .await?;
    // MySQL's last insert id is unsigned; an `auto_increment` on a signed `bigint` never exceeds `i64::MAX`.
    Ok(i64::try_from(done.last_insert_id()).unwrap_or(i64::MAX))
}

pub async fn update_solution(conn: &mut MySqlConnection, row: &SolutionRow) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_solution set name = ?, description = ?, created_at = ? where id = ?"#,
        &row.name,
        row.description.as_deref(),
        UtcInstant(row.created_at),
        row.id
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn delete_solution(conn: &mut MySqlConnection, id: i64) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ delete from t_solution where id = ?"#, id).execute(conn).await?.rows_affected())
}

pub async fn projects(conn: &mut MySqlConnection) -> Result<Vec<ProjectRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, solution_id, name, description, created_at as "created_at: UtcInstant" from t_project order by id"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ProjectRow {
            id: row.id,
            solution_id: row.solution_id,
            name: row.name,
            description: row.description,
            created_at: row.created_at.0,
        })
        .collect())
}

pub async fn project(conn: &mut MySqlConnection, id: i64) -> Result<Option<ProjectRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id, solution_id, name, description, created_at as "created_at: UtcInstant" from t_project where id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| ProjectRow {
        id: row.id,
        solution_id: row.solution_id,
        name: row.name,
        description: row.description,
        created_at: row.created_at.0,
    }))
}

pub async fn projects_by_ids(conn: &mut MySqlConnection, ids: &str) -> Result<Vec<ProjectRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, solution_id, name, description, created_at as "created_at: UtcInstant" from t_project where id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) order by id"#,
        ids
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ProjectRow {
            id: row.id,
            solution_id: row.solution_id,
            name: row.name,
            description: row.description,
            created_at: row.created_at.0,
        })
        .collect())
}

pub async fn project_named(
    conn: &mut MySqlConnection,
    solution_id: i64,
    name: &str,
) -> Result<Option<ProjectRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id, solution_id, name, description, created_at as "created_at: UtcInstant" from t_project where solution_id = ? and upper(name) = upper(?) order by id"#,
        solution_id,
        name
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| ProjectRow {
        id: row.id,
        solution_id: row.solution_id,
        name: row.name,
        description: row.description,
        created_at: row.created_at.0,
    }))
}

pub async fn count_projects_of_solution(conn: &mut MySqlConnection, solution_id: i64) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_project where solution_id = ?"#,
        solution_id
    )
    .fetch_one(conn)
    .await?)
}

pub async fn projects_of_solution(conn: &mut MySqlConnection, solution_id: i64) -> Result<Vec<ProjectRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, solution_id, name, description, created_at as "created_at: UtcInstant" from t_project where solution_id = ? order by id"#,
        solution_id
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ProjectRow {
            id: row.id,
            solution_id: row.solution_id,
            name: row.name,
            description: row.description,
            created_at: row.created_at.0,
        })
        .collect())
}

pub async fn insert_project(conn: &mut MySqlConnection, row: &ProjectRow) -> Result<i64, DbError> {
    let done = sqlx::query!(
        r#"/* mysql */ insert into t_project (solution_id, name, description, created_at) values (?, ?, ?, ?)"#,
        row.solution_id,
        &row.name,
        row.description.as_deref(),
        UtcInstant(row.created_at)
    )
    .execute(conn)
    .await?;
    // MySQL's last insert id is unsigned; an `auto_increment` on a signed `bigint` never exceeds `i64::MAX`.
    Ok(i64::try_from(done.last_insert_id()).unwrap_or(i64::MAX))
}

pub async fn update_project(conn: &mut MySqlConnection, row: &ProjectRow) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_project set solution_id = ?, name = ?, description = ?, created_at = ? where id = ?"#,
        row.solution_id,
        &row.name,
        row.description.as_deref(),
        UtcInstant(row.created_at),
        row.id
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn delete_project(conn: &mut MySqlConnection, id: i64) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ delete from t_project where id = ?"#, id).execute(conn).await?.rows_affected())
}

pub async fn git_tokens(conn: &mut MySqlConnection) -> Result<Vec<GitTokenRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id as "id: TextUuid", name, host, username, token, created_at as "created_at: UtcInstant" from t_git_token order by created_at desc"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| GitTokenRow {
            id: row.id.0,
            name: row.name,
            host: row.host,
            username: row.username,
            token: row.token,
            created_at: row.created_at.0,
        })
        .collect())
}

pub async fn git_token(conn: &mut MySqlConnection, id: Uuid) -> Result<Option<GitTokenRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id as "id: TextUuid", name, host, username, token, created_at as "created_at: UtcInstant" from t_git_token where id = ?"#,
        TextUuid(id)
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| GitTokenRow {
        id: row.id.0,
        name: row.name,
        host: row.host,
        username: row.username,
        token: row.token,
        created_at: row.created_at.0,
    }))
}

pub async fn insert_git_token(conn: &mut MySqlConnection, row: &GitTokenRow) -> Result<(), DbError> {
    sqlx::query!(
        r#"/* mysql */ insert into t_git_token (id, name, host, username, token, created_at) values (?, ?, ?, ?, ?, ?)"#,
        TextUuid(row.id),
        &row.name,
        &row.host,
        row.username.as_deref(),
        &row.token,
        UtcInstant(row.created_at)
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn delete_git_token(conn: &mut MySqlConnection, id: Uuid) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ delete from t_git_token where id = ?"#, TextUuid(id))
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn ssh_keys(conn: &mut MySqlConnection) -> Result<Vec<SshKeyRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id as "id: TextUuid", name, private_key, public_key, created_at as "created_at: UtcInstant" from t_ssh_key order by created_at desc"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| SshKeyRow {
            id: row.id.0,
            name: row.name,
            private_key: row.private_key,
            public_key: row.public_key,
            created_at: row.created_at.0,
        })
        .collect())
}

pub async fn ssh_key(conn: &mut MySqlConnection, id: Uuid) -> Result<Option<SshKeyRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id as "id: TextUuid", name, private_key, public_key, created_at as "created_at: UtcInstant" from t_ssh_key where id = ?"#,
        TextUuid(id)
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| SshKeyRow {
        id: row.id.0,
        name: row.name,
        private_key: row.private_key,
        public_key: row.public_key,
        created_at: row.created_at.0,
    }))
}

pub async fn insert_ssh_key(conn: &mut MySqlConnection, row: &SshKeyRow) -> Result<(), DbError> {
    sqlx::query!(
        r#"/* mysql */ insert into t_ssh_key (id, name, private_key, public_key, created_at) values (?, ?, ?, ?, ?)"#,
        TextUuid(row.id),
        &row.name,
        &row.private_key,
        row.public_key.as_deref(),
        UtcInstant(row.created_at)
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn delete_ssh_key(conn: &mut MySqlConnection, id: Uuid) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ delete from t_ssh_key where id = ?"#, TextUuid(id))
        .execute(conn)
        .await?
        .rows_affected())
}
