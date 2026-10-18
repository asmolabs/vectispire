//! The scans' statements on PostgreSQL, checked against a migrated server while compiling (`super`'s note). A list is
//! one array parameter, `= any($n)`.

use sqlx::PgConnection;
use time::OffsetDateTime;
use vectispire_cp_db::types::UtcInstant;

use super::{ClaimCandidate, DbError, FindingRow, LatestRow, LeaseRow, NewScan, PayloadRow, ResultWrite, ScanRow};

macro_rules! scan_row {
    ($row:expr) => {{
        let row = $row;
        ScanRow {
            id: row.id,
            branch: row.branch,
            sub_path: row.sub_path,
            status: row.status,
            duration_ms: row.duration_ms,
            findings_count: row.findings_count,
            new_issues_count: row.new_issues_count,
            resolved_issues_count: row.resolved_issues_count,
            error: row.error,
            created_at: row.created_at.0,
            version: row.version,
            project_type: row.project_type,
            repo_id: row.repo_id,
            container_id: row.container_id,
            required_agent_label: row.required_agent_label,
            claimed_by: row.claimed_by,
            claimed_at: row.claimed_at.map(|at| at.0),
            lease_expires_at: row.lease_expires_at.map(|at| at.0),
            attempts: row.attempts,
            not_before: row.not_before.map(|at| at.0),
            plugin_steps: row.plugin_steps,
            examined_types: row.examined_types,
            detected_languages: row.detected_languages,
            sast_languages: row.sast_languages,
            has_sbom: row.has_sbom,
        }
    }};
}

pub async fn insert_scan(conn: &mut PgConnection, scan: &NewScan) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ insert into t_scan (status, created_at, repo_id, container_id, branch, sub_path, required_agent_label, not_before, findings_count, new_issues_count, resolved_issues_count, attempts) values ($1, $2, $3, $4, $5, $6, $7, $8, 0, 0, 0, 0) returning id"#,
        scan.status,
        UtcInstant(scan.created_at) as _,
        scan.repo_id,
        scan.container_id,
        scan.branch,
        scan.sub_path,
        scan.required_agent_label,
        scan.not_before.map(UtcInstant) as _
    )
    .fetch_one(conn)
    .await?)
}

pub async fn scan(conn: &mut PgConnection, id: i64) -> Result<Option<ScanRow>, DbError> {
    let row = sqlx::query!(
        r#"/* postgres */ select id, branch, sub_path, status, duration_ms, findings_count, new_issues_count, resolved_issues_count, error, created_at as "created_at: UtcInstant", version, project_type, repo_id, container_id, required_agent_label, claimed_by, claimed_at as "claimed_at: UtcInstant", lease_expires_at as "lease_expires_at: UtcInstant", attempts, not_before as "not_before: UtcInstant", plugin_steps, examined_types, detected_languages, sast_languages, (sbom is not null) as "has_sbom!" from t_scan where id = $1"#,
        id
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| scan_row!(row)))
}

pub async fn scans_by_ids(conn: &mut PgConnection, ids: &[i64]) -> Result<Vec<ScanRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, branch, sub_path, status, duration_ms, findings_count, new_issues_count, resolved_issues_count, error, created_at as "created_at: UtcInstant", version, project_type, repo_id, container_id, required_agent_label, claimed_by, claimed_at as "claimed_at: UtcInstant", lease_expires_at as "lease_expires_at: UtcInstant", attempts, not_before as "not_before: UtcInstant", plugin_steps, examined_types, detected_languages, sast_languages, (sbom is not null) as "has_sbom!" from t_scan where id = any($1) order by id"#,
        ids
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| scan_row!(row)).collect())
}

pub async fn sbom(conn: &mut PgConnection, id: i64) -> Result<Option<Option<String>>, DbError> {
    Ok(sqlx::query_scalar!(r#"/* postgres */ select sbom from t_scan where id = $1"#, id).fetch_optional(conn).await?)
}

pub async fn count_by_status(conn: &mut PgConnection, status: &str) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(r#"/* postgres */ select count(id) as "count!" from t_scan where status = $1"#, status)
        .fetch_one(conn)
        .await?)
}

pub async fn count_of_repository(conn: &mut PgConnection, status: &str, repo: i64) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(id) as "count!" from t_scan where status = $1 and repo_id = $2"#,
        status,
        repo
    )
    .fetch_one(conn)
    .await?)
}

pub async fn count_of_container(conn: &mut PgConnection, status: &str, container: i64) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(id) as "count!" from t_scan where status = $1 and container_id = $2"#,
        status,
        container
    )
    .fetch_one(conn)
    .await?)
}

pub async fn count_in_flight_of_repository(
    conn: &mut PgConnection,
    statuses: [&str; 2],
    repo: i64,
) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(id) as "count!" from t_scan where status in ($1, $2) and repo_id = $3"#,
        statuses[0],
        statuses[1],
        repo
    )
    .fetch_one(conn)
    .await?)
}

pub async fn count_in_flight_of_container(
    conn: &mut PgConnection,
    statuses: [&str; 2],
    container: i64,
) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(id) as "count!" from t_scan where status in ($1, $2) and container_id = $3"#,
        statuses[0],
        statuses[1],
        container
    )
    .fetch_one(conn)
    .await?)
}

pub async fn claimable_unlabelled(
    conn: &mut PgConnection,
    status: &str,
    as_of: OffsetDateTime,
    limit: i64,
) -> Result<Vec<ClaimCandidate>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, repo_id, created_at as "created_at: UtcInstant" from t_scan where status = $1 and required_agent_label is null and (not_before is null or not_before <= $2) order by created_at asc, id asc limit $3"#,
        status,
        UtcInstant(as_of) as _,
        limit
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ClaimCandidate { id: row.id, repo_id: row.repo_id, created_at: row.created_at.0 })
        .collect())
}

pub async fn claimable_unlabelled_after(
    conn: &mut PgConnection,
    status: &str,
    as_of: OffsetDateTime,
    after_at: OffsetDateTime,
    after_id: i64,
    limit: i64,
) -> Result<Vec<ClaimCandidate>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, repo_id, created_at as "created_at: UtcInstant" from t_scan where status = $1 and required_agent_label is null and (not_before is null or not_before <= $2) and (created_at > $3 or (created_at = $3 and id > $4)) order by created_at asc, id asc limit $5"#,
        status,
        UtcInstant(as_of) as _,
        UtcInstant(after_at) as _,
        after_id,
        limit
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ClaimCandidate { id: row.id, repo_id: row.repo_id, created_at: row.created_at.0 })
        .collect())
}

pub async fn claimable(
    conn: &mut PgConnection,
    status: &str,
    labels: &[String],
    as_of: OffsetDateTime,
    limit: i64,
) -> Result<Vec<ClaimCandidate>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, repo_id, created_at as "created_at: UtcInstant" from t_scan where status = $1 and (required_agent_label is null or required_agent_label = any($2)) and (not_before is null or not_before <= $3) order by created_at asc, id asc limit $4"#,
        status,
        labels,
        UtcInstant(as_of) as _,
        limit
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ClaimCandidate { id: row.id, repo_id: row.repo_id, created_at: row.created_at.0 })
        .collect())
}

#[allow(clippy::too_many_arguments)] // The statement's own parameters.
pub async fn claimable_after(
    conn: &mut PgConnection,
    status: &str,
    labels: &[String],
    as_of: OffsetDateTime,
    after_at: OffsetDateTime,
    after_id: i64,
    limit: i64,
) -> Result<Vec<ClaimCandidate>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, repo_id, created_at as "created_at: UtcInstant" from t_scan where status = $1 and (required_agent_label is null or required_agent_label = any($2)) and (not_before is null or not_before <= $3) and (created_at > $4 or (created_at = $4 and id > $5)) order by created_at asc, id asc limit $6"#,
        status,
        labels,
        UtcInstant(as_of) as _,
        UtcInstant(after_at) as _,
        after_id,
        limit
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ClaimCandidate { id: row.id, repo_id: row.repo_id, created_at: row.created_at.0 })
        .collect())
}

pub async fn count_due(conn: &mut PgConnection, status: &str, as_of: OffsetDateTime) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(id) as "count!" from t_scan where status = $1 and (not_before is null or not_before <= $2)"#,
        status,
        UtcInstant(as_of) as _
    )
    .fetch_one(conn)
    .await?)
}

pub async fn take(
    conn: &mut PgConnection,
    id: i64,
    from: &str,
    to: &str,
    worker: &str,
    claimed_at: OffsetDateTime,
    lease_expires_at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_scan set status = $1, claimed_by = $2, claimed_at = $3, lease_expires_at = $4, attempts = attempts + 1, not_before = null where id = $5 and status = $6 and (not_before is null or not_before <= $3)"#,
        to,
        worker,
        UtcInstant(claimed_at) as _,
        UtcInstant(lease_expires_at) as _,
        id,
        from
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn renew_lease(
    conn: &mut PgConnection,
    id: i64,
    status: &str,
    worker: &str,
    lease_expires_at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_scan set lease_expires_at = $1 where id = $2 and status = $3 and claimed_by = $4"#,
        UtcInstant(lease_expires_at) as _,
        id,
        status,
        worker
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn release_owned(
    conn: &mut PgConnection,
    id: i64,
    running: &str,
    owner: &str,
    to: &str,
    error: Option<&str>,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_scan set status = $1, error = $2, claimed_by = null, claimed_at = null, lease_expires_at = null, not_before = null where id = $3 and status = $4 and claimed_by = $5"#,
        to,
        error,
        id,
        running,
        owner
    )
    .execute(conn)
    .await?
    .rows_affected())
}

#[allow(clippy::too_many_arguments)] // The statement's own parameters.
pub async fn release_owned_attempt(
    conn: &mut PgConnection,
    id: i64,
    running: &str,
    owner: &str,
    attempt: i32,
    to: &str,
    error: Option<&str>,
    not_before: Option<OffsetDateTime>,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_scan set status = $1, error = $2, claimed_by = null, claimed_at = null, lease_expires_at = null, not_before = $3 where id = $4 and status = $5 and claimed_by = $6 and attempts = $7"#,
        to,
        error,
        not_before.map(UtcInstant) as _,
        id,
        running,
        owner,
        attempt
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn release_owned_refunded(
    conn: &mut PgConnection,
    id: i64,
    running: &str,
    owner: &str,
    to: &str,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_scan set status = $1, error = null, claimed_by = null, claimed_at = null, lease_expires_at = null, not_before = null, attempts = case when attempts > 0 then attempts - 1 else 0 end where id = $2 and status = $3 and claimed_by = $4"#,
        to,
        id,
        running,
        owner
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn release_lapsed(
    conn: &mut PgConnection,
    id: i64,
    running: &str,
    as_of: OffsetDateTime,
    to: &str,
    error: Option<&str>,
    not_before: Option<OffsetDateTime>,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_scan set status = $1, error = $2, claimed_by = null, claimed_at = null, lease_expires_at = null, not_before = $3 where id = $4 and status = $5 and (lease_expires_at is null or lease_expires_at < $6)"#,
        to,
        error,
        not_before.map(UtcInstant) as _,
        id,
        running,
        UtcInstant(as_of) as _
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn lapsed(conn: &mut PgConnection, status: &str, as_of: OffsetDateTime) -> Result<Vec<(i64, i32)>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, attempts from t_scan where status = $1 and (lease_expires_at is null or lease_expires_at < $2) order by id"#,
        status,
        UtcInstant(as_of) as _
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.id, row.attempts)).collect())
}

pub async fn count_held(
    conn: &mut PgConnection,
    worker: &str,
    status: &str,
    as_of: OffsetDateTime,
) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(id) as "count!" from t_scan where status = $1 and claimed_by = $2 and lease_expires_at is not null and lease_expires_at >= $3"#,
        status,
        worker,
        UtcInstant(as_of) as _
    )
    .fetch_one(conn)
    .await?)
}

pub async fn record_sast_languages(conn: &mut PgConnection, id: i64, column: Option<&str>) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* postgres */ update t_scan set sast_languages = $1 where id = $2"#, column, id)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn write_result(conn: &mut PgConnection, write: &ResultWrite) -> Result<u64, DbError> {
    let (has_project, project_type, version) = match &write.project {
        Some((kind, version)) => (true, kind.as_deref(), version.as_deref()),
        None => (false, None, None),
    };
    Ok(sqlx::query!(
        r#"/* postgres */ update t_scan set status = $1, findings_count = $2, new_issues_count = $3, resolved_issues_count = $4, duration_ms = $5, sbom = coalesce($6, sbom), project_type = case when $7 then $8 else project_type end, version = case when $7 then $9 else version end, error = $10, plugin_steps = $11, detected_languages = $12, examined_types = coalesce($13, examined_types), claimed_by = null, claimed_at = null, lease_expires_at = null where id = $14"#,
        write.status,
        write.findings_count,
        write.new_issues_count,
        write.resolved_issues_count,
        write.duration_ms,
        write.sbom,
        has_project,
        project_type,
        version,
        write.error,
        write.plugin_steps,
        write.detected_languages,
        write.examined_types,
        write.id
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn payload_bearing(conn: &mut PgConnection) -> Result<Vec<PayloadRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, repo_id, container_id, created_at as "created_at: UtcInstant" from t_scan where sbom is not null or cves is not null order by created_at desc, id desc"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PayloadRow {
            id: row.id,
            repo_id: row.repo_id,
            container_id: row.container_id,
            created_at: row.created_at.0,
        })
        .collect())
}

pub async fn count_payload_bearing(conn: &mut PgConnection) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(id) as "count!" from t_scan where sbom is not null or cves is not null"#
    )
    .fetch_one(conn)
    .await?)
}

pub async fn drop_payloads(conn: &mut PgConnection, ids: &[i64]) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* postgres */ update t_scan set sbom = null, cves = null where id = any($1)"#, ids)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn latest_per_repository(conn: &mut PgConnection) -> Result<Vec<LatestRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select s.repo_id as "target_id!", s.id, s.status, s.created_at as "created_at: UtcInstant", s.error from t_scan s where s.repo_id is not null and s.id = (select max(l.id) from t_scan l where l.repo_id = s.repo_id)"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| LatestRow {
            target_id: row.target_id,
            scan_id: row.id,
            status: row.status,
            created_at: row.created_at.0,
            error: row.error,
        })
        .collect())
}

pub async fn latest_per_container(conn: &mut PgConnection) -> Result<Vec<LatestRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select s.container_id as "target_id!", s.id, s.status, s.created_at as "created_at: UtcInstant", s.error from t_scan s where s.container_id is not null and s.id = (select max(l.id) from t_scan l where l.container_id = s.container_id)"#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| LatestRow {
            target_id: row.target_id,
            scan_id: row.id,
            status: row.status,
            created_at: row.created_at.0,
            error: row.error,
        })
        .collect())
}

pub async fn newest_detected_languages(
    conn: &mut PgConnection,
    repositories: &[i64],
    status: &str,
) -> Result<Vec<(i64, Option<String>)>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select s.repo_id as "repo_id!", s.detected_languages from t_scan s where s.repo_id = any($1) and s.id = (select max(l.id) from t_scan l where l.repo_id = s.repo_id and l.status = $2)"#,
        repositories,
        status
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.repo_id, row.detected_languages)).collect())
}

pub async fn history_page(
    conn: &mut PgConnection,
    repo: Option<i64>,
    container: Option<i64>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ScanRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, branch, sub_path, status, duration_ms, findings_count, new_issues_count, resolved_issues_count, error, created_at as "created_at: UtcInstant", version, project_type, repo_id, container_id, required_agent_label, claimed_by, claimed_at as "claimed_at: UtcInstant", lease_expires_at as "lease_expires_at: UtcInstant", attempts, not_before as "not_before: UtcInstant", plugin_steps, examined_types, detected_languages, sast_languages, (sbom is not null) as "has_sbom!" from t_scan where ($1::bigint is null or repo_id = $1) and ($2::bigint is null or container_id = $2) order by created_at desc, id desc limit $3 offset $4"#,
        repo,
        container,
        limit,
        offset
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| scan_row!(row)).collect())
}

#[allow(clippy::too_many_arguments)] // The statement's own parameters.
pub async fn history_within(
    conn: &mut PgConnection,
    repo: Option<i64>,
    container: Option<i64>,
    repositories: &[i64],
    containers: &[i64],
    limit: i64,
    offset: i64,
) -> Result<Vec<ScanRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, branch, sub_path, status, duration_ms, findings_count, new_issues_count, resolved_issues_count, error, created_at as "created_at: UtcInstant", version, project_type, repo_id, container_id, required_agent_label, claimed_by, claimed_at as "claimed_at: UtcInstant", lease_expires_at as "lease_expires_at: UtcInstant", attempts, not_before as "not_before: UtcInstant", plugin_steps, examined_types, detected_languages, sast_languages, (sbom is not null) as "has_sbom!" from t_scan where ($1::bigint is null or repo_id = $1) and ($2::bigint is null or container_id = $2) and (repo_id = any($3) or (repo_id is null and container_id = any($4))) order by created_at desc, id desc limit $5 offset $6"#,
        repo,
        container,
        repositories,
        containers,
        limit,
        offset
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| scan_row!(row)).collect())
}

pub async fn findings_of_scan(conn: &mut PgConnection, scan: i64, limit: i64) -> Result<Vec<FindingRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, type as kind, severity, identifier, package_name, package_version, fix_versions, file_path, line, description, link, tool, tool_name, tool_version from t_finding where scan_id = $1 order by case severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 when 'negligible' then 4 else 5 end asc, id asc limit $2"#,
        scan,
        limit
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| FindingRow {
            id: row.id,
            kind: row.kind,
            severity: row.severity,
            identifier: row.identifier,
            package_name: row.package_name,
            package_version: row.package_version,
            fix_versions: row.fix_versions,
            file_path: row.file_path,
            line: row.line,
            description: row.description,
            link: row.link,
            tool: row.tool,
            tool_name: row.tool_name,
            tool_version: row.tool_version,
        })
        .collect())
}

pub async fn count_findings_of_scan(conn: &mut PgConnection, scan: i64) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(r#"/* postgres */ select count(id) as "count!" from t_finding where scan_id = $1"#, scan)
        .fetch_one(conn)
        .await?)
}

pub async fn ids_of_repository(conn: &mut PgConnection, repo: i64) -> Result<Vec<i64>, DbError> {
    Ok(sqlx::query_scalar!(r#"/* postgres */ select id from t_scan where repo_id = $1 order by id"#, repo)
        .fetch_all(conn)
        .await?)
}

pub async fn ids_of_container(conn: &mut PgConnection, container: i64) -> Result<Vec<i64>, DbError> {
    Ok(sqlx::query_scalar!(r#"/* postgres */ select id from t_scan where container_id = $1 order by id"#, container)
        .fetch_all(conn)
        .await?)
}

/// Named after Java's repository method, which `cp-arch-tests/data/sql-known.toml` lists by that name.
pub struct ScanRepository;

impl ScanRepository {
    /// The one statement naming `targets`' tables: the orphan sweep's anti-join (`sql-known.toml` says why).
    pub async fn find_orphaned_ids(conn: &mut PgConnection) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar!(
            r#"/* postgres */ select s.id from t_scan s where (s.container_id is not null and s.container_id not in (select c.id from t_container c)) or (s.repo_id is not null and s.repo_id not in (select r.id from t_repository r)) order by s.id"#
        )
        .fetch_all(conn)
        .await?)
    }
}

pub async fn delete_scans(conn: &mut PgConnection, ids: &[i64]) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* postgres */ delete from t_scan where id = any($1)"#, ids)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn delete_findings_of_scans(conn: &mut PgConnection, ids: &[i64]) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* postgres */ delete from t_finding where scan_id = any($1)"#, ids)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn delete_findings_of_issues(conn: &mut PgConnection, ids: &[i64]) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* postgres */ delete from t_finding where issue_id = any($1)"#, ids)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn attempted_repository_scans(conn: &mut PgConnection, status: &str) -> Result<Vec<(i64, i64)>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, repo_id as "repo_id!" from t_scan where status = $1 and repo_id is not null and attempts > 0 order by id"#,
        status
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.id, row.repo_id)).collect())
}

pub async fn reset_attempts(conn: &mut PgConnection, ids: &[i64], status: &str) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_scan set attempts = 0, not_before = null where id = any($1) and status = $2 and attempts > 0"#,
        ids,
        status
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn waiting_by_label_and_repository(
    conn: &mut PgConnection,
    status: &str,
) -> Result<Vec<(Option<String>, i64, i64)>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select required_agent_label, repo_id as "repo_id!", count(id) as "count!" from t_scan where status = $1 and repo_id is not null group by required_agent_label, repo_id order by required_agent_label, repo_id"#,
        status
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.required_agent_label, row.repo_id, row.count)).collect())
}

pub async fn count_by_claimant(conn: &mut PgConnection, status: &str) -> Result<Vec<(String, i64)>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select claimed_by as "claimed_by!", count(id) as "count!" from t_scan where status = $1 and claimed_by is not null group by claimed_by order by claimed_by"#,
        status
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.claimed_by, row.count)).collect())
}

pub async fn count_by_required_label(conn: &mut PgConnection, status: &str) -> Result<Vec<(String, i64)>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select required_agent_label as "label!", count(id) as "count!" from t_scan where status = $1 and required_agent_label is not null group by required_agent_label order by required_agent_label"#,
        status
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.label, row.count)).collect())
}

pub async fn count_claimed_by(conn: &mut PgConnection, status: &str, claimant: &str) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(id) as "count!" from t_scan where status = $1 and claimed_by = $2"#,
        status,
        claimant
    )
    .fetch_one(conn)
    .await?)
}

pub async fn with_status_oldest_first(conn: &mut PgConnection, statuses: [&str; 2]) -> Result<Vec<ScanRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id, branch, sub_path, status, duration_ms, findings_count, new_issues_count, resolved_issues_count, error, created_at as "created_at: UtcInstant", version, project_type, repo_id, container_id, required_agent_label, claimed_by, claimed_at as "claimed_at: UtcInstant", lease_expires_at as "lease_expires_at: UtcInstant", attempts, not_before as "not_before: UtcInstant", plugin_steps, examined_types, detected_languages, sast_languages, (sbom is not null) as "has_sbom!" from t_scan where status in ($1, $2) order by created_at asc, id asc"#,
        statuses[0],
        statuses[1]
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| scan_row!(row)).collect())
}

pub async fn count_since(conn: &mut PgConnection, status: &str, after: OffsetDateTime) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(id) as "count!" from t_scan where status = $1 and created_at > $2"#,
        status,
        UtcInstant(after) as _
    )
    .fetch_one(conn)
    .await?)
}

pub async fn average_duration_since(
    conn: &mut PgConnection,
    status: &str,
    after: OffsetDateTime,
) -> Result<Option<f64>, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select avg(duration_ms)::float8 as "average" from t_scan where status = $1 and created_at >= $2 and duration_ms is not null"#,
        status,
        UtcInstant(after) as _
    )
    .fetch_one(conn)
    .await?)
}

pub async fn labels_of(conn: &mut PgConnection, ids: &[i64]) -> Result<Vec<(i64, String, Option<String>)>, DbError> {
    let rows =
        sqlx::query!(r#"/* postgres */ select id, branch, version from t_scan where id = any($1) order by id"#, ids)
            .fetch_all(conn)
            .await?;
    Ok(rows.into_iter().map(|row| (row.id, row.branch, row.version)).collect())
}

pub async fn lease(conn: &mut PgConnection, name: &str) -> Result<Option<LeaseRow>, DbError> {
    let row = sqlx::query!(
        r#"/* postgres */ select holder, expires_at as "expires_at: UtcInstant" from t_leader_lease where name = $1"#,
        name
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| LeaseRow { holder: row.holder, expires_at: row.expires_at.map(|at| at.0) }))
}

pub async fn renew_leadership(
    conn: &mut PgConnection,
    name: &str,
    holder: &str,
    expires_at: OffsetDateTime,
    at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_leader_lease set expires_at = $1, updated_at = $2 where name = $3 and holder = $4"#,
        UtcInstant(expires_at) as _,
        UtcInstant(at) as _,
        name,
        holder
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn take_over_from(
    conn: &mut PgConnection,
    name: &str,
    holder: &str,
    expires_at: OffsetDateTime,
    at: OffsetDateTime,
    previous_holder: &str,
    previous_expiry: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_leader_lease set holder = $1, expires_at = $2, acquired_at = $3, updated_at = $3 where name = $4 and holder = $5 and expires_at = $6"#,
        holder,
        UtcInstant(expires_at) as _,
        UtcInstant(at) as _,
        name,
        previous_holder,
        UtcInstant(previous_expiry) as _
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn take_over_released(
    conn: &mut PgConnection,
    name: &str,
    holder: &str,
    expires_at: OffsetDateTime,
    at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_leader_lease set holder = $1, expires_at = $2, acquired_at = $3, updated_at = $3 where name = $4 and holder is null and expires_at is null"#,
        holder,
        UtcInstant(expires_at) as _,
        UtcInstant(at) as _,
        name
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn release_leadership(
    conn: &mut PgConnection,
    name: &str,
    holder: &str,
    at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ update t_leader_lease set holder = null, expires_at = null, updated_at = $1 where name = $2 and holder = $3"#,
        UtcInstant(at) as _,
        name,
        holder
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn insert_lease(
    conn: &mut PgConnection,
    name: &str,
    holder: &str,
    at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ insert into t_leader_lease (name, holder, acquired_at, expires_at, updated_at) values ($1, $2, $3, $4, $3)"#,
        name,
        holder,
        UtcInstant(at) as _,
        UtcInstant(expires_at) as _
    )
    .execute(conn)
    .await?
    .rows_affected())
}
