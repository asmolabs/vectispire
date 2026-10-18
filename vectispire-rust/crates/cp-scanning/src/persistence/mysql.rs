//! The scans' statements on MySQL, checked against a migrated server while compiling (`super`'s note). MySQL describes
//! no parameter type, so the binds are checked at run time by the engine suite, on this engine. A list is one JSON
//! array read by `json_table` — MySQL has no array parameter — and a parameter used twice is bound twice.

use sqlx::MySqlConnection;
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
            has_sbom: row.has_sbom != 0,
        }
    }};
}

pub async fn insert_scan(conn: &mut MySqlConnection, scan: &NewScan) -> Result<i64, DbError> {
    let done = sqlx::query!(
        r#"/* mysql */ insert into t_scan (status, created_at, repo_id, container_id, branch, sub_path, required_agent_label, not_before, findings_count, new_issues_count, resolved_issues_count, attempts) values (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0)"#,
        scan.status,
        UtcInstant(scan.created_at),
        scan.repo_id,
        scan.container_id,
        scan.branch,
        scan.sub_path,
        scan.required_agent_label,
        scan.not_before.map(UtcInstant)
    )
    .execute(conn)
    .await?;
    // `bigint auto_increment`: the identifier fits an `i64` by the column's type.
    Ok(i64::try_from(done.last_insert_id()).unwrap_or(i64::MAX))
}

pub async fn scan(conn: &mut MySqlConnection, id: i64) -> Result<Option<ScanRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select id, branch, sub_path, status, duration_ms, findings_count, new_issues_count, resolved_issues_count, error, created_at as "created_at: UtcInstant", version, project_type, repo_id, container_id, required_agent_label, claimed_by, claimed_at as "claimed_at: UtcInstant", lease_expires_at as "lease_expires_at: UtcInstant", attempts, not_before as "not_before: UtcInstant", plugin_steps, examined_types, detected_languages, sast_languages, case when sbom is null then 0 else 1 end as "has_sbom!: i64" from t_scan where id = ?"#,
        id
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| scan_row!(row)))
}

pub async fn scans_by_ids(conn: &mut MySqlConnection, ids: &str) -> Result<Vec<ScanRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, branch, sub_path, status, duration_ms, findings_count, new_issues_count, resolved_issues_count, error, created_at as "created_at: UtcInstant", version, project_type, repo_id, container_id, required_agent_label, claimed_by, claimed_at as "claimed_at: UtcInstant", lease_expires_at as "lease_expires_at: UtcInstant", attempts, not_before as "not_before: UtcInstant", plugin_steps, examined_types, detected_languages, sast_languages, case when sbom is null then 0 else 1 end as "has_sbom!: i64" from t_scan where id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) order by id"#,
        ids
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| scan_row!(row)).collect())
}

pub async fn sbom(conn: &mut MySqlConnection, id: i64) -> Result<Option<Option<String>>, DbError> {
    Ok(sqlx::query_scalar!(r#"/* mysql */ select sbom from t_scan where id = ?"#, id).fetch_optional(conn).await?)
}

pub async fn count_by_status(conn: &mut MySqlConnection, status: &str) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(r#"/* mysql */ select count(id) as "count!: i64" from t_scan where status = ?"#, status)
        .fetch_one(conn)
        .await?)
}

pub async fn count_of_repository(conn: &mut MySqlConnection, status: &str, repo: i64) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_scan where status = ? and repo_id = ?"#,
        status,
        repo
    )
    .fetch_one(conn)
    .await?)
}

pub async fn count_of_container(conn: &mut MySqlConnection, status: &str, container: i64) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_scan where status = ? and container_id = ?"#,
        status,
        container
    )
    .fetch_one(conn)
    .await?)
}

pub async fn count_in_flight_of_repository(
    conn: &mut MySqlConnection,
    statuses: [&str; 2],
    repo: i64,
) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_scan where status in (?, ?) and repo_id = ?"#,
        statuses[0],
        statuses[1],
        repo
    )
    .fetch_one(conn)
    .await?)
}

pub async fn count_in_flight_of_container(
    conn: &mut MySqlConnection,
    statuses: [&str; 2],
    container: i64,
) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_scan where status in (?, ?) and container_id = ?"#,
        statuses[0],
        statuses[1],
        container
    )
    .fetch_one(conn)
    .await?)
}

pub async fn claimable_unlabelled(
    conn: &mut MySqlConnection,
    status: &str,
    as_of: OffsetDateTime,
    limit: i64,
) -> Result<Vec<ClaimCandidate>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, repo_id, created_at as "created_at: UtcInstant" from t_scan where status = ? and required_agent_label is null and (not_before is null or not_before <= ?) order by created_at asc, id asc limit ?"#,
        status,
        UtcInstant(as_of),
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
    conn: &mut MySqlConnection,
    status: &str,
    as_of: OffsetDateTime,
    after_at: OffsetDateTime,
    after_id: i64,
    limit: i64,
) -> Result<Vec<ClaimCandidate>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, repo_id, created_at as "created_at: UtcInstant" from t_scan where status = ? and required_agent_label is null and (not_before is null or not_before <= ?) and (created_at > ? or (created_at = ? and id > ?)) order by created_at asc, id asc limit ?"#,
        status,
        UtcInstant(as_of),
        UtcInstant(after_at),
        UtcInstant(after_at),
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
    conn: &mut MySqlConnection,
    status: &str,
    labels: &str,
    as_of: OffsetDateTime,
    limit: i64,
) -> Result<Vec<ClaimCandidate>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, repo_id, created_at as "created_at: UtcInstant" from t_scan where status = ? and (required_agent_label is null or required_agent_label in (select j.label from json_table(?, '$[*]' columns (label varchar(255) path '$')) as j)) and (not_before is null or not_before <= ?) order by created_at asc, id asc limit ?"#,
        status,
        labels,
        UtcInstant(as_of),
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
    conn: &mut MySqlConnection,
    status: &str,
    labels: &str,
    as_of: OffsetDateTime,
    after_at: OffsetDateTime,
    after_id: i64,
    limit: i64,
) -> Result<Vec<ClaimCandidate>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, repo_id, created_at as "created_at: UtcInstant" from t_scan where status = ? and (required_agent_label is null or required_agent_label in (select j.label from json_table(?, '$[*]' columns (label varchar(255) path '$')) as j)) and (not_before is null or not_before <= ?) and (created_at > ? or (created_at = ? and id > ?)) order by created_at asc, id asc limit ?"#,
        status,
        labels,
        UtcInstant(as_of),
        UtcInstant(after_at),
        UtcInstant(after_at),
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

pub async fn count_due(conn: &mut MySqlConnection, status: &str, as_of: OffsetDateTime) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_scan where status = ? and (not_before is null or not_before <= ?)"#,
        status,
        UtcInstant(as_of)
    )
    .fetch_one(conn)
    .await?)
}

pub async fn take(
    conn: &mut MySqlConnection,
    id: i64,
    from: &str,
    to: &str,
    worker: &str,
    claimed_at: OffsetDateTime,
    lease_expires_at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_scan set status = ?, claimed_by = ?, claimed_at = ?, lease_expires_at = ?, attempts = attempts + 1, not_before = null where id = ? and status = ? and (not_before is null or not_before <= ?)"#,
        to,
        worker,
        UtcInstant(claimed_at),
        UtcInstant(lease_expires_at),
        id,
        from,
        UtcInstant(claimed_at)
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn renew_lease(
    conn: &mut MySqlConnection,
    id: i64,
    status: &str,
    worker: &str,
    lease_expires_at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_scan set lease_expires_at = ? where id = ? and status = ? and claimed_by = ?"#,
        UtcInstant(lease_expires_at),
        id,
        status,
        worker
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn release_owned(
    conn: &mut MySqlConnection,
    id: i64,
    running: &str,
    owner: &str,
    to: &str,
    error: Option<&str>,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_scan set status = ?, error = ?, claimed_by = null, claimed_at = null, lease_expires_at = null, not_before = null where id = ? and status = ? and claimed_by = ?"#,
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
    conn: &mut MySqlConnection,
    id: i64,
    running: &str,
    owner: &str,
    attempt: i32,
    to: &str,
    error: Option<&str>,
    not_before: Option<OffsetDateTime>,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_scan set status = ?, error = ?, claimed_by = null, claimed_at = null, lease_expires_at = null, not_before = ? where id = ? and status = ? and claimed_by = ? and attempts = ?"#,
        to,
        error,
        not_before.map(UtcInstant),
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
    conn: &mut MySqlConnection,
    id: i64,
    running: &str,
    owner: &str,
    to: &str,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_scan set status = ?, error = null, claimed_by = null, claimed_at = null, lease_expires_at = null, not_before = null, attempts = case when attempts > 0 then attempts - 1 else 0 end where id = ? and status = ? and claimed_by = ?"#,
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
    conn: &mut MySqlConnection,
    id: i64,
    running: &str,
    as_of: OffsetDateTime,
    to: &str,
    error: Option<&str>,
    not_before: Option<OffsetDateTime>,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_scan set status = ?, error = ?, claimed_by = null, claimed_at = null, lease_expires_at = null, not_before = ? where id = ? and status = ? and (lease_expires_at is null or lease_expires_at < ?)"#,
        to,
        error,
        not_before.map(UtcInstant),
        id,
        running,
        UtcInstant(as_of)
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn lapsed(
    conn: &mut MySqlConnection,
    status: &str,
    as_of: OffsetDateTime,
) -> Result<Vec<(i64, i32)>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, attempts from t_scan where status = ? and (lease_expires_at is null or lease_expires_at < ?) order by id"#,
        status,
        UtcInstant(as_of)
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.id, row.attempts)).collect())
}

pub async fn count_held(
    conn: &mut MySqlConnection,
    worker: &str,
    status: &str,
    as_of: OffsetDateTime,
) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_scan where status = ? and claimed_by = ? and lease_expires_at is not null and lease_expires_at >= ?"#,
        status,
        worker,
        UtcInstant(as_of)
    )
    .fetch_one(conn)
    .await?)
}

pub async fn record_sast_languages(conn: &mut MySqlConnection, id: i64, column: Option<&str>) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ update t_scan set sast_languages = ? where id = ?"#, column, id)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn write_result(conn: &mut MySqlConnection, write: &ResultWrite) -> Result<u64, DbError> {
    let (has_project, project_type, version) = match &write.project {
        Some((kind, version)) => (true, kind.as_deref(), version.as_deref()),
        None => (false, None, None),
    };
    Ok(sqlx::query!(
        r#"/* mysql */ update t_scan set status = ?, findings_count = ?, new_issues_count = ?, resolved_issues_count = ?, duration_ms = ?, sbom = coalesce(?, sbom), project_type = case when ? then ? else project_type end, version = case when ? then ? else version end, error = ?, plugin_steps = ?, detected_languages = ?, examined_types = coalesce(?, examined_types), claimed_by = null, claimed_at = null, lease_expires_at = null where id = ?"#,
        write.status,
        write.findings_count,
        write.new_issues_count,
        write.resolved_issues_count,
        write.duration_ms,
        write.sbom,
        has_project,
        project_type,
        has_project,
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

pub async fn payload_bearing(conn: &mut MySqlConnection) -> Result<Vec<PayloadRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, repo_id, container_id, created_at as "created_at: UtcInstant" from t_scan where sbom is not null or cves is not null order by created_at desc, id desc"#
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

pub async fn count_payload_bearing(conn: &mut MySqlConnection) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_scan where sbom is not null or cves is not null"#
    )
    .fetch_one(conn)
    .await?)
}

pub async fn drop_payloads(conn: &mut MySqlConnection, ids: &str) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ update t_scan set sbom = null, cves = null where id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j)"#,
        ids
    )
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn latest_per_repository(conn: &mut MySqlConnection) -> Result<Vec<LatestRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select s.repo_id as "target_id!", s.id, s.status, s.created_at as "created_at: UtcInstant", s.error from t_scan s where s.repo_id is not null and s.id = (select max(l.id) from t_scan l where l.repo_id = s.repo_id)"#
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

pub async fn latest_per_container(conn: &mut MySqlConnection) -> Result<Vec<LatestRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select s.container_id as "target_id!", s.id, s.status, s.created_at as "created_at: UtcInstant", s.error from t_scan s where s.container_id is not null and s.id = (select max(l.id) from t_scan l where l.container_id = s.container_id)"#
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
    conn: &mut MySqlConnection,
    repositories: &str,
    status: &str,
) -> Result<Vec<(i64, Option<String>)>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select s.repo_id as "repo_id!", s.detected_languages from t_scan s where s.repo_id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) and s.id = (select max(l.id) from t_scan l where l.repo_id = s.repo_id and l.status = ?)"#,
        repositories,
        status
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.repo_id, row.detected_languages)).collect())
}

pub async fn history_page(
    conn: &mut MySqlConnection,
    repo: Option<i64>,
    container: Option<i64>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ScanRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, branch, sub_path, status, duration_ms, findings_count, new_issues_count, resolved_issues_count, error, created_at as "created_at: UtcInstant", version, project_type, repo_id, container_id, required_agent_label, claimed_by, claimed_at as "claimed_at: UtcInstant", lease_expires_at as "lease_expires_at: UtcInstant", attempts, not_before as "not_before: UtcInstant", plugin_steps, examined_types, detected_languages, sast_languages, case when sbom is null then 0 else 1 end as "has_sbom!: i64" from t_scan where (? is null or repo_id = ?) and (? is null or container_id = ?) order by created_at desc, id desc limit ? offset ?"#,
        repo,
        repo,
        container,
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
    conn: &mut MySqlConnection,
    repo: Option<i64>,
    container: Option<i64>,
    repositories: &str,
    containers: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ScanRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, branch, sub_path, status, duration_ms, findings_count, new_issues_count, resolved_issues_count, error, created_at as "created_at: UtcInstant", version, project_type, repo_id, container_id, required_agent_label, claimed_by, claimed_at as "claimed_at: UtcInstant", lease_expires_at as "lease_expires_at: UtcInstant", attempts, not_before as "not_before: UtcInstant", plugin_steps, examined_types, detected_languages, sast_languages, case when sbom is null then 0 else 1 end as "has_sbom!: i64" from t_scan where (? is null or repo_id = ?) and (? is null or container_id = ?) and (repo_id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) or (repo_id is null and container_id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j))) order by created_at desc, id desc limit ? offset ?"#,
        repo,
        repo,
        container,
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

pub async fn findings_of_scan(conn: &mut MySqlConnection, scan: i64, limit: i64) -> Result<Vec<FindingRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, type as kind, severity, identifier, package_name, package_version, fix_versions, file_path, line, description, link, tool, tool_name, tool_version from t_finding where scan_id = ? order by case severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 when 'negligible' then 4 else 5 end asc, id asc limit ?"#,
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

pub async fn count_findings_of_scan(conn: &mut MySqlConnection, scan: i64) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(r#"/* mysql */ select count(id) as "count!: i64" from t_finding where scan_id = ?"#, scan)
        .fetch_one(conn)
        .await?)
}

pub async fn ids_of_repository(conn: &mut MySqlConnection, repo: i64) -> Result<Vec<i64>, DbError> {
    Ok(sqlx::query_scalar!(r#"/* mysql */ select id from t_scan where repo_id = ? order by id"#, repo)
        .fetch_all(conn)
        .await?)
}

pub async fn ids_of_container(conn: &mut MySqlConnection, container: i64) -> Result<Vec<i64>, DbError> {
    Ok(sqlx::query_scalar!(r#"/* mysql */ select id from t_scan where container_id = ? order by id"#, container)
        .fetch_all(conn)
        .await?)
}

/// Named after Java's repository method, which `cp-arch-tests/data/sql-known.toml` lists by that name.
pub struct ScanRepository;

impl ScanRepository {
    /// The one statement naming `targets`' tables: the orphan sweep's anti-join (`sql-known.toml` says why).
    pub async fn find_orphaned_ids(conn: &mut MySqlConnection) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar!(
            r#"/* mysql */ select s.id from t_scan s where (s.container_id is not null and s.container_id not in (select c.id from t_container c)) or (s.repo_id is not null and s.repo_id not in (select r.id from t_repository r)) order by s.id"#
    )
        .fetch_all(conn)
        .await?)
    }
}

pub async fn delete_scans(conn: &mut MySqlConnection, ids: &str) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ delete from t_scan where id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j)"#,
        ids
    ).execute(conn).await?.rows_affected())
}

pub async fn delete_findings_of_scans(conn: &mut MySqlConnection, ids: &str) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ delete from t_finding where scan_id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j)"#,
        ids
    )
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn delete_findings_of_issues(conn: &mut MySqlConnection, ids: &str) -> Result<u64, DbError> {
    Ok(sqlx::query!(r#"/* mysql */ delete from t_finding where issue_id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j)"#,
        ids
    )
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn attempted_repository_scans(conn: &mut MySqlConnection, status: &str) -> Result<Vec<(i64, i64)>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, repo_id as "repo_id!" from t_scan where status = ? and repo_id is not null and attempts > 0 order by id"#,
        status
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.id, row.repo_id)).collect())
}

pub async fn reset_attempts(conn: &mut MySqlConnection, ids: &str, status: &str) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_scan set attempts = 0, not_before = null where id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) and status = ? and attempts > 0"#,
        ids,
        status
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn waiting_by_label_and_repository(
    conn: &mut MySqlConnection,
    status: &str,
) -> Result<Vec<(Option<String>, i64, i64)>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select required_agent_label, repo_id as "repo_id!", count(id) as "count!: i64" from t_scan where status = ? and repo_id is not null group by required_agent_label, repo_id order by required_agent_label, repo_id"#,
        status
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.required_agent_label, row.repo_id, row.count)).collect())
}

pub async fn count_by_claimant(conn: &mut MySqlConnection, status: &str) -> Result<Vec<(String, i64)>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select claimed_by as "claimed_by!", count(id) as "count!: i64" from t_scan where status = ? and claimed_by is not null group by claimed_by order by claimed_by"#,
        status
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.claimed_by, row.count)).collect())
}

pub async fn count_by_required_label(conn: &mut MySqlConnection, status: &str) -> Result<Vec<(String, i64)>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select required_agent_label as "label!", count(id) as "count!: i64" from t_scan where status = ? and required_agent_label is not null group by required_agent_label order by required_agent_label"#,
        status
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| (row.label, row.count)).collect())
}

pub async fn count_claimed_by(conn: &mut MySqlConnection, status: &str, claimant: &str) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_scan where status = ? and claimed_by = ?"#,
        status,
        claimant
    )
    .fetch_one(conn)
    .await?)
}

pub async fn with_status_oldest_first(
    conn: &mut MySqlConnection,
    statuses: [&str; 2],
) -> Result<Vec<ScanRow>, DbError> {
    let rows = sqlx::query!(
        r#"/* mysql */ select id, branch, sub_path, status, duration_ms, findings_count, new_issues_count, resolved_issues_count, error, created_at as "created_at: UtcInstant", version, project_type, repo_id, container_id, required_agent_label, claimed_by, claimed_at as "claimed_at: UtcInstant", lease_expires_at as "lease_expires_at: UtcInstant", attempts, not_before as "not_before: UtcInstant", plugin_steps, examined_types, detected_languages, sast_languages, case when sbom is null then 0 else 1 end as "has_sbom!: i64" from t_scan where status in (?, ?) order by created_at asc, id asc"#,
        statuses[0],
        statuses[1]
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|row| scan_row!(row)).collect())
}

pub async fn count_since(conn: &mut MySqlConnection, status: &str, after: OffsetDateTime) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select count(id) as "count!: i64" from t_scan where status = ? and created_at > ?"#,
        status,
        UtcInstant(after)
    )
    .fetch_one(conn)
    .await?)
}

pub async fn average_duration_since(
    conn: &mut MySqlConnection,
    status: &str,
    after: OffsetDateTime,
) -> Result<Option<f64>, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* mysql */ select cast(avg(duration_ms) as double) as "average: f64" from t_scan where status = ? and created_at >= ? and duration_ms is not null"#,
        status,
        UtcInstant(after)
    )
    .fetch_one(conn)
    .await?)
}

pub async fn labels_of(conn: &mut MySqlConnection, ids: &str) -> Result<Vec<(i64, String, Option<String>)>, DbError> {
    let rows = sqlx::query!(r#"/* mysql */ select id, branch, version from t_scan where id in (select j.id from json_table(?, '$[*]' columns (id bigint path '$')) as j) order by id"#,
        ids
    )
        .fetch_all(conn)
        .await?;
    Ok(rows.into_iter().map(|row| (row.id, row.branch, row.version)).collect())
}

pub async fn lease(conn: &mut MySqlConnection, name: &str) -> Result<Option<LeaseRow>, DbError> {
    let row = sqlx::query!(
        r#"/* mysql */ select holder, expires_at as "expires_at: UtcInstant" from t_leader_lease where name = ?"#,
        name
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| LeaseRow { holder: row.holder, expires_at: row.expires_at.map(|at| at.0) }))
}

pub async fn renew_leadership(
    conn: &mut MySqlConnection,
    name: &str,
    holder: &str,
    expires_at: OffsetDateTime,
    at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_leader_lease set expires_at = ?, updated_at = ? where name = ? and holder = ?"#,
        UtcInstant(expires_at),
        UtcInstant(at),
        name,
        holder
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn take_over_from(
    conn: &mut MySqlConnection,
    name: &str,
    holder: &str,
    expires_at: OffsetDateTime,
    at: OffsetDateTime,
    previous_holder: &str,
    previous_expiry: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_leader_lease set holder = ?, expires_at = ?, acquired_at = ?, updated_at = ? where name = ? and holder = ? and expires_at = ?"#,
        holder,
        UtcInstant(expires_at),
        UtcInstant(at),
        UtcInstant(at),
        name,
        previous_holder,
        UtcInstant(previous_expiry)
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn take_over_released(
    conn: &mut MySqlConnection,
    name: &str,
    holder: &str,
    expires_at: OffsetDateTime,
    at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_leader_lease set holder = ?, expires_at = ?, acquired_at = ?, updated_at = ? where name = ? and holder is null and expires_at is null"#,
        holder,
        UtcInstant(expires_at),
        UtcInstant(at),
        UtcInstant(at),
        name
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn release_leadership(
    conn: &mut MySqlConnection,
    name: &str,
    holder: &str,
    at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ update t_leader_lease set holder = null, expires_at = null, updated_at = ? where name = ? and holder = ?"#,
        UtcInstant(at),
        name,
        holder
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn insert_lease(
    conn: &mut MySqlConnection,
    name: &str,
    holder: &str,
    at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        r#"/* mysql */ insert into t_leader_lease (name, holder, acquired_at, expires_at, updated_at) values (?, ?, ?, ?, ?)"#,
        name,
        holder,
        UtcInstant(at),
        UtcInstant(expires_at),
        UtcInstant(at)
    )
    .execute(conn)
    .await?
    .rows_affected())
}
