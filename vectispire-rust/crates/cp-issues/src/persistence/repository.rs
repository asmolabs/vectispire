//! Persistence operations for issues tables:
//! `t_issue` and `t_issue_triage_event`.

use sqlx::{AssertSqlSafe, Row};
use time::OffsetDateTime;
use vectispire_cp_db::types::UtcInstant;
use vectispire_cp_db::{ScanTarget, Tx, Visibility};

use super::filters::IssueFilters;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct IssueRow {
    pub id: i64,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub fingerprint: String,
    pub type_: String,
    pub identifier: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub purl: Option<String>,
    pub file_path: Option<String>,
    pub owasp_category: Option<String>,
    pub source: String,
    pub tool: Option<String>,
    pub tool_name: Option<String>,
    pub tool_version: Option<String>,
    pub import_source: Option<String>,
    pub severity: String,
    pub epss_score: Option<f64>,
    pub is_kev: bool,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub fix_state: Option<String>,
    pub fix_versions: Option<String>,
    pub link: Option<String>,
    pub description: Option<String>,
    pub reachability: String,
    pub reachable_symbols: Option<String>,
    pub state: String,
    pub first_seen_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
    pub resolution_seconds: Option<i64>,
    pub sla_breach_signalled_at: Option<OffsetDateTime>,
    pub first_seen_scan_id: Option<i64>,
    pub last_seen_scan_id: Option<i64>,
    pub times_seen: i32,
    pub triage_status: String,
    pub triage_justification: Option<String>,
    pub triage_comment: Option<String>,
    pub triaged_by: Option<String>,
    pub triaged_at: Option<OffsetDateTime>,
    pub triage_expires_at: Option<OffsetDateTime>,
    pub triage_requested_status: Option<String>,
    pub is_direct_dependency: Option<bool>,
    pub line: Option<i32>,
    pub ticket_ref: Option<String>,
    pub ticket_url: Option<String>,
    pub ticket_attached_by: Option<String>,
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewIssue {
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub fingerprint: String,
    pub type_: String,
    pub identifier: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub purl: Option<String>,
    pub file_path: Option<String>,
    pub owasp_category: Option<String>,
    pub source: String,
    pub tool: Option<String>,
    pub tool_name: Option<String>,
    pub tool_version: Option<String>,
    pub import_source: Option<String>,
    pub severity: String,
    pub epss_score: Option<f64>,
    pub is_kev: bool,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub fix_state: Option<String>,
    pub fix_versions: Option<String>,
    pub link: Option<String>,
    pub description: Option<String>,
    pub reachability: String,
    pub reachable_symbols: Option<String>,
    pub state: String,
    pub first_seen_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
    pub resolution_seconds: Option<i64>,
    pub sla_breach_signalled_at: Option<OffsetDateTime>,
    pub first_seen_scan_id: Option<i64>,
    pub last_seen_scan_id: Option<i64>,
    pub times_seen: i32,
    pub triage_status: String,
    pub triage_justification: Option<String>,
    pub triage_comment: Option<String>,
    pub triaged_by: Option<String>,
    pub triaged_at: Option<OffsetDateTime>,
    pub triage_expires_at: Option<OffsetDateTime>,
    pub triage_requested_status: Option<String>,
    pub is_direct_dependency: Option<bool>,
    pub line: Option<i32>,
    pub ticket_ref: Option<String>,
    pub ticket_url: Option<String>,
    pub ticket_attached_by: Option<String>,
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TriageEventRow {
    pub id: i64,
    pub issue_id: i64,
    pub from_status: String,
    pub to_status: String,
    pub justification: Option<String>,
    pub comment: Option<String>,
    pub actor: Option<String>,
    pub origin: String,
    pub occurred_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub requested_status: Option<String>,
    pub scan_id: Option<i64>,
    pub previous_resolved_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewTriageEvent {
    pub issue_id: i64,
    pub from_status: String,
    pub to_status: String,
    pub justification: Option<String>,
    pub comment: Option<String>,
    pub actor: Option<String>,
    pub origin: String,
    pub occurred_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub requested_status: Option<String>,
    pub scan_id: Option<i64>,
    pub previous_resolved_at: Option<OffsetDateTime>,
}

macro_rules! parse_bool {
    ($r:expr, $col:literal) => {
        match $r.try_get::<bool, _>($col) {
            Ok(b) => Some(b),
            Err(_) => match $r.try_get::<i8, _>($col) {
                Ok(n) => Some(n != 0),
                Err(_) => match $r.try_get::<i16, _>($col) {
                    Ok(n) => Some(n != 0),
                    Err(_) => match $r.try_get::<i32, _>($col) {
                        Ok(n) => Some(n != 0),
                        Err(_) => None,
                    },
                },
            },
        }
    };
}

macro_rules! parse_bool_required {
    ($r:expr, $col:literal) => {
        match parse_bool!($r, $col) {
            Some(b) => b,
            None => false,
        }
    };
}

macro_rules! parse_issue_row {
    ($r:expr) => {{
        let first_seen_at: UtcInstant = $r.get("first_seen_at");
        let last_seen_at: UtcInstant = $r.get("last_seen_at");
        let resolved_at: Option<UtcInstant> = $r.try_get("resolved_at").ok().flatten();
        let sla_breach_signalled_at: Option<UtcInstant> = $r.try_get("sla_breach_signalled_at").ok().flatten();
        let triaged_at: Option<UtcInstant> = $r.try_get("triaged_at").ok().flatten();
        let triage_expires_at: Option<UtcInstant> = $r.try_get("triage_expires_at").ok().flatten();

        let is_kev = parse_bool_required!($r, "is_kev");
        let is_direct_dependency = parse_bool!($r, "is_direct_dependency");

        let reachability: String = $r.try_get("reachability").unwrap_or_else(|_| "UNKNOWN".to_owned());

        IssueRow {
            id: $r.get("id"),
            repo_id: $r.try_get("repo_id").ok().flatten(),
            container_id: $r.try_get("container_id").ok().flatten(),
            fingerprint: $r.get("fingerprint"),
            type_: $r.get("type"),
            identifier: $r.try_get("identifier").unwrap_or_default(),
            package_name: $r.try_get("package_name").ok().flatten(),
            package_version: $r.try_get("package_version").ok().flatten(),
            purl: $r.try_get("purl").ok().flatten(),
            file_path: $r.try_get("file_path").ok().flatten(),
            owasp_category: $r.try_get("owasp_category").ok().flatten(),
            source: $r.try_get("source").unwrap_or_default(),
            tool: $r.try_get("tool").ok().flatten(),
            tool_name: $r.try_get("tool_name").ok().flatten(),
            tool_version: $r.try_get("tool_version").ok().flatten(),
            import_source: $r.try_get("import_source").ok().flatten(),
            severity: $r.try_get("severity").unwrap_or_default(),
            epss_score: $r.try_get("epss_score").ok().flatten(),
            is_kev,
            cvss_score: $r.try_get("cvss_score").ok().flatten(),
            cvss_vector: $r.try_get("cvss_vector").ok().flatten(),
            fix_state: $r.try_get("fix_state").ok().flatten(),
            fix_versions: $r.try_get("fix_versions").ok().flatten(),
            link: $r.try_get("link").ok().flatten(),
            description: $r.try_get("description").ok().flatten(),
            reachability,
            reachable_symbols: $r.try_get("reachable_symbols").ok().flatten(),
            state: $r.get("state"),
            first_seen_at: first_seen_at.0,
            last_seen_at: last_seen_at.0,
            resolved_at: resolved_at.map(|t| t.0),
            resolution_seconds: $r.try_get("resolution_seconds").ok().flatten(),
            sla_breach_signalled_at: sla_breach_signalled_at.map(|t| t.0),
            first_seen_scan_id: $r.try_get("first_seen_scan_id").ok().flatten(),
            last_seen_scan_id: $r.try_get("last_seen_scan_id").ok().flatten(),
            times_seen: $r.get("times_seen"),
            triage_status: $r.get("triage_status"),
            triage_justification: $r.try_get("triage_justification").ok().flatten(),
            triage_comment: $r.try_get("triage_comment").ok().flatten(),
            triaged_by: $r.try_get("triaged_by").ok().flatten(),
            triaged_at: triaged_at.map(|t| t.0),
            triage_expires_at: triage_expires_at.map(|t| t.0),
            triage_requested_status: $r.try_get("triage_requested_status").ok().flatten(),
            is_direct_dependency,
            line: $r.try_get("line").ok().flatten(),
            ticket_ref: $r.try_get("ticket_ref").ok().flatten(),
            ticket_url: $r.try_get("ticket_url").ok().flatten(),
            ticket_attached_by: $r.try_get("ticket_attached_by").ok().flatten(),
            revision: $r.try_get("revision").unwrap_or(0),
        }
    }};
}

macro_rules! parse_triage_event_row {
    ($r:expr) => {{
        let occurred_at: UtcInstant = $r.get("occurred_at");
        let expires_at: Option<UtcInstant> = $r.try_get("expires_at").ok().flatten();
        let previous_resolved_at: Option<UtcInstant> = $r.try_get("previous_resolved_at").ok().flatten();

        TriageEventRow {
            id: $r.get("id"),
            issue_id: $r.get("issue_id"),
            from_status: $r.get("from_status"),
            to_status: $r.get("to_status"),
            justification: $r.try_get("justification").ok().flatten(),
            comment: $r.try_get("comment").ok().flatten(),
            actor: $r.try_get("actor").ok().flatten(),
            origin: $r.get("origin"),
            occurred_at: occurred_at.0,
            expires_at: expires_at.map(|t| t.0),
            requested_status: $r.try_get("requested_status").ok().flatten(),
            scan_id: $r.try_get("scan_id").ok().flatten(),
            previous_resolved_at: previous_resolved_at.map(|t| t.0),
        }
    }};
}

#[derive(Debug, Clone, Copy)]
pub struct IssueRepository;

impl IssueRepository {
    // -------------------------------------------------------------------------
    // t_issue queries
    // -------------------------------------------------------------------------

    pub async fn find_by_id(tx: &mut Tx, id: i64) -> Result<Option<IssueRow>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "select * from t_issue where id = ?",
            Tx::PostgreSql(_) => "select * from t_issue where id = $1",
        };
        let row = match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(id).fetch_optional(&mut **conn).await?.map(|r| parse_issue_row!(r))
            }
            Tx::PostgreSql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(id).fetch_optional(&mut **conn).await?.map(|r| parse_issue_row!(r))
            }
        };
        Ok(row)
    }

    pub async fn find_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<Vec<IssueRow>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut results = Vec::new();
        for chunk in ids.chunks(1000) {
            let rows = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("select * from t_issue where id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("select * from t_issue where id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
                }
            };
            results.extend(rows);
        }
        Ok(results)
    }

    pub async fn find_by_fingerprints(tx: &mut Tx, fingerprints: &[String]) -> Result<Vec<IssueRow>, StoreError> {
        if fingerprints.is_empty() {
            return Ok(Vec::new());
        }
        let mut results = Vec::new();
        for chunk in fingerprints.chunks(1000) {
            let rows = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("select * from t_issue where fingerprint in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for fp in chunk {
                        q = q.bind(fp);
                    }
                    q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("select * from t_issue where fingerprint in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for fp in chunk {
                        q = q.bind(fp);
                    }
                    q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
                }
            };
            results.extend(rows);
        }
        Ok(results)
    }

    pub async fn find_open_by_target(
        tx: &mut Tx,
        state: &str,
        types: &[String],
        repo_id: Option<i64>,
        container_id: Option<i64>,
    ) -> Result<Vec<IssueRow>, StoreError> {
        if types.is_empty() {
            return Ok(Vec::new());
        }
        let rows = match tx {
            Tx::MySql(conn) => {
                let placeholders = vec!["?"; types.len()].join(",");
                let sql = format!(
                    "select * from t_issue where state = ? and type in ({placeholders}) and ((? is not null and repo_id = ?) or (? is not null and container_id = ?))"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql)).bind(state);
                for t in types {
                    q = q.bind(t);
                }
                q = q.bind(repo_id).bind(repo_id).bind(container_id).bind(container_id);
                q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
            }
            Tx::PostgreSql(conn) => {
                let placeholders =
                    (2..=types.len().saturating_add(1)).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                let r1 = types.len().saturating_add(2);
                let r2 = types.len().saturating_add(3);
                let c1 = types.len().saturating_add(4);
                let c2 = types.len().saturating_add(5);
                let sql = format!(
                    "select * from t_issue where state = $1 and type in ({placeholders}) and ((${} is not null and repo_id = ${}) or (${} is not null and container_id = ${}))",
                    r1, r2, c1, c2
                );
                let mut q = sqlx::query(AssertSqlSafe(sql)).bind(state);
                for t in types {
                    q = q.bind(t);
                }
                q = q.bind(repo_id).bind(repo_id).bind(container_id).bind(container_id);
                q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
            }
        };
        Ok(rows)
    }

    pub async fn find_open_by_target_and_tools(
        tx: &mut Tx,
        state: &str,
        types: &[String],
        tools: &[String],
        repo_id: Option<i64>,
        container_id: Option<i64>,
    ) -> Result<Vec<IssueRow>, StoreError> {
        if types.is_empty() || tools.is_empty() {
            return Ok(Vec::new());
        }
        let rows = match tx {
            Tx::MySql(conn) => {
                let type_ph = vec!["?"; types.len()].join(",");
                let tool_ph = vec!["?"; tools.len()].join(",");
                let sql = format!(
                    "select * from t_issue where state = ? and type in ({type_ph}) and tool in ({tool_ph}) and ((? is not null and repo_id = ?) or (? is not null and container_id = ?))"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql)).bind(state);
                for t in types {
                    q = q.bind(t);
                }
                for t in tools {
                    q = q.bind(t);
                }
                q = q.bind(repo_id).bind(repo_id).bind(container_id).bind(container_id);
                q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
            }
            Tx::PostgreSql(conn) => {
                let mut idx = 1usize;
                idx = idx.saturating_add(1); // 2
                let type_ph =
                    (idx..idx.saturating_add(types.len())).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                idx = idx.saturating_add(types.len());
                let tool_ph =
                    (idx..idx.saturating_add(tools.len())).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                idx = idx.saturating_add(tools.len());
                let r1 = idx;
                let r2 = idx.saturating_add(1);
                let c1 = idx.saturating_add(2);
                let c2 = idx.saturating_add(3);
                let sql = format!(
                    "select * from t_issue where state = $1 and type in ({type_ph}) and tool in ({tool_ph}) and ((${} is not null and repo_id = ${}) or (${} is not null and container_id = ${}))",
                    r1, r2, c1, c2
                );
                let mut q = sqlx::query(AssertSqlSafe(sql)).bind(state);
                for t in types {
                    q = q.bind(t);
                }
                for t in tools {
                    q = q.bind(t);
                }
                q = q.bind(repo_id).bind(repo_id).bind(container_id).bind(container_id);
                q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
            }
        };
        Ok(rows)
    }

    pub async fn insert_issue(tx: &mut Tx, issue: &NewIssue) -> Result<IssueRow, StoreError> {
        match tx {
            Tx::MySql(conn) => {
                let sql = "insert into t_issue (repo_id, container_id, fingerprint, type, identifier, package_name, package_version, purl, file_path, owasp_category, source, tool, tool_name, tool_version, import_source, severity, epss_score, is_kev, cvss_score, cvss_vector, fix_state, fix_versions, link, description, reachability, reachable_symbols, state, first_seen_at, last_seen_at, resolved_at, resolution_seconds, sla_breach_signalled_at, first_seen_scan_id, last_seen_scan_id, times_seen, triage_status, triage_justification, triage_comment, triaged_by, triaged_at, triage_expires_at, triage_requested_status, is_direct_dependency, line, ticket_ref, ticket_url, ticket_attached_by, revision) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                let res = sqlx::query(AssertSqlSafe(sql))
                    .bind(issue.repo_id)
                    .bind(issue.container_id)
                    .bind(&issue.fingerprint)
                    .bind(&issue.type_)
                    .bind(&issue.identifier)
                    .bind(&issue.package_name)
                    .bind(&issue.package_version)
                    .bind(&issue.purl)
                    .bind(&issue.file_path)
                    .bind(&issue.owasp_category)
                    .bind(&issue.source)
                    .bind(&issue.tool)
                    .bind(&issue.tool_name)
                    .bind(&issue.tool_version)
                    .bind(&issue.import_source)
                    .bind(&issue.severity)
                    .bind(issue.epss_score)
                    .bind(issue.is_kev)
                    .bind(issue.cvss_score)
                    .bind(&issue.cvss_vector)
                    .bind(&issue.fix_state)
                    .bind(&issue.fix_versions)
                    .bind(&issue.link)
                    .bind(&issue.description)
                    .bind(&issue.reachability)
                    .bind(&issue.reachable_symbols)
                    .bind(&issue.state)
                    .bind(UtcInstant(issue.first_seen_at))
                    .bind(UtcInstant(issue.last_seen_at))
                    .bind(issue.resolved_at.map(UtcInstant))
                    .bind(issue.resolution_seconds)
                    .bind(issue.sla_breach_signalled_at.map(UtcInstant))
                    .bind(issue.first_seen_scan_id)
                    .bind(issue.last_seen_scan_id)
                    .bind(issue.times_seen)
                    .bind(&issue.triage_status)
                    .bind(&issue.triage_justification)
                    .bind(&issue.triage_comment)
                    .bind(&issue.triaged_by)
                    .bind(issue.triaged_at.map(UtcInstant))
                    .bind(issue.triage_expires_at.map(UtcInstant))
                    .bind(&issue.triage_requested_status)
                    .bind(issue.is_direct_dependency)
                    .bind(issue.line)
                    .bind(&issue.ticket_ref)
                    .bind(&issue.ticket_url)
                    .bind(&issue.ticket_attached_by)
                    .bind(issue.revision)
                    .execute(&mut **conn)
                    .await?;
                let id = i64::try_from(res.last_insert_id()).unwrap_or(0);
                Self::find_by_id(tx, id).await?.ok_or_else(|| StoreError::Other("Inserted issue not found".to_owned()))
            }
            Tx::PostgreSql(conn) => {
                let sql = "insert into t_issue (repo_id, container_id, fingerprint, type, identifier, package_name, package_version, purl, file_path, owasp_category, source, tool, tool_name, tool_version, import_source, severity, epss_score, is_kev, cvss_score, cvss_vector, fix_state, fix_versions, link, description, reachability, reachable_symbols, state, first_seen_at, last_seen_at, resolved_at, resolution_seconds, sla_breach_signalled_at, first_seen_scan_id, last_seen_scan_id, times_seen, triage_status, triage_justification, triage_comment, triaged_by, triaged_at, triage_expires_at, triage_requested_status, is_direct_dependency, line, ticket_ref, ticket_url, ticket_attached_by, revision) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48) returning *";
                let row = sqlx::query(AssertSqlSafe(sql))
                    .bind(issue.repo_id)
                    .bind(issue.container_id)
                    .bind(&issue.fingerprint)
                    .bind(&issue.type_)
                    .bind(&issue.identifier)
                    .bind(&issue.package_name)
                    .bind(&issue.package_version)
                    .bind(&issue.purl)
                    .bind(&issue.file_path)
                    .bind(&issue.owasp_category)
                    .bind(&issue.source)
                    .bind(&issue.tool)
                    .bind(&issue.tool_name)
                    .bind(&issue.tool_version)
                    .bind(&issue.import_source)
                    .bind(&issue.severity)
                    .bind(issue.epss_score)
                    .bind(issue.is_kev)
                    .bind(issue.cvss_score)
                    .bind(&issue.cvss_vector)
                    .bind(&issue.fix_state)
                    .bind(&issue.fix_versions)
                    .bind(&issue.link)
                    .bind(&issue.description)
                    .bind(&issue.reachability)
                    .bind(&issue.reachable_symbols)
                    .bind(&issue.state)
                    .bind(UtcInstant(issue.first_seen_at))
                    .bind(UtcInstant(issue.last_seen_at))
                    .bind(issue.resolved_at.map(UtcInstant))
                    .bind(issue.resolution_seconds)
                    .bind(issue.sla_breach_signalled_at.map(UtcInstant))
                    .bind(issue.first_seen_scan_id)
                    .bind(issue.last_seen_scan_id)
                    .bind(issue.times_seen)
                    .bind(&issue.triage_status)
                    .bind(&issue.triage_justification)
                    .bind(&issue.triage_comment)
                    .bind(&issue.triaged_by)
                    .bind(issue.triaged_at.map(UtcInstant))
                    .bind(issue.triage_expires_at.map(UtcInstant))
                    .bind(&issue.triage_requested_status)
                    .bind(issue.is_direct_dependency)
                    .bind(issue.line)
                    .bind(&issue.ticket_ref)
                    .bind(&issue.ticket_url)
                    .bind(&issue.ticket_attached_by)
                    .bind(issue.revision)
                    .fetch_one(&mut **conn)
                    .await?;
                Ok(parse_issue_row!(row))
            }
        }
    }

    pub async fn update_issue(tx: &mut Tx, issue: &IssueRow) -> Result<bool, StoreError> {
        let new_revision = issue.revision.saturating_add(1);
        let sql = match tx {
            Tx::MySql(_) => {
                "update t_issue set repo_id = ?, container_id = ?, fingerprint = ?, type = ?, identifier = ?, package_name = ?, package_version = ?, purl = ?, file_path = ?, owasp_category = ?, source = ?, tool = ?, tool_name = ?, tool_version = ?, import_source = ?, severity = ?, epss_score = ?, is_kev = ?, cvss_score = ?, cvss_vector = ?, fix_state = ?, fix_versions = ?, link = ?, description = ?, reachability = ?, reachable_symbols = ?, state = ?, first_seen_at = ?, last_seen_at = ?, resolved_at = ?, resolution_seconds = ?, sla_breach_signalled_at = ?, first_seen_scan_id = ?, last_seen_scan_id = ?, times_seen = ?, triage_status = ?, triage_justification = ?, triage_comment = ?, triaged_by = ?, triaged_at = ?, triage_expires_at = ?, triage_requested_status = ?, is_direct_dependency = ?, line = ?, ticket_ref = ?, ticket_url = ?, ticket_attached_by = ?, revision = ? where id = ? and revision = ?"
            }
            Tx::PostgreSql(_) => {
                "update t_issue set repo_id = $1, container_id = $2, fingerprint = $3, type = $4, identifier = $5, package_name = $6, package_version = $7, purl = $8, file_path = $9, owasp_category = $10, source = $11, tool = $12, tool_name = $13, tool_version = $14, import_source = $15, severity = $16, epss_score = $17, is_kev = $18, cvss_score = $19, cvss_vector = $20, fix_state = $21, fix_versions = $22, link = $23, description = $24, reachability = $25, reachable_symbols = $26, state = $27, first_seen_at = $28, last_seen_at = $29, resolved_at = $30, resolution_seconds = $31, sla_breach_signalled_at = $32, first_seen_scan_id = $33, last_seen_scan_id = $34, times_seen = $35, triage_status = $36, triage_justification = $37, triage_comment = $38, triaged_by = $39, triaged_at = $40, triage_expires_at = $41, triage_requested_status = $42, is_direct_dependency = $43, line = $44, ticket_ref = $45, ticket_url = $46, ticket_attached_by = $47, revision = $48 where id = $49 and revision = $50"
            }
        };
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(issue.repo_id)
                .bind(issue.container_id)
                .bind(&issue.fingerprint)
                .bind(&issue.type_)
                .bind(&issue.identifier)
                .bind(&issue.package_name)
                .bind(&issue.package_version)
                .bind(&issue.purl)
                .bind(&issue.file_path)
                .bind(&issue.owasp_category)
                .bind(&issue.source)
                .bind(&issue.tool)
                .bind(&issue.tool_name)
                .bind(&issue.tool_version)
                .bind(&issue.import_source)
                .bind(&issue.severity)
                .bind(issue.epss_score)
                .bind(issue.is_kev)
                .bind(issue.cvss_score)
                .bind(&issue.cvss_vector)
                .bind(&issue.fix_state)
                .bind(&issue.fix_versions)
                .bind(&issue.link)
                .bind(&issue.description)
                .bind(&issue.reachability)
                .bind(&issue.reachable_symbols)
                .bind(&issue.state)
                .bind(UtcInstant(issue.first_seen_at))
                .bind(UtcInstant(issue.last_seen_at))
                .bind(issue.resolved_at.map(UtcInstant))
                .bind(issue.resolution_seconds)
                .bind(issue.sla_breach_signalled_at.map(UtcInstant))
                .bind(issue.first_seen_scan_id)
                .bind(issue.last_seen_scan_id)
                .bind(issue.times_seen)
                .bind(&issue.triage_status)
                .bind(&issue.triage_justification)
                .bind(&issue.triage_comment)
                .bind(&issue.triaged_by)
                .bind(issue.triaged_at.map(UtcInstant))
                .bind(issue.triage_expires_at.map(UtcInstant))
                .bind(&issue.triage_requested_status)
                .bind(issue.is_direct_dependency)
                .bind(issue.line)
                .bind(&issue.ticket_ref)
                .bind(&issue.ticket_url)
                .bind(&issue.ticket_attached_by)
                .bind(new_revision)
                .bind(issue.id)
                .bind(issue.revision)
                .execute(&mut **conn)
                .await?
                .rows_affected(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(issue.repo_id)
                .bind(issue.container_id)
                .bind(&issue.fingerprint)
                .bind(&issue.type_)
                .bind(&issue.identifier)
                .bind(&issue.package_name)
                .bind(&issue.package_version)
                .bind(&issue.purl)
                .bind(&issue.file_path)
                .bind(&issue.owasp_category)
                .bind(&issue.source)
                .bind(&issue.tool)
                .bind(&issue.tool_name)
                .bind(&issue.tool_version)
                .bind(&issue.import_source)
                .bind(&issue.severity)
                .bind(issue.epss_score)
                .bind(issue.is_kev)
                .bind(issue.cvss_score)
                .bind(&issue.cvss_vector)
                .bind(&issue.fix_state)
                .bind(&issue.fix_versions)
                .bind(&issue.link)
                .bind(&issue.description)
                .bind(&issue.reachability)
                .bind(&issue.reachable_symbols)
                .bind(&issue.state)
                .bind(UtcInstant(issue.first_seen_at))
                .bind(UtcInstant(issue.last_seen_at))
                .bind(issue.resolved_at.map(UtcInstant))
                .bind(issue.resolution_seconds)
                .bind(issue.sla_breach_signalled_at.map(UtcInstant))
                .bind(issue.first_seen_scan_id)
                .bind(issue.last_seen_scan_id)
                .bind(issue.times_seen)
                .bind(&issue.triage_status)
                .bind(&issue.triage_justification)
                .bind(&issue.triage_comment)
                .bind(&issue.triaged_by)
                .bind(issue.triaged_at.map(UtcInstant))
                .bind(issue.triage_expires_at.map(UtcInstant))
                .bind(&issue.triage_requested_status)
                .bind(issue.is_direct_dependency)
                .bind(issue.line)
                .bind(&issue.ticket_ref)
                .bind(&issue.ticket_url)
                .bind(&issue.ticket_attached_by)
                .bind(new_revision)
                .bind(issue.id)
                .bind(issue.revision)
                .execute(&mut **conn)
                .await?
                .rows_affected(),
        };
        Ok(rows > 0)
    }

    pub async fn resolve_disappeared(tx: &mut Tx, ids: &[i64], moment: OffsetDateTime) -> Result<u64, StoreError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for chunk in ids.chunks(1000) {
            let res = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!(
                        "update t_issue set state = 'resolved', resolved_at = ?, resolution_seconds = TIMESTAMPDIFF(SECOND, first_seen_at, ?), revision = revision + 1 where id in ({placeholders})"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql)).bind(UtcInstant(moment)).bind(UtcInstant(moment));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders =
                        (3..=chunk.len().saturating_add(2)).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!(
                        "update t_issue set state = 'resolved', resolved_at = $1, resolution_seconds = EXTRACT(EPOCH FROM ($2 - first_seen_at))::bigint, revision = revision + 1 where id in ({placeholders})"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql)).bind(UtcInstant(moment)).bind(UtcInstant(moment));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
            };
            total = total.saturating_add(res);
        }
        Ok(total)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn find_unsignalled_breaches(
        tx: &mut Tx,
        state: &str,
        severity: &str,
        before: OffsetDateTime,
        since: OffsetDateTime,
        settled: &[String],
        after_id: i64,
        limit: i64,
    ) -> Result<Vec<IssueRow>, StoreError> {
        let rows = match tx {
            Tx::MySql(conn) => {
                let settled_ph = if settled.is_empty() { "''".to_owned() } else { vec!["?"; settled.len()].join(",") };
                let sql = format!(
                    "select * from t_issue where state = ? and severity = ? and first_seen_at < ? and first_seen_at >= ? and sla_breach_signalled_at is null and triage_status not in ({settled_ph}) and id > ? order by id asc limit ?"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql))
                    .bind(state)
                    .bind(severity)
                    .bind(UtcInstant(before))
                    .bind(UtcInstant(since));
                for s in settled {
                    q = q.bind(s);
                }
                q = q.bind(after_id).bind(limit);
                q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
            }
            Tx::PostgreSql(conn) => {
                let mut idx = 1usize;
                let s1 = idx; // state: 1
                idx = idx.saturating_add(1);
                let s2 = idx; // severity: 2
                idx = idx.saturating_add(1);
                let b1 = idx; // before: 3
                idx = idx.saturating_add(1);
                let si1 = idx; // since: 4
                idx = idx.saturating_add(1);
                let settled_ph = if settled.is_empty() {
                    "''".to_owned()
                } else {
                    let ph =
                        (idx..idx.saturating_add(settled.len())).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    idx = idx.saturating_add(settled.len());
                    ph
                };
                let a1 = idx;
                idx = idx.saturating_add(1);
                let l1 = idx;
                let sql = format!(
                    "select * from t_issue where state = ${s1} and severity = ${s2} and first_seen_at < ${b1} and first_seen_at >= ${si1} and sla_breach_signalled_at is null and triage_status not in ({settled_ph}) and id > ${a1} order by id asc limit ${l1}"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql))
                    .bind(state)
                    .bind(severity)
                    .bind(UtcInstant(before))
                    .bind(UtcInstant(since));
                for s in settled {
                    q = q.bind(s);
                }
                q = q.bind(after_id).bind(limit);
                q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
            }
        };
        Ok(rows)
    }

    pub async fn mark_sla_breach_signalled(
        tx: &mut Tx,
        ids: &[i64],
        moment: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for chunk in ids.chunks(1000) {
            let res = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("update t_issue set sla_breach_signalled_at = ? where id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql)).bind(UtcInstant(moment));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders =
                        (2..=chunk.len().saturating_add(1)).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("update t_issue set sla_breach_signalled_at = $1 where id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql)).bind(UtcInstant(moment));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
            };
            total = total.saturating_add(res);
        }
        Ok(total)
    }

    pub async fn find_with_expired_triage(tx: &mut Tx, now: OffsetDateTime) -> Result<Vec<IssueRow>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "select * from t_issue where triage_expires_at is not null and triage_expires_at <= ?",
            Tx::PostgreSql(_) => {
                "select * from t_issue where triage_expires_at is not null and triage_expires_at <= $1"
            }
        };
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(UtcInstant(now))
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| parse_issue_row!(r))
                .collect::<Vec<IssueRow>>(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(UtcInstant(now))
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| parse_issue_row!(r))
                .collect::<Vec<IssueRow>>(),
        };
        Ok(rows)
    }

    pub async fn count_open_by_repository(tx: &mut Tx, state: &str) -> Result<Vec<(i64, i64)>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => {
                "select repo_id, count(id) as c from t_issue where state = ? and repo_id is not null group by repo_id"
            }
            Tx::PostgreSql(_) => {
                "select repo_id, count(id) as c from t_issue where state = $1 and repo_id is not null group by repo_id"
            }
        };
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(state)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| (r.get::<i64, _>("repo_id"), r.get::<i64, _>("c")))
                .collect::<Vec<(i64, i64)>>(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(state)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| (r.get::<i64, _>("repo_id"), r.get::<i64, _>("c")))
                .collect::<Vec<(i64, i64)>>(),
        };
        Ok(rows)
    }

    pub async fn count_open_by_container(tx: &mut Tx, state: &str) -> Result<Vec<(i64, i64)>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => {
                "select container_id, count(id) as c from t_issue where state = ? and container_id is not null group by container_id"
            }
            Tx::PostgreSql(_) => {
                "select container_id, count(id) as c from t_issue where state = $1 and container_id is not null group by container_id"
            }
        };
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(state)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| (r.get::<i64, _>("container_id"), r.get::<i64, _>("c")))
                .collect::<Vec<(i64, i64)>>(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(state)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| (r.get::<i64, _>("container_id"), r.get::<i64, _>("c")))
                .collect::<Vec<(i64, i64)>>(),
        };
        Ok(rows)
    }

    pub async fn count_open_by_target_and_severity(
        tx: &mut Tx,
        allowed: &Visibility,
    ) -> Result<Vec<(Option<i64>, Option<i64>, String, i64)>, StoreError> {
        let base_sql = "select repo_id, container_id, severity, count(id) as c from t_issue where state = 'open' and triage_status not in ('not_affected', 'fixed', 'will_not_fix')";
        match allowed {
            Visibility::Everything => {
                let sql = format!("{base_sql} group by repo_id, container_id, severity");
                let rows = match tx {
                    Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql.clone()))
                        .fetch_all(&mut **conn)
                        .await?
                        .into_iter()
                        .map(|r| {
                            (
                                r.try_get::<Option<i64>, _>("repo_id").ok().flatten(),
                                r.try_get::<Option<i64>, _>("container_id").ok().flatten(),
                                r.get::<String, _>("severity"),
                                r.get::<i64, _>("c"),
                            )
                        })
                        .collect::<Vec<(Option<i64>, Option<i64>, String, i64)>>(),
                    Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql.clone()))
                        .fetch_all(&mut **conn)
                        .await?
                        .into_iter()
                        .map(|r| {
                            (
                                r.try_get::<Option<i64>, _>("repo_id").ok().flatten(),
                                r.try_get::<Option<i64>, _>("container_id").ok().flatten(),
                                r.get::<String, _>("severity"),
                                r.get::<i64, _>("c"),
                            )
                        })
                        .collect::<Vec<(Option<i64>, Option<i64>, String, i64)>>(),
                };
                Ok(rows)
            }
            Visibility::Only(targets) => {
                let mut repos = Vec::new();
                let mut containers = Vec::new();
                for t in targets {
                    match t {
                        ScanTarget::Repository(id) => repos.push(*id),
                        ScanTarget::Container(id) => containers.push(*id),
                    }
                }
                if repos.is_empty() && containers.is_empty() {
                    return Ok(Vec::new());
                }
                // Grouped count for the allowed repositories/containers
                let mut results = Vec::new();
                if !repos.is_empty() {
                    for chunk in repos.chunks(1000) {
                        let rows = match tx {
                            Tx::MySql(conn) => {
                                let placeholders = vec!["?"; chunk.len()].join(",");
                                let sql = format!(
                                    "{base_sql} and repo_id in ({placeholders}) group by repo_id, container_id, severity"
                                );
                                let mut q = sqlx::query(AssertSqlSafe(sql));
                                for id in chunk {
                                    q = q.bind(id);
                                }
                                q.fetch_all(&mut **conn)
                                    .await?
                                    .into_iter()
                                    .map(|r| {
                                        (
                                            r.try_get::<Option<i64>, _>("repo_id").ok().flatten(),
                                            r.try_get::<Option<i64>, _>("container_id").ok().flatten(),
                                            r.get::<String, _>("severity"),
                                            r.get::<i64, _>("c"),
                                        )
                                    })
                                    .collect::<Vec<(Option<i64>, Option<i64>, String, i64)>>()
                            }
                            Tx::PostgreSql(conn) => {
                                let placeholders =
                                    (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                                let sql = format!(
                                    "{base_sql} and repo_id in ({placeholders}) group by repo_id, container_id, severity"
                                );
                                let mut q = sqlx::query(AssertSqlSafe(sql));
                                for id in chunk {
                                    q = q.bind(id);
                                }
                                q.fetch_all(&mut **conn)
                                    .await?
                                    .into_iter()
                                    .map(|r| {
                                        (
                                            r.try_get::<Option<i64>, _>("repo_id").ok().flatten(),
                                            r.try_get::<Option<i64>, _>("container_id").ok().flatten(),
                                            r.get::<String, _>("severity"),
                                            r.get::<i64, _>("c"),
                                        )
                                    })
                                    .collect::<Vec<(Option<i64>, Option<i64>, String, i64)>>()
                            }
                        };
                        results.extend(rows);
                    }
                }
                if !containers.is_empty() {
                    for chunk in containers.chunks(1000) {
                        let rows = match tx {
                            Tx::MySql(conn) => {
                                let placeholders = vec!["?"; chunk.len()].join(",");
                                let sql = format!(
                                    "{base_sql} and container_id in ({placeholders}) group by repo_id, container_id, severity"
                                );
                                let mut q = sqlx::query(AssertSqlSafe(sql));
                                for id in chunk {
                                    q = q.bind(id);
                                }
                                q.fetch_all(&mut **conn)
                                    .await?
                                    .into_iter()
                                    .map(|r| {
                                        (
                                            r.try_get::<Option<i64>, _>("repo_id").ok().flatten(),
                                            r.try_get::<Option<i64>, _>("container_id").ok().flatten(),
                                            r.get::<String, _>("severity"),
                                            r.get::<i64, _>("c"),
                                        )
                                    })
                                    .collect::<Vec<(Option<i64>, Option<i64>, String, i64)>>()
                            }
                            Tx::PostgreSql(conn) => {
                                let placeholders =
                                    (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                                let sql = format!(
                                    "{base_sql} and container_id in ({placeholders}) group by repo_id, container_id, severity"
                                );
                                let mut q = sqlx::query(AssertSqlSafe(sql));
                                for id in chunk {
                                    q = q.bind(id);
                                }
                                q.fetch_all(&mut **conn)
                                    .await?
                                    .into_iter()
                                    .map(|r| {
                                        (
                                            r.try_get::<Option<i64>, _>("repo_id").ok().flatten(),
                                            r.try_get::<Option<i64>, _>("container_id").ok().flatten(),
                                            r.get::<String, _>("severity"),
                                            r.get::<i64, _>("c"),
                                        )
                                    })
                                    .collect::<Vec<(Option<i64>, Option<i64>, String, i64)>>()
                            }
                        };
                        results.extend(rows);
                    }
                }
                Ok(results)
            }
        }
    }

    pub async fn find_ids_by_repo_id(tx: &mut Tx, repo_id: i64) -> Result<Vec<i64>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "select id from t_issue where repo_id = ?",
            Tx::PostgreSql(_) => "select id from t_issue where repo_id = $1",
        };
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(repo_id)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| r.get::<i64, _>("id"))
                .collect::<Vec<i64>>(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(repo_id)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| r.get::<i64, _>("id"))
                .collect::<Vec<i64>>(),
        };
        Ok(rows)
    }

    pub async fn find_ids_by_container_id(tx: &mut Tx, container_id: i64) -> Result<Vec<i64>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "select id from t_issue where container_id = ?",
            Tx::PostgreSql(_) => "select id from t_issue where container_id = $1",
        };
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(container_id)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| r.get::<i64, _>("id"))
                .collect::<Vec<i64>>(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(container_id)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| r.get::<i64, _>("id"))
                .collect::<Vec<i64>>(),
        };
        Ok(rows)
    }

    /// `IssueRepository::find_orphaned_ids`: cross-module orphan sweep checked against `t_container` and `t_repository`.
    pub async fn find_orphaned_ids(tx: &mut Tx) -> Result<Vec<i64>, StoreError> {
        super::checked::find_orphaned_ids(tx).await
    }

    pub async fn delete_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<u64, StoreError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for chunk in ids.chunks(1000) {
            let res = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("delete from t_issue where id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("delete from t_issue where id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
            };
            total = total.saturating_add(res);
        }
        Ok(total)
    }

    // -------------------------------------------------------------------------
    // t_issue_triage_event queries
    // -------------------------------------------------------------------------

    pub async fn insert_triage_events(tx: &mut Tx, events: &[NewTriageEvent]) -> Result<(), StoreError> {
        for event in events {
            super::checked::insert_triage_event(tx, event).await?;
        }
        Ok(())
    }

    pub async fn find_triage_events_for_issues(
        tx: &mut Tx,
        issue_ids: &[i64],
    ) -> Result<Vec<TriageEventRow>, StoreError> {
        if issue_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut results = Vec::new();
        for chunk in issue_ids.chunks(1000) {
            let rows = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!(
                        "select * from t_issue_triage_event where issue_id in ({placeholders}) order by occurred_at desc, id desc"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.fetch_all(&mut **conn)
                        .await?
                        .into_iter()
                        .map(|r| parse_triage_event_row!(r))
                        .collect::<Vec<TriageEventRow>>()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!(
                        "select * from t_issue_triage_event where issue_id in ({placeholders}) order by occurred_at desc, id desc"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.fetch_all(&mut **conn)
                        .await?
                        .into_iter()
                        .map(|r| parse_triage_event_row!(r))
                        .collect::<Vec<TriageEventRow>>()
                }
            };
            results.extend(rows);
        }
        Ok(results)
    }

    pub async fn find_triage_events_by_issue_id(tx: &mut Tx, issue_id: i64) -> Result<Vec<TriageEventRow>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "select * from t_issue_triage_event where issue_id = ? order by occurred_at asc, id asc",
            Tx::PostgreSql(_) => {
                "select * from t_issue_triage_event where issue_id = $1 order by occurred_at asc, id asc"
            }
        };
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(issue_id)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| parse_triage_event_row!(r))
                .collect::<Vec<TriageEventRow>>(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(issue_id)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| parse_triage_event_row!(r))
                .collect::<Vec<TriageEventRow>>(),
        };
        Ok(rows)
    }

    pub async fn delete_triage_events_by_issue_ids(tx: &mut Tx, issue_ids: &[i64]) -> Result<u64, StoreError> {
        if issue_ids.is_empty() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for chunk in issue_ids.chunks(1000) {
            let res = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("delete from t_issue_triage_event where issue_id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("delete from t_issue_triage_event where issue_id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
            };
            total = total.saturating_add(res);
        }
        Ok(total)
    }

    // -------------------------------------------------------------------------
    // Backlog Paging & Filters
    // -------------------------------------------------------------------------

    pub async fn page_issues(
        tx: &mut Tx,
        filters: &IssueFilters,
        limit: i32,
        offset: i32,
    ) -> Result<(Vec<IssueRow>, i64), StoreError> {
        let (where_clauses, binds) = build_where_clauses(filters);
        let where_sql =
            if where_clauses.is_empty() { "".to_owned() } else { format!("where {}", where_clauses.join(" and ")) };

        // Count query
        let count_sql = format!("select count(id) as total from t_issue {where_sql}");
        let total: i64 = match tx {
            Tx::MySql(conn) => {
                let mut q = sqlx::query(AssertSqlSafe(count_sql.clone()));
                for b in &binds {
                    q = bind_value_mysql(q, b);
                }
                let r = q.fetch_one(&mut **conn).await?;
                r.get("total")
            }
            Tx::PostgreSql(conn) => {
                let count_sql_pg = to_pg_sql(&count_sql);
                let mut q = sqlx::query(AssertSqlSafe(count_sql_pg.clone()));
                for b in &binds {
                    q = bind_value_pg(q, b);
                }
                let r = q.fetch_one(&mut **conn).await?;
                r.get("total")
            }
        };

        if total == 0 {
            return Ok((Vec::new(), 0));
        }

        // Most severe first:
        // CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, first_seen_at desc, id desc
        let order_sql = "order by case upper(severity) when 'CRITICAL' then 1 when 'HIGH' then 2 when 'MEDIUM' then 3 when 'LOW' then 4 else 5 end asc, first_seen_at desc, id desc";
        let page_sql = format!("select * from t_issue {where_sql} {order_sql} limit ? offset ?");

        let rows = match tx {
            Tx::MySql(conn) => {
                let mut q = sqlx::query(AssertSqlSafe(page_sql.clone()));
                for b in &binds {
                    q = bind_value_mysql(q, b);
                }
                q = q.bind(i64::from(limit)).bind(i64::from(offset));
                q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
            }
            Tx::PostgreSql(conn) => {
                let page_sql_pg = to_pg_sql(&page_sql);
                let mut q = sqlx::query(AssertSqlSafe(page_sql_pg.clone()));
                for b in &binds {
                    q = bind_value_pg(q, b);
                }
                q = q.bind(i64::from(limit)).bind(i64::from(offset));
                q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
            }
        };

        Ok((rows, total))
    }

    pub async fn count_issues(tx: &mut Tx, filters: &IssueFilters) -> Result<i64, StoreError> {
        let (where_clauses, binds) = build_where_clauses(filters);
        let where_sql =
            if where_clauses.is_empty() { "".to_owned() } else { format!("where {}", where_clauses.join(" and ")) };
        let count_sql = format!("select count(id) as total from t_issue {where_sql}");
        let total: i64 = match tx {
            Tx::MySql(conn) => {
                let mut q = sqlx::query(AssertSqlSafe(count_sql.clone()));
                for b in &binds {
                    q = bind_value_mysql(q, b);
                }
                let r = q.fetch_one(&mut **conn).await?;
                r.get("total")
            }
            Tx::PostgreSql(conn) => {
                let count_sql_pg = to_pg_sql(&count_sql);
                let mut q = sqlx::query(AssertSqlSafe(count_sql_pg.clone()));
                for b in &binds {
                    q = bind_value_pg(q, b);
                }
                let r = q.fetch_one(&mut **conn).await?;
                r.get("total")
            }
        };
        Ok(total)
    }

    // -------------------------------------------------------------------------
    // Exceptions Register
    // -------------------------------------------------------------------------

    pub async fn register_exceptions(
        tx: &mut Tx,
        allowed: &Visibility,
        cursor: Option<(OffsetDateTime, i64)>,
        limit: usize,
    ) -> Result<Vec<IssueRow>, StoreError> {
        let mut where_clauses =
            vec!["triage_status in ('not_affected', 'will_not_fix', 'pending_approval')".to_owned()];
        let mut binds = Vec::new();

        match allowed {
            Visibility::Everything => {}
            Visibility::Only(targets) => {
                let mut repos = Vec::new();
                let mut containers = Vec::new();
                for t in targets {
                    match t {
                        ScanTarget::Repository(id) => repos.push(*id),
                        ScanTarget::Container(id) => containers.push(*id),
                    }
                }
                if repos.is_empty() && containers.is_empty() {
                    return Ok(Vec::new());
                }
                let mut target_clauses = Vec::new();
                if !repos.is_empty() {
                    let ph = vec!["?"; repos.len()].join(",");
                    target_clauses.push(format!("repo_id in ({ph})"));
                    for id in repos {
                        binds.push(BindVal::Int(id));
                    }
                }
                if !containers.is_empty() {
                    let ph = vec!["?"; containers.len()].join(",");
                    target_clauses.push(format!("container_id in ({ph})"));
                    for id in containers {
                        binds.push(BindVal::Int(id));
                    }
                }
                where_clauses.push(format!("({})", target_clauses.join(" or ")));
            }
        }

        if let Some((at, id)) = cursor {
            // (triaged_at < at) or (triaged_at = at and id < id)
            where_clauses.push("(triaged_at < ? or (triaged_at = ? and id < ?))".to_owned());
            binds.push(BindVal::Time(at));
            binds.push(BindVal::Time(at));
            binds.push(BindVal::Int(id));
        }

        let where_sql = format!("where {}", where_clauses.join(" and "));
        let sql = format!("select * from t_issue {where_sql} order by triaged_at desc, id desc limit ?");

        let rows = match tx {
            Tx::MySql(conn) => {
                let mut q = sqlx::query(AssertSqlSafe(sql.clone()));
                for b in &binds {
                    q = bind_value_mysql(q, b);
                }
                let l = i64::try_from(limit).unwrap_or(500);
                q = q.bind(l);
                q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
            }
            Tx::PostgreSql(conn) => {
                let sql_pg = to_pg_sql(&sql);
                let mut q = sqlx::query(AssertSqlSafe(sql_pg.clone()));
                for b in &binds {
                    q = bind_value_pg(q, b);
                }
                let l = i64::try_from(limit).unwrap_or(500);
                q = q.bind(l);
                q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_issue_row!(r)).collect::<Vec<IssueRow>>()
            }
        };

        Ok(rows)
    }

    pub async fn find_page(
        tx: &mut Tx,
        filters: &IssueFilters,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<IssueRow>, i64), StoreError> {
        let l = i32::try_from(limit).unwrap_or(500);
        let o = i32::try_from(offset).unwrap_or(0);
        Self::page_issues(tx, filters, l, o).await
    }

    pub async fn count(tx: &mut Tx, filters: &IssueFilters) -> Result<i64, StoreError> {
        Self::count_issues(tx, filters).await
    }

    pub async fn count_by_state_and_repository(tx: &mut Tx, state: &str, repo_id: i64) -> Result<i64, StoreError> {
        super::checked::count_by_state_and_repository(tx, state, repo_id).await
    }

    pub async fn count_for_repository(tx: &mut Tx, repo_id: i64, not_a_decision: &str) -> Result<i64, StoreError> {
        super::checked::count_decisions_for_repository(tx, repo_id, not_a_decision).await
    }

    // -------------------------------------------------------------------------
}

pub struct TriageEventRepository;

impl TriageEventRepository {
    pub async fn find_for_issues(tx: &mut Tx, issue_ids: &[i64]) -> Result<Vec<TriageEventRow>, StoreError> {
        IssueRepository::find_triage_events_for_issues(tx, issue_ids).await
    }

    pub async fn count_for_repository(tx: &mut Tx, repo_id: i64, not_a_decision: &str) -> Result<i64, StoreError> {
        IssueRepository::count_for_repository(tx, repo_id, not_a_decision).await
    }
}

#[derive(Debug, Clone)]
enum BindVal {
    Int(i64),
    String(String),
    Bool(bool),
    Time(OffsetDateTime),
}

fn bind_value_mysql<'q>(
    q: sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments>,
    val: &BindVal,
) -> sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments> {
    match val {
        BindVal::Int(i) => q.bind(*i),
        BindVal::String(s) => q.bind(s.clone()),
        BindVal::Bool(b) => q.bind(*b),
        BindVal::Time(t) => q.bind(UtcInstant(*t)),
    }
}

fn bind_value_pg<'q>(
    q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    val: &BindVal,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    match val {
        BindVal::Int(i) => q.bind(*i),
        BindVal::String(s) => q.bind(s.clone()),
        BindVal::Bool(b) => q.bind(*b),
        BindVal::Time(t) => q.bind(UtcInstant(*t)),
    }
}

fn to_pg_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len().saturating_add(32));
    let mut param_idx = 1usize;
    for c in sql.chars() {
        if c == '?' {
            out.push('$');
            out.push_str(&param_idx.to_string());
            param_idx = param_idx.saturating_add(1);
        } else {
            out.push(c);
        }
    }
    out
}

fn build_where_clauses(filters: &IssueFilters) -> (Vec<String>, Vec<BindVal>) {
    let mut clauses = Vec::new();
    let mut binds = Vec::new();

    if let Some(state) = &filters.state {
        clauses.push("state = ?".to_owned());
        binds.push(BindVal::String(state.clone()));
    }

    if let Some(severity) = &filters.severity {
        clauses.push("upper(severity) = upper(?)".to_owned());
        binds.push(BindVal::String(severity.clone()));
    }

    if let Some(type_) = &filters.type_ {
        clauses.push("type = ?".to_owned());
        binds.push(BindVal::String(type_.clone()));
    }

    if let Some(triage) = &filters.triage_status {
        clauses.push("triage_status = ?".to_owned());
        binds.push(BindVal::String(triage.clone()));
    }

    if let Some(repo_id) = filters.repo_id {
        clauses.push("repo_id = ?".to_owned());
        binds.push(BindVal::Int(repo_id));
    }

    if let Some(container_id) = filters.container_id {
        clauses.push("container_id = ?".to_owned());
        binds.push(BindVal::Int(container_id));
    }

    if filters.only_direct {
        clauses.push("is_direct_dependency = ?".to_owned());
        binds.push(BindVal::Bool(true));
    }

    if filters.only_kev {
        clauses.push("is_kev = ?".to_owned());
        binds.push(BindVal::Bool(true));
    }

    if filters.exclude_settled {
        clauses.push("triage_status not in ('not_affected', 'fixed', 'will_not_fix')".to_owned());
    }

    if filters.cve_only {
        clauses.push("upper(identifier) like 'CVE-%'".to_owned());
    }

    if let Some(search) = &filters.search
        && !search.trim().is_empty()
    {
        let pat = format!("%{}%", search.trim());
        clauses.push(
            "(lower(identifier) like lower(?) or lower(package_name) like lower(?) or lower(file_path) like lower(?))"
                .to_owned(),
        );
        binds.push(BindVal::String(pat.clone()));
        binds.push(BindVal::String(pat.clone()));
        binds.push(BindVal::String(pat));
    }

    if let Some(id_exact) = &filters.identifier
        && !id_exact.trim().is_empty()
    {
        clauses.push("lower(identifier) = lower(?)".to_owned());
        binds.push(BindVal::String(id_exact.trim().to_owned()));
    }

    if let Some(owasp) = &filters.owasp_category {
        if owasp.eq_ignore_ascii_case("any") {
            clauses.push("owasp_category is not null".to_owned());
        } else {
            clauses.push("upper(owasp_category) = upper(?)".to_owned());
            binds.push(BindVal::String(owasp.clone()));
        }
    }

    if let Some(touching) = filters.touching_since {
        // an issue that touched a window starting at touching_since:
        // resolved_at is null or resolved_at >= touching
        clauses.push("(resolved_at is null or resolved_at >= ?)".to_owned());
        binds.push(BindVal::Time(touching));
    }

    // Overdue thresholds per severity
    if !filters.overdue_before.is_empty() {
        let mut overdue_parts = Vec::new();
        for (sev, threshold) in &filters.overdue_before {
            overdue_parts.push("(upper(severity) = upper(?) and first_seen_at < ?)".to_owned());
            binds.push(BindVal::String(sev.clone()));
            binds.push(BindVal::Time(*threshold));
        }
        clauses.push(format!("({})", overdue_parts.join(" or ")));
    }

    // Lifetime filters
    if let Some(lt) = &filters.lifetime {
        if let Some(open_at) = lt.open_at {
            clauses.push("(first_seen_at <= ? and (resolved_at is null or resolved_at > ?))".to_owned());
            binds.push(BindVal::Time(open_at));
            binds.push(BindVal::Time(open_at));
        }
        if let Some(fs_from) = lt.first_seen_from {
            clauses.push("first_seen_at >= ?".to_owned());
            binds.push(BindVal::Time(fs_from));
        }
        if let Some(fs_before) = lt.first_seen_before {
            clauses.push("first_seen_at < ?".to_owned());
            binds.push(BindVal::Time(fs_before));
        }
        if let Some(res_from) = lt.resolved_from {
            clauses.push("resolved_at >= ?".to_owned());
            binds.push(BindVal::Time(res_from));
        }
        if let Some(res_before) = lt.resolved_before {
            clauses.push("resolved_at < ?".to_owned());
            binds.push(BindVal::Time(res_before));
        }
    }

    // Targets within project or solution
    if let Some(within) = &filters.targets_within {
        if within.is_empty() {
            clauses.push("1 = 0".to_owned());
        } else {
            let mut repos: Vec<i64> = Vec::new();
            let mut containers: Vec<i64> = Vec::new();
            for t in within {
                match *t {
                    ScanTarget::Repository(id) => repos.push(id),
                    ScanTarget::Container(id) => containers.push(id),
                }
            }
            let mut target_parts = Vec::new();
            if !repos.is_empty() {
                let ph = vec!["?"; repos.len()].join(",");
                target_parts.push(format!("repo_id in ({ph})"));
                for id in repos {
                    binds.push(BindVal::Int(id));
                }
            }
            if !containers.is_empty() {
                let ph = vec!["?"; containers.len()].join(",");
                target_parts.push(format!("container_id in ({ph})"));
                for id in containers {
                    binds.push(BindVal::Int(id));
                }
            }
            if target_parts.is_empty() {
                clauses.push("1 = 0".to_owned());
            } else {
                clauses.push(format!("({})", target_parts.join(" or ")));
            }
        }
    }

    // Visibility
    match &filters.visibility {
        Visibility::Everything => {}
        Visibility::Only(targets) => {
            if targets.is_empty() {
                clauses.push("1 = 0".to_owned());
            } else {
                let mut repos: Vec<i64> = Vec::new();
                let mut containers: Vec<i64> = Vec::new();
                for t in targets {
                    match *t {
                        ScanTarget::Repository(id) => repos.push(id),
                        ScanTarget::Container(id) => containers.push(id),
                    }
                }
                let mut vis_parts = Vec::new();
                if !repos.is_empty() {
                    let ph = vec!["?"; repos.len()].join(",");
                    vis_parts.push(format!("repo_id in ({ph})"));
                    for id in repos {
                        binds.push(BindVal::Int(id));
                    }
                }
                if !containers.is_empty() {
                    let ph = vec!["?"; containers.len()].join(",");
                    vis_parts.push(format!("container_id in ({ph})"));
                    for id in containers {
                        binds.push(BindVal::Int(id));
                    }
                }
                if vis_parts.is_empty() {
                    clauses.push("1 = 0".to_owned());
                } else {
                    clauses.push(format!("({})", vis_parts.join(" or ")));
                }
            }
        }
    }

    (clauses, binds)
}

opaque_debug!(TriageEventRepository);
