//! Ingestion's statements on `t_finding` — task 2.8's file, declared by task 2.7. The reads of the scan routes and the
//! purge's deletes are in `persistence`'s engine modules, beside the other statements of task 2.7.

use time::OffsetDateTime;
use vectispire_cp_db::Tx;

#[cfg(any(not(feature = "mysql-queries"), not(feature = "postgres-queries")))]
use super::DbError;
use super::StoreError;

/// A finding ready to be written to `t_finding`, after columns have clipped its display copies.
#[derive(Debug, Clone, PartialEq)]
pub struct NewFinding {
    pub scan_id: i64,
    pub issue_id: Option<i64>,
    pub type_: String,
    pub source: String,
    pub tool: Option<String>,
    pub tool_name: Option<String>,
    pub tool_version: Option<String>,
    pub identifier: Option<String>,
    pub severity: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub purl: Option<String>,
    pub file_path: Option<String>,
    pub line: Option<i32>,
    pub direct_dependency: Option<bool>,
    pub owasp_category: Option<String>,
    pub epss_score: Option<f64>,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub fix_state: Option<String>,
    pub fix_versions: Option<String>,
    pub link: Option<String>,
    pub is_kev: bool,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
}

/// Saves findings in `tx`. Does nothing if `findings` is empty.
pub async fn save_all(tx: &mut Tx, findings: &[NewFinding]) -> Result<(), StoreError> {
    if findings.is_empty() {
        return Ok(());
    }
    match tx {
        #[cfg(feature = "mysql-queries")]
        Tx::MySql(conn) => mysql::save_all(conn, findings).await.map_err(StoreError::from),
        #[cfg(not(feature = "mysql-queries"))]
        Tx::MySql(_) => Err(StoreError::from(DbError::EngineNotCompiled("MySQL"))),
        #[cfg(feature = "postgres-queries")]
        Tx::PostgreSql(conn) => postgres::save_all(conn, findings).await.map_err(StoreError::from),
        #[cfg(not(feature = "postgres-queries"))]
        Tx::PostgreSql(_) => Err(StoreError::from(DbError::EngineNotCompiled("PostgreSQL"))),
    }
}

#[cfg(feature = "mysql-queries")]
mod mysql {
    use super::NewFinding;
    use crate::persistence::DbError;
    use sqlx::MySqlConnection;
    use vectispire_cp_db::types::UtcInstant;

    pub async fn save_all(conn: &mut MySqlConnection, findings: &[NewFinding]) -> Result<(), DbError> {
        for finding in findings {
            sqlx::query!(
                r#"/* mysql */ insert into t_finding (
                    scan_id, issue_id, type, source, tool, tool_name, tool_version,
                    identifier, severity, package_name, package_version, purl, file_path, line,
                    is_direct_dependency, owasp_category, epss_score, cvss_score, cvss_vector,
                    fix_state, fix_versions, link, is_kev, description, created_at, reachability
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'UNKNOWN')"#,
                finding.scan_id,
                finding.issue_id,
                finding.type_,
                finding.source,
                finding.tool,
                finding.tool_name,
                finding.tool_version,
                finding.identifier,
                finding.severity,
                finding.package_name,
                finding.package_version,
                finding.purl,
                finding.file_path,
                finding.line,
                finding.direct_dependency,
                finding.owasp_category,
                finding.epss_score,
                finding.cvss_score,
                finding.cvss_vector,
                finding.fix_state,
                finding.fix_versions,
                finding.link,
                finding.is_kev,
                finding.description,
                UtcInstant(finding.created_at),
            )
            .execute(&mut *conn)
            .await?;
        }
        Ok(())
    }
}

#[cfg(feature = "postgres-queries")]
mod postgres {
    use super::NewFinding;
    use crate::persistence::DbError;
    use sqlx::PgConnection;

    pub async fn save_all(conn: &mut PgConnection, findings: &[NewFinding]) -> Result<(), DbError> {
        for finding in findings {
            sqlx::query!(
                r#"/* postgres */ insert into t_finding (
                    scan_id, issue_id, type, source, tool, tool_name, tool_version,
                    identifier, severity, package_name, package_version, purl, file_path, line,
                    is_direct_dependency, owasp_category, epss_score, cvss_score, cvss_vector,
                    fix_state, fix_versions, link, is_kev, description, created_at, reachability
                ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, 'UNKNOWN')"#,
                finding.scan_id,
                finding.issue_id,
                finding.type_,
                finding.source,
                finding.tool,
                finding.tool_name,
                finding.tool_version,
                finding.identifier,
                finding.severity,
                finding.package_name,
                finding.package_version,
                finding.purl,
                finding.file_path,
                finding.line,
                finding.direct_dependency,
                finding.owasp_category,
                finding.epss_score,
                finding.cvss_score,
                finding.cvss_vector,
                finding.fix_state,
                finding.fix_versions,
                finding.link,
                finding.is_kev,
                finding.description,
                finding.created_at,
            )
            .execute(&mut *conn)
            .await?;
        }
        Ok(())
    }
}
