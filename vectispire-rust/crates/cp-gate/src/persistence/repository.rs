//! Persistence repository for gate policies and verdicts.

use sqlx::{AssertSqlSafe, Row};
use time::OffsetDateTime;
use vectispire_cp_db::Tx;
use vectispire_cp_db::types::UtcInstant;

use super::{GatePolicyRow, GateVerdictRow, NewGatePolicyRow, StoreError};

const POLICY_COLS: &str = "id, target_kind, target_id, version, is_active, fail_on_severity, fail_on_kev, fixable_only, include_triaged, include_ai_review, fail_on_uncovered_languages, include_plugins, note, created_by, created_at";

const VERDICT_COLS: &str = "id, repo_id, container_id, passed, evaluated, violations, critical_count, high_count, medium_count, low_count, fail_on_severity, policy_source, policy_version, relaxations_ignored, decided_at, decided_by, ip_address";

macro_rules! parse_policy_row {
    ($r:ident) => {{
        let created_at: UtcInstant = $r.get("created_at");
        let parse_bool = |col: &str| -> bool {
            match $r.try_get::<bool, _>(col) {
                Ok(v) => v,
                Err(_) => match $r.try_get::<i8, _>(col) {
                    Ok(i) => i != 0,
                    _ => false,
                },
            }
        };
        let is_active = match $r.try_get::<Option<bool>, _>("is_active") {
            Ok(v) => v,
            Err(_) => match $r.try_get::<Option<i8>, _>("is_active") {
                Ok(Some(i)) => Some(i != 0),
                _ => None,
            },
        };
        GatePolicyRow {
            id: $r.get("id"),
            target_kind: $r.get("target_kind"),
            target_id: $r.get("target_id"),
            version: $r.get("version"),
            is_active,
            fail_on_severity: $r.get("fail_on_severity"),
            fail_on_kev: parse_bool("fail_on_kev"),
            fixable_only: parse_bool("fixable_only"),
            include_triaged: parse_bool("include_triaged"),
            include_ai_review: parse_bool("include_ai_review"),
            fail_on_uncovered_languages: parse_bool("fail_on_uncovered_languages"),
            include_plugins: parse_bool("include_plugins"),
            note: $r.get("note"),
            created_by: $r.get("created_by"),
            created_at: created_at.0,
        }
    }};
}

macro_rules! parse_verdict_row {
    ($r:ident) => {{
        let decided_at: UtcInstant = $r.get("decided_at");
        let passed = match $r.try_get::<bool, _>("passed") {
            Ok(v) => v,
            Err(_) => match $r.try_get::<i8, _>("passed") {
                Ok(i) => i != 0,
                _ => false,
            },
        };
        let relaxations_ignored = match $r.try_get::<bool, _>("relaxations_ignored") {
            Ok(v) => v,
            Err(_) => match $r.try_get::<i8, _>("relaxations_ignored") {
                Ok(i) => i != 0,
                _ => false,
            },
        };
        GateVerdictRow {
            id: $r.get("id"),
            repo_id: $r.get("repo_id"),
            container_id: $r.get("container_id"),
            passed,
            evaluated: $r.get("evaluated"),
            violations: $r.get("violations"),
            critical_count: $r.get("critical_count"),
            high_count: $r.get("high_count"),
            medium_count: $r.get("medium_count"),
            low_count: $r.get("low_count"),
            fail_on_severity: $r.get("fail_on_severity"),
            policy_source: $r.get("policy_source"),
            policy_version: $r.get("policy_version"),
            relaxations_ignored,
            decided_at: decided_at.0,
            decided_by: $r.get("decided_by"),
            ip_address: $r.get("ip_address"),
        }
    }};
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

pub struct GatePolicyRepository;

impl GatePolicyRepository {
    pub async fn find_active(tx: &mut Tx) -> Result<Vec<GatePolicyRow>, StoreError> {
        let sql = format!("select {POLICY_COLS} from t_gate_policy where is_active is not null and is_active = true");
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| parse_policy_row!(r))
                .collect(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql))
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| parse_policy_row!(r))
                .collect(),
        };
        Ok(rows)
    }

    #[allow(dead_code)]
    pub async fn find_active_by_target(tx: &mut Tx, kind: &str, id: i64) -> Result<Option<GatePolicyRow>, StoreError> {
        let sql = format!(
            "select {POLICY_COLS} from t_gate_policy where target_kind = ? and target_id = ? and is_active is not null and is_active = true limit 1"
        );
        let row = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(kind)
                .bind(id)
                .fetch_optional(&mut **conn)
                .await?
                .map(|r| parse_policy_row!(r)),
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(&sql);
                sqlx::query(AssertSqlSafe(pg_sql))
                    .bind(kind)
                    .bind(id)
                    .fetch_optional(&mut **conn)
                    .await?
                    .map(|r| parse_policy_row!(r))
            }
        };
        Ok(row)
    }

    pub async fn highest_version(tx: &mut Tx, kind: &str, id: i64) -> Result<i32, StoreError> {
        let sql =
            "select coalesce(max(version), 0) as max_v from t_gate_policy where target_kind = ? and target_id = ?";
        let max_v: i32 = match tx {
            Tx::MySql(conn) => {
                let r = sqlx::query(AssertSqlSafe(sql)).bind(kind).bind(id).fetch_one(&mut **conn).await?;
                r.get("max_v")
            }
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(sql);
                let r = sqlx::query(AssertSqlSafe(pg_sql)).bind(kind).bind(id).fetch_one(&mut **conn).await?;
                r.get("max_v")
            }
        };
        Ok(max_v)
    }

    pub async fn supersede(tx: &mut Tx, kind: &str, id: i64) -> Result<u64, StoreError> {
        let sql = "update t_gate_policy set is_active = null where target_kind = ? and target_id = ? and is_active is not null and is_active = true";
        let affected = match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(kind).bind(id).execute(&mut **conn).await?.rows_affected()
            }
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(sql);
                sqlx::query(AssertSqlSafe(pg_sql)).bind(kind).bind(id).execute(&mut **conn).await?.rows_affected()
            }
        };
        Ok(affected)
    }

    pub async fn insert(tx: &mut Tx, row: &NewGatePolicyRow) -> Result<i64, StoreError> {
        let sql = "insert into t_gate_policy (target_kind, target_id, version, is_active, fail_on_severity, fail_on_kev, fixable_only, include_triaged, include_ai_review, fail_on_uncovered_languages, include_plugins, note, created_by, created_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        match tx {
            Tx::MySql(conn) => {
                let res = sqlx::query(AssertSqlSafe(sql))
                    .bind(&row.target_kind)
                    .bind(row.target_id)
                    .bind(row.version)
                    .bind(row.is_active)
                    .bind(&row.fail_on_severity)
                    .bind(row.fail_on_kev)
                    .bind(row.fixable_only)
                    .bind(row.include_triaged)
                    .bind(row.include_ai_review)
                    .bind(row.fail_on_uncovered_languages)
                    .bind(row.include_plugins)
                    .bind(&row.note)
                    .bind(&row.created_by)
                    .bind(UtcInstant(row.created_at))
                    .execute(&mut **conn)
                    .await?;
                Ok(i64::try_from(res.last_insert_id()).unwrap_or(0))
            }
            Tx::PostgreSql(conn) => {
                let pg_sql = format!("{} returning id", to_pg_sql(sql));
                let r = sqlx::query(AssertSqlSafe(pg_sql))
                    .bind(&row.target_kind)
                    .bind(row.target_id)
                    .bind(row.version)
                    .bind(row.is_active)
                    .bind(&row.fail_on_severity)
                    .bind(row.fail_on_kev)
                    .bind(row.fixable_only)
                    .bind(row.include_triaged)
                    .bind(row.include_ai_review)
                    .bind(row.fail_on_uncovered_languages)
                    .bind(row.include_plugins)
                    .bind(&row.note)
                    .bind(&row.created_by)
                    .bind(UtcInstant(row.created_at))
                    .fetch_one(&mut **conn)
                    .await?;
                Ok(r.get("id"))
            }
        }
    }

    pub async fn delete_by_target(tx: &mut Tx, kind: &str, id: i64) -> Result<u64, StoreError> {
        let sql = "delete from t_gate_policy where target_kind = ? and target_id = ?";
        let affected = match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(kind).bind(id).execute(&mut **conn).await?.rows_affected()
            }
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(sql);
                sqlx::query(AssertSqlSafe(pg_sql)).bind(kind).bind(id).execute(&mut **conn).await?.rows_affected()
            }
        };
        Ok(affected)
    }
}

pub struct GateVerdictRepository;

impl GateVerdictRepository {
    pub async fn insert(tx: &mut Tx, row: &GateVerdictRow) -> Result<(), StoreError> {
        let sql = "insert into t_gate_verdict (id, repo_id, container_id, passed, evaluated, violations, critical_count, high_count, medium_count, low_count, fail_on_severity, policy_source, policy_version, relaxations_ignored, decided_at, decided_by, ip_address) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql))
                    .bind(&row.id)
                    .bind(row.repo_id)
                    .bind(row.container_id)
                    .bind(row.passed)
                    .bind(row.evaluated)
                    .bind(row.violations)
                    .bind(row.critical_count)
                    .bind(row.high_count)
                    .bind(row.medium_count)
                    .bind(row.low_count)
                    .bind(&row.fail_on_severity)
                    .bind(&row.policy_source)
                    .bind(row.policy_version)
                    .bind(row.relaxations_ignored)
                    .bind(UtcInstant(row.decided_at))
                    .bind(&row.decided_by)
                    .bind(&row.ip_address)
                    .execute(&mut **conn)
                    .await?;
            }
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(sql);
                sqlx::query(AssertSqlSafe(pg_sql))
                    .bind(&row.id)
                    .bind(row.repo_id)
                    .bind(row.container_id)
                    .bind(row.passed)
                    .bind(row.evaluated)
                    .bind(row.violations)
                    .bind(row.critical_count)
                    .bind(row.high_count)
                    .bind(row.medium_count)
                    .bind(row.low_count)
                    .bind(&row.fail_on_severity)
                    .bind(&row.policy_source)
                    .bind(row.policy_version)
                    .bind(row.relaxations_ignored)
                    .bind(UtcInstant(row.decided_at))
                    .bind(&row.decided_by)
                    .bind(&row.ip_address)
                    .execute(&mut **conn)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn first_page(tx: &mut Tx, limit: i32) -> Result<Vec<GateVerdictRow>, StoreError> {
        let sql = format!("select {VERDICT_COLS} from t_gate_verdict order by decided_at desc, id desc limit ?");
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(i64::from(limit))
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| parse_verdict_row!(r))
                .collect(),
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(&sql);
                sqlx::query(AssertSqlSafe(pg_sql))
                    .bind(i64::from(limit))
                    .fetch_all(&mut **conn)
                    .await?
                    .into_iter()
                    .map(|r| parse_verdict_row!(r))
                    .collect()
            }
        };
        Ok(rows)
    }

    pub async fn page_after(
        tx: &mut Tx,
        decided_at: OffsetDateTime,
        id: &str,
        limit: i32,
    ) -> Result<Vec<GateVerdictRow>, StoreError> {
        let sql = format!(
            "select {VERDICT_COLS} from t_gate_verdict where decided_at < ? or (decided_at = ? and id < ?) order by decided_at desc, id desc limit ?"
        );
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(UtcInstant(decided_at))
                .bind(UtcInstant(decided_at))
                .bind(id)
                .bind(i64::from(limit))
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| parse_verdict_row!(r))
                .collect(),
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(&sql);
                sqlx::query(AssertSqlSafe(pg_sql))
                    .bind(UtcInstant(decided_at))
                    .bind(UtcInstant(decided_at))
                    .bind(id)
                    .bind(i64::from(limit))
                    .fetch_all(&mut **conn)
                    .await?
                    .into_iter()
                    .map(|r| parse_verdict_row!(r))
                    .collect()
            }
        };
        Ok(rows)
    }

    pub async fn first_page_within(
        tx: &mut Tx,
        repo_ids: &[i64],
        container_ids: &[i64],
        limit: i32,
    ) -> Result<Vec<GateVerdictRow>, StoreError> {
        let repo_q = if repo_ids.is_empty() { "?".to_owned() } else { vec!["?"; repo_ids.len()].join(",") };
        let cont_q = if container_ids.is_empty() { "?".to_owned() } else { vec!["?"; container_ids.len()].join(",") };
        let sql = format!(
            "select {VERDICT_COLS} from t_gate_verdict where (repo_id in ({repo_q}) or (repo_id is null and container_id in ({cont_q}))) order by decided_at desc, id desc limit ?"
        );

        match tx {
            Tx::MySql(conn) => {
                let mut q = sqlx::query(AssertSqlSafe(sql));
                if repo_ids.is_empty() {
                    q = q.bind(-1i64);
                } else {
                    for &id in repo_ids {
                        q = q.bind(id);
                    }
                }
                if container_ids.is_empty() {
                    q = q.bind(-1i64);
                } else {
                    for &id in container_ids {
                        q = q.bind(id);
                    }
                }
                q = q.bind(i64::from(limit));
                let rows = q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_verdict_row!(r)).collect();
                Ok(rows)
            }
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(&sql);
                let mut q = sqlx::query(AssertSqlSafe(pg_sql));
                if repo_ids.is_empty() {
                    q = q.bind(-1i64);
                } else {
                    for &id in repo_ids {
                        q = q.bind(id);
                    }
                }
                if container_ids.is_empty() {
                    q = q.bind(-1i64);
                } else {
                    for &id in container_ids {
                        q = q.bind(id);
                    }
                }
                q = q.bind(i64::from(limit));
                let rows = q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_verdict_row!(r)).collect();
                Ok(rows)
            }
        }
    }

    pub async fn page_after_within(
        tx: &mut Tx,
        repo_ids: &[i64],
        container_ids: &[i64],
        decided_at: OffsetDateTime,
        id: &str,
        limit: i32,
    ) -> Result<Vec<GateVerdictRow>, StoreError> {
        let repo_q = if repo_ids.is_empty() { "?".to_owned() } else { vec!["?"; repo_ids.len()].join(",") };
        let cont_q = if container_ids.is_empty() { "?".to_owned() } else { vec!["?"; container_ids.len()].join(",") };
        let sql = format!(
            "select {VERDICT_COLS} from t_gate_verdict where (repo_id in ({repo_q}) or (repo_id is null and container_id in ({cont_q}))) and (decided_at < ? or (decided_at = ? and id < ?)) order by decided_at desc, id desc limit ?"
        );

        match tx {
            Tx::MySql(conn) => {
                let mut q = sqlx::query(AssertSqlSafe(sql));
                if repo_ids.is_empty() {
                    q = q.bind(-1i64);
                } else {
                    for &r_id in repo_ids {
                        q = q.bind(r_id);
                    }
                }
                if container_ids.is_empty() {
                    q = q.bind(-1i64);
                } else {
                    for &c_id in container_ids {
                        q = q.bind(c_id);
                    }
                }
                q = q.bind(UtcInstant(decided_at)).bind(UtcInstant(decided_at)).bind(id).bind(i64::from(limit));
                let rows = q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_verdict_row!(r)).collect();
                Ok(rows)
            }
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(&sql);
                let mut q = sqlx::query(AssertSqlSafe(pg_sql));
                if repo_ids.is_empty() {
                    q = q.bind(-1i64);
                } else {
                    for &r_id in repo_ids {
                        q = q.bind(r_id);
                    }
                }
                if container_ids.is_empty() {
                    q = q.bind(-1i64);
                } else {
                    for &c_id in container_ids {
                        q = q.bind(c_id);
                    }
                }
                q = q.bind(UtcInstant(decided_at)).bind(UtcInstant(decided_at)).bind(id).bind(i64::from(limit));
                let rows = q.fetch_all(&mut **conn).await?.into_iter().map(|r| parse_verdict_row!(r)).collect();
                Ok(rows)
            }
        }
    }

    pub async fn newest(tx: &mut Tx, limit: i32) -> Result<Vec<GateVerdictRow>, StoreError> {
        let sql = format!("select {VERDICT_COLS} from t_gate_verdict order by decided_at desc limit ?");
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(i64::from(limit))
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| parse_verdict_row!(r))
                .collect(),
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(&sql);
                sqlx::query(AssertSqlSafe(pg_sql))
                    .bind(i64::from(limit))
                    .fetch_all(&mut **conn)
                    .await?
                    .into_iter()
                    .map(|r| parse_verdict_row!(r))
                    .collect()
            }
        };
        Ok(rows)
    }

    pub async fn last_for_repository(
        tx: &mut Tx,
        repo_id: i64,
        from: OffsetDateTime,
        until: Option<OffsetDateTime>,
    ) -> Result<Option<GateVerdictRow>, StoreError> {
        let (sql, binds_until) = match until {
            Some(_) => (
                format!(
                    "select {VERDICT_COLS} from t_gate_verdict where repo_id = ? and decided_at >= ? and decided_at < ? order by decided_at desc limit 1"
                ),
                true,
            ),
            None => (
                format!(
                    "select {VERDICT_COLS} from t_gate_verdict where repo_id = ? and decided_at >= ? order by decided_at desc limit 1"
                ),
                false,
            ),
        };

        match tx {
            Tx::MySql(conn) => {
                let mut q = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).bind(UtcInstant(from));
                if binds_until {
                    q = q.bind(UtcInstant(until.unwrap_or(from)));
                }
                let row = q.fetch_optional(&mut **conn).await?.map(|r| parse_verdict_row!(r));
                Ok(row)
            }
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(&sql);
                let mut q = sqlx::query(AssertSqlSafe(pg_sql)).bind(repo_id).bind(UtcInstant(from));
                if binds_until {
                    q = q.bind(UtcInstant(until.unwrap_or(from)));
                }
                let row = q.fetch_optional(&mut **conn).await?.map(|r| parse_verdict_row!(r));
                Ok(row)
            }
        }
    }

    pub async fn last_for_container(
        tx: &mut Tx,
        container_id: i64,
        from: OffsetDateTime,
        until: Option<OffsetDateTime>,
    ) -> Result<Option<GateVerdictRow>, StoreError> {
        let (sql, binds_until) = match until {
            Some(_) => (
                format!(
                    "select {VERDICT_COLS} from t_gate_verdict where container_id = ? and decided_at >= ? and decided_at < ? order by decided_at desc limit 1"
                ),
                true,
            ),
            None => (
                format!(
                    "select {VERDICT_COLS} from t_gate_verdict where container_id = ? and decided_at >= ? order by decided_at desc limit 1"
                ),
                false,
            ),
        };

        match tx {
            Tx::MySql(conn) => {
                let mut q = sqlx::query(AssertSqlSafe(sql)).bind(container_id).bind(UtcInstant(from));
                if binds_until {
                    q = q.bind(UtcInstant(until.unwrap_or(from)));
                }
                let row = q.fetch_optional(&mut **conn).await?.map(|r| parse_verdict_row!(r));
                Ok(row)
            }
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(&sql);
                let mut q = sqlx::query(AssertSqlSafe(pg_sql)).bind(container_id).bind(UtcInstant(from));
                if binds_until {
                    q = q.bind(UtcInstant(until.unwrap_or(from)));
                }
                let row = q.fetch_optional(&mut **conn).await?.map(|r| parse_verdict_row!(r));
                Ok(row)
            }
        }
    }

    pub async fn delete_before(tx: &mut Tx, cutoff: OffsetDateTime) -> Result<u64, StoreError> {
        let sql = "delete from t_gate_verdict where decided_at < ?";
        let affected = match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(UtcInstant(cutoff)).execute(&mut **conn).await?.rows_affected()
            }
            Tx::PostgreSql(conn) => {
                let pg_sql = to_pg_sql(sql);
                sqlx::query(AssertSqlSafe(pg_sql)).bind(UtcInstant(cutoff)).execute(&mut **conn).await?.rows_affected()
            }
        };
        Ok(affected)
    }
}
