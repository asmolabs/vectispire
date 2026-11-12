//! Database operations on `t_semgrep_rule_set`.

use sqlx::Row;
use time::OffsetDateTime;
use vectispire_cp_db::{Db, Mode, Tx};

/// A database failure in the persistence layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error("{0}")]
    Other(String),
}

/// A stored rule set record matching `t_semgrep_rule_set`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemgrepRuleSetRecord {
    pub id: i64,
    pub name: String,
    pub files: String,
    pub content_hash: String,
    pub rule_count: i32,
    pub file_count: i32,
    pub size_bytes: i64,
    pub is_active: Option<bool>,
    pub uploaded_by: Option<String>,
    pub uploaded_at: OffsetDateTime,
    pub activation_note: Option<String>,
}

/// A summary of a rule set (without the full files JSON), for listings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemgrepRuleSetSummary {
    pub id: i64,
    pub name: String,
    pub content_hash: String,
    pub rule_count: i32,
    pub file_count: i32,
    pub size_bytes: String,
    pub active: Option<bool>,
    pub uploaded_by: Option<String>,
    pub uploaded_at: OffsetDateTime,
    pub activation_note: Option<String>,
}

/// Parameters for creating a new `t_semgrep_rule_set` row.
#[derive(Debug, Clone)]
pub struct NewSemgrepRuleSet {
    pub name: String,
    pub files: String,
    pub content_hash: String,
    pub rule_count: i32,
    pub file_count: i32,
    pub size_bytes: i64,
    pub is_active: Option<bool>,
    pub uploaded_by: Option<String>,
    pub uploaded_at: OffsetDateTime,
    pub activation_note: Option<String>,
}

macro_rules! parse_record {
    ($row:ident) => {{
        let is_active = match $row.try_get::<Option<bool>, _>("is_active") {
            Ok(b) => b,
            Err(_) => match $row.try_get::<Option<i8>, _>("is_active") {
                Ok(Some(i)) => Some(i != 0),
                _ => None,
            },
        };
        SemgrepRuleSetRecord {
            id: $row.get("id"),
            name: $row.get("name"),
            files: $row.get("files"),
            content_hash: $row.get("content_hash"),
            rule_count: $row.get("rule_count"),
            file_count: $row.get("file_count"),
            size_bytes: $row.get("size_bytes"),
            is_active,
            uploaded_by: $row.get("uploaded_by"),
            uploaded_at: $row.get("uploaded_at"),
            activation_note: $row.get("activation_note"),
        }
    }};
}

macro_rules! parse_summary {
    ($row:ident) => {{
        let is_active = match $row.try_get::<Option<bool>, _>("is_active") {
            Ok(b) => b,
            Err(_) => match $row.try_get::<Option<i8>, _>("is_active") {
                Ok(Some(i)) => Some(i != 0),
                _ => None,
            },
        };
        let size_bytes: i64 = $row.get("size_bytes");
        SemgrepRuleSetSummary {
            id: $row.get("id"),
            name: $row.get("name"),
            content_hash: $row.get("content_hash"),
            rule_count: $row.get("rule_count"),
            file_count: $row.get("file_count"),
            size_bytes: size_bytes.to_string(),
            active: is_active,
            uploaded_by: $row.get("uploaded_by"),
            uploaded_at: $row.get("uploaded_at"),
            activation_note: $row.get("activation_note"),
        }
    }};
}

#[derive(Debug, Clone)]
pub struct SemgrepRuleSetRepository {
    db: Db,
}

impl SemgrepRuleSetRepository {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub async fn insert(&self, item: &NewSemgrepRuleSet) -> Result<i64, StoreError> {
        match &self.db {
            Db::MySql(pool) => {
                let sql = "insert into t_semgrep_rule_set (name, files, content_hash, rule_count, file_count, size_bytes, is_active, uploaded_by, uploaded_at, activation_note) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                let res = sqlx::query(sql)
                    .bind(&item.name)
                    .bind(&item.files)
                    .bind(&item.content_hash)
                    .bind(item.rule_count)
                    .bind(item.file_count)
                    .bind(item.size_bytes)
                    .bind(item.is_active)
                    .bind(&item.uploaded_by)
                    .bind(item.uploaded_at)
                    .bind(&item.activation_note)
                    .execute(pool)
                    .await?;
                #[allow(clippy::cast_possible_wrap)]
                Ok(res.last_insert_id() as i64)
            }
            Db::PostgreSql(pool) => {
                let sql = "insert into t_semgrep_rule_set (name, files, content_hash, rule_count, file_count, size_bytes, is_active, uploaded_by, uploaded_at, activation_note) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) returning id";
                let row = sqlx::query(sql)
                    .bind(&item.name)
                    .bind(&item.files)
                    .bind(&item.content_hash)
                    .bind(item.rule_count)
                    .bind(item.file_count)
                    .bind(item.size_bytes)
                    .bind(item.is_active)
                    .bind(&item.uploaded_by)
                    .bind(item.uploaded_at)
                    .bind(&item.activation_note)
                    .fetch_one(pool)
                    .await?;
                Ok(row.get("id"))
            }
        }
    }

    pub async fn find_active(&self) -> Result<Option<SemgrepRuleSetRecord>, StoreError> {
        match &self.db {
            Db::MySql(pool) => {
                let sql = "select id, name, files, content_hash, rule_count, file_count, size_bytes, is_active, uploaded_by, uploaded_at, activation_note from t_semgrep_rule_set where is_active is not null order by id limit 1";
                let row = sqlx::query(sql).fetch_optional(pool).await?;
                Ok(row.as_ref().map(|r| parse_record!(r)))
            }
            Db::PostgreSql(pool) => {
                let sql = "select id, name, files, content_hash, rule_count, file_count, size_bytes, is_active, uploaded_by, uploaded_at, activation_note from t_semgrep_rule_set where is_active is not null order by id limit 1";
                let row = sqlx::query(sql).fetch_optional(pool).await?;
                Ok(row.as_ref().map(|r| parse_record!(r)))
            }
        }
    }

    pub async fn find_by_id(&self, id: i64) -> Result<Option<SemgrepRuleSetRecord>, StoreError> {
        match &self.db {
            Db::MySql(pool) => {
                let sql = "select id, name, files, content_hash, rule_count, file_count, size_bytes, is_active, uploaded_by, uploaded_at, activation_note from t_semgrep_rule_set where id = ?";
                let row = sqlx::query(sql).bind(id).fetch_optional(pool).await?;
                Ok(row.as_ref().map(|r| parse_record!(r)))
            }
            Db::PostgreSql(pool) => {
                let sql = "select id, name, files, content_hash, rule_count, file_count, size_bytes, is_active, uploaded_by, uploaded_at, activation_note from t_semgrep_rule_set where id = $1";
                let row = sqlx::query(sql).bind(id).fetch_optional(pool).await?;
                Ok(row.as_ref().map(|r| parse_record!(r)))
            }
        }
    }

    pub async fn find_first_by_content_hash_order_by_id_asc(
        &self,
        content_hash: &str,
    ) -> Result<Option<SemgrepRuleSetRecord>, StoreError> {
        match &self.db {
            Db::MySql(pool) => {
                let sql = "select id, name, files, content_hash, rule_count, file_count, size_bytes, is_active, uploaded_by, uploaded_at, activation_note from t_semgrep_rule_set where content_hash = ? order by id asc limit 1";
                let row = sqlx::query(sql).bind(content_hash).fetch_optional(pool).await?;
                Ok(row.as_ref().map(|r| parse_record!(r)))
            }
            Db::PostgreSql(pool) => {
                let sql = "select id, name, files, content_hash, rule_count, file_count, size_bytes, is_active, uploaded_by, uploaded_at, activation_note from t_semgrep_rule_set where content_hash = $1 order by id asc limit 1";
                let row = sqlx::query(sql).bind(content_hash).fetch_optional(pool).await?;
                Ok(row.as_ref().map(|r| parse_record!(r)))
            }
        }
    }

    pub async fn summaries(&self) -> Result<Vec<SemgrepRuleSetSummary>, StoreError> {
        match &self.db {
            Db::MySql(pool) => {
                let sql = "select id, name, content_hash, rule_count, file_count, size_bytes, is_active, uploaded_by, uploaded_at, activation_note from t_semgrep_rule_set order by uploaded_at desc, id desc";
                let rows = sqlx::query(sql).fetch_all(pool).await?;
                Ok(rows.iter().map(|r| parse_summary!(r)).collect())
            }
            Db::PostgreSql(pool) => {
                let sql = "select id, name, content_hash, rule_count, file_count, size_bytes, is_active, uploaded_by, uploaded_at, activation_note from t_semgrep_rule_set order by uploaded_at desc, id desc";
                let rows = sqlx::query(sql).fetch_all(pool).await?;
                Ok(rows.iter().map(|r| parse_summary!(r)).collect())
            }
        }
    }

    pub async fn deactivate_all(&self) -> Result<u64, StoreError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await?;
        let count = deactivate_all_in_tx(&mut tx).await?;
        tx.commit().await?;
        Ok(count)
    }

    pub async fn activate(&self, id: i64, note: Option<&str>) -> Result<u64, StoreError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await?;
        deactivate_all_in_tx(&mut tx).await?;
        let count = activate_in_tx(&mut tx, id, note).await?;
        tx.commit().await?;
        Ok(count)
    }
}

pub async fn deactivate_all_in_tx(tx: &mut Tx) -> Result<u64, StoreError> {
    match tx {
        Tx::MySql(c) => {
            let sql = "update t_semgrep_rule_set set is_active = null where is_active is not null";
            let res = sqlx::query(sql).execute(&mut **c).await?;
            Ok(res.rows_affected())
        }
        Tx::PostgreSql(c) => {
            let sql = "update t_semgrep_rule_set set is_active = null where is_active is not null";
            let res = sqlx::query(sql).execute(&mut **c).await?;
            Ok(res.rows_affected())
        }
    }
}

pub async fn activate_in_tx(tx: &mut Tx, id: i64, note: Option<&str>) -> Result<u64, StoreError> {
    match tx {
        Tx::MySql(c) => {
            let sql = "update t_semgrep_rule_set set is_active = true, activation_note = ? where id = ?";
            let res = sqlx::query(sql).bind(note).bind(id).execute(&mut **c).await?;
            Ok(res.rows_affected())
        }
        Tx::PostgreSql(c) => {
            let sql = "update t_semgrep_rule_set set is_active = true, activation_note = $1 where id = $2";
            let res = sqlx::query(sql).bind(note).bind(id).execute(&mut **c).await?;
            Ok(res.rows_affected())
        }
    }
}
