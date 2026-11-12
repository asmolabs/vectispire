#![allow(dead_code)]

use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_access::credentials::AgentRef;
use vectispire_cp_db::{Db, Tx};

use crate::persistence::StoreError;

/// Data reported by an agent during hello/heartbeat.
#[derive(Debug, Clone, Default)]
pub struct HeartbeatData<'a> {
    pub hostname: Option<&'a str>,
    pub platform: Option<&'a str>,
    pub version: Option<&'a str>,
    pub scanner_engine: Option<&'a str>,
    pub capabilities: Option<&'a str>,
    pub contract_version: Option<&'a str>,
}

/// A row of `t_agent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub kind: String,
    pub labels: Option<String>,
    pub credentials_mode: String,
    pub enabled: bool,
    pub max_concurrent: Option<i32>,
    pub api_key_id: Option<Uuid>,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub version: Option<String>,
    pub scanner_engine: Option<String>,
    pub capabilities: Option<String>,
    pub contract_version: Option<String>,
    pub sealing_public_key: Option<String>,
    pub sealing_key_generation: Option<i64>,
    pub signing_public_key: Option<String>,
    pub last_seen_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

macro_rules! parse_agent_row {
    ($row:ident) => {{
        let id_str: String = $row.get("id");
        let id = Uuid::parse_str(id_str.trim()).unwrap_or_default();
        let api_key_id: Option<Uuid> =
            $row.get::<Option<String>, _>("api_key_id").and_then(|s| Uuid::parse_str(s.trim()).ok());
        let enabled = match $row.try_get::<bool, _>("enabled") {
            Ok(b) => b,
            Err(_) => {
                let i: i8 = $row.try_get("enabled").unwrap_or(0);
                i != 0
            }
        };
        AgentRow {
            id,
            name: $row.get("name"),
            description: $row.get("description"),
            kind: $row.get("kind"),
            labels: $row.get("labels"),
            credentials_mode: $row.get("credentials_mode"),
            enabled,
            max_concurrent: $row.get("max_concurrent"),
            api_key_id,
            hostname: $row.get("hostname"),
            platform: $row.get("platform"),
            version: $row.get("version"),
            scanner_engine: $row.get("scanner_engine"),
            capabilities: $row.get("capabilities"),
            contract_version: $row.get("contract_version"),
            sealing_public_key: $row.get("sealing_public_key"),
            sealing_key_generation: $row.get("sealing_key_generation"),
            signing_public_key: $row.get("signing_public_key"),
            last_seen_at: $row.get("last_seen_at"),
            created_at: $row.get("created_at"),
        }
    }};
}

pub async fn find_by_id(db: &Db, id: Uuid) -> Result<Option<AgentRow>, StoreError> {
    let id_str = id.as_hyphenated().to_string();
    match db {
        Db::MySql(pool) => {
            let row = sqlx::query(
                "select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent, \
                 api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version, \
                 sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at \
                 from t_agent where id = ?",
            )
            .bind(&id_str)
            .fetch_optional(pool)
            .await?;
            Ok(row.as_ref().map(|r| parse_agent_row!(r)))
        }
        Db::PostgreSql(pool) => {
            let row = sqlx::query(
                "select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent, \
                 api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version, \
                 sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at \
                 from t_agent where id = $1",
            )
            .bind(&id_str)
            .fetch_optional(pool)
            .await?;
            Ok(row.as_ref().map(|r| parse_agent_row!(r)))
        }
    }
}

pub async fn find_by_name(db: &Db, name: &str) -> Result<Option<AgentRow>, StoreError> {
    match db {
        Db::MySql(pool) => {
            let row = sqlx::query(
                "select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent, \
                 api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version, \
                 sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at \
                 from t_agent where name = ?",
            )
            .bind(name)
            .fetch_optional(pool)
            .await?;
            Ok(row.as_ref().map(|r| parse_agent_row!(r)))
        }
        Db::PostgreSql(pool) => {
            let row = sqlx::query(
                "select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent, \
                 api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version, \
                 sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at \
                 from t_agent where name = $1",
            )
            .bind(name)
            .fetch_optional(pool)
            .await?;
            Ok(row.as_ref().map(|r| parse_agent_row!(r)))
        }
    }
}

pub async fn find_by_api_key_id(db: &Db, api_key_id: Uuid) -> Result<Option<AgentRow>, StoreError> {
    let key_str = api_key_id.as_hyphenated().to_string();
    match db {
        Db::MySql(pool) => {
            let row = sqlx::query(
                "select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent, \
                 api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version, \
                 sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at \
                 from t_agent where api_key_id = ?",
            )
            .bind(&key_str)
            .fetch_optional(pool)
            .await?;
            Ok(row.as_ref().map(|r| parse_agent_row!(r)))
        }
        Db::PostgreSql(pool) => {
            let row = sqlx::query(
                "select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent, \
                 api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version, \
                 sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at \
                 from t_agent where api_key_id = $1",
            )
            .bind(&key_str)
            .fetch_optional(pool)
            .await?;
            Ok(row.as_ref().map(|r| parse_agent_row!(r)))
        }
    }
}

pub async fn find_all_ordered(db: &Db) -> Result<Vec<AgentRow>, StoreError> {
    match db {
        Db::MySql(pool) => {
            let list = sqlx::query(
                "select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent, \
                 api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version, \
                 sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at \
                 from t_agent order by name asc, id asc",
            )
            .fetch_all(pool)
            .await?;
            Ok(list.iter().map(|r| parse_agent_row!(r)).collect())
        }
        Db::PostgreSql(pool) => {
            let list = sqlx::query(
                "select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent, \
                 api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version, \
                 sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at \
                 from t_agent order by name asc, id asc",
            )
            .fetch_all(pool)
            .await?;
            Ok(list.iter().map(|r| parse_agent_row!(r)).collect())
        }
    }
}

pub async fn find_enabled(db: &Db) -> Result<Vec<AgentRow>, StoreError> {
    match db {
        Db::MySql(pool) => {
            let list = sqlx::query(
                "select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent, \
                 api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version, \
                 sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at \
                 from t_agent where enabled = 1",
            )
            .fetch_all(pool)
            .await?;
            Ok(list.iter().map(|r| parse_agent_row!(r)).collect())
        }
        Db::PostgreSql(pool) => {
            let list = sqlx::query(
                "select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent, \
                 api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version, \
                 sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at \
                 from t_agent where enabled = true",
            )
            .fetch_all(pool)
            .await?;
            Ok(list.iter().map(|r| parse_agent_row!(r)).collect())
        }
    }
}

pub async fn insert(tx: &mut Tx, row: &AgentRow) -> Result<(), StoreError> {
    let id_str = row.id.as_hyphenated().to_string();
    let api_key_id_str = row.api_key_id.map(|k| k.as_hyphenated().to_string());
    match tx {
        Tx::MySql(c) => {
            let sql = r#"
                insert into t_agent (
                    id, name, description, kind, labels, credentials_mode, enabled, max_concurrent,
                    api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                    sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#;
            sqlx::query(sql)
                .bind(&id_str)
                .bind(&row.name)
                .bind(&row.description)
                .bind(&row.kind)
                .bind(&row.labels)
                .bind(&row.credentials_mode)
                .bind(row.enabled)
                .bind(row.max_concurrent)
                .bind(&api_key_id_str)
                .bind(&row.hostname)
                .bind(&row.platform)
                .bind(&row.version)
                .bind(&row.scanner_engine)
                .bind(&row.capabilities)
                .bind(&row.contract_version)
                .bind(&row.sealing_public_key)
                .bind(row.sealing_key_generation)
                .bind(&row.signing_public_key)
                .bind(row.last_seen_at)
                .bind(row.created_at)
                .execute(&mut **c)
                .await?;
        }
        Tx::PostgreSql(c) => {
            let sql = r#"
                insert into t_agent (
                    id, name, description, kind, labels, credentials_mode, enabled, max_concurrent,
                    api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                    sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at
                ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
            "#;
            sqlx::query(sql)
                .bind(&id_str)
                .bind(&row.name)
                .bind(&row.description)
                .bind(&row.kind)
                .bind(&row.labels)
                .bind(&row.credentials_mode)
                .bind(row.enabled)
                .bind(row.max_concurrent)
                .bind(&api_key_id_str)
                .bind(&row.hostname)
                .bind(&row.platform)
                .bind(&row.version)
                .bind(&row.scanner_engine)
                .bind(&row.capabilities)
                .bind(&row.contract_version)
                .bind(&row.sealing_public_key)
                .bind(row.sealing_key_generation)
                .bind(&row.signing_public_key)
                .bind(row.last_seen_at)
                .bind(row.created_at)
                .execute(&mut **c)
                .await?;
        }
    }
    Ok(())
}

pub async fn update(tx: &mut Tx, row: &AgentRow) -> Result<bool, StoreError> {
    let id_str = row.id.as_hyphenated().to_string();
    let api_key_id_str = row.api_key_id.map(|k| k.as_hyphenated().to_string());
    let rows = match tx {
        Tx::MySql(c) => {
            let sql = r#"
                update t_agent
                   set name = ?, description = ?, kind = ?, labels = ?, credentials_mode = ?,
                       enabled = ?, max_concurrent = ?, api_key_id = ?
                 where id = ?
            "#;
            sqlx::query(sql)
                .bind(&row.name)
                .bind(&row.description)
                .bind(&row.kind)
                .bind(&row.labels)
                .bind(&row.credentials_mode)
                .bind(row.enabled)
                .bind(row.max_concurrent)
                .bind(&api_key_id_str)
                .bind(&id_str)
                .execute(&mut **c)
                .await?
                .rows_affected()
        }
        Tx::PostgreSql(c) => {
            let sql = r#"
                update t_agent
                   set name = $1, description = $2, kind = $3, labels = $4, credentials_mode = $5,
                       enabled = $6, max_concurrent = $7, api_key_id = $8
                 where id = $9
            "#;
            sqlx::query(sql)
                .bind(&row.name)
                .bind(&row.description)
                .bind(&row.kind)
                .bind(&row.labels)
                .bind(&row.credentials_mode)
                .bind(row.enabled)
                .bind(row.max_concurrent)
                .bind(&api_key_id_str)
                .bind(&id_str)
                .execute(&mut **c)
                .await?
                .rows_affected()
        }
    };
    Ok(rows > 0)
}

pub async fn delete_by_id(tx: &mut Tx, id: Uuid) -> Result<bool, StoreError> {
    let id_str = id.as_hyphenated().to_string();
    let rows = match tx {
        Tx::MySql(c) => {
            sqlx::query("delete from t_agent where id = ?").bind(&id_str).execute(&mut **c).await?.rows_affected()
        }
        Tx::PostgreSql(c) => {
            sqlx::query("delete from t_agent where id = $1").bind(&id_str).execute(&mut **c).await?.rows_affected()
        }
    };
    Ok(rows > 0)
}

/// Updates `last_seen_at` for the claiming agent. Returns whether the row exists.
pub async fn lock_for_claim(tx: &mut Tx, agent: Uuid, at: OffsetDateTime) -> Result<bool, StoreError> {
    let id_str = agent.as_hyphenated().to_string();
    let rows = match tx {
        Tx::MySql(tx) => sqlx::query("update t_agent set last_seen_at = ? where id = ?")
            .bind(at)
            .bind(&id_str)
            .execute(&mut **tx)
            .await?
            .rows_affected(),
        Tx::PostgreSql(tx) => sqlx::query("update t_agent set last_seen_at = $1 where id = $2")
            .bind(at)
            .bind(&id_str)
            .execute(&mut **tx)
            .await?
            .rows_affected(),
    };
    Ok(rows > 0)
}

/// Records that an agent was heard from, unless it already was since `stale_before`.
pub async fn record_seen(
    db: &Db,
    id: Uuid,
    at: OffsetDateTime,
    stale_before: OffsetDateTime,
) -> Result<bool, StoreError> {
    let id_str = id.as_hyphenated().to_string();
    let rows = match db {
        Db::MySql(pool) => {
            let sql = "update t_agent set last_seen_at = ? where id = ? and (last_seen_at is null or last_seen_at < ?)";
            sqlx::query(sql).bind(at).bind(&id_str).bind(stale_before).execute(pool).await?.rows_affected()
        }
        Db::PostgreSql(pool) => {
            let sql =
                "update t_agent set last_seen_at = $1 where id = $2 and (last_seen_at is null or last_seen_at < $3)";
            sqlx::query(sql).bind(at).bind(&id_str).bind(stale_before).execute(pool).await?.rows_affected()
        }
    };
    Ok(rows > 0)
}

/// Records that an agent has just been heard from, and what it said about itself.
pub async fn record_heartbeat(
    db: &Db,
    id: Uuid,
    at: OffsetDateTime,
    data: &HeartbeatData<'_>,
) -> Result<bool, StoreError> {
    let id_str = id.as_hyphenated().to_string();
    let rows = match db {
        Db::MySql(pool) => {
            let sql = r#"
                update t_agent
                   set last_seen_at = ?, hostname = ?, platform = ?, version = ?,
                       scanner_engine = ?, capabilities = ?, contract_version = ?
                 where id = ?
            "#;
            sqlx::query(sql)
                .bind(at)
                .bind(data.hostname)
                .bind(data.platform)
                .bind(data.version)
                .bind(data.scanner_engine)
                .bind(data.capabilities)
                .bind(data.contract_version)
                .bind(&id_str)
                .execute(pool)
                .await?
                .rows_affected()
        }
        Db::PostgreSql(pool) => {
            let sql = r#"
                update t_agent
                   set last_seen_at = $1, hostname = $2, platform = $3, version = $4,
                       scanner_engine = $5, capabilities = $6, contract_version = $7
                 where id = $8
            "#;
            sqlx::query(sql)
                .bind(at)
                .bind(data.hostname)
                .bind(data.platform)
                .bind(data.version)
                .bind(data.scanner_engine)
                .bind(data.capabilities)
                .bind(data.contract_version)
                .bind(&id_str)
                .execute(pool)
                .await?
                .rows_affected()
        }
    };
    Ok(rows > 0)
}

/// Records a sealing key whose signature was verified, if newer than the one held.
pub async fn accept_sealing_key(db: &Db, id: Uuid, key: &str, generation: i64) -> Result<bool, StoreError> {
    let id_str = id.as_hyphenated().to_string();
    let rows = match db {
        Db::MySql(pool) => {
            let sql = r#"
                update t_agent
                   set sealing_public_key = ?, sealing_key_generation = ?
                 where id = ?
                   and (sealing_key_generation is null
                        or sealing_key_generation < ?
                        or (sealing_key_generation = ? and sealing_public_key = ?))
            "#;
            sqlx::query(sql)
                .bind(key)
                .bind(generation)
                .bind(&id_str)
                .bind(generation)
                .bind(generation)
                .bind(key)
                .execute(pool)
                .await?
                .rows_affected()
        }
        Db::PostgreSql(pool) => {
            let sql = r#"
                update t_agent
                   set sealing_public_key = $1, sealing_key_generation = $2
                 where id = $3
                   and (sealing_key_generation is null
                        or sealing_key_generation < $4
                        or (sealing_key_generation = $5 and sealing_public_key = $6))
            "#;
            sqlx::query(sql)
                .bind(key)
                .bind(generation)
                .bind(&id_str)
                .bind(generation)
                .bind(generation)
                .bind(key)
                .execute(pool)
                .await?
                .rows_affected()
        }
    };
    Ok(rows > 0)
}

/// Forgets the agent's sealing key and generation.
pub async fn forget_sealing_key(tx: &mut Tx, id: Uuid) -> Result<bool, StoreError> {
    let id_str = id.as_hyphenated().to_string();
    let rows = match tx {
        Tx::MySql(c) => {
            sqlx::query("update t_agent set sealing_public_key = null, sealing_key_generation = null where id = ?")
                .bind(&id_str)
                .execute(&mut **c)
                .await?
                .rows_affected()
        }
        Tx::PostgreSql(c) => {
            sqlx::query("update t_agent set sealing_public_key = null, sealing_key_generation = null where id = $1")
                .bind(&id_str)
                .execute(&mut **c)
                .await?
                .rows_affected()
        }
    };
    Ok(rows > 0)
}

/// Pins or unpins the signing public key for an agent.
pub async fn pin_signing_key(tx: &mut Tx, id: Uuid, key: Option<&str>) -> Result<bool, StoreError> {
    let id_str = id.as_hyphenated().to_string();
    let rows = match tx {
        Tx::MySql(c) => sqlx::query("update t_agent set signing_public_key = ? where id = ?")
            .bind(key)
            .bind(&id_str)
            .execute(&mut **c)
            .await?
            .rows_affected(),
        Tx::PostgreSql(c) => sqlx::query("update t_agent set signing_public_key = $1 where id = $2")
            .bind(key)
            .bind(&id_str)
            .execute(&mut **c)
            .await?
            .rows_affected(),
    };
    Ok(rows > 0)
}

/// Resolves an agent by its API key ID.
pub async fn by_api_key(db: &Db, key_id: Uuid) -> Result<Option<AgentRef>, StoreError> {
    let key_str = key_id.as_hyphenated().to_string();
    let row: Option<(String, String)> = match db {
        Db::MySql(pool) => {
            sqlx::query_as("select id, name from t_agent where api_key_id = ?")
                .bind(&key_str)
                .fetch_optional(pool)
                .await?
        }
        Db::PostgreSql(pool) => {
            sqlx::query_as("select id, name from t_agent where api_key_id = $1")
                .bind(&key_str)
                .fetch_optional(pool)
                .await?
        }
    };

    let Some((id_str, name)) = row else {
        return Ok(None);
    };
    let id = Uuid::parse_str(id_str.trim()).map_err(|e| StoreError(Box::new(e)))?;
    Ok(Some(AgentRef { id, name }))
}

/// Checks whether at least one agent is declared in `delegated` credentials mode.
pub async fn has_delegated_mode(tx: &mut Tx) -> Result<bool, StoreError> {
    let count: (i64,) = match tx {
        Tx::MySql(c) => {
            sqlx::query_as("select count(*) from t_agent where credentials_mode = 'delegated'")
                .fetch_one(&mut **c)
                .await?
        }
        Tx::PostgreSql(c) => {
            sqlx::query_as("select count(*) from t_agent where credentials_mode = 'delegated'")
                .fetch_one(&mut **c)
                .await?
        }
    };
    Ok(count.0 > 0)
}
