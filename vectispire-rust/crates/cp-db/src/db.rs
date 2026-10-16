//! The pool, one per control plane, on whichever engine the URL names.

use sqlx::Executor;
use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions, MySqlSslMode};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgSslMode};

use crate::engine::Engine;
use crate::settings::{DbSettings, PoolSettings, SettingsError, Tls};

/// The database: a pool on MySQL or on PostgreSQL.
///
/// **An enum, not `sqlx::Any`.** `Any` erases the engine, and with it the compile-time check of every
/// query against the schema (`sqlx::query!`) — the check that stands in for Hibernate validating the
/// 319 `@Query` methods at start. A persistence module writes each query once per engine, in the
/// engine's own placeholder syntax, and matches on this.
#[derive(Debug, Clone)]
pub enum Db {
    MySql(MySqlPool),
    PostgreSql(PgPool),
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error("the {engine} database at {host}:{port} could not be reached: {source}")]
    Unreachable {
        engine: Engine,
        host: String,
        port: u16,
        #[source]
        source: sqlx::Error,
    },
}

impl Db {
    /// Opens the pool and proves one connection works, so a wrong password fails the start rather
    /// than the first request — as Hikari's `initializationFailTimeout` does by default.
    pub async fn connect(settings: &DbSettings) -> Result<Db, ConnectError> {
        settings.pool.validate()?;
        let url = &settings.url;
        let unreachable =
            |source| ConnectError::Unreachable { engine: url.engine, host: url.host.clone(), port: url.port, source };
        match url.engine {
            Engine::MySql => {
                let pool =
                    mysql_pool(&settings.pool).connect_with(mysql_options(settings)).await.map_err(unreachable)?;
                Ok(Db::MySql(pool))
            }
            Engine::PostgreSql => {
                let pool = postgres_pool(&settings.pool)
                    .connect_with(postgres_options(settings)?)
                    .await
                    .map_err(unreachable)?;
                Ok(Db::PostgreSql(pool))
            }
        }
    }

    pub fn engine(&self) -> Engine {
        match self {
            Db::MySql(_) => Engine::MySql,
            Db::PostgreSql(_) => Engine::PostgreSql,
        }
    }

    pub async fn close(&self) {
        match self {
            Db::MySql(pool) => pool.close().await,
            Db::PostgreSql(pool) => pool.close().await,
        }
    }
}

fn mysql_pool(settings: &PoolSettings) -> MySqlPoolOptions {
    MySqlPoolOptions::new()
        .max_connections(settings.max_connections)
        .min_connections(settings.min_connections)
        .acquire_timeout(settings.acquire_timeout)
        .idle_timeout(settings.idle_timeout)
        .max_lifetime(settings.max_lifetime)
        // **The server's `sql_mode`, put back.** sqlx announces `CLIENT_IGNORE_SPACE` in its handshake,
        // and the server answers by adding `IGNORE_SPACE` to the session's mode — under which every
        // built-in function's name becomes a reserved word, so a column named like one reads
        // differently than under Connector/J, which announces no such thing. Found by the session test.
        .after_connect(|connection, _| {
            Box::pin(async move {
                connection.execute("set session sql_mode = @@global.sql_mode").await?;
                Ok(())
            })
        })
}

fn postgres_pool(settings: &PoolSettings) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .min_connections(settings.min_connections)
        .acquire_timeout(settings.acquire_timeout)
        .idle_timeout(settings.idle_timeout)
        .max_lifetime(settings.max_lifetime)
}

/// The session the Java driver opens, as near as two drivers allow.
///
/// - **`sql_mode` is the server's, untouched.** sqlx appends `PIPES_AS_CONCAT` and
///   `NO_ENGINE_SUBSTITUTION` by default; the first changes what `||` means in every statement, and
///   Connector/J adds neither, so both are off — the same SQL then means the same thing under both
///   control planes.
/// - **`time_zone` is `+00:00`.** Every timestamp column is `datetime(6)` holding UTC, and
///   `CURRENT_TIMESTAMP` defaults are evaluated in the session's zone; the shipped server also runs at
///   `--default-time-zone=+00:00`, so this only states it.
/// - **`SET NAMES utf8mb4` without a collation**, so the server's default collation for it applies —
///   what Connector/J negotiates. sqlx would otherwise pick `utf8mb4_unicode_ci`, and `lower(x) like`
///   and `=` on text compare under the collation of the connection.
/// - The isolation level is the engine's default (REPEATABLE READ here): nothing on the Java side sets one.
fn mysql_options(settings: &DbSettings) -> MySqlConnectOptions {
    let url = &settings.url;
    let mut options = MySqlConnectOptions::new()
        .host(&url.host)
        .port(url.port)
        .database(&url.database)
        .username(&settings.username)
        .password(settings.password.expose())
        .pipes_as_concat(false)
        .no_engine_substitution(false)
        .timezone(Some("+00:00".to_owned()))
        .charset("utf8mb4")
        .ssl_mode(match url.tls {
            Tls::Disabled => MySqlSslMode::Disabled,
            Tls::Preferred => MySqlSslMode::Preferred,
            Tls::Required => MySqlSslMode::Required,
            Tls::VerifyCa => MySqlSslMode::VerifyCa,
            Tls::VerifyIdentity => MySqlSslMode::VerifyIdentity,
        });
    if let Some(ca) = &settings.ca_pem {
        options = options.ssl_ca(ca);
    }
    options
}

/// The session pgjdbc opens: UTF-8, ISO dates and `TimeZone=UTC` — sqlx sends all three at startup —
/// the server's `search_path` and READ COMMITTED, the engine's default.
fn postgres_options(settings: &DbSettings) -> Result<PgConnectOptions, SettingsError> {
    let url = &settings.url;
    let mut options = PgConnectOptions::new()
        .host(&url.host)
        .port(url.port)
        .database(&url.database)
        .username(&settings.username)
        .password(settings.password.expose())
        .application_name("vectispire")
        .ssl_mode(match url.tls {
            Tls::Disabled => PgSslMode::Disable,
            Tls::Preferred => PgSslMode::Prefer,
            Tls::Required => PgSslMode::Require,
            Tls::VerifyCa => PgSslMode::VerifyCa,
            Tls::VerifyIdentity => PgSslMode::VerifyFull,
        });
    match (&url.root_cert, &settings.ca_pem) {
        (Some(_), Some(_)) => {
            return Err(SettingsError::Url(
                "names an sslrootcert while the database CA setting names another: keep one".into(),
            ));
        }
        (Some(ca), None) | (None, Some(ca)) => options = options.ssl_root_cert(ca),
        (None, None) => {}
    }
    Ok(options)
}
