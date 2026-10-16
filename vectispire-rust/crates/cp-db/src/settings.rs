//! What it takes to reach the database: the JDBC URL operators already write, the account, the pool.
//!
//! **The URL is the one `VECTISPIRE_DB_URL` holds today**, `jdbc:mysql://…` or `jdbc:postgresql://…`,
//! so an installation switching control planes changes no setting. Reading the variables is
//! `cp-runtime`'s; this module turns their values into connect options and refuses what it cannot honour.

use std::path::PathBuf;
use std::time::Duration;

use vectispire_domain::secret::Secret;

use crate::engine::Engine;

/// The connection settings of one control plane.
#[derive(Debug, Clone)]
pub struct DbSettings {
    pub url: DatabaseUrl,
    pub username: String,
    pub password: Secret,
    pub pool: PoolSettings,
    /// A PEM file of the certificate authority the server's certificate is checked against, for the
    /// modes that verify it. The Java side reads a PKCS12 truststore named in the URL instead
    /// (`trustCertificateKeyStoreUrl`), which this one refuses rather than ignores.
    pub ca_pem: Option<PathBuf>,
}

/// The pool, with HikariCP's defaults — the ones the Java control plane runs with, since nothing in
/// its configuration overrides them.
///
/// | Hikari | here |
/// |---|---|
/// | `maximumPoolSize` 10 | `max_connections` |
/// | `minimumIdle` = maximum | `min_connections` |
/// | `connectionTimeout` 30 s | `acquire_timeout` |
/// | `idleTimeout` 10 min (inert while minimum = maximum) | `idle_timeout` |
/// | `maxLifetime` 30 min | `max_lifetime` |
///
/// **The size matters beyond throughput.** A write that must outlive its caller's transaction — the
/// audit entry (`REQUIRES_NEW`) — takes a second connection while the first is held, so a pool of one
/// deadlocks on the first audited action. [`PoolSettings::validate`] refuses fewer than two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSettings {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl Default for PoolSettings {
    fn default() -> PoolSettings {
        PoolSettings {
            max_connections: 10,
            min_connections: 10,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
        }
    }
}

impl PoolSettings {
    pub fn validate(&self) -> Result<(), SettingsError> {
        if self.max_connections < 2 {
            return Err(SettingsError::Pool(format!(
                "the pool must hold at least 2 connections, {} is set: an audited action writes its entry \
                 on a second connection while the first is held",
                self.max_connections
            )));
        }
        if self.min_connections > self.max_connections {
            return Err(SettingsError::Pool(format!(
                "the pool's minimum ({}) is above its maximum ({})",
                self.min_connections, self.max_connections
            )));
        }
        Ok(())
    }
}

/// How the connection is encrypted, in the vocabulary both JDBC drivers share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls {
    /// No TLS.
    Disabled,
    /// TLS when the server offers it — the default of both Java drivers (`sslMode=PREFERRED`,
    /// `sslmode=prefer`).
    Preferred,
    /// TLS required, the certificate not checked.
    Required,
    /// TLS, the certificate checked against the authority.
    VerifyCa,
    /// TLS, the certificate checked and its name matched to the host.
    VerifyIdentity,
}

/// A parsed `jdbc:` URL: the engine, the server, the database, the TLS mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseUrl {
    pub engine: Engine,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub tls: Tls,
    /// The PostgreSQL driver's `sslrootcert`, a PEM file: kept, since it is already the form this side reads.
    pub root_cert: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SettingsError {
    #[error("the database URL {0}")]
    Url(String),
    #[error("the database pool: {0}")]
    Pool(String),
}

impl DatabaseUrl {
    /// Reads `jdbc:mysql://host[:port]/database[?…]` or `jdbc:postgresql://…`.
    ///
    /// **An unknown parameter is refused, not ignored.** The Java drivers accept dozens; one this side
    /// silently dropped could be the one that turned verification on, and the connection would succeed
    /// with less security than the operator wrote.
    pub fn parse(jdbc: &str) -> Result<DatabaseUrl, SettingsError> {
        let rest = jdbc.strip_prefix("jdbc:").ok_or_else(|| {
            SettingsError::Url("must start with jdbc: — jdbc:mysql://… or jdbc:postgresql://…".into())
        })?;
        let (engine, default_port, rest) = if let Some(rest) = rest.strip_prefix("mysql://") {
            (Engine::MySql, 3306, rest)
        } else if let Some(rest) = rest.strip_prefix("postgresql://") {
            (Engine::PostgreSql, 5432, rest)
        } else {
            return Err(SettingsError::Url("names neither mysql nor postgresql".into()));
        };
        let (authority_and_path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (authority, database) =
            authority_and_path.split_once('/').ok_or_else(|| SettingsError::Url("names no database".into()))?;
        if database.is_empty() || database.contains('/') {
            return Err(SettingsError::Url("names no single database".into()));
        }
        if authority.contains('@') {
            return Err(SettingsError::Url(
                "carries credentials: the account is VECTISPIRE_DB_USER and VECTISPIRE_DB_PASSWORD".into(),
            ));
        }
        if authority.contains(',') {
            return Err(SettingsError::Url(
                "names several hosts, which this control plane does not fail over between".into(),
            ));
        }
        let (host, port) = split_host_port(authority, default_port)?;

        let mut tls = Tls::Preferred;
        let mut root_cert = None;
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            match (engine, name) {
                (Engine::MySql, "sslMode") => tls = mysql_ssl_mode(value)?,
                (Engine::PostgreSql, "sslmode") => tls = postgres_ssl_mode(value)?,
                (Engine::PostgreSql, "sslrootcert") => root_cert = Some(PathBuf::from(value)),
                (
                    Engine::MySql,
                    "trustCertificateKeyStoreUrl" | "trustCertificateKeyStoreType" | "trustCertificateKeyStorePassword",
                ) => {
                    return Err(SettingsError::Url(format!(
                        "names a Java truststore ({name}): give the authority as a PEM file in the database CA setting instead"
                    )));
                }
                _ => {
                    return Err(SettingsError::Url(format!(
                        "carries the parameter {name}, which this control plane does not read"
                    )));
                }
            }
        }
        Ok(DatabaseUrl { engine, host, port, database: database.to_owned(), tls, root_cert })
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16), SettingsError> {
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, after) =
            bracketed.split_once(']').ok_or_else(|| SettingsError::Url("has an unclosed IPv6 address".into()))?;
        (host, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(SettingsError::Url("names no host".into()));
    }
    let port = match port {
        None => default_port,
        Some(port) => port.parse().map_err(|_| SettingsError::Url(format!("has a port that is not one: {port}")))?,
    };
    Ok((host.to_owned(), port))
}

fn mysql_ssl_mode(value: &str) -> Result<Tls, SettingsError> {
    Ok(match value.to_ascii_uppercase().as_str() {
        "DISABLED" => Tls::Disabled,
        "PREFERRED" => Tls::Preferred,
        "REQUIRED" => Tls::Required,
        "VERIFY_CA" => Tls::VerifyCa,
        "VERIFY_IDENTITY" => Tls::VerifyIdentity,
        _ => return Err(SettingsError::Url(format!("has an sslMode this control plane does not know: {value}"))),
    })
}

fn postgres_ssl_mode(value: &str) -> Result<Tls, SettingsError> {
    Ok(match value {
        "disable" => Tls::Disabled,
        // `allow` tries without TLS first; nothing here is weaker than what was asked if it is read as
        // `prefer`, which tries with TLS first.
        "allow" | "prefer" => Tls::Preferred,
        "require" => Tls::Required,
        "verify-ca" => Tls::VerifyCa,
        "verify-full" => Tls::VerifyIdentity,
        _ => return Err(SettingsError::Url(format!("has an sslmode this control plane does not know: {value}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_compositions_urls_are_read() {
        let url = DatabaseUrl::parse("jdbc:mysql://db:3306/vectispire").unwrap();
        assert_eq!(url.engine, Engine::MySql);
        assert_eq!((url.host.as_str(), url.port, url.database.as_str()), ("db", 3306, "vectispire"));
        assert_eq!(url.tls, Tls::Preferred);

        let url = DatabaseUrl::parse(
            "jdbc:postgresql://pg.example.org/vectispire?sslmode=verify-full&sslrootcert=/etc/ca.pem",
        )
        .unwrap();
        assert_eq!((url.engine, url.port, url.tls), (Engine::PostgreSql, 5432, Tls::VerifyIdentity));
        assert_eq!(url.root_cert, Some(PathBuf::from("/etc/ca.pem")));

        let url = DatabaseUrl::parse("jdbc:mysql://[::1]:3307/v?sslMode=VERIFY_IDENTITY").unwrap();
        assert_eq!((url.host.as_str(), url.port, url.tls), ("::1", 3307, Tls::VerifyIdentity));
    }

    #[test]
    fn what_cannot_be_honoured_is_refused() {
        for (url, says) in [
            ("mysql://db/v", "must start with jdbc:"),
            ("jdbc:sqlite:/tmp/x", "names neither"),
            ("jdbc:mysql://db", "names no database"),
            ("jdbc:mysql://u:p@db/v", "carries credentials"),
            ("jdbc:mysql://a,b/v", "several hosts"),
            ("jdbc:mysql://db/v?useSSL=false", "parameter useSSL"),
            ("jdbc:mysql://db/v?sslMode=SOMETIMES", "sslMode this control plane does not know"),
            ("jdbc:postgresql://db/v?sslmode=verify", "sslmode this control plane does not know"),
            ("jdbc:mysql://db/v?trustCertificateKeyStoreUrl=file:/t.p12", "Java truststore"),
            ("jdbc:mysql://db:http/v", "port that is not one"),
        ] {
            let refusal = DatabaseUrl::parse(url).unwrap_err().to_string();
            assert!(refusal.contains(says), "{url}: {refusal}");
        }
    }

    #[test]
    fn a_pool_too_small_for_a_separate_audit_write_is_refused() {
        assert!(PoolSettings::default().validate().is_ok());
        let one = PoolSettings { max_connections: 1, min_connections: 1, ..PoolSettings::default() };
        assert!(one.validate().unwrap_err().to_string().contains("at least 2"));
        let inverted = PoolSettings { min_connections: 11, ..PoolSettings::default() };
        assert!(inverted.validate().is_err());
    }
}
