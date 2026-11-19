//! The credentials an executor's pulls use, and the one way they leave this crate — `PullCredentials` and
//! `MountedPullCredentials`.
//!
//! **Vectispire stores no registry credential.** An image is pulled with what the executor's own Docker
//! configuration holds (`DOCKER_CONFIG`, else `~/.docker/config.json`); nothing of it reaches the control plane.
//! **The pull's rule, docker-java's**: which entry applies to an image — the registry's host, Docker Hub's legacy
//! key, a key written with a scheme or a path — is decided as docker-java 3.7 decides it for the Java agent, and
//! held to `reference/plugins/credentials/`. A second rule would verify anonymously what the daemon then pulls
//! authenticated, or the other way round.
//!
//! **Read once, when the runner is built**, as docker-java reads it: a configuration that cannot be read stops the
//! start rather than sending a tool to the registry anonymously. Credential helpers (`credsStore`, `credHelpers`)
//! are not run, as docker-java does not run them: the entry they leave is empty, and the pull goes anonymous.
//!
//! Not ported: docker-java's `registry.username`/`registry.password`/`registry.url` properties, which override
//! every entry; the Java agent sets none of them.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Docker Hub's key in a configuration, and the registry every image without a host is pulled from.
pub const DEFAULT_SERVER_ADDRESS: &str = "https://index.docker.io/v1/";

/// One entry of a configuration, decoded — docker-java's `AuthConfig`.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    pub identity_token: Option<String>,
    pub registry_token: Option<String>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the credentials, whoever logs this.
        formatter.write_str("AuthConfig[redacted]")
    }
}

impl AuthConfig {
    /// `PullCredentials.usable`: an entry a client can answer a challenge with. A helper's empty entry is not.
    pub fn usable(&self) -> bool {
        (self.username.is_some() && self.password.is_some())
            || self.identity_token.is_some()
            || self.registry_token.is_some()
    }

    /// The `X-Registry-Auth` document a pull sends — docker-java's `AuthConfig` as its mapper writes it.
    pub fn registry_auth(&self, server_address: &str) -> String {
        serde_json::json!({
            "username": self.username,
            "password": self.password,
            "identitytoken": self.identity_token,
            "registrytoken": self.registry_token,
            "serveraddress": server_address,
        })
        .to_string()
    }

    /// `PullCredentials.configuration`: a Docker configuration holding this entry alone, keyed `registry`.
    pub fn configuration(&self, registry: &str) -> String {
        let mut entry = serde_json::Map::new();
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            entry.insert("auth".into(), Value::String(STANDARD.encode(format!("{username}:{password}"))));
        }
        if let Some(token) = &self.identity_token {
            entry.insert("identitytoken".into(), Value::String(token.clone()));
        }
        if let Some(token) = &self.registry_token {
            entry.insert("registrytoken".into(), Value::String(token.clone()));
        }
        let mut auths = serde_json::Map::new();
        auths.insert(registry.to_owned(), Value::Object(entry));
        serde_json::json!({ "auths": auths }).to_string()
    }

    /// `PullCredentials.redact`: `text` with every secret of this entry replaced — the base64 form the file holds,
    /// the password, the tokens. A tool's words reach the scan's failures and the screen.
    pub fn redact(&self, text: &str) -> String {
        let mut redacted = text.to_owned();
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            redacted = replace(&redacted, Some(&STANDARD.encode(format!("{username}:{password}"))));
        }
        redacted = replace(&redacted, self.password.as_deref());
        redacted = replace(&redacted, self.identity_token.as_deref());
        replace(&redacted, self.registry_token.as_deref())
    }
}

fn replace(text: &str, secret: Option<&str>) -> String {
    match secret {
        Some(secret) if !secret.is_empty() => text.replace(secret, "[redacted]"),
        _ => text.to_owned(),
    }
}

/// A Docker configuration, its entries decoded — docker-java's `DockerConfigFile`.
#[derive(Clone, Default)]
pub struct DockerConfig {
    /// Keyed as the file keys them.
    auths: BTreeMap<String, AuthConfig>,
}

impl std::fmt::Debug for DockerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DockerConfig").field("registries", &self.auths.keys().collect::<Vec<_>>()).finish()
    }
}

/// Why a configuration could not be read — its path, never its content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("The registry credentials in {path} could not be read: {reason}")]
pub struct UnreadableConfig {
    pub path: String,
    pub reason: String,
}

impl DockerConfig {
    /// The directory's `config.json`: empty when there is none, refused when it is there and cannot be read.
    pub fn load(directory: &Path) -> Result<DockerConfig, UnreadableConfig> {
        let file = directory.join("config.json");
        let unreadable =
            |reason: &str| UnreadableConfig { path: directory.display().to_string(), reason: reason.into() };
        if !file.is_file() {
            return Ok(DockerConfig::default());
        }
        let text = std::fs::read(&file).map_err(|error| unreadable(&error.to_string()))?;
        DockerConfig::parse(&text).map_err(unreadable)
    }

    /// The configuration's bytes, read as docker-java reads them: unknown fields ignored, each `auth` decoded into a
    /// user and a password — and the whole file refused when one cannot be.
    pub fn parse(text: &[u8]) -> Result<DockerConfig, &'static str> {
        let root: Value = serde_json::from_slice(text).map_err(|_| "Failed to parse docker config.json")?;
        let Value::Object(root) = root else { return Err("Failed to parse docker config.json") };
        let mut auths = BTreeMap::new();
        match root.get("auths") {
            None | Some(Value::Null) => {}
            Some(Value::Object(entries)) => {
                for (key, entry) in entries {
                    auths.insert(key.clone(), entry_of(entry)?);
                }
            }
            Some(_) => return Err("Failed to parse docker config.json"),
        }
        Ok(DockerConfig { auths })
    }

    /// `effectiveAuthConfig(reference)` then `usable`: the entry the pull of `reference` sends, or `None` when it goes
    /// anonymous.
    pub fn credentials_for(&self, reference: &str) -> Option<&AuthConfig> {
        let host = resolved_host(reference).ok()?;
        self.resolve(&host).filter(|auth| auth.usable())
    }

    /// `DockerConfigFile.resolveAuthConfig`: Hub by its one key; another host by its exact key, else by the first
    /// key that names the same host once a scheme and a path are dropped.
    fn resolve(&self, host: &str) -> Option<&AuthConfig> {
        if host.is_empty() || host == DEFAULT_SERVER_ADDRESS {
            return self.auths.get(DEFAULT_SERVER_ADDRESS);
        }
        if let Some(exact) = self.auths.get(host) {
            return Some(exact);
        }
        let normalized = to_hostname(host);
        self.auths.iter().find(|(key, _)| to_hostname(key) == normalized).map(|(_, auth)| auth)
    }
}

fn entry_of(entry: &Value) -> Result<AuthConfig, &'static str> {
    let Value::Object(fields) = entry else { return Err("Failed to parse docker config.json") };
    let text = |name: &str| -> Result<Option<String>, &'static str> {
        match fields.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            Some(Value::Number(number)) => Ok(Some(number.to_string())),
            Some(Value::Bool(flag)) => Ok(Some(flag.to_string())),
            Some(_) => Err("Failed to parse docker config.json"),
        }
    };
    let mut auth = AuthConfig {
        username: text("username")?,
        password: text("password")?,
        identity_token: text("identitytoken")?,
        registry_token: text("registrytoken")?,
    };
    if let Some(encoded) = text("auth")? {
        let decoded = STANDARD.decode(encoded.as_bytes()).map_err(|_| "Invalid auth configuration file")?;
        let decoded = String::from_utf8_lossy(&decoded).into_owned();
        let (username, password) = decoded.split_once(':').ok_or("Invalid auth configuration file")?;
        auth.username = Some(username.to_owned());
        auth.password = Some(password.to_owned());
    }
    Ok(auth)
}

/// `convertToHostname`: a scheme and a path dropped.
fn to_hostname(server: &str) -> &str {
    let stripped = server.strip_prefix("http://").or_else(|| server.strip_prefix("https://")).unwrap_or(server);
    stripped.split('/').next().unwrap_or(stripped)
}

/// `NameParser.parseRepositoryTag(reference).repos`: a digest reference keeps everything; a tag after the last
/// colon is dropped when it names no path.
fn repository_of(reference: &str) -> &str {
    let Some((before, tag)) = reference.rsplit_once(':') else { return reference };
    if reference.to_ascii_lowercase().contains("@sha256:") || tag.contains('/') { reference } else { before }
}

/// `NameParser.resolveRepositoryName(repos).hostname`, `Err` where docker-java throws.
fn resolved_host(reference: &str) -> Result<String, ()> {
    let repository = repository_of(reference);
    if repository.contains("://") {
        return Err(());
    }
    let (first, rest) = match repository.split_once('/') {
        Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => (first, rest),
        _ => return Ok(DEFAULT_SERVER_ADDRESS.to_owned()),
    };
    if first.contains("index.docker.io") {
        return Err(());
    }
    let mut name = rest;
    // `substringBeforeLast`, which matches case-sensitively whatever `containsIgnoreCase` let through.
    if let Some((before, _)) = name.rsplit_once("@sha256:") {
        name = before;
    }
    if let Some((before, _)) = name.rsplit_once(':') {
        name = before;
    }
    validate_repository_name(name)?;
    Ok(first.to_owned())
}

/// `NameParser.validateRepoName`: not empty, at most 255 characters, each component `[a-z0-9]+([._-][a-z0-9]+)*`.
fn validate_repository_name(name: &str) -> Result<(), ()> {
    if name.is_empty() || name.chars().count() > 255 {
        return Err(());
    }
    let component = |part: &str| {
        let alphanumeric = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        let bytes = part.as_bytes();
        !bytes.is_empty()
            && bytes.first().copied().is_some_and(alphanumeric)
            && bytes.last().copied().is_some_and(alphanumeric)
            && bytes.windows(2).all(|pair| match pair {
                [a, b] => alphanumeric(*a) || alphanumeric(*b),
                _ => true,
            })
            && bytes.iter().all(|b| alphanumeric(*b) || b"._-".contains(b))
    };
    if name.split('/').all(component) { Ok(()) } else { Err(()) }
}

/// `PullCredentials.registryOf`: the registry of `reference` as the pull keys it — its host, or Docker Hub's
/// address — and, for a name docker-java refuses, what precedes its first slash.
pub fn registry_of(reference: &str) -> String {
    resolved_host(reference)
        .unwrap_or_else(|()| reference.split_once('/').map_or(reference, |(first, _)| first).to_owned())
}

/// What the executor holds to read a registry — never the credentials — `ContainerRunner.RegistryAccess`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryAccess {
    pub registry: String,
    pub credentials_held: bool,
}

/// `PullCredentials.write`: a Docker configuration holding `auth` for `registry` alone, in a directory of its own
/// under `parent`, created 0700 with its file 0600 — there is no instant at which anyone else may read it.
pub fn write(auth: &AuthConfig, registry: &str, parent: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(parent)?;
    let mut builder = tempfile::Builder::new();
    builder.prefix("registry-login");
    #[cfg(unix)]
    builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let directory = builder.tempdir_in(parent)?;
    let file = directory.path().join("config.json");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(&file)?, auth.configuration(registry).as_bytes())?;
    Ok(directory.keep())
}

/// `PullCredentials.erase`: removes what [`write`] wrote. Never fails: it runs once the run is over, whatever
/// happened, and the workspace it sits in is deleted with the scan.
pub fn erase(directory: Option<&Path>) {
    if let Some(directory) = directory {
        let _ = std::fs::remove_dir_all(directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_is_keyed_by_its_legacy_address_and_a_host_by_itself() {
        let d = "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(registry_of(&format!("lint{d}")), DEFAULT_SERVER_ADDRESS);
        assert_eq!(registry_of(&format!("acme/lint{d}")), DEFAULT_SERVER_ADDRESS);
        assert_eq!(registry_of(&format!("r.io/acme/lint{d}")), "r.io");
        assert_eq!(registry_of(&format!("localhost:5000/lint{d}")), "localhost:5000");
        assert_eq!(registry_of(&format!("index.docker.io/acme/lint{d}")), "index.docker.io");
    }

    #[test]
    fn the_file_written_holds_one_entry_owner_only_and_is_erased() {
        let parent = tempfile::tempdir().unwrap();
        let auth = AuthConfig {
            username: Some("u".into()),
            password: Some("p".into()),
            identity_token: None,
            registry_token: None,
        };
        let directory = write(&auth, "r.io", parent.path()).unwrap();
        let written = std::fs::read_to_string(directory.join("config.json")).unwrap();
        assert_eq!(written, r#"{"auths":{"r.io":{"auth":"dTpw"}}}"#);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(std::fs::metadata(directory.join("config.json")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        erase(Some(&directory));
        assert!(!directory.exists());
    }
}
