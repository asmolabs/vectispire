//! The clone credentials: HTTPS tokens (`GitTokenAdministrationService`), SSH deployment keys
//! (`SshKeyAdministrationService`), and the stored forms the dispatcher reads (`CloneCredentials`).
//!
//! **Encrypted at rest under Java's contexts** — `git_token:<id>:token`, `ssh_key:<id>:private_key`, built by
//! `cp-crypto`'s functions and nowhere else: a context spelled twice is a secret that does not read. The context binds
//! the ciphertext to its row, so a value copied elsewhere becomes unreadable rather than decrypting the wrong secret.
//!
//! **A secret is never returned, logged or printed.** What a route answers is the row's description and the state of
//! its ciphertext; the plain text exists between the request and the `encrypt` call and nowhere after.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_audit::{AuditOperation, RequestActor};
use vectispire_cp_crypto::{SecretState, git_token_context, private_key_context};
use vectispire_domain::bounded_text::{self, TEXT_MAX};
use vectispire_domain::{java, repository_url};

use crate::Targets;
use crate::error::TargetError;
use crate::persistence::{self, GitTokenRow, SshKeyRow, StoreError};
use crate::schedule;

const NAME_LENGTH: usize = 255;
/// A token goes into `text` encrypted, a third longer: bounded so the ciphertext always fits MySQL's 64 KB. No forge
/// issues a token within two orders of magnitude of it.
const MAX_TOKEN_LENGTH: usize = 8_192;

#[allow(clippy::expect_used)] // A literal pattern: a typo fails every test, not a request.
static PRIVATE_KEY_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----").expect("the private key header"));

/// An HTTPS token as the screen lists it: never the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenView {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub username: Option<String>,
    pub created_at: OffsetDateTime,
    /// `current`, `previous_key` or `unreadable`: whether a rotation is finished, and which secret was lost.
    pub encryption_state: String,
    pub used_by_repositories: i64,
}

/// An SSH key as the screen lists it: the public half, never the private one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyView {
    pub id: Uuid,
    pub name: String,
    pub public_key: Option<String>,
    pub created_at: OffsetDateTime,
    pub encryption_state: String,
    pub used_by_repositories: i64,
}

/// A repository's HTTPS token as the dispatcher needs it — **still encrypted**: the dispatcher is where a deployment
/// key is decrypted, only there, and only when it is to be delivered. That decision is an authorization, and it stays
/// whole in one place.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredGitToken {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub username: Option<String>,
    pub ciphertext: String,
}

impl std::fmt::Debug for StoredGitToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("StoredGitToken").field("id", &self.id).field("host", &self.host).finish_non_exhaustive()
    }
}

/// An SSH private key as stored, bound to `id`.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredSshKey {
    pub id: Uuid,
    pub name: String,
    pub ciphertext: String,
}

impl std::fmt::Debug for StoredSshKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("StoredSshKey").field("id", &self.id).finish_non_exhaustive()
    }
}

fn state_name(state: SecretState) -> String {
    java::to_lower_root(state.name())
}

impl Targets {
    // ── HTTPS tokens ─────────────────────────────────────────────────────────────────────

    /// Newest first, each with how many repositories use it.
    pub async fn git_tokens(&self) -> Result<Vec<TokenView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let usage: BTreeMap<Uuid, i64> = persistence::usage_by_https_token(&mut tx).await?.into_iter().collect();
        let tokens = persistence::git_tokens(&mut tx).await?;
        tx.commit().await.map_err(StoreError::from)?;
        let mut views = Vec::with_capacity(tokens.len());
        for token in tokens {
            let context = git_token_context(&token.id.as_hyphenated().to_string());
            let state = self.encryption.inspect(&token.token, &context).await.state();
            views.push(TokenView {
                used_by_repositories: usage.get(&token.id).copied().unwrap_or(0),
                id: token.id,
                name: token.name,
                host: token.host,
                username: token.username,
                created_at: token.created_at,
                encryption_state: state_name(state),
            });
        }
        Ok(views)
    }

    /// Stores a token encrypted, bound to its host: it is sent to no other.
    pub async fn add_git_token(
        &self,
        name: Option<&str>,
        host: Option<&str>,
        username: Option<&str>,
        token: Option<&str>,
        actor: &RequestActor,
    ) -> Result<TokenView, TargetError> {
        let name = schedule::trim(name);
        let token = schedule::trim(token);
        let username = schedule::trim(username);
        if name.is_empty() {
            return Err(TargetError::invalid("A name is required."));
        }
        if token.is_empty() {
            return Err(TargetError::invalid("The token is required."));
        }
        bounded_text::within(name, NAME_LENGTH, "The name")?;
        bounded_text::within(username, NAME_LENGTH, "The username")?;
        bounded_text::within(token, MAX_TOKEN_LENGTH, "The token")?;
        if token.chars().any(java::is_whitespace) {
            // A pasted line break or a "Bearer " prefix: the forge would refuse it at the first clone, far from here.
            return Err(TargetError::invalid("The token contains spaces or line breaks: paste the token alone."));
        }
        let host =
            repository_url::normalize_host(host.unwrap_or("")).map_err(|refused| TargetError::Invalid(refused.0))?;
        let id = Uuid::new_v4();
        let ciphertext = self.encryption.encrypt(token, &git_token_context(&id.as_hyphenated().to_string())).await?;
        let row = GitTokenRow {
            id,
            name: name.to_owned(),
            host: host.clone(),
            username: (!username.is_empty()).then(|| username.to_owned()),
            token: ciphertext,
            created_at: self.clock.now(),
        };
        let mut tx = persistence::write(&self.db).await?;
        persistence::insert_git_token(&mut tx, &row).await?;
        tx.commit().await.map_err(StoreError::from)?;
        self.audit
            .record(actor.entry(
                AuditOperation::SettingUpdated,
                &id.as_hyphenated().to_string(),
                &format!("HTTPS token added: {name} ({host})"),
            ))
            .await;
        Ok(TokenView {
            id,
            name: row.name,
            host: row.host,
            username: row.username,
            created_at: row.created_at,
            encryption_state: state_name(SecretState::Current),
            used_by_repositories: 0,
        })
    }

    /// Refused while a repository uses it: the next scan of those would break, far from here.
    pub async fn remove_git_token(&self, id: Uuid, actor: &RequestActor) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let token =
                persistence::git_token(&mut tx, id).await?.ok_or_else(|| TargetError::not_found("Token not found."))?;
            let in_use = persistence::count_by_https_token(&mut tx, id).await?;
            if in_use > 0 {
                return Err(TargetError::invalid(format!(
                    "This token is used by {in_use} repository(ies). Detach it from them first."
                )));
            }
            persistence::delete_git_token(&mut tx, id).await?;
            Ok::<_, TargetError>(token.name)
        }
        .await;
        let name = crate::solutions::finish(tx, outcome).await?;
        self.audit
            .record(actor.entry(
                AuditOperation::SettingUpdated,
                &id.as_hyphenated().to_string(),
                &format!("HTTPS token deleted: {name}"),
            ))
            .await;
        Ok(())
    }

    // ── SSH keys ─────────────────────────────────────────────────────────────────────────

    pub async fn ssh_keys(&self) -> Result<Vec<KeyView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let usage: BTreeMap<Uuid, i64> = persistence::usage_by_ssh_key(&mut tx).await?.into_iter().collect();
        let keys = persistence::ssh_keys(&mut tx).await?;
        tx.commit().await.map_err(StoreError::from)?;
        let mut views = Vec::with_capacity(keys.len());
        for key in keys {
            let context = private_key_context(&key.id.as_hyphenated().to_string());
            let state = self.encryption.inspect(&key.private_key, &context).await.state();
            views.push(KeyView {
                used_by_repositories: usage.get(&key.id).copied().unwrap_or(0),
                id: key.id,
                name: key.name,
                public_key: key.public_key,
                created_at: key.created_at,
                encryption_state: state_name(state),
            });
        }
        Ok(views)
    }

    /// Stores a deployment key, its private half encrypted. Refused on entry when it is not a private key: otherwise
    /// the error only shows at the first clone, in an agent's log, and looks like a network problem.
    pub async fn add_ssh_key(
        &self,
        name: Option<&str>,
        private_key: Option<&str>,
        public_key: Option<&str>,
        actor: &RequestActor,
    ) -> Result<KeyView, TargetError> {
        let name = schedule::trim(name);
        let private_key = schedule::trim(private_key);
        let public_key = schedule::trim(public_key);
        if name.is_empty() {
            return Err(TargetError::invalid("A name is required."));
        }
        if private_key.is_empty() {
            return Err(TargetError::invalid("The private key is required."));
        }
        bounded_text::within(name, NAME_LENGTH, "The name")?;
        bounded_text::within(private_key, TEXT_MAX, "The private key")?;
        bounded_text::within(public_key, TEXT_MAX, "The public key")?;
        if !PRIVATE_KEY_HEADER.is_match(private_key) {
            return Err(TargetError::invalid(
                "This does not look like a private key: expected a \"-----BEGIN … PRIVATE KEY-----\" block.",
            ));
        }
        let id = Uuid::new_v4();
        let ciphertext =
            self.encryption.encrypt(private_key, &private_key_context(&id.as_hyphenated().to_string())).await?;
        let row = SshKeyRow {
            id,
            name: name.to_owned(),
            private_key: ciphertext,
            public_key: (!public_key.is_empty()).then(|| public_key.to_owned()),
            created_at: self.clock.now(),
        };
        let mut tx = persistence::write(&self.db).await?;
        persistence::insert_ssh_key(&mut tx, &row).await?;
        tx.commit().await.map_err(StoreError::from)?;
        self.audit
            .record(actor.entry(
                AuditOperation::SettingUpdated,
                &id.as_hyphenated().to_string(),
                &format!("SSH key added: {name}"),
            ))
            .await;
        Ok(KeyView {
            id,
            name: row.name,
            public_key: row.public_key,
            created_at: row.created_at,
            encryption_state: state_name(SecretState::Current),
            used_by_repositories: 0,
        })
    }

    /// Refused while a repository uses it, saying how many to detach first.
    pub async fn remove_ssh_key(&self, id: Uuid, actor: &RequestActor) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let key =
                persistence::ssh_key(&mut tx, id).await?.ok_or_else(|| TargetError::not_found("Key not found."))?;
            let in_use = persistence::count_by_ssh_key(&mut tx, id).await?;
            if in_use > 0 {
                return Err(TargetError::invalid(format!(
                    "This key is used by {in_use} repository(ies). Detach it from them first."
                )));
            }
            persistence::delete_ssh_key(&mut tx, id).await?;
            Ok::<_, TargetError>(key.name)
        }
        .await;
        let name = crate::solutions::finish(tx, outcome).await?;
        self.audit
            .record(actor.entry(
                AuditOperation::SettingUpdated,
                &id.as_hyphenated().to_string(),
                &format!("SSH key deleted: {name}"),
            ))
            .await;
        Ok(())
    }

    // ── what the dispatcher reads ────────────────────────────────────────────────────────

    /// `CloneCredentials.gitToken`: `None` when the token was deleted since the repository named it.
    pub async fn stored_git_token(&self, id: Uuid) -> Result<Option<StoredGitToken>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let found = persistence::git_token(&mut tx, id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(found.map(|row| StoredGitToken {
            id: row.id,
            name: row.name,
            host: row.host,
            username: row.username,
            ciphertext: row.token,
        }))
    }

    /// `CloneCredentials.sshKey`.
    pub async fn stored_ssh_key(&self, id: Uuid) -> Result<Option<StoredSshKey>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let found = persistence::ssh_key(&mut tx, id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(found.map(|row| StoredSshKey { id: row.id, name: row.name, ciphertext: row.private_key }))
    }
}

/// `PRIVATE_KEY_HEADER.matcher(key).find()`, for the reference set.
pub fn looks_like_a_private_key(key: &str) -> bool {
    PRIVATE_KEY_HEADER.is_match(key)
}
