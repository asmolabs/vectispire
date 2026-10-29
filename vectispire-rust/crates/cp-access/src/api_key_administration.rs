//! Issuing, listing and revoking API keys — `ApiKeyAdministrationService`.
//!
//! The issuing itself — the name, the scopes, the lifetime, the restriction checked against what the issuer sees, the
//! hash — is the credentials task's ([`CredentialService::issue_integration_key`]); this is what the key screen adds
//! around it: the list with its labels and owners, the audit entries, who may revoke a governor's key, and the
//! targets a key may be restricted to.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::Db;
use vectispire_domain::list_window::ListWindow;
use vectispire_domain::secret::Secret;

use crate::account_rules::{Role, refuse_governor_administration};
use crate::accounts::{Audit, AuditOperation, Clock, RequestActor};
use crate::administration::{AdminError, record};
use crate::credentials::{CredentialService, IssueError, IssueRefusal, IssuerSees, KeyRequest};
use crate::persistence::administration as store;
use crate::persistence::credentials::api_keys::{self as key_store, KeyRow};
use crate::visibility::{GrantableTargets, Labels};

/// `KeyView`: a key as it may be shown — never its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyView {
    pub id: Uuid,
    pub name: String,
    pub prefix: Option<String>,
    /// The stored scopes, split as Java's `String.split(",")` splits them: trailing empty pieces dropped.
    pub scopes: Vec<String>,
    pub target_kind: Option<String>,
    pub target_id: Option<i64>,
    /// The restriction's target by name; `<kind> <id> (deleted)` once it is gone.
    pub target_label: Option<String>,
    /// The account the key acts for, by username; `None` for a key issued before keys had one, or whose account the
    /// answer does not name.
    pub owner: Option<String>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    /// Computed here, not on the screen: two notions of "expired" would eventually disagree by a timezone.
    pub expired: bool,
}

/// `Issued`: the key and **the only occurrence of its plaintext**.
#[derive(Debug)]
pub struct Issued {
    pub key: KeyView,
    pub secret: Secret,
}

/// `TargetOption`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetOption {
    pub id: i64,
    pub label: String,
}

/// `TargetOptions`: what a key may be restricted to, so the screen offers names rather than numbers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetOptions {
    pub repositories: Vec<TargetOption>,
    pub containers: Vec<TargetOption>,
}

/// What the key administration is built from.
#[allow(missing_debug_implementations)] // a bag of parts, moved into the service at once
pub struct ApiKeyParts<A, C> {
    pub db: Db,
    pub credentials: CredentialService,
    pub targets: Arc<dyn GrantableTargets>,
    pub issuer_sees: Arc<dyn IssuerSees>,
    pub audit: A,
    pub clock: C,
}

/// `ApiKeyAdministrationService`.
pub struct ApiKeyAdministration<A, C> {
    db: Db,
    credentials: CredentialService,
    targets: Arc<dyn GrantableTargets>,
    issuer_sees: Arc<dyn IssuerSees>,
    audit: A,
    clock: C,
}

impl<A, C> std::fmt::Debug for ApiKeyAdministration<A, C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ApiKeyAdministration").field("db", &self.db).finish_non_exhaustive()
    }
}

impl<A: Audit + Sync, C: Clock + Sync> ApiKeyAdministration<A, C> {
    pub fn new(parts: ApiKeyParts<A, C>) -> ApiKeyAdministration<A, C> {
        let ApiKeyParts { db, credentials, targets, issuer_sees, audit, clock } = parts;
        ApiKeyAdministration { db, credentials, targets, issuer_sees, audit, clock }
    }

    /// `list`: every key, newest first, or the page `window` names — **every key, whoever issued it**, as Java lists
    /// them to the administrators the route admits. Each names its owner and its restriction's target.
    pub async fn list(&self, window: Option<ListWindow>) -> Result<Vec<KeyView>, AdminError> {
        let as_of = self.clock.now();
        let labels = self.targets.labels().await?;
        let owners: BTreeMap<i64, String> = {
            let mut tx = store::read(&self.db).await?;
            let names = store::usernames(&mut tx).await?;
            store::commit(tx).await?;
            names.into_iter().collect()
        };
        let every = key_store::all_newest_first(&self.db).await?;
        let page = match window {
            Some(window) => window.of(&every),
            None => every,
        };
        Ok(page.into_iter().map(|key| view_of(key, as_of, &labels, &owners)).collect())
    }

    /// `issue`: a key acting for `owner`, the account issuing it (decision 0024), **returned once**. The entry is
    /// written under the key's id, with its scopes as stored.
    pub async fn issue(&self, owner: i64, request: &KeyRequest, actor: &RequestActor) -> Result<Issued, AdminError> {
        let issued = self.credentials.issue_integration_key(owner, request, self.issuer_sees.as_ref()).await.map_err(
            |failure| match failure {
                IssueError::Refused(IssueRefusal::InvalidInput(message)) => AdminError::InvalidInput(message),
                IssueError::Refused(IssueRefusal::InvalidKey(message)) => AdminError::InvalidApiKey(message),
                IssueError::Store(error) => error.into(),
            },
        )?;
        let id = issued.key.id;
        record(
            &self.audit,
            actor,
            AuditOperation::ApiKeyCreated,
            id.as_hyphenated().to_string(),
            issued.audit_description.clone(),
        )
        .await;

        // The owner by id, active or not: the one who just issued it.
        let owners: BTreeMap<i64, String> = {
            let mut tx = store::read(&self.db).await?;
            let found = store::account(&mut tx, owner).await?;
            store::commit(tx).await?;
            found.map(|account| (account.id, account.username)).into_iter().collect()
        };
        let labels = self.targets.labels().await?;
        let key = KeyRow {
            id,
            name: issued.key.name.clone(),
            key_hash: String::new(),
            prefix: issued.key.prefix.clone(),
            created_at: issued.key.created_at,
            last_used_at: issued.key.last_used_at,
            scopes: issued.key.scopes.clone(),
            target_kind: issued.key.target_kind.clone(),
            target_id: issued.key.target_id,
            expires_at: issued.key.expires_at,
            owner_user_id: issued.key.owner_user_id,
        };
        Ok(Issued { key: view_of(key, issued.key.created_at, &labels, &owners), secret: issued.secret })
    }

    /// `key`: a key as the list shows it, for a module that binds one to something of its own (a declared SARIF
    /// source) and must check what it is first. Its owner is named only while active.
    pub async fn key(&self, id: Uuid) -> Result<Option<KeyView>, AdminError> {
        let as_of = self.clock.now();
        let Some(key) = key_store::find(&self.db, id).await? else {
            return Ok(None);
        };
        let owners: BTreeMap<i64, String> = match key.owner_user_id {
            None => BTreeMap::new(),
            Some(owner) => {
                let mut tx = store::read(&self.db).await?;
                let found = store::account(&mut tx, owner).await?;
                store::commit(tx).await?;
                found
                    .filter(|account| account.is_active)
                    .map(|account| (account.id, account.username))
                    .into_iter()
                    .collect()
            }
        };
        let labels = self.targets.labels().await?;
        Ok(Some(view_of(key, as_of, &labels, &owners)))
    }

    /// `names`: the names of these keys, for a module listing rows bound to a key to readers who may not open the key
    /// list. A key revoked since is missing from the answer.
    ///
    /// One lookup per distinct key, where Java binds a thousand per statement: the rows bound to a key are a handful,
    /// and a fixed statement stays checked on both engines.
    pub async fn names(&self, ids: &[Uuid]) -> Result<BTreeMap<Uuid, String>, AdminError> {
        let mut names = BTreeMap::new();
        for id in ids.iter().collect::<BTreeSet<_>>() {
            if let Some(key) = key_store::find(&self.db, *id).await? {
                names.insert(key.id, key.name);
            }
        }
        Ok(names)
    }

    /// `revoke`: deletes the row — a "disabled" key something could re-enable by accident would be worse than an
    /// absent one; the audit trail keeps the record. **A governor's key is administered by a governor**, as its
    /// account is: an administrator could not reset a governor's password and could still revoke the key its
    /// pipeline signs in with (the audit of 10 October 2026). The acting role is read, not trusted.
    pub async fn revoke(
        &self,
        id: Uuid,
        acting_account_id: Option<i64>,
        actor: &RequestActor,
    ) -> Result<(), AdminError> {
        let Some(key) = key_store::find(&self.db, id).await? else {
            return Err(AdminError::NotFound("Key not found.".to_owned()));
        };
        if let Some(owner_id) = key.owner_user_id {
            let mut tx = store::read(&self.db).await?;
            let owner = store::account(&mut tx, owner_id).await?.and_then(|account| Role::of(Some(&account.role)));
            let acting = match acting_account_id {
                Some(acting) => {
                    store::account(&mut tx, acting).await?.and_then(|account| Role::of(Some(&account.role)))
                }
                None => None,
            };
            store::commit(tx).await?;
            if let Some(refusal) = refuse_governor_administration(acting, owner, None) {
                return Err(AdminError::InvalidInput(refusal));
            }
        }
        self.credentials.revoke_key(id).await?;
        record(
            &self.audit,
            actor,
            AuditOperation::ApiKeyDeleted,
            id.as_hyphenated().to_string(),
            format!("API key revoked: {}", key.name),
        )
        .await;
        Ok(())
    }

    /// `targets`: every repository and image a key may be restricted to, by name, in the order they were created.
    pub async fn targets(&self) -> Result<TargetOptions, AdminError> {
        let labels = self.targets.labels().await?;
        let options = |labels: Vec<(i64, String)>| {
            labels.into_iter().map(|(id, label)| TargetOption { id, label }).collect::<Vec<_>>()
        };
        Ok(TargetOptions { repositories: options(labels.repositories), containers: options(labels.containers) })
    }
}

/// `viewOf`.
fn view_of(key: KeyRow, as_of: OffsetDateTime, labels: &Labels, owners: &BTreeMap<i64, String>) -> KeyView {
    let target_label = target_label(key.target_kind.as_deref(), key.target_id, labels);
    KeyView {
        id: key.id,
        name: key.name,
        prefix: key.prefix,
        scopes: java_split_commas(&key.scopes),
        target_kind: key.target_kind,
        target_id: key.target_id,
        target_label,
        owner: key.owner_user_id.and_then(|owner| owners.get(&owner).cloned()),
        created_at: key.created_at,
        last_used_at: key.last_used_at,
        // `!expiresAt.isAfter(asOf)`: a key is expired from its expiry's instant on.
        expired: key.expires_at.is_some_and(|expires| expires <= as_of),
        expires_at: key.expires_at,
    }
}

/// `targetLabel`: say a target was deleted rather than show a blank. Any kind but `repository` is looked up among
/// the images, as Java's ternary does.
fn target_label(kind: Option<&str>, id: Option<i64>, labels: &Labels) -> Option<String> {
    let (Some(kind), Some(id)) = (kind, id) else {
        return None;
    };
    let found = if kind == "repository" { labels.repository(id) } else { labels.container(id) };
    Some(found.map_or_else(|| format!("{kind} {id} (deleted)"), str::to_owned))
}

/// `String.split(",")`: every piece, the trailing empty ones dropped — `"read,"` is `[read]`, `","` is `[]`, and an
/// empty string is `[]` (Java's `isEmpty()` guard before the split).
pub fn java_split_commas(stored: &str) -> Vec<String> {
    if stored.is_empty() {
        return Vec::new();
    }
    let mut pieces: Vec<String> = stored.split(',').map(str::to_owned).collect();
    while pieces.last().is_some_and(String::is_empty) {
        pieces.pop();
    }
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_split_as_java_splits_them() {
        assert_eq!(java_split_commas(""), Vec::<String>::new());
        assert_eq!(java_split_commas(","), Vec::<String>::new());
        assert_eq!(java_split_commas("read"), vec!["read"]);
        assert_eq!(java_split_commas("read,scan,export"), vec!["read", "scan", "export"]);
        assert_eq!(java_split_commas("read,,"), vec!["read"]);
        assert_eq!(java_split_commas(",read"), vec!["", "read"]);
        assert_eq!(java_split_commas("read,,scan"), vec!["read", "", "scan"]);
    }

    #[test]
    fn a_deleted_target_is_said_rather_than_blank() {
        let labels = Labels { repositories: vec![(1, "api".to_owned())], containers: vec![(2, "web:1".to_owned())] };
        assert_eq!(target_label(Some("repository"), Some(1), &labels).as_deref(), Some("api"));
        assert_eq!(target_label(Some("container"), Some(2), &labels).as_deref(), Some("web:1"));
        assert_eq!(target_label(Some("repository"), Some(2), &labels).as_deref(), Some("repository 2 (deleted)"));
        assert_eq!(target_label(Some("container"), Some(1), &labels).as_deref(), Some("container 1 (deleted)"));
        // Any kind but `repository` reads the images, as the ternary does.
        assert_eq!(target_label(Some("project"), Some(2), &labels).as_deref(), Some("web:1"));
        assert_eq!(target_label(None, Some(1), &labels), None);
        assert_eq!(target_label(Some("repository"), None, &labels), None);
    }
}
