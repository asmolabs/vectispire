//! `ForgeConnectionService`: a read-only credential to a GitHub or a GitLab, probed against the forge before it is
//! kept, stored encrypted with its row as context, never read back out (decision 0037 §2).
//!
//! **Probed on creation and on every change of what the token is presented to** — a new token, a new pinned CA, a new
//! network statement — before any write and outside any transaction: an outbound call of up to thirty seconds holds
//! no row lock. **Two refusals are recorded and signalled** (`FORGE_CONNECTION_REFUSED`, `VECTI-SEC-036`): an address
//! the guard blocks and a token broader than read-only. **Suspended, never deleted, when its forge is switched off**
//! (decision 0040 §2): a rename and a deletion still go through. **The address cannot be changed**: another server is
//! another connection.

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_audit::{AuditLog, AuditOperation, Record, RequestActor, Signal};
use vectispire_cp_crypto::{CensusFuture, Counter, Encryption, SealedStore, SecretState, forge_connection_context};
use vectispire_cp_db::Db;
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::Clock;
use vectispire_domain::bounded_text;
use vectispire_domain::forges::{ForgeAddress, ForgeConnectionState, ForgeEdition, ForgeKind};
use vectispire_domain::java;
use vectispire_domain::list_window::ListWindow;
use vectispire_domain::pinned_ca::PinnedCa;
use vectispire_domain::siem::SecurityEventType;

use crate::error::{ForgeError, connection_not_found};
use crate::internal::integrations::ForgeIntegrations;
use crate::internal::probes::{ForgeProbes, Probe, ProbeError};
use crate::internal::targets::{self, CA, ForgeTarget, Trust};
use crate::persistence::{self, ConnectionRow};
use crate::token_watch;
use crate::views::{ForgeConnectionView, ForgeDiscoveryView, instant, iso, stored};

pub(crate) const NAME_LENGTH: usize = 255;

/// No forge issues a token within an order of magnitude of this; encrypted, it fits the column.
pub(crate) const MAX_TOKEN_LENGTH: usize = 1_024;

/// What a connection's creation asks for.
#[derive(Debug, Clone, Default)]
pub struct Creation {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub base_url: Option<String>,
    pub owner: Option<String>,
    pub internal_network: Option<bool>,
    pub ca_pem: Option<String>,
    pub token: Option<String>,
}

/// What a change asks for; a `None` component keeps what is stored, a blank `ca_pem` unpins the CA.
#[derive(Debug, Clone, Default)]
pub struct Change {
    pub name: Option<String>,
    pub internal_network: Option<bool>,
    pub ca_pem: Option<String>,
}

/// The service.
pub struct ForgeConnectionService {
    db: Db,
    probes: ForgeProbes,
    integrations: ForgeIntegrations,
    encryption: Arc<Encryption>,
    settings: Settings,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ForgeConnectionService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ForgeConnectionService").finish_non_exhaustive()
    }
}

impl ForgeConnectionService {
    pub(crate) fn new(
        db: Db,
        probes: ForgeProbes,
        integrations: ForgeIntegrations,
        encryption: Arc<Encryption>,
        settings: Settings,
        audit: Arc<AuditLog>,
        clock: Arc<dyn Clock>,
    ) -> ForgeConnectionService {
        ForgeConnectionService { db, probes, integrations, encryption, settings, audit, clock }
    }

    /// The connections by name, all of them or one page.
    pub async fn list(&self, limit: Option<i64>, offset: Option<i64>) -> Result<Vec<ForgeConnectionView>, ForgeError> {
        let window = ListWindow::requested(limit, offset).map_err(ForgeError::InvalidInput)?;
        let mut tx = persistence::read(&self.db).await?;
        let every = persistence::connections(&mut tx).await?;
        tx.commit().await.map_err(persistence::StoreError::from)?;
        let suspended = self.integrations.disabled().await?;
        let shown = match window {
            Some(page) => page.of(&every),
            None => every,
        };
        let mut views = Vec::with_capacity(shown.len());
        for row in &shown {
            views.push(self.view_of(row, &suspended).await?);
        }
        Ok(views)
    }

    pub async fn get(&self, id: &str) -> Result<ForgeConnectionView, ForgeError> {
        let row = self.require(id).await?;
        self.view(&row).await
    }

    /// Probes the token against the forge, then keeps the connection.
    pub async fn create(
        &self,
        request: Option<Creation>,
        actor: &RequestActor,
    ) -> Result<ForgeConnectionView, ForgeError> {
        let Some(request) = request else {
            return Err(ForgeError::InvalidInput("Describe the connection: a name, a forge and a token.".to_owned()));
        };
        let name = bounded_text::required(request.name.as_deref(), NAME_LENGTH, "The name")?;
        let kind = ForgeKind::parse(request.kind.as_deref())?;
        // Before the form's other words: no field of it can make a disabled forge acceptable.
        self.integrations.require_enabled(kind).await?;
        let address = ForgeAddress::of(kind, request.base_url.as_deref())?;
        let owner = owner_of(kind, request.owner.as_deref())?;
        let internal = request.internal_network == Some(true);
        let ca = self.ca_of(request.ca_pem.as_deref())?;
        refuse_for_cloud(address.edition, internal, ca.is_some())?;
        let token = token_of(request.token.as_deref())?;
        if self.name_taken(&name, None).await? {
            return Err(name_exists(&name));
        }

        let target = ForgeTarget {
            address: address.clone(),
            owner: owner.clone(),
            policy: targets::policy_of(internal),
            trust: ca,
        };
        let probe = self.probe(&target, &token, None, &format!("Forge connection {name} refused"), actor).await?;

        let now = self.clock.now();
        let id = uuid::Uuid::new_v4().as_hyphenated().to_string();
        let mut row = ConnectionRow {
            id: id.clone(),
            name: name.clone(),
            kind: kind.wire_name().to_owned(),
            edition: address.edition.wire_name().to_owned(),
            base_url: address.base_url.clone(),
            owner,
            internal_network: internal,
            ca_pem: target.trust.as_ref().map(|trust| trust.ca.pem().to_owned()),
            token: self.encryption.encrypt(&token, &forge_connection_context(&id)).await?,
            credential_kind: String::new(),
            scopes: None,
            can_write: None,
            token_expires_at: None,
            forge_version: None,
            probed_at: now,
            created_at: now,
            created_by: actor_name(actor),
            updated_at: now,
            updated_by: actor_name(actor),
        };
        apply(&mut row, &probe, now);
        let mut tx = persistence::write(&self.db).await?;
        if let Err(refused) = persistence::insert_connection(&mut tx, &row).await {
            // Two administrators creating the same name at once: the second learns it here.
            return Err(if refused.is_unique_violation() { name_exists(&name) } else { refused.into() });
        }
        tx.commit().await.map_err(persistence::StoreError::from)?;
        self.record(actor, &id, &format!("Forge connection created: {}", describe(&row)), true).await;
        self.view(&row).await
    }

    /// Replaces the token in place, re-probed: the row and whatever hangs on it are kept.
    pub async fn replace_token(
        &self,
        id: &str,
        raw_token: Option<&str>,
        actor: &RequestActor,
    ) -> Result<ForgeConnectionView, ForgeError> {
        let mut row = self.require(id).await?;
        let token = token_of(raw_token)?;
        let target = targets::of(&row, row.internal_network, self.stored_ca(&row)?)?;
        let probe = self
            .probe(&target, &token, Some(id), &format!("Forge connection {}: new token refused", row.name), actor)
            .await?;

        let now = self.clock.now();
        row.token = self.encryption.encrypt(&token, &forge_connection_context(id)).await?;
        apply(&mut row, &probe, now);
        touch(&mut row, actor, now);
        let mut tx = persistence::write(&self.db).await?;
        persistence::update_connection(&mut tx, &row).await?;
        tx.commit().await.map_err(persistence::StoreError::from)?;
        self.record(actor, id, &format!("Forge connection token replaced: {}", describe(&row)), true).await;
        self.view(&row).await
    }

    /// Renames a connection, or changes what its token is presented through — probed again with the stored token
    /// first. **Saving re-seals the token** under the current `ENCRYPTION_KEY` when it was still under a previous one.
    pub async fn update(
        &self,
        id: &str,
        change: Option<Change>,
        actor: &RequestActor,
    ) -> Result<ForgeConnectionView, ForgeError> {
        let mut row = self.require(id).await?;
        let Some(change) = change else {
            return Err(ForgeError::InvalidInput(
                "Say what changes: the name, the network statement or the CA.".to_owned(),
            ));
        };
        let edition = edition_of(&row)?;
        let name = match change.name.as_deref() {
            None => row.name.clone(),
            Some(name) => bounded_text::required(Some(name), NAME_LENGTH, "The name")?,
        };
        let internal = change.internal_network.unwrap_or(row.internal_network);
        let ca = match change.ca_pem.as_deref() {
            None => self.stored_ca(&row)?,
            Some(pem) => self.ca_of(Some(pem))?,
        };
        refuse_for_cloud(edition, internal, ca.is_some())?;
        if java::compare_ignore_case(&name, &row.name) != std::cmp::Ordering::Equal
            && self.name_taken(&name, Some(id)).await?
        {
            return Err(name_exists(&name));
        }
        let pem = ca.as_ref().map(|trust| trust.ca.pem().to_owned());
        let trust_changed = internal != row.internal_network || row.ca_pem != pem;

        let context = forge_connection_context(id);
        let sealed = self.encryption.inspect(&row.token, &context).await;
        let now = self.clock.now();
        let subject = ca.as_ref().map(|trust| trust.ca.subject().to_owned());
        if trust_changed {
            if sealed.state() == SecretState::Unreadable {
                return Err(ForgeError::InvalidInput(
                    "The token can no longer be decrypted by any configured key: replace it first, then change how it \
                     is presented."
                        .to_owned(),
                ));
            }
            let target = targets::of(&row, internal, ca)?;
            let probe = self
                .probe(
                    &target,
                    sealed.plain_text(),
                    Some(id),
                    &format!("Forge connection {}: change refused", row.name),
                    actor,
                )
                .await?;
            apply(&mut row, &probe, now);
        }
        if sealed.state() == SecretState::PreviousKey {
            row.token = self.encryption.encrypt(sealed.plain_text(), &context).await?;
        }
        let previous_name = std::mem::replace(&mut row.name, name.clone());
        row.internal_network = internal;
        row.ca_pem = pem;
        touch(&mut row, actor, now);
        let mut tx = persistence::write(&self.db).await?;
        if let Err(refused) = persistence::update_connection(&mut tx, &row).await {
            return Err(if refused.is_unique_violation() { name_exists(&name) } else { refused.into() });
        }
        tx.commit().await.map_err(persistence::StoreError::from)?;
        let mut what = String::new();
        if previous_name != name {
            what.push_str(&format!("renamed from {previous_name}; "));
        }
        if trust_changed {
            what.push_str(&format!(
                "presented {}{}; ",
                if internal { "on the internal network" } else { "on the public network" },
                subject
                    .map_or_else(|| ", runtime trust store".to_owned(), |subject| format!(", CA \"{subject}\" pinned"))
            ));
        }
        if sealed.state() == SecretState::PreviousKey {
            what.push_str("token re-sealed under the current key; ");
        }
        self.record(actor, id, &format!("Forge connection updated: {what}{}", describe(&row)), trust_changed).await;
        self.view(&row).await
    }

    /// Deletes a connection with its discoveries, its snapshot, its provenance links and its readings, in one
    /// transaction — the discoveries first, so that a running page's commit is waited for. No target goes with it.
    pub async fn delete(&self, id: &str, actor: &RequestActor) -> Result<(), ForgeError> {
        let row = self.require(id).await?;
        let mut tx = persistence::write(&self.db).await?;
        persistence::delete_discoveries_of(&mut tx, id).await?;
        persistence::delete_snapshot_of(&mut tx, id).await?;
        persistence::delete_links_of(&mut tx, id).await?;
        persistence::delete_readings_of(&mut tx, id).await?;
        // What was said of its token: a row outside the catalog, which nothing else would ever remove.
        self.settings.remove_internal(&mut tx, &token_watch::announced_key(id)).await?;
        persistence::delete_connection(&mut tx, id).await?;
        tx.commit().await.map_err(persistence::StoreError::from)?;
        self.record(actor, id, &format!("Forge connection deleted: {}", describe(&row)), true).await;
        Ok(())
    }

    async fn probe(
        &self,
        target: &ForgeTarget,
        token: &str,
        id: Option<&str>,
        refusal: &str,
        actor: &RequestActor,
    ) -> Result<Probe, ForgeError> {
        match self.probes.probe(target, token).await {
            Ok(probe) => Ok(probe),
            Err(ProbeError::Disabled(disabled)) => Err(disabled.into()),
            Err(ProbeError::Refused(refused)) => {
                if refused.reason.signalled() {
                    let mut entry = actor.entry(
                        AuditOperation::ForgeConnectionRefused,
                        id.unwrap_or(""),
                        &format!(
                            "{refusal} ({}, {}): {}",
                            refused.reason.lower_name(),
                            target.where_(),
                            refused.message
                        ),
                    );
                    if id.is_none() {
                        entry.resource_id = None;
                    }
                    self.audit.record(entry).await;
                }
                Err(refused.into())
            }
        }
    }

    async fn record(&self, actor: &RequestActor, id: &str, description: &str, signalled: bool) {
        let entry: Record = actor.entry(AuditOperation::ForgeConnectionChanged, id, description);
        self.audit
            .record(if signalled {
                entry.signalling(Signal(SecurityEventType::ForgeConnectionChanged.wire_name()))
            } else {
                entry
            })
            .await;
    }

    async fn view(&self, row: &ConnectionRow) -> Result<ForgeConnectionView, ForgeError> {
        let suspended = self.integrations.disabled().await?;
        self.view_of(row, &suspended).await
    }

    async fn view_of(
        &self,
        row: &ConnectionRow,
        suspended: &BTreeSet<ForgeKind>,
    ) -> Result<ForgeConnectionView, ForgeError> {
        let kind = ForgeKind::parse(Some(&row.kind))?;
        let ca = row
            .ca_pem
            .as_deref()
            .map(|pem| PinnedCa::read(Some(pem), &CA))
            .transpose()
            .map_err(|unreadable| ForgeError::Unexpected(unreadable.0))?;
        let state = self.encryption.inspect(&row.token, &forge_connection_context(&row.id)).await.state();
        let mut tx = persistence::read(&self.db).await?;
        let last = persistence::discoveries_of(&mut tx, &row.id, 1, 0).await?;
        let imported = persistence::count_links(&mut tx, &row.id).await?;
        tx.commit().await.map_err(persistence::StoreError::from)?;
        Ok(ForgeConnectionView {
            id: row.id.clone(),
            name: row.name.clone(),
            kind: row.kind.clone(),
            edition: row.edition.clone(),
            base_url: row.base_url.clone(),
            owner: row.owner.clone(),
            internal_network: row.internal_network,
            ca_subject: ca.as_ref().map(|ca| ca.subject().to_owned()),
            ca_not_after: ca.as_ref().and_then(|ca| ca.not_after().to_java_string()),
            credential_kind: row.credential_kind.clone(),
            scopes: row.scopes.as_deref().map(java_split_comma),
            can_write: row.can_write,
            token_expires_at: row.token_expires_at.map(iso),
            forge_version: row.forge_version.clone(),
            probed_at: iso(row.probed_at),
            encryption_state: java::to_lower_root(state.name()),
            state: ForgeConnectionState::of(!suspended.contains(&kind)).wire_name(),
            integration: kind.integration_key(),
            created_at: iso(row.created_at),
            created_by: row.created_by.clone(),
            updated_at: iso(row.updated_at),
            updated_by: row.updated_by.clone(),
            last_discovery: last.first().map(ForgeDiscoveryView::of).transpose()?,
            imported_targets: imported,
        })
    }

    async fn require(&self, id: &str) -> Result<ConnectionRow, ForgeError> {
        let mut tx = persistence::read(&self.db).await?;
        let row = persistence::connection(&mut tx, id).await?;
        tx.commit().await.map_err(persistence::StoreError::from)?;
        row.ok_or_else(connection_not_found)
    }

    async fn name_taken(&self, name: &str, except: Option<&str>) -> Result<bool, ForgeError> {
        let mut tx = persistence::read(&self.db).await?;
        let taken = persistence::name_taken(&mut tx, name, except).await?;
        tx.commit().await.map_err(persistence::StoreError::from)?;
        Ok(taken)
    }

    fn stored_ca(&self, row: &ConnectionRow) -> Result<Option<Trust>, ForgeError> {
        Ok(targets::stored_ca(row, instant(self.clock.now()))?)
    }

    fn ca_of(&self, pem: Option<&str>) -> Result<Option<Trust>, ForgeError> {
        match pem.filter(|pem| !java::is_blank(pem)) {
            None => Ok(None),
            Some(pem) => Ok(Some(Trust::of(PinnedCa::parse_pasted(Some(pem), instant(self.clock.now()), &CA)?)?)),
        }
    }

    /// `census`: how each connection's token is sealed.
    async fn token_census(&self) -> Result<Vec<vectispire_cp_crypto::StoreCensus>, ForgeError> {
        let mut counter = Counter::new(
            "Forge connection tokens",
            "save the connection (PATCH /api/v1/forge-connections/{id} with {}) or replace its token",
        );
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::connections(&mut tx).await?;
        tx.commit().await.map_err(persistence::StoreError::from)?;
        for row in rows {
            counter =
                counter.count(self.encryption.seal_of(Some(&row.token), &forge_connection_context(&row.id)).await);
        }
        Ok(vec![counter.done()])
    }
}

impl SealedStore for ForgeConnectionService {
    fn census(&self) -> CensusFuture<'_> {
        Box::pin(async move { self.token_census().await.map_err(|failure| failure.to_string()) })
    }
}

/// `Arrays.asList(scopes.split(","))`: trailing empty strings dropped, as `String.split` does.
fn java_split_comma(text: &str) -> Vec<String> {
    let mut parts: Vec<String> = text.split(',').map(str::to_owned).collect();
    while parts.len() > 1 && parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    parts
}

fn apply(row: &mut ConnectionRow, probe: &Probe, now: time::OffsetDateTime) {
    row.credential_kind = probe.credential.kind.wire_name().to_owned();
    row.scopes = probe.credential.scopes.as_ref().map(|scopes| scopes.join(","));
    row.can_write = probe.credential.can_write;
    row.token_expires_at = probe.expires_at.and_then(stored);
    row.forge_version =
        probe.version.as_deref().and_then(|version| bounded_text::clip(Some(version), 64)).map(str::to_owned);
    row.probed_at = now;
}

fn touch(row: &mut ConnectionRow, actor: &RequestActor, now: time::OffsetDateTime) {
    row.updated_at = now;
    row.updated_by = actor_name(actor);
}

/// What an audit entry and a SIEM event say about a connection — never the token.
pub(crate) fn describe(row: &ConnectionRow) -> String {
    let label =
        ForgeEdition::of_stored(&row.edition).map_or_else(|| row.edition.clone(), |edition| edition.label().to_owned());
    format!(
        "{} ({label} at {}{}{}{}; {} token{}{})",
        row.name,
        row.base_url,
        row.owner.as_deref().map(|owner| format!(", owner {owner}")).unwrap_or_default(),
        if row.internal_network { ", internal network" } else { "" },
        if row.ca_pem.is_some() { ", CA pinned" } else { "" },
        row.credential_kind.replace('_', " "),
        row.scopes
            .as_deref()
            .map_or_else(|| ", permissions not reported".to_owned(), |scopes| format!(", scopes {scopes}")),
        if row.can_write == Some(true) { ", CAN WRITE" } else { "" },
    )
}

pub(crate) fn edition_of(row: &ConnectionRow) -> Result<ForgeEdition, ForgeError> {
    ForgeEdition::of_stored(&row.edition)
        .ok_or_else(|| ForgeError::Unexpected(format!("No enum constant ForgeEdition.{}", row.edition)))
}

fn name_exists(name: &str) -> ForgeError {
    ForgeError::InvalidInput(format!("A forge connection named \"{name}\" already exists."))
}

fn refuse_for_cloud(edition: ForgeEdition, internal: bool, pinned: bool) -> Result<(), ForgeError> {
    if !edition.cloud() {
        return Ok(());
    }
    if internal {
        return Err(ForgeError::InvalidInput(format!(
            "{} is not on your internal network: the statement is for a server you host.",
            edition.label()
        )));
    }
    if pinned {
        return Err(ForgeError::InvalidInput(format!(
            "{} is verified against the public CAs: a pinned CA is for a server you host.",
            edition.label()
        )));
    }
    Ok(())
}

/// GitHub's own rule for a login is narrower; Enterprise Server's directory-synchronised logins may carry
/// underscores and dots: `^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98})$`.
fn github_owner(owner: &str) -> bool {
    let bytes = owner.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 99
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..].iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn owner_of(kind: ForgeKind, raw: Option<&str>) -> Result<Option<String>, ForgeError> {
    let owner = java::trim(raw.unwrap_or(""));
    match kind {
        ForgeKind::Github => {
            if owner.is_empty() {
                return Err(ForgeError::InvalidInput(
                    "A GitHub connection names the organisation or user its token was issued for.".to_owned(),
                ));
            }
            if !github_owner(owner) {
                return Err(ForgeError::InvalidInput(format!(
                    "\"{}\" is not a GitHub organisation or user name.",
                    bounded_text::clip(Some(owner), 100).unwrap_or_default()
                )));
            }
            Ok(Some(owner.to_owned()))
        }
        ForgeKind::Gitlab => {
            if !owner.is_empty() {
                return Err(ForgeError::InvalidInput(
                    "A GitLab connection names no owner: the groups its token can read are discovered.".to_owned(),
                ));
            }
            Ok(None)
        }
    }
}

fn token_of(raw: Option<&str>) -> Result<String, ForgeError> {
    let token = java::trim(raw.unwrap_or(""));
    if token.is_empty() {
        return Err(ForgeError::InvalidInput("The token is required.".to_owned()));
    }
    bounded_text::within(token, MAX_TOKEN_LENGTH, "The token")?;
    if token.chars().any(java::is_whitespace) {
        // A pasted line break or a "Bearer " prefix: the forge would refuse it as a bad token.
        return Err(ForgeError::InvalidInput(
            "The token contains spaces or line breaks: paste the token alone.".to_owned(),
        ));
    }
    Ok(token.to_owned())
}

pub(crate) fn actor_name(actor: &RequestActor) -> String {
    actor
        .username
        .as_deref()
        .map_or_else(|| "unknown".to_owned(), |name| bounded_text::clip(Some(name), 255).unwrap_or_default().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owners_and_tokens_are_refused_in_words() {
        assert_eq!(owner_of(ForgeKind::Gitlab, Some(" ")).unwrap(), None);
        assert!(owner_of(ForgeKind::Gitlab, Some("acme")).is_err());
        assert_eq!(owner_of(ForgeKind::Github, Some(" acme.corp_1 ")).unwrap().as_deref(), Some("acme.corp_1"));
        assert!(owner_of(ForgeKind::Github, Some("-acme")).is_err());
        assert!(owner_of(ForgeKind::Github, Some(&"a".repeat(100))).is_err());
        assert!(owner_of(ForgeKind::Github, Some(&"a".repeat(99))).is_ok());
        assert!(token_of(Some("Bearer x")).is_err());
        assert!(token_of(Some(&"x".repeat(1025))).is_err());
        assert_eq!(token_of(Some(" glpat-x ")).unwrap(), "glpat-x");
    }

    #[test]
    fn scopes_split_as_java_splits() {
        assert_eq!(java_split_comma("read_api,read_user"), vec!["read_api", "read_user"]);
        assert_eq!(java_split_comma(""), vec![""]);
    }
}
