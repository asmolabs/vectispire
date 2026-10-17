//! `RepositoryAdministrationService`: the repositories under watch — listing them within an allowance, and changing
//! the inventory.
//!
//! **One transaction per write, committed before its entry.** Java opened none of its own — each `save` carried the
//! repository's — and audited straight after it; here the lookup and the write share one, and the entry is recorded
//! once it has committed, which is what Java's order gave: an entry never describes a write that may still roll back.

use std::collections::BTreeSet;

use uuid::Uuid;
use vectispire_cp_audit::{AuditOperation, Record, RequestActor};
use vectispire_cp_db::{ScanTarget, Tx, Visibility};
use vectispire_domain::asset_tier::AssetTier;
use vectispire_domain::list_window::ListWindow;
use vectispire_domain::repository_identity::RepositoryIdentity;
use vectispire_domain::{bounded_text, repository_url, sub_path};

use crate::error::TargetError;
use crate::persistence::{self, RepositoryRow, StoreError};
use crate::ports::{LatestScan, QueueError, Queued};
use crate::schedule::{self, COLUMN_LENGTH, ScheduleChoice};
use crate::views::RepositoryView;
use crate::{Targets, deletion, naming, schedules_in_force};

/// The problem type's last word for a target filed twice — published in the routes' descriptions.
pub const ALREADY_REGISTERED: &str = "target-already-registered";

/// A repository as the inventory shows it: the row, its latest scan, what waits on it, its project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub repository: RepositoryView,
    pub latest_scan: Option<LatestScan>,
    pub open_issues: i64,
    /// `Solution / Project`, or `None` for a repository in no project.
    pub project_name: Option<String>,
    /// The languages its newest completed scan found, as wire names; `None` when unknown — never the empty set.
    pub detected_languages: Option<BTreeSet<String>>,
    pub schedule: vectispire_domain::schedules::InForce,
}

/// What an operator asked for, field by field — strings, because on update `None` is "leave alone" and the empty
/// string is "clear", which a typed field could not say both of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    pub url: Option<String>,
    pub branch: Option<String>,
    pub name: Option<String>,
    pub sub_path: Option<String>,
    pub scan_interval_minutes: Option<i32>,
    pub scan_cron: Option<String>,
    pub required_agent_label: Option<String>,
    pub ssh_key_id: Option<String>,
    pub tier: Option<String>,
    pub https_token_id: Option<String>,
    pub scan_manual_only: Option<bool>,
}

/// One target filed more than once, and each of its filings, oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Duplicated {
    pub identity: RepositoryIdentity,
    pub targets: Vec<Listed>,
}

/// A scan queued on request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triggered {
    pub repository: RepositoryView,
    pub scan: Queued,
}

impl Targets {
    /// Every repository the allowance permits, with each one's latest scan and open issue count — or one page of
    /// them, **cut from what the caller sees**: an offset counting the estate's rows would start a restricted reader's
    /// second page among targets they may not see. By identifier in both forms.
    pub async fn list_repositories(
        &self,
        allowed: &Visibility,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<Listed>, TargetError> {
        let window = ListWindow::requested(limit, offset).map_err(TargetError::Invalid)?;
        self.repositories_listed(allowed, window).await
    }

    async fn repositories_listed(
        &self,
        allowed: &Visibility,
        window: Option<ListWindow>,
    ) -> Result<Vec<Listed>, TargetError> {
        let latest = self.scans.latest_per_repository().await.map_err(TargetError::Unexpected)?;
        let open = self.backlog.open_per_repository().await.map_err(TargetError::Unexpected)?;
        // Narrowed in the statement: a hidden repository's row is never read.
        let permitted = persistence::visible_repositories(&self.db, allowed).await?;
        let visible = match window {
            Some(page) => page.of(&permitted),
            None => permitted,
        };
        // Named for the visible rows only: a project's name is shown only beside a repository the reader already sees,
        // so the list reveals no project the tree would not.
        let projects: BTreeSet<i64> = visible.iter().filter_map(|row| row.project_id).collect();
        let mut tx = persistence::read(&self.db).await?;
        let project_names = naming::project_names(&mut tx, &projects).await?;
        tx.commit().await.map_err(StoreError::from)?;
        // Asked for the visible rows only: which languages a hidden repository is written in is as much its own as
        // its findings.
        let ids: Vec<i64> = visible.iter().map(|row| row.id).collect();
        let mut languages = self.scans.detected_languages(&ids).await.map_err(TargetError::Unexpected)?;
        let default_minutes = self.default_interval_minutes().await?;
        Ok(visible
            .iter()
            .map(|row| {
                let view = RepositoryView::from(row);
                let schedule = schedules_in_force(
                    view.scan_manual_only,
                    view.scan_cron.as_deref(),
                    view.scan_interval_minutes,
                    default_minutes,
                );
                Listed {
                    latest_scan: latest.get(&row.id).cloned(),
                    open_issues: open.get(&row.id).copied().unwrap_or(0),
                    project_name: row.project_id.and_then(|project| project_names.get(&project).cloned()),
                    detected_languages: languages.remove(&row.id),
                    schedule,
                    repository: view,
                }
            })
            .collect())
    }

    /// One row of the list, read the same way — so that what a create or an update answers is exactly the row the
    /// inventory will show, and the allowance decides it the same way.
    pub async fn listed_repository(&self, allowed: &Visibility, id: i64) -> Result<Option<Listed>, TargetError> {
        Ok(self.repositories_listed(allowed, None).await?.into_iter().find(|listed| listed.repository.id == id))
    }

    /// Files a new repository target. `allowed` decides only how a duplicate is refused.
    pub async fn create_repository(
        &self,
        changes: &Changes,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<RepositoryView, TargetError> {
        let mut row = self.built(changes).await?;
        let mut tx = persistence::write(&self.db).await?;
        let filed = self.file_in(&mut tx, &mut row, allowed).await;
        let committed = match filed {
            Ok(()) => tx.commit().await.map_err(StoreError::from),
            Err(Filing::Refused(refusal)) => {
                let _ = tx.rollback().await;
                return Err(refusal);
            }
            Err(Filing::Failed(failure)) => {
                let _ = tx.rollback().await;
                Err(failure)
            }
        };
        if let Err(failure) = committed {
            return Err(self.after_failed_write(&row, None, allowed, failure).await);
        }
        self.audit.record(added(actor, &row, "")).await;
        Ok(RepositoryView::from(&row))
    }

    /// `refusal`: why a creation would refuse these changes, without writing — decision 0037's import preview. A
    /// target already registered is not asked here; the caller has its own words for it.
    pub async fn repository_refusal(&self, changes: &Changes) -> Result<Option<String>, TargetError> {
        match self.built(changes).await {
            Ok(_) => Ok(None),
            Err(TargetError::Invalid(message)) => Ok(Some(message)),
            Err(other) => Err(other),
        }
    }

    /// A new target's row, validated as the form validates it, not yet written.
    pub(crate) async fn built(&self, changes: &Changes) -> Result<RepositoryRow, TargetError> {
        let url = bounded_text::within(schedule::trim(changes.url.as_deref()), COLUMN_LENGTH, "The repository URL")?;
        // Validated here and not only at scan time: an unvalidated URL reaching a git clone is arbitrary code
        // execution, not a typo.
        if let Some(message) = repository_url::validate(url) {
            return Err(TargetError::Invalid(message));
        }
        refuse_credential_in_url(url)?;
        self.refuse_unlisted_host(url)?;
        let choice = ScheduleChoice::NONE.apply(
            changes.scan_manual_only,
            changes.scan_interval_minutes,
            changes.scan_cron.as_deref(),
        )?;
        let mut row = RepositoryRow {
            url: url.to_owned(),
            branch: branch(changes.branch.as_deref())?,
            name: bounded_text::optional(changes.name.as_deref(), COLUMN_LENGTH, "The repository name")?,
            // Checked like the URL, and for the same reason: it is resolved against a clone on the scanning host.
            sub_path: schedule::optional(Some(&normalized_sub_path(changes.sub_path.as_deref())?)),
            required_agent_label: schedule::required_label(changes.required_agent_label.as_deref())?,
            tier: AssetTier::from_input(changes.tier.as_deref()).map_err(TargetError::Invalid)?.name().to_owned(),
            ..RepositoryRow::default()
        };
        apply_schedule(&mut row, choice);
        let mut tx = persistence::read(&self.db).await?;
        row.ssh_key_id = ssh_key_id(&mut tx, changes.ssh_key_id.as_deref()).await?;
        row.https_token_id = credential_id(changes.https_token_id.as_deref(), "HTTPS token")?;
        require_matching_credential(&mut tx, &row).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(row)
    }

    /// Writes a new target in the caller's transaction, refusing the twin of one already registered. Checked before
    /// the write although the unique index would refuse the row anyway: the ordinary duplicate — the SSH URL of a
    /// repository filed over HTTPS — is then refused without a failed statement. The index is for the race this check
    /// cannot see, which [`Targets::after_failed_write`] reads once the caller has rolled back.
    pub(crate) async fn file_in(
        &self,
        tx: &mut Tx,
        row: &mut RepositoryRow,
        allowed: &Visibility,
    ) -> Result<(), Filing> {
        let identity = identity_of(row);
        if let Some(target) = &identity {
            refuse_if_registered(tx, target, None, allowed).await.map_err(Filing::from)?;
        }
        stamp(row, identity.as_ref(), true);
        row.id = persistence::insert_repository(tx, row).await.map_err(Filing::Failed)?;
        Ok(())
    }

    /// A write that failed, read as the race it may have been: **a failed write does not say why it failed** — a lock
    /// timeout or a dropped connection fails it the same way — so the refusal is not read from the error. Once it
    /// has rolled back, the committed row answers: present, the caller is answered the 409 the check would have given
    /// a moment later; absent, the failure was something else and is answered as it came.
    pub(crate) async fn after_failed_write(
        &self,
        row: &RepositoryRow,
        this: Option<i64>,
        allowed: &Visibility,
        failure: StoreError,
    ) -> TargetError {
        let Some(target) = identity_of(row).filter(|target| Some(target.guard()) == row.identity_guard) else {
            return TargetError::from(failure);
        };
        let refusal = async {
            let mut tx = persistence::read(&self.db).await?;
            let refused = refuse_if_registered(&mut tx, &target, this, allowed).await;
            tx.commit().await.map_err(StoreError::from)?;
            Ok::<_, TargetError>(refused)
        };
        match refusal.await {
            Ok(Err(conflict)) => conflict,
            _ => TargetError::from(failure),
        }
    }

    /// Applies what was sent and leaves the rest. **Absent means unchanged, not cleared.** The entry names the
    /// previous URL as well, redacted, because changing the URL keeps the issues.
    pub async fn update_repository(
        &self,
        id: i64,
        changes: &Changes,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<RepositoryView, TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let result = self.updated(&mut tx, id, changes, allowed).await;
        let (row, previous_url) = match result {
            Ok(done) => done,
            Err(refusal) => {
                let _ = tx.rollback().await;
                return Err(refusal);
            }
        };
        let written = persistence::update_repository(&mut tx, &row).await;
        let committed = match written {
            Ok(_) => tx.commit().await.map_err(StoreError::from),
            Err(failure) => {
                let _ = tx.rollback().await;
                Err(failure)
            }
        };
        if let Err(failure) = committed {
            return Err(self.after_failed_write(&row, Some(id), allowed, failure).await);
        }
        let moved = if row.url == previous_url {
            String::new()
        } else {
            format!(" (was {})", repository_url::redact(&previous_url))
        };
        self.audit
            .record(actor.entry(
                AuditOperation::SettingUpdated,
                &id.to_string(),
                &format!("Repository updated: {}{moved}", repository_url::redact(&row.url)),
            ))
            .await;
        Ok(RepositoryView::from(&row))
    }

    async fn updated(
        &self,
        tx: &mut Tx,
        id: i64,
        changes: &Changes,
        allowed: &Visibility,
    ) -> Result<(RepositoryRow, String), TargetError> {
        // Absent and hidden refused in one sentence: the absent row used to say "No repository with id 7." and the
        // hidden one "Target not found.", which told them apart.
        let found = persistence::repository(tx, id).await?;
        let mut row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Repository(id), allowed)?;
        let previous_url = row.url.clone();
        let previous_identity = identity_of(&row);
        // The list sends the URL masked; a form saved without touching it sends the mask back, which must leave the
        // stored URL — credential included — as it was.
        if let Some(url) = changes.url.as_deref()
            && !repository_url::is_masked_form_of(schedule::trim(Some(url)), &previous_url)
        {
            let url = bounded_text::within(schedule::trim(Some(url)), COLUMN_LENGTH, "The repository URL")?;
            // Validated on update exactly as on create: a row edited later is no safer than a row added.
            if let Some(message) = repository_url::validate(url) {
                return Err(TargetError::Invalid(message));
            }
            refuse_credential_in_url(url)?;
            self.refuse_unlisted_host(url)?;
            row.url = url.to_owned();
        }
        if let Some(value) = changes.branch.as_deref() {
            row.branch = branch(Some(value))?;
        }
        if let Some(value) = changes.name.as_deref() {
            row.name = bounded_text::optional(Some(value), COLUMN_LENGTH, "The repository name")?;
        }
        if let Some(value) = changes.sub_path.as_deref() {
            row.sub_path = schedule::optional(Some(&normalized_sub_path(Some(value))?));
        }
        let choice = ScheduleChoice {
            manual_only: row.scan_manual_only,
            interval_minutes: row.scan_interval_minutes,
            cron: row.scan_cron.clone(),
        }
        .apply(changes.scan_manual_only, changes.scan_interval_minutes, changes.scan_cron.as_deref())?;
        apply_schedule(&mut row, choice);
        if changes.required_agent_label.is_some() {
            row.required_agent_label = schedule::required_label(changes.required_agent_label.as_deref())?;
        }
        if changes.ssh_key_id.is_some() {
            row.ssh_key_id = ssh_key_id(tx, changes.ssh_key_id.as_deref()).await?;
        }
        if changes.https_token_id.is_some() {
            row.https_token_id = credential_id(changes.https_token_id.as_deref(), "HTTPS token")?;
        }
        // Checked whenever what the credential is paired with changes — not on an unrelated edit of a row that
        // predates the rule: renaming it must not fail over a pairing nobody touched.
        if row.url != previous_url || changes.ssh_key_id.is_some() || changes.https_token_id.is_some() {
            require_matching_credential(tx, &row).await?;
        }
        if changes.tier.is_some() {
            row.tier = AssetTier::from_input(changes.tier.as_deref()).map_err(TargetError::Invalid)?.name().to_owned();
        }
        // Refused only when the edit makes this row another target's twin: a row filed twice before the rule keeps its
        // name, schedule and credential editable.
        let identity = identity_of(&row);
        if identity != previous_identity
            && let Some(target) = &identity
        {
            refuse_if_registered(tx, target, Some(id), allowed).await?;
        }
        let holds = guard_is_free(tx, identity.as_ref(), id).await?;
        stamp(&mut row, identity.as_ref(), holds);
        Ok((row, previous_url))
    }

    /// Queues a scan. `allowed` matters although only administrators reach the route: an integration key acting for
    /// one is narrowed to its target, and without it a key restricted to one repository scanned any other.
    pub async fn trigger_repository(
        &self,
        id: i64,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<Triggered, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let found = persistence::repository(&mut tx, id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        let row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Repository(id), allowed)?;
        let view = RepositoryView::from(&row);
        let scan = self.scans.queue_repository(&view, None).await.map_err(queue_refusal)?;
        self.audit
            .record(actor.entry(
                AuditOperation::ScanTriggered,
                &scan.id.to_string(),
                &format!("Scan requested: {}", repository_url::redact(&row.url)),
            ))
            .await;
        Ok(Triggered { repository: view, scan })
    }

    /// Deletes the repository and everything hanging off it. "Repository not found." for an absent one and for one
    /// `allowed` does not permit — only administrators reach the route, and an administrator sees everything, so
    /// the check changes nothing Java answered; it is there because a route naming a target refuses through it.
    pub async fn delete_repository(
        &self,
        id: i64,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let found = persistence::repository(&mut tx, id).await?;
            let row = vectispire_cp_access::rows::require_visible_repository(found, id, allowed)?;
            let revoked = deletion::delete_repository(&self.purge, &mut tx, id).await?;
            Ok::<_, TargetError>((row, revoked))
        }
        .await;
        let (row, revoked) = match outcome {
            Ok(done) => done,
            Err(refusal) => {
                let _ = tx.rollback().await;
                return Err(refusal);
            }
        };
        tx.commit().await.map_err(StoreError::from)?;
        tracing::info!(repository = id, "Repository deleted.");
        deletion::record(
            self.audit.as_ref(),
            actor,
            id,
            &format!("repository {id}"),
            &format!("Repository deleted: {}", repository_url::redact(&row.url)),
            &revoked,
        )
        .await;
        Ok(())
    }

    /// The targets filed twice: repositories sharing one identity, oldest first in each group, groups by their oldest
    /// member — over the rows the caller sees, computed from the URLs as they are, so a row the keying has not reached
    /// is listed all the same. Nothing deletes them: either may hold the triage.
    pub async fn duplicates(&self, allowed: &Visibility) -> Result<Vec<Duplicated>, TargetError> {
        let mut groups: Vec<(RepositoryIdentity, Vec<Listed>)> = Vec::new();
        for listed in self.repositories_listed(allowed, None).await? {
            let repository = &listed.repository;
            let Some(identity) =
                RepositoryIdentity::of(&repository.url, Some(&repository.branch), repository.sub_path.as_deref())
            else {
                continue;
            };
            match groups.iter_mut().find(|(known, _)| *known == identity) {
                Some((_, members)) => members.push(listed),
                None => groups.push((identity, vec![listed])),
            }
        }
        Ok(groups
            .into_iter()
            .filter(|(_, members)| members.len() > 1)
            .map(|(identity, targets)| Duplicated { identity, targets })
            .collect())
    }

    fn refuse_unlisted_host(&self, url: &str) -> Result<(), TargetError> {
        if self.allowed_hosts.permits(url) {
            Ok(())
        } else {
            Err(TargetError::Invalid(self.allowed_hosts.refusal(url)))
        }
    }

    /// The installation's default interval, in minutes — `scan_default_interval_days`.
    pub(crate) async fn default_interval_minutes(&self) -> Result<i64, TargetError> {
        let days = self
            .settings
            .as_int(vectispire_cp_settings::Setting::ScanDefaultIntervalDays)
            .await
            .map_err(TargetError::unexpected)?;
        Ok(i64::from(days).saturating_mul(24 * 60))
    }
}

/// A filing that did not happen: refused by a rule, or failed at the database — which the caller reads again once it
/// has rolled back.
#[derive(Debug)]
pub(crate) enum Filing {
    Refused(TargetError),
    Failed(StoreError),
}

impl From<TargetError> for Filing {
    fn from(refusal: TargetError) -> Filing {
        Filing::Refused(refusal)
    }
}

pub(crate) fn added(actor: &RequestActor, row: &RepositoryRow, provenance: &str) -> Record {
    actor.entry(
        AuditOperation::SettingUpdated,
        &row.id.to_string(),
        &format!("Repository added: {}{provenance}", repository_url::redact(&row.url)),
    )
}

fn queue_refusal(error: QueueError) -> TargetError {
    match error {
        QueueError::AlreadyQueued(message) => TargetError::Conflict { message, cause: None, members: Vec::new() },
        QueueError::Failed(failure) => TargetError::Unexpected(failure),
    }
}

pub(crate) fn identity_of(row: &RepositoryRow) -> Option<RepositoryIdentity> {
    RepositoryIdentity::of(&row.url, Some(&row.branch), row.sub_path.as_deref())
}

/// Whether no row but `this` holds the guard — always, for a URL that names no host.
async fn guard_is_free(tx: &mut Tx, identity: Option<&RepositoryIdentity>, this: i64) -> Result<bool, TargetError> {
    let Some(target) = identity else { return Ok(true) };
    Ok(persistence::repository_by_guard(tx, &target.guard()).await?.is_none_or(|holder| holder.id == this))
}

fn stamp(row: &mut RepositoryRow, identity: Option<&RepositoryIdentity>, holds_guard: bool) {
    row.url_identity = identity.map(|target| target.repository.clone());
    row.identity_guard = if holds_guard { identity.map(RepositoryIdentity::guard) } else { None };
}

/// The same repository, branch and sub-path filed a second time: 409, typed `target-already-registered`.
///
/// **Named only to a caller who sees it.** The sentence then names the target and the problem carries its id, so the
/// screen can lead to it. To a caller who does not, the refusal is the same 409 without either: the database refuses
/// the row whoever asks, and a 404 or a 400 would be the pretence; what it reveals is one bit about a URL the caller
/// already holds, and nothing of which target, in which project, or what it found.
pub(crate) async fn refuse_if_registered(
    tx: &mut Tx,
    identity: &RepositoryIdentity,
    this: Option<i64>,
    allowed: &Visibility,
) -> Result<(), TargetError> {
    let Some(existing) =
        persistence::repository_by_guard(tx, &identity.guard()).await?.filter(|holder| Some(holder.id) != this)
    else {
        return Ok(());
    };
    if !allowed.permits(ScanTarget::Repository(existing.id)) {
        return Err(TargetError::conflict(
            "This repository is already registered, on this branch and sub-path.",
            ALREADY_REGISTERED,
        ));
    }
    let place =
        if identity.sub_path.is_empty() { "at its root".to_owned() } else { format!("under {}", identity.sub_path) };
    Err(TargetError::Conflict {
        message: format!(
            "This repository is already registered as \"{}\" (id {}), on branch {}, {place}. Edit that target, or \
             choose another branch or sub-path.",
            naming::of_repository(&existing),
            existing.id,
            identity.branch
        ),
        cause: Some(ALREADY_REGISTERED),
        members: vec![("existingRepositoryId", serde_json::Value::from(existing.id))],
    })
}

fn apply_schedule(row: &mut RepositoryRow, choice: ScheduleChoice) {
    row.scan_manual_only = choice.manual_only;
    row.scan_interval_minutes = choice.interval_minutes;
    row.scan_cron = choice.cron;
}

/// `RepositorySubPath.normalize`, its refusal as a 400.
fn normalized_sub_path(value: Option<&str>) -> Result<String, TargetError> {
    sub_path::normalize(value).map_err(TargetError::invalid)
}

/// A credential in the URL is refused for new URLs (decision 0022): it was stored in the clear in this row and handed
/// to every agent. A URL already stored that way keeps working — refusing it on upgrade would stop its scans silently.
fn refuse_credential_in_url(url: &str) -> Result<(), TargetError> {
    if repository_url::carries_credential(url) {
        return Err(TargetError::invalid(
            "The URL carries a credential. Remove it from the URL and attach an HTTPS token instead: it is stored \
             encrypted and sent only to its own host.",
        ));
    }
    Ok(())
}

/// One credential, of the kind the URL uses, and for a token the token's own host — what makes a token safe to
/// attach at all: pointing a repository at another server would otherwise send that server the forge's token.
async fn require_matching_credential(tx: &mut Tx, row: &RepositoryRow) -> Result<(), TargetError> {
    if row.https_token_id.is_some() && row.ssh_key_id.is_some() {
        return Err(TargetError::invalid("A repository uses an SSH key or an HTTPS token, not both."));
    }
    if let Some(token) = row.https_token_id {
        if !repository_url::is_https(&row.url) {
            return Err(TargetError::invalid("An HTTPS token only works with an https:// URL."));
        }
        let host = persistence::git_token(tx, token)
            .await?
            .ok_or_else(|| TargetError::invalid(format!("No HTTPS token with id {token}.")))?
            .host;
        if !repository_url::has_host(&row.url, &host) {
            return Err(TargetError::invalid(format!(
                "This token is issued for {host} and would be sent to no other host; the URL names another one."
            )));
        }
    }
    if row.ssh_key_id.is_some() && repository_url::is_https(&row.url) {
        return Err(TargetError::invalid(
            "An SSH key is not used over HTTPS. Use an ssh:// or git@ URL, or attach an HTTPS token.",
        ));
    }
    Ok(())
}

/// `UUID.fromString` of a trimmed identifier, blank meaning none.
fn credential_id(value: Option<&str>, what: &str) -> Result<Option<Uuid>, TargetError> {
    let trimmed = schedule::trim(value);
    if trimmed.is_empty() {
        return Ok(None);
    }
    java_uuid(trimmed)
        .map(Some)
        .ok_or_else(|| TargetError::invalid(format!("\"{trimmed}\" is not a valid {what} identifier.")))
}

/// The deployment key the form named, blank meaning none — and **a well-formed identifier of no key refused too**:
/// the foreign key used to refuse it at the write, a 500 whose message was a constraint name.
async fn ssh_key_id(tx: &mut Tx, value: Option<&str>) -> Result<Option<Uuid>, TargetError> {
    let trimmed = schedule::trim(value);
    if trimmed.is_empty() {
        return Ok(None);
    }
    let id = java_uuid(trimmed)
        .ok_or_else(|| TargetError::invalid(format!("\"{trimmed}\" is not a valid SSH key identifier.")))?;
    if persistence::ssh_key(tx, id).await?.is_none() {
        return Err(TargetError::invalid(format!("No SSH key with id {id}.")));
    }
    Ok(Some(id))
}

/// `UUID.fromString`, as the JDK reads a string that is not the canonical 36 characters: five groups split on `-`,
/// each read by `Long.parseLong(…, 16)` — a `+` sign and any length it accepts — and **masked** to its width, so
/// `1-1-1-1-1` is a UUID and so is a first group of nine digits, its top digit dropped. `Uuid::parse_str` refuses
/// both; an identifier Java accepted must not become a 400 here.
pub(crate) fn java_uuid(text: &str) -> Option<Uuid> {
    if text.len() > 36 {
        return None;
    }
    let groups: Vec<&str> = text.split('-').collect();
    if groups.len() != 5 {
        return None;
    }
    let widths = [8u32, 4, 4, 4, 12];
    let mut value: u128 = 0;
    for (group, width) in groups.iter().zip(widths) {
        let digits = group.strip_prefix('+').unwrap_or(group);
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        // `Long.parseLong` overflows past 2^63 - 1 and throws.
        let parsed = i64::from_str_radix(digits, 16).ok()?;
        let mask = (1u128 << (width * 4)) - 1;
        value = (value << (width * 4)) | (u128::from(parsed.unsigned_abs()) & mask);
    }
    Some(Uuid::from_u128(value))
}

/// Blank is `main`, the branch the clone falls back to; anything else must fit its column.
fn branch(value: Option<&str>) -> Result<String, TargetError> {
    Ok(bounded_text::optional(value, COLUMN_LENGTH, "The branch")?.unwrap_or_else(|| "main".to_owned()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn a_java_uuid_takes_short_groups_and_nothing_else() {
        assert_eq!(java_uuid("1-1-1-1-1"), Some(Uuid::from_u128(0x0000_0001_0001_0001_0001_0000_0000_0001)));
        assert_eq!(
            java_uuid("123e4567-e89b-12d3-a456-426614174000").map(|id| id.to_string()),
            Some("123e4567-e89b-12d3-a456-426614174000".to_owned())
        );
        assert_eq!(java_uuid("123e4567e89b12d3a456426614174000"), None);
        assert_eq!(java_uuid("1-1-1-1"), None);
        assert_eq!(java_uuid("g-1-1-1-1"), None);
        // Masked to its width, as Java does: the ninth digit is dropped.
        assert_eq!(java_uuid("123456789-1-1-1-1"), java_uuid("23456789-1-1-1-1"));
        assert_eq!(java_uuid("+1-1-1-1-1"), java_uuid("1-1-1-1-1"));
        assert_eq!(java_uuid("1--1-1-1"), None);
    }

    #[test]
    fn listing_languages_keeps_unknown_apart_from_none() {
        let mut languages: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
        languages.insert(1, BTreeSet::new());
        assert_eq!(languages.remove(&1), Some(BTreeSet::new()));
        assert_eq!(languages.remove(&2), None);
    }
}
