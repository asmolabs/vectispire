//! Teams: who is in one, what it owns, and where its alerts go — `TeamAdministrationService` and `TeamChannels`.
//!
//! **Why teams exist beside per-account assignment.** Assignment per account is the tool for an exception; a team is
//! the relation factorised, so onboarding somebody is one membership rather than a pairing per target. The two are
//! **unioned** by the visibility: intersecting them would make joining a team narrow what somebody already had.
//!
//! **One transaction per gesture.** Java's service holds none: each repository call commits on its own, so a
//! replacement's delete could commit without its inserts — the half-applied grant set `AccountAdminService` exists to
//! rule out for accounts. Here the delete and the inserts of a replacement, and a team's deletion with the rows that
//! name it, commit together. The answer of a gesture that succeeds is the same; the audit entry is written after the
//! commit, as Java writes it after the repository returns.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Visibility};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_outbound::{OutboundPolicy, OutboundUrlGuard};
use vectispire_domain::list_window::ListWindow;
use vectispire_domain::{bounded_text, java, team_rules};

use crate::accounts::{Audit, AuditOperation, Clock, RequestActor};
use crate::administration::{AdminError, record};
use crate::internal::grant_targets;
use crate::persistence::administration as store;
use crate::persistence::administration::TeamRow;
use crate::visibility::{AccessError, Grant, GrantableTargets, TargetGrant};

/// The width of `t_team_webhook.url`.
const MAX_WEBHOOK_URL_LENGTH: usize = 500;

/// The guard's label for this destination, which its refusals quote.
const WEBHOOK_LABEL: &str = "team webhook URL";

/// `TeamMemberEntity.Origin.MANUAL`: set by a person, removed only by a person — a sign-in's group sync and the
/// directory each reconcile their own rows only.
pub const ORIGIN_MANUAL: &str = "manual";

/// `TeamView`: the row's properties under their own names and the counts beside them. **Whether it is notified,
/// never where**: a webhook URL is a bearer capability and has no way out of this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamView {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
    pub member_count: i32,
    pub target_count: i32,
    pub notified: bool,
}

impl TeamView {
    fn of(team: &TeamRow, member_count: usize, target_count: usize, notified: bool) -> TeamView {
        TeamView {
            id: team.id,
            name: team.name.clone(),
            description: team.description.clone(),
            created_at: team.created_at,
            member_count: as_int(member_count),
            target_count: as_int(target_count),
            notified,
        }
    }
}

/// `TargetAssignment`: a grant as the screen sends it — `repository`, `container` or `project`, and an identifier.
/// Either may be absent in the body; an entry without an identifier is skipped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetAssignment {
    pub kind: Option<String>,
    pub id: Option<i64>,
}

/// What the team's channel may name: the settings' `notification_allow_private_url`, read at each change as the
/// global webhook's rule reads it — **the same rule for both**, `OutboundUrlGuard` owning it.
pub trait WebhookPolicy: Send + Sync {
    /// `settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)`.
    fn private_destinations_allowed(&self) -> BoxFuture<'_, Result<bool, AccessError>>;
}

impl WebhookPolicy for vectispire_cp_settings::Settings {
    fn private_destinations_allowed(&self) -> BoxFuture<'_, Result<bool, AccessError>> {
        Box::pin(async move {
            self.is_enabled(vectispire_cp_settings::Setting::NotificationAllowPrivateUrl)
                .await
                .map_err(|error| AccessError::Port(error.to_string()))
        })
    }
}

/// What a team administration is built from.
#[allow(missing_debug_implementations)] // a bag of parts, moved into the service at once
pub struct TeamParts<A, C> {
    pub db: Db,
    pub audit: A,
    pub clock: C,
    pub outbound: OutboundUrlGuard,
    pub policy: Arc<dyn WebhookPolicy>,
    pub targets: Arc<dyn GrantableTargets>,
}

/// `TeamAdministrationService`.
pub struct TeamAdministration<A, C> {
    db: Db,
    audit: A,
    clock: C,
    outbound: OutboundUrlGuard,
    policy: Arc<dyn WebhookPolicy>,
    targets: Arc<dyn GrantableTargets>,
}

impl<A, C> std::fmt::Debug for TeamAdministration<A, C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("TeamAdministration").field("db", &self.db).finish_non_exhaustive()
    }
}

impl<A: Audit + Sync, C: Clock + Sync> TeamAdministration<A, C> {
    pub fn new(parts: TeamParts<A, C>) -> TeamAdministration<A, C> {
        let TeamParts { db, audit, clock, outbound, policy, targets } = parts;
        TeamAdministration { db, audit, clock, outbound, policy, targets }
    }

    /// The teams by name, case-insensitively as `String.CASE_INSENSITIVE_ORDER` compares — unique whatever the
    /// casing, so a page can be cut from that order; the identifier settles what the rule would let through. Every
    /// team, or the page `window` names (`ListWindow.requested` is the route's).
    pub async fn list(&self, window: Option<ListWindow>) -> Result<Vec<TeamView>, AdminError> {
        let mut tx = store::read(&self.db).await?;
        let members = counts(store::member_counts(&mut tx).await?);
        let owned = counts(store::target_counts(&mut tx).await?);
        let notified: BTreeSet<i64> = store::teams_with_webhook(&mut tx).await?.into_iter().collect();
        let mut teams = store::teams(&mut tx).await?;
        store::commit(tx).await?;

        teams.sort_by(|left, right| java::compare_ignore_case(&left.name, &right.name).then(left.id.cmp(&right.id)));
        let page = match window {
            Some(window) => window.of(&teams),
            None => teams,
        };
        Ok(page
            .iter()
            .map(|team| TeamView {
                member_count: members.get(&team.id).copied().map_or(0, as_int_i64),
                target_count: owned.get(&team.id).copied().map_or(0, as_int_i64),
                ..TeamView::of(team, 0, 0, notified.contains(&team.id))
            })
            .collect())
    }

    /// `create`.
    pub async fn create(
        &self,
        requested_name: Option<&str>,
        description: Option<&str>,
        actor: &RequestActor,
    ) -> Result<TeamView, AdminError> {
        let name = team_rules::validate_name(requested_name).map_err(|refused| AdminError::InvalidInput(refused.0))?;
        let mut tx = store::write(&self.db).await?;
        refuse_if_name_taken(&mut tx, &name, None).await?;
        let team = TeamRow {
            id: 0,
            name: name.clone(),
            description: team_rules::trim_description(description),
            created_at: self.clock.now(),
        };
        let id = store::insert_team(&mut tx, &team.name, team.description.as_deref(), team.created_at).await?;
        store::commit(tx).await?;

        record(&self.audit, actor, AuditOperation::TeamUpdated, id.to_string(), format!("Team created: {name}")).await;
        Ok(TeamView::of(&TeamRow { id, ..team }, 0, 0, false))
    }

    /// `rename`: either field may be absent, which leaves it as it is. The entry is written whether or not anything
    /// changed, as Java writes it.
    pub async fn rename(
        &self,
        id: i64,
        requested_name: Option<&str>,
        description: Option<&str>,
        actor: &RequestActor,
    ) -> Result<TeamView, AdminError> {
        let mut tx = store::write(&self.db).await?;
        let mut team = require_team(&mut tx, id).await?;
        let previous = team.name.clone();
        if requested_name.is_some() {
            let name =
                team_rules::validate_name(requested_name).map_err(|refused| AdminError::InvalidInput(refused.0))?;
            refuse_if_name_taken(&mut tx, &name, Some(id)).await?;
            team.name = name;
        }
        if description.is_some() {
            team.description = team_rules::trim_description(description);
        }
        store::update_team(&mut tx, id, &team.name, team.description.as_deref()).await?;
        store::commit(tx).await?;

        let renamed = if previous == team.name { String::new() } else { format!(" → {}", team.name) };
        record(
            &self.audit,
            actor,
            AuditOperation::TeamUpdated,
            id.to_string(),
            format!("Team {previous} updated{renamed}"),
        )
        .await;
        self.view(&team).await
    }

    /// `delete`: its memberships, its grants **and its channel** go explicitly, with the row — a cascade an engine
    /// does not honour is decoration, and the channel is a bearer capability that would outlive its owner in a table
    /// no screen shows. The entry names the counts: every member loses, at once, everything the team owned.
    pub async fn delete(&self, id: i64, actor: &RequestActor) -> Result<(), AdminError> {
        let mut tx = store::write(&self.db).await?;
        let team = require_team(&mut tx, id).await?;
        let members = store::members_of(&mut tx, id).await?.len();
        let owned = store::team_targets(&mut tx, id).await?.len();
        store::delete_members(&mut tx, id).await?;
        store::delete_team_targets(&mut tx, id).await?;
        store::delete_webhook(&mut tx, id).await?;
        store::delete_team(&mut tx, id).await?;
        store::commit(tx).await?;

        record(
            &self.audit,
            actor,
            AuditOperation::TeamUpdated,
            id.to_string(),
            format!("Team deleted: {} ({members} member(s), {owned} target(s))", team.name),
        )
        .await;
        Ok(())
    }

    /// `members`: the accounts in the team, by identifier.
    pub async fn members(&self, id: i64) -> Result<Vec<i64>, AdminError> {
        let mut tx = store::read(&self.db).await?;
        require_team(&mut tx, id).await?;
        let members = store::members_of(&mut tx, id).await?;
        store::commit(tx).await?;
        Ok(members)
    }

    /// `replaceMembers`: wholesale — the operation that matters is removing somebody, and a server that only adds is
    /// a revocation that silently does nothing. Absent entries and repeats are dropped; **an account that does not
    /// exist is refused, not skipped**: a screen sending a stale identifier would otherwise be told nothing of the
    /// difference between what it sent and what was saved. Every membership is rewritten as set by hand.
    pub async fn replace_members(
        &self,
        id: i64,
        requested: &[Option<i64>],
        actor: &RequestActor,
    ) -> Result<Vec<i64>, AdminError> {
        let mut wanted: Vec<i64> = Vec::new();
        for user_id in requested.iter().flatten() {
            if !wanted.contains(user_id) {
                wanted.push(*user_id);
            }
        }
        let mut tx = store::write(&self.db).await?;
        let team = require_team(&mut tx, id).await?;
        let mut unknown = Vec::new();
        for user_id in &wanted {
            if store::account(&mut tx, *user_id).await?.is_none() {
                unknown.push(user_id.to_string());
            }
        }
        if !unknown.is_empty() {
            // `List.toString`.
            return Err(AdminError::InvalidInput(format!("No such account(s): [{}]", unknown.join(", "))));
        }
        store::delete_members(&mut tx, id).await?;
        for user_id in &wanted {
            store::insert_member(&mut tx, id, *user_id, ORIGIN_MANUAL).await?;
        }
        store::commit(tx).await?;

        record(
            &self.audit,
            actor,
            AuditOperation::TeamAccessChanged,
            id.to_string(),
            format!("Members of {}: {}", team.name, wanted.len()),
        )
        .await;
        Ok(wanted)
    }

    /// `targets`: what the team owns, each named — a project grant included, which no selector lists.
    pub async fn targets(&self, id: i64) -> Result<Vec<TargetGrant>, AdminError> {
        let mut tx = store::read(&self.db).await?;
        require_team(&mut tx, id).await?;
        let grants = store::team_targets(&mut tx, id).await?;
        store::commit(tx).await?;
        Ok(self.targets.named(&grants).await?)
    }

    /// `replaceTargets`: wholesale. An entry absent or without an identifier is skipped; the kind is validated against
    /// those that exist and a new grant's target must exist and be one `granter` sees — a grant already held is kept
    /// ([`grant_targets`]). One refused entry refuses the whole replacement, before anything is written.
    ///
    /// **Repeats are kept in the answer and in the count**, as Java keeps them: its list is not de-duplicated, and the
    /// second save of a pair merges into the first row. The account path de-duplicates; this one does not (reported
    /// on the Java side, see the crate's README).
    pub async fn replace_targets(
        &self,
        id: i64,
        requested: &[Option<TargetAssignment>],
        granter: &Visibility,
        actor: &RequestActor,
    ) -> Result<Vec<TargetGrant>, AdminError> {
        let mut tx = store::read(&self.db).await?;
        let team = require_team(&mut tx, id).await?;
        let held: BTreeSet<(String, i64)> =
            store::team_targets(&mut tx, id).await?.into_iter().map(|grant| (grant.kind, grant.id)).collect();
        store::commit(tx).await?;

        let mut wanted = Vec::new();
        for assignment in requested.iter().flatten() {
            let Some(target_id) = assignment.id else { continue };
            let kind = grant_targets::validate(
                self.targets.as_ref(),
                assignment.kind.as_deref(),
                target_id,
                granter,
                |kind, target| held.contains(&(kind.to_owned(), target)),
            )
            .await?;
            // The pair is the table's key: the same target sent twice is one grant, as for an account
            // (asmolabs/vectispire#87 — Java answered and audited two while storing one).
            let grant = Grant { kind, id: target_id };
            if !wanted.contains(&grant) {
                wanted.push(grant);
            }
        }

        let mut tx = store::write(&self.db).await?;
        store::delete_team_targets(&mut tx, id).await?;
        for grant in &wanted {
            store::insert_team_target(&mut tx, id, &grant.kind, grant.id).await?;
        }
        store::commit(tx).await?;

        record(
            &self.audit,
            actor,
            AuditOperation::TeamAccessChanged,
            id.to_string(),
            format!("Targets of {}: {}", team.name, wanted.len()),
        )
        .await;
        Ok(self.targets.named(&wanted).await?)
    }

    /// `setWebhook`: sets or clears the team's channel. Empty removes it — the team then falls back to the global
    /// webhook. **Validated here as well as at send time**: refusing a private address while the administrator is
    /// still looking at the field tells them what is wrong; the check at send time stops a value written straight into
    /// the database. The column's width is checked first, so an over-long URL costs no DNS lookup. **The URL is never
    /// in the entry**: the audit log is read by people who may not post in that channel.
    pub async fn set_webhook(
        &self,
        id: i64,
        requested_url: Option<&str>,
        actor: &RequestActor,
    ) -> Result<TeamView, AdminError> {
        let team = {
            let mut tx = store::read(&self.db).await?;
            let team = require_team(&mut tx, id).await?;
            store::commit(tx).await?;
            team
        };
        let url = java::trim(requested_url.unwrap_or("")).to_owned();

        if url.is_empty() {
            let mut tx = store::write(&self.db).await?;
            store::delete_webhook(&mut tx, id).await?;
            store::commit(tx).await?;
            record(
                &self.audit,
                actor,
                AuditOperation::TeamAccessChanged,
                id.to_string(),
                format!("Webhook removed from {}", team.name),
            )
            .await;
        } else {
            bounded_text::within(&url, MAX_WEBHOOK_URL_LENGTH, "The webhook URL")
                .map_err(|refused| AdminError::InvalidInput(refused.0))?;
            let policy = if self.policy.private_destinations_allowed().await? {
                OutboundPolicy::InternalAllowed
            } else {
                OutboundPolicy::PublicOnly
            };
            // The guard resolves the host: off the runtime's threads, as every other caller of it does.
            let guard = self.outbound.clone();
            let checked = url.clone();
            tokio::task::spawn_blocking(move || guard.validate(&checked, policy, WEBHOOK_LABEL))
                .await
                .map_err(|failed| AdminError::Failed(failed.to_string()))?
                .map_err(|refused| AdminError::UnsafeUrl(refused.0))?;
            // Stored as typed (trimmed), not as the guard's cleaned form, as Java stores it.
            let mut tx = store::write(&self.db).await?;
            store::delete_webhook(&mut tx, id).await?;
            store::insert_webhook(&mut tx, id, &url).await?;
            store::commit(tx).await?;
            record(
                &self.audit,
                actor,
                AuditOperation::TeamAccessChanged,
                id.to_string(),
                format!("Webhook set on {}", team.name),
            )
            .await;
        }

        let mut tx = store::read(&self.db).await?;
        let members = store::members_of(&mut tx, id).await?.len();
        let owned = store::team_targets(&mut tx, id).await?.len();
        store::commit(tx).await?;
        Ok(TeamView::of(&team, members, owned, !url.is_empty()))
    }

    /// The team as the list shows it, counted now.
    async fn view(&self, team: &TeamRow) -> Result<TeamView, AdminError> {
        let mut tx = store::read(&self.db).await?;
        let members = store::members_of(&mut tx, team.id).await?.len();
        let owned = store::team_targets(&mut tx, team.id).await?.len();
        let notified = store::webhook_url(&mut tx, team.id).await?.is_some();
        store::commit(tx).await?;
        Ok(TeamView::of(team, members, owned, notified))
    }
}

/// `TeamChannels`: which teams own a target, and where a team is told — what notification routing reads of the teams.
/// Reads only, in the caller's transaction: the scan-delta routing asks them inside the transaction that queues its
/// messages.
#[derive(Clone, Copy, Debug, Default)]
pub struct TeamChannels;

impl TeamChannels {
    /// `teamsGranted`: the teams granted the target directly, by identifier.
    pub async fn teams_granted(
        tx: &mut vectispire_cp_db::Tx,
        kind: &str,
        target_id: i64,
    ) -> Result<Vec<i64>, AdminError> {
        Ok(store::teams_granted(tx, kind, target_id).await?)
    }

    /// `withChannel`: of `team_ids`, those with a channel of their own, by identifier.
    pub async fn with_channel(tx: &mut vectispire_cp_db::Tx, team_ids: &[i64]) -> Result<Vec<i64>, AdminError> {
        Ok(store::teams_with_webhook(tx).await?.into_iter().filter(|team| team_ids.contains(team)).collect())
    }

    /// `anyTeamHasOne`: notifications are on when one does.
    pub async fn any_team_has_one(tx: &mut vectispire_cp_db::Tx) -> Result<bool, AdminError> {
        Ok(!store::teams_with_webhook(tx).await?.is_empty())
    }

    /// `webhookUrl`: the team's channel as stored; `None` when it has none.
    pub async fn webhook_url(tx: &mut vectispire_cp_db::Tx, team_id: i64) -> Result<Option<String>, AdminError> {
        Ok(store::webhook_url(tx, team_id).await?)
    }
}

async fn require_team(tx: &mut vectispire_cp_db::Tx, id: i64) -> Result<TeamRow, AdminError> {
    store::team(tx, id).await?.ok_or_else(|| AdminError::NotFound("Team not found.".to_owned()))
}

/// Caught here rather than left to the unique constraint, whose violation is a 500 carrying a driver's message —
/// and which, on PostgreSQL, would accept the same name in another casing.
async fn refuse_if_name_taken(
    tx: &mut vectispire_cp_db::Tx,
    name: &str,
    allowed: Option<i64>,
) -> Result<(), AdminError> {
    match store::team_named(tx, name).await? {
        Some(existing) if Some(existing.id) != allowed => {
            Err(AdminError::InvalidInput(format!("A team named \"{name}\" already exists.")))
        }
        _ => Ok(()),
    }
}

fn counts(rows: Vec<store::Count>) -> BTreeMap<i64, i64> {
    rows.into_iter().map(|row| (row.team_id, row.count)).collect()
}

/// `Long.intValue()` / `List.size()` as the view's `int`: no table holds two billion rows of one team.
fn as_int(count: usize) -> i32 {
    i32::try_from(count).unwrap_or(i32::MAX)
}

fn as_int_i64(count: i64) -> i32 {
    i32::try_from(count).unwrap_or(i32::MAX)
}
