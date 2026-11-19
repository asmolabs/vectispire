//! `ScanDeltaNotifier`: the bridge between a reconciliation's outcome and the notification queue — `issues`'
//! [`ScanDeltaSink`]. The only place that knows both what an issue is and what a channel is, and the only place that
//! knows which target the delta is about — so it is where a message is routed: one copy per listening channel, and one
//! webhook copy per owning team with a channel of its own.

use std::collections::BTreeSet;
use std::sync::Arc;

use futures_util::future::BoxFuture;
use vectispire_cp_access::teams::TeamChannels;
use vectispire_cp_db::{Db, ScanTarget, Tx};
use vectispire_cp_issues::{IssueView, ScanDelta, ScanDeltaSink};
use vectispire_cp_outbox::Outbox;
use vectispire_cp_settings::Integrations;
use vectispire_cp_targets::Targets;
use vectispire_domain::notifications::NotifiableIssue;
use vectispire_domain::team_rules::{KIND_CONTAINER, KIND_PROJECT, KIND_REPOSITORY};
use vectispire_domain::{FindingType, Severity};

use crate::channels::Channel;
use crate::gate;
use crate::service::NotificationService;

type PortError = Box<dyn std::error::Error + Send + Sync>;

/// What the routing reads of the targets: a message names its target, and a team owns a repository or an image
/// through the project it is filed in (decision 0023).
pub trait TargetDirectory: Send + Sync {
    fn name_of(&self, target: ScanTarget) -> BoxFuture<'_, Result<String, PortError>>;
    /// `None` for an unfiled target, or one that is gone.
    fn project_of(&self, target: ScanTarget) -> BoxFuture<'_, Result<Option<i64>, PortError>>;
}

/// The targets module's answer.
pub struct TargetsDirectory {
    targets: Arc<Targets>,
    db: Db,
}

impl std::fmt::Debug for TargetsDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetsDirectory").finish_non_exhaustive()
    }
}

impl TargetsDirectory {
    pub fn new(targets: Arc<Targets>, db: Db) -> TargetsDirectory {
        TargetsDirectory { targets, db }
    }
}

impl TargetDirectory for TargetsDirectory {
    fn name_of(&self, target: ScanTarget) -> BoxFuture<'_, Result<String, PortError>> {
        Box::pin(async move {
            let (repositories, containers): (BTreeSet<i64>, BTreeSet<i64>) = match target {
                ScanTarget::Repository(id) => ([id].into(), BTreeSet::new()),
                ScanTarget::Container(id) => (BTreeSet::new(), [id].into()),
            };
            let names = vectispire_cp_targets::naming::for_ids(&self.db, &repositories, &containers).await?;
            Ok(match target {
                ScanTarget::Repository(id) => names.of(Some(id), None),
                ScanTarget::Container(id) => names.of(None, Some(id)),
            })
        })
    }

    fn project_of(&self, target: ScanTarget) -> BoxFuture<'_, Result<Option<i64>, PortError>> {
        Box::pin(async move {
            Ok(match target {
                ScanTarget::Repository(id) => self.targets.project_of(id).await?.flatten(),
                ScanTarget::Container(id) => self.targets.catalog_container(id).await?.and_then(|view| view.project_id),
            })
        })
    }
}

/// The router.
pub struct ScanDeltaNotifier {
    notifications: Arc<NotificationService>,
    channels: Vec<Arc<dyn Channel>>,
    outbox: Arc<Outbox>,
    targets: Arc<dyn TargetDirectory>,
    integrations: Integrations,
}

impl std::fmt::Debug for ScanDeltaNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanDeltaNotifier").finish_non_exhaustive()
    }
}

impl ScanDeltaNotifier {
    pub fn new(
        notifications: Arc<NotificationService>,
        channels: Vec<Arc<dyn Channel>>,
        outbox: Arc<Outbox>,
        targets: Arc<dyn TargetDirectory>,
        integrations: Integrations,
    ) -> ScanDeltaNotifier {
        ScanDeltaNotifier { notifications, channels, outbox, targets, integrations }
    }

    /// Queues the delta **inside the caller's transaction**, or does nothing. Nothing is sent here.
    pub async fn route(&self, tx: &mut Tx, delta: &ScanDelta) -> Result<(), PortError> {
        // **Who listens, decided first and from every channel.** A channel with no destination, or switched off by
        // the governor, is queued nothing: a row for it would be held for as long as the switch stays off.
        let mut listening = Vec::new();
        for channel in &self.channels {
            if channel.configured().await? && gate::is_on(&self.integrations, channel.kind()).await? {
                listening.push(channel.kind());
            }
        }
        let teams_may_listen = self.notifications.is_switched_on().await? && TeamChannels::any_team_has_one(tx).await?;
        if listening.is_empty() && !teams_may_listen {
            return Ok(());
        }
        let name = self.targets.name_of(delta.target).await?;
        let Some(payload) = self
            .notifications
            .build_scan_delta(
                &name,
                delta.scan_id,
                &notifiable(&delta.new_issues),
                &notifiable(&delta.reopened_issues),
                delta.resolved,
            )
            .await?
        else {
            return Ok(());
        };
        // **One row per configured destination**: one row for three makes a partial failure unrepresentable.
        for kind in listening {
            self.outbox.enqueue(tx, &payload, kind.outbox_type(), None).await?;
        }
        if teams_may_listen {
            for team in self.teams_to_tell(tx, delta.target).await? {
                self.outbox.enqueue(tx, &payload, vectispire_cp_outbox::TYPE_SCAN_DELTA, Some(team)).await?;
            }
        }
        Ok(())
    }

    /// The teams that own this target — directly, or through its project — **and** have somewhere to be told.
    async fn teams_to_tell(&self, tx: &mut Tx, target: ScanTarget) -> Result<Vec<i64>, PortError> {
        let (kind, id) = match target {
            ScanTarget::Repository(id) => (KIND_REPOSITORY, id),
            ScanTarget::Container(id) => (KIND_CONTAINER, id),
        };
        let mut claims = TeamChannels::teams_granted(tx, kind, id).await?;
        if let Some(project) = self.targets.project_of(target).await? {
            claims.extend(TeamChannels::teams_granted(tx, KIND_PROJECT, project).await?);
        }
        // `distinct()`: the first occurrence's place kept.
        let mut owners = Vec::new();
        for team in claims {
            if !owners.contains(&team) {
                owners.push(team);
            }
        }
        if owners.is_empty() {
            return Ok(Vec::new());
        }
        Ok(TeamChannels::with_channel(tx, &owners).await?)
    }
}

impl ScanDeltaSink for ScanDeltaNotifier {
    fn enqueue<'a>(&'a self, tx: &'a mut Tx, delta: &'a ScanDelta) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(self.route(tx, delta))
    }
}

fn notifiable(issues: &[IssueView]) -> Vec<NotifiableIssue> {
    issues
        .iter()
        .map(|issue| NotifiableIssue {
            id: issue.id,
            identifier: Some(issue.identifier.clone()),
            kind: FindingType::from_wire_name(Some(&issue.type_)),
            severity: Some(Severity::of(Some(&issue.severity))),
            kev: issue.is_kev,
            epss_score: issue.epss_score,
            package_name: issue.package_name.clone(),
            file_path: issue.file_path.clone(),
            fix_versions: issue.fix_versions.clone(),
            link: issue.link.clone(),
        })
        .collect()
}
