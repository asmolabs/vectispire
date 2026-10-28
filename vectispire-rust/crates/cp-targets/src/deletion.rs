//! Deleting a target atomically with every row that names it — `TargetDeletionService` — and the purge each owner of
//! a target's rows runs: `TargetPurge`, its phases, and the registry of listeners.
//!
//! **This deletes the target and announces it; each domain purges its own rows.** Target deletion used to be one
//! method issuing thirty deletes into seven domains' tables. Each owning module now registers a [`PurgeListener`] and
//! purges its own; this knows nobody else's table.
//!
//! **In the deletion's transaction, never after the commit.** The listeners are handed the `&mut Tx` the deletion
//! runs in — Java's `Propagation.MANDATORY`, which here is a matter of types: a listener cannot run outside a
//! transaction, so none can commit its deletes on its own while the target stays. A target deleted with its issues
//! left behind is an orphan no screen shows; issues purged for a deletion that then rolled back are triage lost.
//!
//! **The grants are revoked by a call, not by a listener**, before the first phase: `access` sits below `targets`
//! and cannot hear its event (decision 0029).

use std::sync::Arc;

use vectispire_cp_access::target_grants::{self, Revoked};
use vectispire_cp_audit::{AuditOperation, RequestActor};
use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_http::credentials::BoxFuture;

use crate::audit::{ACCESS_GRANT_CHANGED, AuditSink};
use crate::error::TargetError;
use crate::persistence::{self, StoreError};

/// Rows that name a target which is going away — `TargetDeleted` — or whose target is already gone —
/// `OrphanedTargetRows`, left by deletions from before the foreign keys were enforced (MySQL before V19). Both go
/// through the same listeners in the same order, so the two purges cannot come to disagree about what a target's
/// rows are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetPurge {
    Deleted(ScanTarget),
    Orphans,
}

impl TargetPurge {
    /// The kind as grants and gate policies store it next to the identifier — `TargetDeleted.kind()`.
    pub fn kind(target: ScanTarget) -> &'static str {
        match target {
            ScanTarget::Repository(_) => vectispire_cp_access::visibility::KIND_REPOSITORY,
            ScanTarget::Container(_) => vectispire_cp_access::visibility::KIND_CONTAINER,
        }
    }
}

/// The order the listeners run in, children before parents, so the purge never depends on a cascade the schema
/// declares — **and holds still if a key is ever declared `restrict`**: a parent deleted before its children would
/// then fail at the commit, on a target nobody can delete. Listeners of one phase touch disjoint tables (or, for the
/// findings, one table by two selections whose union is the same whatever the order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    /// Rows naming the target by kind and identifier, with no foreign key: gate policies, plugin activations… (the
    /// grants are revoked by the publisher just before this phase).
    References = 100,
    /// What hangs off an issue alone: triage events, ticket links.
    IssueChildren = 200,
    /// Findings, which hang off both an issue and a scan.
    Findings = 300,
    /// The issues, once nothing refers to them; before the scans they were first and last seen in.
    Issues = 400,
    /// What hangs off a scan alone: components, AI reviews.
    ScanChildren = 500,
    /// The scans, last; the publisher deletes the target itself after every listener returned.
    Scans = 600,
}

/// A listener's failure: it rolls the whole deletion back.
pub type PurgeError = Box<dyn std::error::Error + Send + Sync>;

/// One owner's purge — Java's `@EventListener @Order(Phase.X)` on `TargetPurge` (or `TargetDeleted` alone).
pub trait PurgeListener: Send + Sync {
    /// The module that owns the rows, and its Java class and method — what the composition test compares.
    fn name(&self) -> ListenerName;
    fn phase(&self) -> Phase;
    /// Purges this owner's rows for `purge`, in the deletion's transaction.
    fn purge<'a>(&'a self, tx: &'a mut Tx, purge: &'a TargetPurge) -> BoxFuture<'a, Result<(), PurgeError>>;
}

/// Who a listener is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ListenerName {
    pub module: &'static str,
    /// `Class.method` of the Java listener it ports or stands in for.
    pub listener: &'static str,
}

/// Every `TargetPurge` listener of the 0.11.1 line, with its phase and whether it hears the orphan sweep too — the
/// composition a binary's registry is held to (`tests/purge_composition.rs`). Read from the `@Order` annotations of
/// `core/*/…Purge.java` (b8bd7e8d0); `ProjectDeleted`'s listeners are [`JAVA_PROJECT_LISTENERS`].
pub const JAVA_LISTENERS: &[(&str, &str, Phase, bool)] = &[
    ("compliance", "OwaspCoveragePurge.purge", Phase::References, false),
    ("compliance", "OwaspCoveragePurge.sweep", Phase::References, true),
    ("forges", "ForgeImportLinkPurge.purge", Phase::References, false),
    ("gate", "GatePolicyPurge.purge", Phase::References, false),
    ("inventory", "BuildSbomPurge.purge", Phase::References, false),
    ("plugins", "PluginPurge.purge", Phase::References, false),
    ("issues", "IssuePurge.purgeTriageHistory", Phase::IssueChildren, true),
    ("tickets", "TicketLinkPurge.purge", Phase::IssueChildren, true),
    ("issues", "IssuePurge.purgeFindings", Phase::Findings, true),
    ("scanning", "ScanPurge.purgeFindings", Phase::Findings, true),
    ("issues", "IssuePurge.purgeIssues", Phase::Issues, true),
    ("compliance", "AiReviewPurge.purge", Phase::ScanChildren, true),
    ("inventory", "ComponentPurge.purge", Phase::ScanChildren, true),
    ("scanning", "ScanPurge.purgeScans", Phase::Scans, true),
];

/// `ProjectDeleted`'s listeners: what modules above keep naming a project — the plugins activated for it, the SARIF
/// sources scoped to it, its checklists, its report plugins.
pub const JAVA_PROJECT_LISTENERS: &[(&str, &str)] = &[
    ("checklists", "ChecklistPurge.purge"),
    ("plugins", "PluginPurge.purge"),
    ("reportplugins", "ReportPluginPurge.purge"),
];

/// A listener a later module will replace: it purges nothing, and says whose it is. **The foreign keys cascade from
/// the target and its scans on both engines (V19 and later)**, so a deletion still takes those rows; what a stand-in
/// leaves undone is the order — and, for the orphan sweep, the rows whose target was deleted while the keys were off,
/// which stay until their owner's listener lands. Counted by the composition test, so none survives cut-over unseen.
#[derive(Debug, Clone, Copy)]
pub struct StandIn {
    pub name: ListenerName,
    pub phase: Phase,
}

impl PurgeListener for StandIn {
    fn name(&self) -> ListenerName {
        self.name
    }

    fn phase(&self) -> Phase {
        self.phase
    }

    fn purge<'a>(&'a self, _tx: &'a mut Tx, _purge: &'a TargetPurge) -> BoxFuture<'a, Result<(), PurgeError>> {
        Box::pin(async { Ok(()) })
    }
}

/// The listeners, sorted by phase — a stable sort, so listeners of one phase keep the order they were registered in.
#[derive(Clone, Default)]
pub struct PurgeRegistry {
    listeners: Vec<Arc<dyn PurgeListener>>,
}

impl std::fmt::Debug for PurgeRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_list().entries(self.listeners.iter().map(|listener| listener.name())).finish()
    }
}

impl PurgeRegistry {
    pub fn new(mut listeners: Vec<Arc<dyn PurgeListener>>) -> PurgeRegistry {
        listeners.sort_by_key(|listener| listener.phase());
        PurgeRegistry { listeners }
    }

    /// Java's listeners, each a [`StandIn`] — what a binary composes before any owner's purge is ported.
    pub fn stand_ins() -> PurgeRegistry {
        PurgeRegistry::new(
            JAVA_LISTENERS
                .iter()
                .map(|(module, listener, phase, _)| {
                    Arc::new(StandIn { name: ListenerName { module, listener }, phase: *phase })
                        as Arc<dyn PurgeListener>
                })
                .collect(),
        )
    }

    /// The same, with `ported` in place of the stand-ins of the same name.
    pub fn with(self, ported: Vec<Arc<dyn PurgeListener>>) -> PurgeRegistry {
        let names: Vec<ListenerName> = ported.iter().map(|listener| listener.name()).collect();
        let mut listeners: Vec<Arc<dyn PurgeListener>> =
            self.listeners.into_iter().filter(|listener| !names.contains(&listener.name())).collect();
        listeners.extend(ported);
        PurgeRegistry::new(listeners)
    }

    /// The listeners, in the order they run.
    pub fn names(&self) -> Vec<(ListenerName, Phase)> {
        self.listeners.iter().map(|listener| (listener.name(), listener.phase())).collect()
    }

    /// Runs every listener, phase by phase, in `tx`. The first failure stops the purge and is returned: the caller
    /// rolls the whole deletion back.
    pub async fn publish(&self, tx: &mut Tx, purge: &TargetPurge) -> Result<(), PurgeError> {
        for listener in &self.listeners {
            listener.purge(tx, purge).await?;
        }
        Ok(())
    }
}

/// `purge(TargetDeleted)`: the grants and restricted keys first, then each owner's listeners in phase order.
async fn purge(registry: &PurgeRegistry, tx: &mut Tx, target: ScanTarget) -> Result<Revoked, TargetError> {
    let id = match target {
        ScanTarget::Repository(id) | ScanTarget::Container(id) => id,
    };
    let revoked =
        target_grants::revoke_all(tx, TargetPurge::kind(target), id).await.map_err(TargetError::unexpected)?;
    registry.publish(tx, &TargetPurge::Deleted(target)).await.map_err(TargetError::Unexpected)?;
    Ok(revoked)
}

/// `deleteRepository`, in the caller's transaction: purged, then the row. Answers what went with it, for the caller
/// to audit once the transaction has committed.
pub async fn delete_repository(registry: &PurgeRegistry, tx: &mut Tx, id: i64) -> Result<Revoked, TargetError> {
    let revoked = purge(registry, tx, ScanTarget::Repository(id)).await?;
    persistence::delete_repository(tx, id).await?;
    Ok(revoked)
}

/// `deleteContainer`, the same for an image.
pub async fn delete_container(registry: &PurgeRegistry, tx: &mut Tx, id: i64) -> Result<Revoked, TargetError> {
    let revoked = purge(registry, tx, ScanTarget::Container(id)).await?;
    persistence::delete_container(tx, id).await?;
    Ok(revoked)
}

/// `purgeOrphanedTargetData`: the orphan sweep through the same listeners, in a transaction of its own — at start-up
/// and on the hourly turn.
pub async fn purge_orphans(registry: &PurgeRegistry, db: &vectispire_cp_db::Db) -> Result<(), TargetError> {
    let mut tx = persistence::write(db).await?;
    if let Err(failure) = registry.publish(&mut tx, &TargetPurge::Orphans).await {
        let _ = tx.rollback().await;
        return Err(TargetError::Unexpected(failure));
    }
    tx.commit().await.map_err(StoreError::from)?;
    Ok(())
}

/// `TargetDeletionAudit.record`: the deletion's entry, saying what went with it — signalling an access change when a
/// grant went, which nobody else will announce — and one `API_KEY_DELETED` entry per key revoked with the target,
/// under the key's own id: a key revoked by hand is filed there, which is where whoever runs the pipeline looks, and
/// one revoked by a deletion is the same act. Written after the deletion committed.
pub async fn record(
    audit: &dyn AuditSink,
    actor: &RequestActor,
    target_id: i64,
    what: &str,
    description: &str,
    revoked: &Revoked,
) {
    let deleted = actor.entry(
        AuditOperation::SettingUpdated,
        &target_id.to_string(),
        &format!("{description} ({})", revoked.summary()),
    );
    audit.record(if revoked.grants > 0 { deleted.signalling(ACCESS_GRANT_CHANGED) } else { deleted }).await;
    for key in &revoked.keys {
        audit
            .record(actor.entry(
                AuditOperation::ApiKeyDeleted,
                &key.id.as_hyphenated().to_string(),
                &format!("API key revoked with its target: {} (restricted to {what}, deleted)", key.name),
            ))
            .await;
    }
}
