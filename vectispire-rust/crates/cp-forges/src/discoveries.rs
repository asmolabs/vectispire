//! `ForgeDiscoveryService`: a connection's discoveries — requested, queued for a control-plane instance, polled while
//! they run, and the snapshot they compared themselves with, read per run (decision 0037 §3).
//!
//! **Queued, never run in the request.** **One per connection at a time**: the connection's id is the run's active
//! key, unique while it is pending or running; a refused insert is read as "in progress" only once the committed row
//! says so. **A queued discovery is audited** (`FORGE_DISCOVERY_REQUESTED`, after the commit); a refused request
//! records nothing.

use std::sync::Arc;

use serde::Serialize;
use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor};
use vectispire_cp_db::Db;
use vectispire_cp_targets::Clock;
use vectispire_domain::bounded_text;
use vectispire_domain::forges::{DiscoveryReason, DiscoveryState, ForgeKind};
use vectispire_domain::java;
use vectispire_domain::list_window::ListWindow;

use crate::connections::actor_name;
use crate::error::{ForgeError, connection_not_found};
use crate::internal::discovery::DiscoveryExecution;
use crate::internal::integrations::ForgeIntegrations;
use crate::persistence::{self, ConnectionRow, DiscoveryRow, SeenBy, StoreError};
use crate::views::{ForgeDiscoveryView, ForgeRepositoryView};

/// A connection's runs, newest first: a screen's page, not its history.
pub(crate) const LISTED: u64 = 50;

/// `ForgeDiscoveryConflict.Cause`.
pub(crate) const IN_PROGRESS: &str = "forge-discovery-in-progress";
pub(crate) const UNSUPPORTED: &str = "forge-discovery-unsupported";
pub(crate) const NOT_SELECTABLE: &str = "forge-discovery-not-selectable";
pub(crate) const SUPERSEDED: &str = "forge-discovery-superseded";

/// One page of a run's repositories.
#[derive(Debug, Clone, Serialize)]
pub struct RepositoryPage {
    pub items: Vec<ForgeRepositoryView>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// The service.
pub struct ForgeDiscoveryService {
    db: Db,
    integrations: ForgeIntegrations,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ForgeDiscoveryService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ForgeDiscoveryService").finish_non_exhaustive()
    }
}

fn in_progress(running: &DiscoveryRow) -> ForgeError {
    ForgeError::Conflict {
        cause: IN_PROGRESS,
        message: format!(
            "A discovery of this connection is already {} (discovery {}): it is the one to follow.",
            running.state, running.id
        ),
        members: vec![("discoveryId", serde_json::Value::from(running.id))],
    }
}

impl ForgeDiscoveryService {
    pub(crate) fn new(
        db: Db,
        integrations: ForgeIntegrations,
        audit: Arc<AuditLog>,
        clock: Arc<dyn Clock>,
    ) -> ForgeDiscoveryService {
        ForgeDiscoveryService { db, integrations, audit, clock }
    }

    /// Queues a discovery of the connection.
    pub async fn request(&self, connection_id: &str, actor: &RequestActor) -> Result<ForgeDiscoveryView, ForgeError> {
        let connection = self.require_connection(connection_id).await?;
        let kind = ForgeKind::parse(Some(&connection.kind))?;
        self.integrations.require_enabled(kind).await?;
        if !DiscoveryExecution::lists(kind) {
            return Err(ForgeError::Conflict {
                cause: UNSUPPORTED,
                message: format!(
                    "This version does not discover the repositories of a {} connection yet.",
                    kind.wire_name()
                ),
                members: Vec::new(),
            });
        }
        let mut row = DiscoveryRow {
            id: 0,
            connection_id: connection_id.to_owned(),
            state: DiscoveryState::Pending.wire_name().to_owned(),
            reason: None,
            detail: None,
            active_key: Some(connection_id.to_owned()),
            requested_at: self.clock.now(),
            requested_by: actor_name(actor),
            claimed_by: None,
            lease_expires_at: None,
            attempts: 0,
            started_at: None,
            finished_at: None,
            namespaces_seen: 0,
            repositories_seen: 0,
            repositories_skipped: 0,
            requests_made: 0,
            rate_limit_wait_seconds: 0,
            rate_limit_reset_at: None,
            new_count: None,
            changed_count: None,
            gone_count: None,
            unreadable_namespaces: None,
        };
        let queued = async {
            let mut tx = persistence::write(&self.db).await?;
            if let Some(running) = persistence::discovery_by_active_key(&mut tx, connection_id).await? {
                tx.rollback().await?;
                return Ok(Err(in_progress(&running)));
            }
            let id = persistence::insert_discovery(&mut tx, &row).await?;
            tx.commit().await?;
            Ok::<_, StoreError>(Ok(id))
        };
        match queued.await {
            Ok(Ok(id)) => row.id = id,
            Ok(Err(conflict)) => return Err(conflict),
            Err(refused) => {
                // The unique key refuses the second of two racing requests — and a lock timeout fails an insert too.
                let mut tx = persistence::read(&self.db).await?;
                let running = persistence::discovery_by_active_key(&mut tx, connection_id).await?;
                tx.commit().await.map_err(StoreError::from)?;
                return Err(running.as_ref().map_or_else(|| refused.into(), in_progress));
            }
        }
        // After the commit, as every entry here.
        self.audit
            .record(actor.entry(
                AuditOperation::ForgeDiscoveryRequested,
                connection_id,
                &format!(
                    "Forge discovery {} requested of connection {} ({connection_id}, {} at {}): queued for the control \
                     plane.",
                    row.id,
                    connection.name,
                    kind.wire_name(),
                    connection.base_url
                ),
            ))
            .await;
        ForgeDiscoveryView::of(&row)
    }

    /// The connection's discoveries, newest first: the latest fifty unless a page is asked for.
    pub async fn list(
        &self,
        connection_id: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<ForgeDiscoveryView>, ForgeError> {
        self.require_connection(connection_id).await?;
        let (limit, offset) = match ListWindow::requested(limit, offset).map_err(ForgeError::InvalidInput)? {
            Some(window) => (window.limit.unsigned_abs(), window.offset.unsigned_abs()),
            None => (LISTED, 0),
        };
        let mut tx = persistence::read(&self.db).await?;
        let runs = persistence::discoveries_of(&mut tx, connection_id, limit, offset).await?;
        tx.commit().await.map_err(StoreError::from)?;
        runs.iter().map(ForgeDiscoveryView::of).collect()
    }

    /// One discovery of the connection; the connection's 404 first, then the run's.
    pub async fn get(&self, connection_id: &str, discovery_id: i64) -> Result<ForgeDiscoveryView, ForgeError> {
        ForgeDiscoveryView::of(&self.require_discovery(connection_id, discovery_id).await?)
    }

    /// A page of the repositories a run listed, found new, changed or gone, by full path. Gone is a completed run's
    /// word only: asked of any other run, it is refused rather than answered empty.
    pub async fn repositories(
        &self,
        connection_id: &str,
        discovery_id: i64,
        change: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<RepositoryPage, ForgeError> {
        let run = self.require_discovery(connection_id, discovery_id).await?;
        let wanted = change_of(change)?;
        let window = ListWindow::new(limit.unwrap_or(100), offset.unwrap_or(0)).map_err(ForgeError::InvalidInput)?;
        if wanted == SeenBy::Gone && DiscoveryState::of_stored(&run.state).ok() != Some(DiscoveryState::Completed) {
            let reason = DiscoveryReason::of_stored(run.reason.as_deref()).ok().flatten();
            return Err(ForgeError::InvalidInput(format!(
                "Only a completed discovery says which repositories are gone; this one is {}{}.",
                run.state,
                reason.map(|reason| format!(" ({})", reason.wire_name())).unwrap_or_default()
            )));
        }
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::seen_page(
            &mut tx,
            connection_id,
            wanted,
            discovery_id,
            window.limit.unsigned_abs(),
            window.offset.unsigned_abs(),
        )
        .await?;
        let total = persistence::count_seen(&mut tx, connection_id, wanted, discovery_id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(RepositoryPage {
            items: rows.iter().map(ForgeRepositoryView::of).collect(),
            total,
            limit: window.limit,
            offset: window.offset,
        })
    }

    async fn require_connection(&self, connection_id: &str) -> Result<ConnectionRow, ForgeError> {
        let mut tx = persistence::read(&self.db).await?;
        let row = persistence::connection(&mut tx, connection_id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        row.ok_or_else(connection_not_found)
    }

    async fn require_discovery(&self, connection_id: &str, discovery_id: i64) -> Result<DiscoveryRow, ForgeError> {
        self.require_connection(connection_id).await?;
        let mut tx = persistence::read(&self.db).await?;
        let run = persistence::discovery_of(&mut tx, discovery_id, connection_id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        run.ok_or_else(|| ForgeError::NotFound(format!("Forge discovery {discovery_id} not found.")))
    }
}

/// `Change.parse`: a reader's word; blank is every repository the run listed.
fn change_of(raw: Option<&str>) -> Result<SeenBy, ForgeError> {
    let Some(raw) = raw.filter(|raw| !java::is_blank(raw)) else {
        return Ok(SeenBy::Last);
    };
    match java::to_lower_root(java::trim(raw)).as_str() {
        "all" => Ok(SeenBy::Last),
        "new" => Ok(SeenBy::First),
        "changed" => Ok(SeenBy::Changed),
        "gone" => Ok(SeenBy::Gone),
        _ => Err(ForgeError::InvalidInput(format!(
            "\"{}\" is not a change: all, new, changed or gone.",
            bounded_text::clip(Some(java::trim(raw)), 40).unwrap_or_default()
        ))),
    }
}
