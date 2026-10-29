//! Purging the authentication tables — `SessionCleanupService.prune`, the `SESSION_CLEANUP` maintenance task.
//!
//! **This is not a security control, and saying so matters.** An expired session is already refused on read, an
//! attempt outside the window is already not counted, a closed rate window is never read again. This only stops four
//! tables accumulating rows nobody will read — so it may fail, skip a turn or not run at all with nothing bad
//! happening, which is exactly why it never fails the tick that calls it: each purge is tried on its own, a failure is
//! logged at warn and counted as nothing purged, and the others still run.

use std::sync::Arc;

use time::Duration;
use vectispire_cp_db::Db;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};

use crate::accounts::StoreError;
use crate::credentials::CredentialService;
use crate::login_throttle::WINDOW;
use crate::persistence::sign_in::{RateWindowStore, SignInStore, SqlSignInStore};
use crate::rate_windows::RateWindows;
use crate::sign_in::SessionDoor;
use crate::throttle::SharedClock;

/// Attempts are kept **twice** the window: a purge cutting flush with it would remove rows a count in progress may be
/// reading, and the only effect would be to lower a counter at the wrong moment.
pub const ATTEMPT_RETENTION: Duration = Duration::seconds(WINDOW.whole_seconds().saturating_mul(2));

/// What one pass removed, per table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CleanupResult {
    pub sessions: u64,
    pub attempts: u64,
    /// Sign-ins abandoned between the password and the code — the flow sweeps on write, which only clears what a new
    /// sign-in pays for; on an instance nobody signs into, the rows would sit until one did.
    pub challenges: u64,
    /// The closed windows of the limits counted across instances — one row per address and window.
    pub rate_windows: u64,
}

/// `SessionCleanupService`.
#[derive(Debug)]
pub struct SessionCleanup<D, T, W> {
    sessions: D,
    store: T,
    windows: RateWindows<W>,
    clock: SharedClock,
}

impl<D: SessionDoor, T: SignInStore, W: RateWindowStore> SessionCleanup<D, T, W> {
    pub fn new(sessions: D, store: T, windows: W, clock: SharedClock) -> SessionCleanup<D, T, W> {
        SessionCleanup { sessions, store, windows: RateWindows::new(windows, clock.clone()), clock }
    }

    /// Never fails: see the module's note. No transaction: each statement carries its own, so one failing rolls back
    /// none of the others.
    pub async fn prune(&self) -> CleanupResult {
        CleanupResult {
            sessions: skipped(self.sessions.purge_expired().await, "Session purge"),
            attempts: skipped(
                self.store.delete_attempts_before(self.clock.now().saturating_sub(ATTEMPT_RETENTION)).await,
                "Login attempt purge",
            ),
            challenges: skipped(self.store.delete_expired_challenges(self.clock.now()).await, "MFA challenge purge"),
            rate_windows: skipped(self.windows.purge_closed().await, "Rate window purge"),
        }
    }
}

fn skipped(outcome: Result<u64, StoreError>, what: &str) -> u64 {
    outcome.unwrap_or_else(|failed| {
        tracing::warn!("{what} skipped: {failed}");
        0
    })
}

/// `SessionCleanupTask`: [`SessionCleanup::prune`] in the hourly turn, at `SESSION_CLEANUP`.
#[derive(Debug)]
pub struct SessionCleanupTask<D, T, W>(pub SessionCleanup<D, T, W>);

impl<D, T, W> MaintenanceTask for SessionCleanupTask<D, T, W>
where
    D: SessionDoor + 'static,
    T: SignInStore + 'static,
    W: RateWindowStore + 'static,
{
    fn sequence(&self) -> Sequence {
        Sequence::SessionCleanup
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            let pruned = self.0.prune().await;
            tracing::debug!(?pruned, "Authentication tables pruned");
            Ok(())
        })
    }
}

/// The module's maintenance task, as the binary composes it: the sessions through the credentials, the rest on the
/// database.
pub fn session_cleanup_task(
    credentials: Arc<CredentialService>,
    db: Db,
    clock: SharedClock,
) -> Arc<dyn MaintenanceTask> {
    let store = SqlSignInStore::new(db);
    Arc::new(SessionCleanupTask(SessionCleanup::new(credentials, store.clone(), store, clock)))
}
