//! The integrations' registry (decision 0040) — `Integrations`: which outside systems this installation may talk to,
//! and the refusal every adapter's entry calls before it does.
//!
//! **In `settings`, the foundation**, because every module owning an adapter — forges, SIEM, AI, notifications,
//! trackers — has to ask it. It uses nothing but its own table (`t_integration`, V94). The governor's gesture — the
//! audit entry, the SIEM signal — is the platform module's, which may use the audit log.
//!
//! **A key without a row is disabled.** V94 seeded every integration that existed when the registry was introduced,
//! enabled; one added later has no row and reads off until a governor enables it, so an upgrade never widens what an
//! installation reaches (0040 §5). A row whose key no integration has any more is ignored.
//!
//! **What is in use is not switched off** (0040 §3). The registry asks every [`InUse`] the modules above it contribute
//! and refuses with [`IntegrationsError::InUse`]; the question is asked in the switch's own transaction, once the row
//! is locked `for update`, and a configuration that starts using the integration takes the same row `for share`
//! ([`Integrations::hold_enabled`]) — so no configuration can start using it between the answer and the switch.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Mode, Tx};
use vectispire_domain::integrations::Integration;

use crate::persistence::{self, DbError, IntegrationRow};

/// What a module's answer to [`InUse`] returns.
pub type InUseFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<String>, Box<dyn std::error::Error + Send + Sync>>> + Send + 'a>>;

/// Port: a module whose configuration may be using an integration answers whether it is — what uses it and what to
/// change first, as the sentence the refusal ends with, or `None`. Declared here and implemented by the owner, which
/// sits above the foundation. Called inside the switch's transaction once the integration's row is locked.
pub trait InUse: Send + Sync {
    fn in_use<'a>(&'a self, tx: &'a mut Tx, integration: Integration) -> InUseFuture<'a>;
}

/// One integration as the registry answers it — `IntegrationView`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationView {
    /// `<family>.<name>`, the route's path segment.
    pub key: String,
    pub family: &'static str,
    pub name: &'static str,
    pub enabled: bool,
    /// When a governor last switched it; `None` while nobody has.
    pub updated_at: Option<OffsetDateTime>,
    /// Who did; `None` while nobody has, and for a reader who does not read governance.
    pub updated_by: Option<String>,
}

impl IntegrationView {
    /// The same entry without its author, for a reader the governance trail is not shown to.
    pub fn without_author(self) -> IntegrationView {
        IntegrationView { updated_by: None, ..self }
    }

    fn of(integration: Integration, row: Option<&IntegrationRow>) -> IntegrationView {
        IntegrationView {
            key: integration.key(),
            family: integration.family().wire_name(),
            name: integration.name(),
            enabled: row.is_some_and(|row| row.enabled),
            updated_at: row.and_then(|row| row.updated_at),
            updated_by: row.and_then(|row| row.updated_by.clone()),
        }
    }
}

/// What a switch did: the integration as it now stands, and whether this call changed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switched {
    pub integration: IntegrationView,
    pub changed: bool,
}

/// A refusal of the registry, or a failure.
#[derive(Debug, thiserror::Error)]
pub enum IntegrationsError {
    /// `IntegrationDisabledException`: 409 `integration-disabled`, naming the integration in the member `integration`.
    #[error("{}", .0.disabled_message(""))]
    Disabled(Integration),
    /// `IntegrationInUseException`: 409 `integration-in-use`; the sentence says what uses it.
    #[error("{}", .0.in_use_message(.1))]
    InUse(Integration, String),
    #[error(transparent)]
    Database(#[from] DbError),
    /// A module's answer to [`InUse`] failed: the switch is not made on a question nobody could answer.
    #[error("{0}")]
    Owner(String),
}

/// The registry.
#[derive(Clone)]
pub struct Integrations {
    db: Db,
    uses: Vec<Arc<dyn InUse>>,
    now: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
}

impl std::fmt::Debug for Integrations {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Integrations").field("uses", &self.uses.len()).finish_non_exhaustive()
    }
}

impl Integrations {
    /// `uses`: every module's answer to "is this integration in use"; `now`, the clock a switch is dated by.
    pub fn new(db: Db, uses: Vec<Arc<dyn InUse>>, now: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>) -> Integrations {
        Integrations { db, uses, now }
    }

    /// Every integration this version knows, in [`Integration::all`]'s order, with its state.
    pub async fn list(&self) -> Result<Vec<IntegrationView>, IntegrationsError> {
        let rows = persistence::integrations(&self.db).await?;
        Ok(Integration::all()
            .into_iter()
            .map(|integration| {
                let key = integration.key();
                IntegrationView::of(integration, rows.iter().find(|row| row.key == key))
            })
            .collect())
    }

    pub async fn is_enabled(&self, integration: Integration) -> Result<bool, IntegrationsError> {
        Ok(persistence::integration(&self.db, &integration.key()).await?.is_some_and(|row| row.enabled))
    }

    /// What an adapter's entry calls before it does anything — offers a form, opens a connection, sends.
    pub async fn require_enabled(&self, integration: Integration) -> Result<(), IntegrationsError> {
        if self.is_enabled(integration).await? { Ok(()) } else { Err(IntegrationsError::Disabled(integration)) }
    }

    /// What a configuration calls, in the transaction that writes it, before it starts using an integration: refused
    /// when it is off, and otherwise **held** until that transaction ends. Checked and not held, a save that read
    /// "enabled" and a governor's switch that read "not in use" could both commit and leave the configuration on a
    /// transport that is off. The row is read `for share`: the switch, which takes it `for update` before it asks
    /// [`InUse`], waits for the save and then sees it; a save that comes second waits and then reads "off".
    pub async fn hold_enabled(&self, tx: &mut Tx, integration: Integration) -> Result<(), IntegrationsError> {
        match persistence::lock_integration_for_use(tx, &integration.key()).await? {
            Some(true) => Ok(()),
            _ => Err(IntegrationsError::Disabled(integration)),
        }
    }

    /// Switches an integration on or off, attributing the change to `by`; the same state again changes nothing and
    /// writes nothing — the caller records an audit entry only for a change. Switching off an integration a module
    /// reports in use is refused, and changes nothing.
    ///
    /// The lock is the transaction's first statement: on MySQL's repeatable read the snapshot the owners' reads see
    /// is taken after it, so a configuration that committed while this switch waited for the row is read. A key with
    /// no row gets one when it is enabled.
    pub async fn switch_to(
        &self,
        integration: Integration,
        enabled: bool,
        by: &str,
    ) -> Result<Switched, IntegrationsError> {
        let key = integration.key();
        let mut tx = self.db.begin(Mode::ReadWrite).await.map_err(DbError::from)?;
        let switched = self.switch_in(&mut tx, integration, &key, enabled, by).await;
        match switched {
            Ok(switched) => {
                tx.commit().await.map_err(DbError::from)?;
                Ok(switched)
            }
            Err(refused) => {
                let _ = tx.rollback().await;
                Err(refused)
            }
        }
    }

    async fn switch_in(
        &self,
        tx: &mut Tx,
        integration: Integration,
        key: &str,
        enabled: bool,
        by: &str,
    ) -> Result<Switched, IntegrationsError> {
        let now = (self.now)();
        let changed = match persistence::lock_integration_for_switch(tx, key).await? {
            Some(current) => {
                if !enabled && current {
                    for owner in &self.uses {
                        let using = owner
                            .in_use(&mut *tx, integration)
                            .await
                            .map_err(|failed| IntegrationsError::Owner(failed.to_string()))?;
                        if let Some(using) = using {
                            return Err(IntegrationsError::InUse(integration, using));
                        }
                    }
                }
                persistence::switch_integration(tx, key, enabled, now, by).await? == 1
            }
            None if enabled => persistence::insert_integration(tx, key, now, by).await? == 1,
            // Absent reads disabled: switching it off is the same state again, and writes nothing.
            None => return Ok(Switched { integration: IntegrationView::of(integration, None), changed: false }),
        };
        let row = persistence::integration_in(tx, key).await?;
        Ok(Switched { integration: IntegrationView::of(integration, row.as_ref()), changed })
    }
}
