//! `ForgeTokenWatch`: each forge connection's token expiry, announced fourteen days ahead and when it passes — once
//! per change, never every hour (decision 0037 §2).
//!
//! **What was said is kept in a row per connection** (`forge_token_announced:<id>`, outside the settings catalog) so
//! that a restart says nothing again; it is moved by a conditional update in the transaction that publishes, so that
//! of the instances whose hourly turns notice the same change one announces it, and the message commits with the
//! record that it was said. **The expiry only**: nothing here calls the forge.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use vectispire_cp_db::{Db, Mode, Tx};
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::Clock;
use vectispire_domain::forges::ForgeEdition;
use vectispire_domain::forges::expiry::Standing;
use vectispire_domain::token_alert::{Credential, Notice, TokenAlert};

use crate::error::ForgeError;
use crate::persistence::{self, ConnectionRow};
use crate::views::instant;

/// The settings row holding what was last said of a connection's token. A data contract: it must not move.
pub(crate) const ANNOUNCED: &str = "forge_token_announced:";

pub(crate) fn announced_key(connection_id: &str) -> String {
    format!("{ANNOUNCED}{connection_id}")
}

/// Where a token's change of state is told — `notifications`' listener on the Java side, which queues the audit
/// entry and a message per channel **in the caller's transaction**.
pub trait TokenAlerts: Send + Sync {
    fn publish<'a>(
        &'a self,
        tx: &'a mut Tx,
        alert: &'a TokenAlert,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// The watch.
pub struct ForgeTokenWatch {
    db: Db,
    settings: Settings,
    alerts: Arc<dyn TokenAlerts>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ForgeTokenWatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ForgeTokenWatch").finish_non_exhaustive()
    }
}

impl ForgeTokenWatch {
    pub fn new(db: Db, settings: Settings, alerts: Arc<dyn TokenAlerts>, clock: Arc<dyn Clock>) -> ForgeTokenWatch {
        ForgeTokenWatch { db, settings, alerts, clock }
    }

    /// Every connection's token compared with the clock, and each change announced: how many this instance
    /// announced. A connection whose announcement fails is logged and tried again next hour.
    pub async fn watch(&self) -> Result<usize, ForgeError> {
        let now = self.clock.now();
        let mut tx = persistence::read(&self.db).await?;
        let connections = persistence::connections(&mut tx).await?;
        tx.commit().await.map_err(persistence::StoreError::from)?;
        let mut announced = 0;
        for connection in &connections {
            match self.watch_one(connection, now).await {
                Ok(true) => announced += 1,
                Ok(false) => {}
                Err(failed) => tracing::warn!(
                    connection = %connection.id,
                    "The token of forge connection {} could not be checked: {failed}",
                    connection.id
                ),
            }
        }
        Ok(announced)
    }

    async fn watch_one(&self, connection: &ConnectionRow, now: time::OffsetDateTime) -> Result<bool, ForgeError> {
        let current = Notice::of(false, Standing::of(connection.token_expires_at.map(instant), instant(now)));
        let key = announced_key(&connection.id);
        let mut stored = self.settings.internal_value(&key).await?;
        if stored.is_none() {
            // The conditional update needs a row to arbitrate on; whoever inserts it, it starts as "nothing said".
            self.settings.store_internal_if_absent(&key, "").await?;
            stored = self.settings.internal_value(&key).await?;
        }
        let expected = stored.unwrap_or_default();
        let previous = Notice::read(Some(&expected));
        if previous == current {
            return Ok(false);
        }
        let alert = TokenAlert {
            credential: Credential::ForgeConnection,
            reference: connection.id.clone(),
            name: connection.name.clone(),
            where_: where_(connection),
            notice: current,
            previous,
            expires_at: connection.token_expires_at.map(instant),
            refused_status: None,
            refused_since: None,
            observed_at: instant(now),
        };
        let mut tx = self.db.begin(Mode::ReadWrite).await.map_err(persistence::StoreError::from)?;
        if !self.settings.replace_internal(&mut tx, &key, &expected, current.wire_name()).await? {
            tx.rollback().await.map_err(persistence::StoreError::from)?;
            return Ok(false);
        }
        self.alerts.publish(&mut tx, &alert).await.map_err(ForgeError::Unexpected)?;
        tx.commit().await.map_err(persistence::StoreError::from)?;
        let expires = connection.token_expires_at.map(crate::views::iso).unwrap_or_else(|| "null".to_owned());
        match current {
            Notice::ExpiresSoon => tracing::warn!(
                "The token of forge connection {} expires on {expires}: replace it before then.",
                connection.name
            ),
            Notice::Expired | Notice::Refused => {
                tracing::warn!("The token of forge connection {} expired on {expires}: replace it.", connection.name)
            }
            Notice::None => tracing::info!(
                "The token of forge connection {} is no longer expired nor about to expire.",
                connection.name
            ),
        }
        Ok(true)
    }
}

/// The forge, for a reader: its edition and address — never the token.
fn where_(connection: &ConnectionRow) -> String {
    let label = ForgeEdition::of_stored(&connection.edition)
        .map_or_else(|| connection.edition.clone(), |edition| edition.label().to_owned());
    format!("{label} at {}", connection.base_url)
}

/// The stand-in for `notifications`' listener until that module is ported: the alert's audit entry
/// (`TokenAlertAudit`), and through the log's hook its SIEM event — not the channels' messages, which are that module's.
/// Recorded by the log in a transaction of its own rather than queued in the caller's: there is no outbox handler for
/// it yet, and a message queued for nobody would never be relayed.
#[derive(Debug, Clone)]
pub struct AuditedAlerts(pub vectispire_cp_audit::AuditLog);

impl TokenAlerts for AuditedAlerts {
    fn publish<'a>(
        &'a self,
        _: &'a mut Tx,
        alert: &'a TokenAlert,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let operation = vectispire_cp_audit::AuditOperation::from_wire(alert.operation())
                .ok_or_else(|| format!("{} is no operation of the log", alert.operation()))?;
            self.0.record(vectispire_cp_audit::Record::of(operation, &alert.reference, &alert.sentence(), None)).await;
            Ok(())
        })
    }
}
