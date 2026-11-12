//! The SIEM export's answer to the registry (decision 0040 §3) — `SiemTransportInUse`: the transport an enabled export
//! sends over is in use, and the governor may not switch it off.
//!
//! **Refused rather than suspended**, unlike a forge: every audited action queues a security event in the outbox, and
//! with the transport off they would have nowhere to go — held, they would pile up unseen by the SOC; abandoned, lost
//! in silence, the failure decision 0025 exists to prevent. The security lead points the export elsewhere first, and
//! the collector being left hears it (`VECTI-SEC-028`).
//!
//! A disabled export uses no transport, whatever protocol its row still names. Called inside the switch's transaction,
//! after the integration's row is locked; the configuration is read `for share` so that a save still open is read as
//! it commits.

use vectispire_cp_db::Tx;
use vectispire_cp_settings::{InUse, InUseFuture};
use vectispire_domain::integrations::{Integration, IntegrationFamily};
use vectispire_domain::siem::SiemProtocol;

use crate::persistence;

/// The sentence the governor's refusal ends with.
pub const IN_USE: &str = "it is the transport the SIEM export sends over. Change the SIEM configuration first — \
another transport, or the export switched off: the security events queued in the outbox would otherwise have nowhere \
to go, and be lost in silence.";

/// The answer.
#[derive(Debug, Default)]
pub struct SiemTransportInUse;

impl InUse for SiemTransportInUse {
    fn in_use<'a>(&'a self, tx: &'a mut Tx, integration: Integration) -> InUseFuture<'a> {
        Box::pin(async move {
            if integration.family() != IntegrationFamily::Siem {
                return Ok(None);
            }
            let config = persistence::find_locked(tx).await?;
            Ok(config
                .filter(|(enabled, _)| *enabled)
                .and_then(|(_, protocol)| SiemProtocol::by_name(Some(&protocol)))
                .filter(|protocol| Integration::of_siem(*protocol) == integration)
                .map(|_| IN_USE.to_owned()))
        })
    }
}
