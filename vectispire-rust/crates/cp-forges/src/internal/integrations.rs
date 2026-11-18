//! `ForgeIntegrations`: the forges' side of the integrations' registry (decision 0040 §1–2) — which forge kinds this
//! installation talks to, asked at the entries that hand a forge its token (the probe, a discovery's opening, the
//! change-review reading) and at the import, which acts on what a forge said. **Nothing is written when a forge is
//! switched off**: a connection of a disabled kind reads `suspended` because this says so at every read.

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_settings::{Integrations, IntegrationsError};
use vectispire_domain::forges::ForgeKind;
use vectispire_domain::integrations::Integration;

/// The registry's integration of a forge kind.
pub(crate) fn integration(kind: ForgeKind) -> Integration {
    Integration::by_key(&kind.integration_key()).unwrap_or_else(|| unreachable!("every forge kind is an integration"))
}

#[derive(Clone)]
pub(crate) struct ForgeIntegrations {
    registry: Arc<Integrations>,
}

impl std::fmt::Debug for ForgeIntegrations {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ForgeIntegrations")
    }
}

impl ForgeIntegrations {
    pub(crate) fn new(registry: Arc<Integrations>) -> ForgeIntegrations {
        ForgeIntegrations { registry }
    }

    pub(crate) async fn enabled(&self, kind: ForgeKind) -> Result<bool, IntegrationsError> {
        self.registry.is_enabled(integration(kind)).await
    }

    /// 409 `integration-disabled`, naming `forge.<kind>`.
    pub(crate) async fn require_enabled(&self, kind: ForgeKind) -> Result<(), IntegrationsError> {
        self.registry.require_enabled(integration(kind)).await
    }

    /// The forge kinds switched off, read once for a turn or a listing.
    pub(crate) async fn disabled(&self) -> Result<BTreeSet<ForgeKind>, IntegrationsError> {
        let mut disabled = BTreeSet::new();
        for kind in ForgeKind::ALL {
            if !self.enabled(kind).await? {
                disabled.insert(kind);
            }
        }
        Ok(disabled)
    }
}

/// The registry's keys of these kinds, for a log line: `forge.github, forge.gitlab`.
pub(crate) fn keys(kinds: &BTreeSet<ForgeKind>) -> String {
    kinds.iter().map(|kind| kind.integration_key()).collect::<Vec<_>>().join(", ")
}

/// `ForgeIntegrations.suspension`: why a line fed by a connection of this kind has no data, naming the route that
/// re-enables it.
pub(crate) fn suspension(kind: ForgeKind) -> String {
    let key = kind.integration_key();
    format!(
        "the {key} integration is disabled: the forge connection is suspended and its change reviews are not read; a \
         platform governor re-enables it with PUT /api/v1/integrations/{key}/enabled"
    )
}
