//! `ForgeTargets`: where and how a stored connection's requests go — one reading for the probe, the discovery and
//! the change-review reading, so that the address, the policy and the pinned CA they use are the ones the connection
//! was probed with. The address is derived again from the stored web address: the derivation is the rule.

use vectispire_cp_outbound::OutboundPolicy;
use vectispire_domain::bounded_text::Refused;
use vectispire_domain::forges::{ForgeAddress, ForgeKind};
use vectispire_domain::instant::Instant;
use vectispire_domain::pinned_ca::{PinnedCa, Subject};

use crate::persistence::ConnectionRow;

/// How the pinned CA's refusals name the field.
pub(crate) const CA: Subject = Subject { field: "The forge's CA", server: "the forge" };

/// A CA the server must chain to: what was read of it, and what the sender is handed.
#[derive(Debug, Clone)]
pub(crate) struct Trust {
    pub ca: PinnedCa,
    pub sending: vectispire_cp_outbound::PinnedCa,
}

impl Trust {
    pub(crate) fn of(ca: PinnedCa) -> Result<Trust, Refused> {
        let subject =
            vectispire_cp_outbound::pinned_ca::Subject { field: CA.field.to_owned(), server: CA.server.to_owned() };
        let sending =
            vectispire_cp_outbound::PinnedCa::read(Some(ca.pem()), &subject).map_err(|refused| Refused(refused.0))?;
        Ok(Trust { ca, sending })
    }
}

/// `ForgeClient.Target`: where and how to reach the forge.
#[derive(Debug, Clone)]
pub(crate) struct ForgeTarget {
    pub address: ForgeAddress,
    /// GitHub's organisation or user; `None` for GitLab.
    pub owner: Option<String>,
    pub policy: OutboundPolicy,
    pub trust: Option<Trust>,
}

impl ForgeTarget {
    pub(crate) fn sending(&self) -> Option<&vectispire_cp_outbound::PinnedCa> {
        self.trust.as_ref().map(|trust| &trust.sending)
    }

    /// The forge, for a reader: its edition and address.
    pub(crate) fn where_(&self) -> String {
        format!("{} at {}", self.address.edition.label(), self.address.base_url)
    }
}

/// `ForgeTargets.of`: the target of a stored connection.
pub(crate) fn of(row: &ConnectionRow, internal: bool, trust: Option<Trust>) -> Result<ForgeTarget, Refused> {
    let address = ForgeAddress::of(ForgeKind::parse(Some(&row.kind))?, Some(&row.base_url))?;
    Ok(ForgeTarget { address, owner: row.owner.clone(), policy: policy_of(internal), trust })
}

/// `ForgeTargets.storedCa`: the stored CA, checked current at every use — a lapsed CA must not vouch for the server.
pub(crate) fn stored_ca(row: &ConnectionRow, now: Instant) -> Result<Option<Trust>, Refused> {
    row.ca_pem.as_deref().map(|pem| PinnedCa::parse(Some(pem), now, &CA).and_then(Trust::of)).transpose()
}

/// `INTERNAL_ALLOWED` on the administrator's statement, `PUBLIC_ONLY` otherwise.
pub(crate) fn policy_of(internal: bool) -> OutboundPolicy {
    if internal { OutboundPolicy::InternalAllowed } else { OutboundPolicy::PublicOnly }
}
