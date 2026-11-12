//! `AssetTier`: how critical a target is — stored by its constant's name in `tier`, read by the SLA rules.

use crate::java;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetTier {
    Tier1MissionCritical,
    Tier2BusinessOperational,
    Tier3Internal,
}

impl AssetTier {
    /// In the enum's declaration order — `values()`, which the refusal lists.
    pub const ALL: [AssetTier; 3] =
        [AssetTier::Tier1MissionCritical, AssetTier::Tier2BusinessOperational, AssetTier::Tier3Internal];

    /// The constant's name: what the column stores and the routes send.
    pub fn name(self) -> &'static str {
        match self {
            AssetTier::Tier1MissionCritical => "TIER_1_MISSION_CRITICAL",
            AssetTier::Tier2BusinessOperational => "TIER_2_BUSINESS_OPERATIONAL",
            AssetTier::Tier3Internal => "TIER_3_INTERNAL",
        }
    }

    /// `byName`: `trim`, upper-cased (`Locale.ROOT`: a dotless `ı` is an `I` there as here), compared exactly.
    fn by_name(value: &str) -> Option<AssetTier> {
        let normalized = java::trim(value).to_uppercase();
        AssetTier::ALL.into_iter().find(|tier| tier.name() == normalized)
    }

    /// `fromString`: what a stored value reads as — the default for anything unreadable, since a row must load.
    pub fn from_string(value: Option<&str>) -> AssetTier {
        value
            .filter(|value| !java::is_blank(value))
            .and_then(AssetTier::by_name)
            .unwrap_or(AssetTier::Tier2BusinessOperational)
    }

    /// `fromInput`: what an operator asked for — blank is the default, anything else must name a tier or is refused
    /// with the list, rather than filed quietly under the default.
    pub fn from_input(value: Option<&str>) -> Result<AssetTier, String> {
        let Some(value) = value.filter(|value| !java::is_blank(value)) else {
            return Ok(AssetTier::Tier2BusinessOperational);
        };
        AssetTier::by_name(value).ok_or_else(|| {
            let names: Vec<&str> = AssetTier::ALL.iter().map(|tier| tier.name()).collect();
            format!("Unknown asset tier \"{}\". Expected one of: {}.", java::trim(value), names.join(", "))
        })
    }
}
