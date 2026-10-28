//! Component domain models: origin tracking, purl normalization, and inventory completion.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentOrigin {
    Scanner,
    Build,
    Both,
}

impl ComponentOrigin {
    pub fn of_stored(stored: Option<&str>) -> Self {
        match stored {
            Some("build") => ComponentOrigin::Build,
            Some("both") => ComponentOrigin::Both,
            _ => ComponentOrigin::Scanner,
        }
    }

    pub fn stored(&self) -> Option<&'static str> {
        match self {
            ComponentOrigin::Scanner => None,
            ComponentOrigin::Build => Some("build"),
            ComponentOrigin::Both => Some("both"),
        }
    }

    pub fn wire_name(&self) -> &'static str {
        match self {
            ComponentOrigin::Scanner => "scanner",
            ComponentOrigin::Build => "build",
            ComponentOrigin::Both => "both",
        }
    }

    pub fn from_build(&self) -> bool {
        matches!(self, ComponentOrigin::Build | ComponentOrigin::Both)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Purls;

impl Purls {
    /// Reduces a purl to `pkg:type/namespace/name`, lowercase, with no version and no qualifiers.
    pub fn normalize(purl: &str) -> String {
        let mut value = purl.trim();
        if let Some((head, _)) = value.split_once('?') {
            value = head;
        }
        if let Some((head, _)) = value.split_once('#') {
            value = head;
        }
        if let Some(pos) = value.rfind('@')
            && pos > 0
            && let Some((head, _)) = value.split_at_checked(pos)
        {
            value = head;
        }
        let lower = value.to_ascii_lowercase();
        lower.trim_end_matches('/').to_owned()
    }
}

/// A scanned row before completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedComponent {
    pub id: i64,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
}

/// What a completed row becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedComponent {
    pub id: i64,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub license: Option<String>,
}

/// A build component from CycloneDX.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildComponent {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub r#type: Option<String>,
    pub license: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryCompletionPlan {
    pub completed: Vec<CompletedComponent>,
    pub added: Vec<BuildComponent>,
}

#[derive(Debug, Clone, Copy)]
pub struct InventoryCompletion;

impl InventoryCompletion {
    pub fn of(scanned: &[ScannedComponent], build: &[BuildComponent]) -> InventoryCompletionPlan {
        let mut by_identity: BTreeMap<String, Vec<&BuildComponent>> = BTreeMap::new();
        for component in build {
            if let Some(ref p) = component.purl
                && !p.trim().is_empty()
            {
                let id = Purls::normalize(p);
                by_identity.entry(id).or_default().push(component);
            }
        }

        let mut used = BTreeSet::new();
        let mut completed = Vec::new();

        for row in scanned {
            let identity =
                row.purl.as_deref().and_then(|p| if p.trim().is_empty() { None } else { Some(Purls::normalize(p)) });

            let candidates = identity.and_then(|id| by_identity.get(&id));
            let Some(candidates) = candidates else {
                continue;
            };

            if candidates.is_empty() {
                continue;
            }

            let Some(chosen) = candidates
                .iter()
                .find(|candidate| {
                    if let Some(ref v) = row.version {
                        Self::stated(v) && candidate.version.as_deref() == Some(v.as_str())
                    } else {
                        false
                    }
                })
                .copied()
                .or_else(|| candidates.first().copied())
            else {
                continue;
            };

            // Index in build slice
            if let Some(idx) = build.iter().position(|b| std::ptr::eq(b, chosen)) {
                used.insert(idx);
            }

            let build_states = chosen.version.as_deref().map(Self::stated).unwrap_or(false);

            completed.push(CompletedComponent {
                id: row.id,
                version: if build_states { chosen.version.clone() } else { row.version.clone() },
                purl: if build_states && chosen.purl.is_some() { chosen.purl.clone() } else { row.purl.clone() },
                license: chosen.license.clone(),
            });
        }

        let mut added = Vec::new();
        for (idx, component) in build.iter().enumerate() {
            if !used.contains(&idx) {
                added.push(component.clone());
            }
        }

        InventoryCompletionPlan { completed, added }
    }

    fn stated(version: &str) -> bool {
        let trimmed = version.trim();
        !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("UNKNOWN")
    }
}
