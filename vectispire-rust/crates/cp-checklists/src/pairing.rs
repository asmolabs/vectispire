//! `VersionPairing`: how a new version's items relate to the previous version's — which decides what happens to a
//! project's answers when it moves to the new version (decision 0032 §4).
//!
//! Same key and same digest is unchanged (the answer carried as current), same key and another digest is changed
//! (a carried answer waits for a confirmation), a key only the new version has is added, one only the previous has
//! is removed. A control reworded is, to a key derived from its text, one line removed and another added, so the
//! importer may pair the two by hand: the new item takes the old key and is changed, always.

use std::collections::{BTreeMap, BTreeSet};

use crate::item::{ChecklistItem, ItemKey};
use crate::{Defect, Failure, refused};

/// What became of one item between the two versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Unchanged {
        previous: ChecklistItem,
        next: ChecklistItem,
    },
    /// `paired_by_hand`: the importer said these two are one control; `next` carries the old key.
    Changed {
        previous: ChecklistItem,
        next: ChecklistItem,
        paired_by_hand: bool,
    },
    Added {
        next: ChecklistItem,
    },
    Removed {
        previous: ChecklistItem,
    },
}

/// "The new version's item `added` is the previous version's `removed`, reworded."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualPair {
    pub added: ItemKey,
    pub removed: ItemKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPairing {
    /// The new version's items in their order, then the removed ones in theirs.
    pub changes: Vec<Change>,
    /// The new version's items, re-keyed where paired by hand.
    pub next: Vec<ChecklistItem>,
}

impl VersionPairing {
    /// Pairs two versions' items; each pair made by hand must join an item only the new version has with one only
    /// the previous version has, and each item may be paired once.
    pub fn of(
        previous: &[ChecklistItem],
        next: &[ChecklistItem],
        by_hand: &[ManualPair],
    ) -> Result<VersionPairing, Failure> {
        let before = index(previous)?;
        let after = index(next)?;
        let mut renamed: BTreeMap<&ItemKey, &ItemKey> = BTreeMap::new();
        let mut claimed: BTreeSet<&ItemKey> = BTreeSet::new();
        for pair in by_hand {
            if !after.contains_key(&pair.added) || before.contains_key(&pair.added) {
                return Err(refused(format!(
                    "An item paired by hand must be one the new version adds; {} is not.",
                    describe(&pair.added, &after)
                ))
                .into());
            }
            if !before.contains_key(&pair.removed) || after.contains_key(&pair.removed) {
                return Err(refused(format!(
                    "An item paired by hand must be one the new version removes; {} is not.",
                    describe(&pair.removed, &before)
                ))
                .into());
            }
            if renamed.contains_key(&pair.added) {
                return Err(refused(format!("{} is paired twice.", describe(&pair.added, &after))).into());
            }
            renamed.insert(&pair.added, &pair.removed);
            if !claimed.insert(&pair.removed) {
                return Err(refused(format!("{} is paired twice.", describe(&pair.removed, &before))).into());
            }
        }
        let mut changes = Vec::new();
        let mut rekeyed = Vec::new();
        for item in next {
            if let Some(&old_key) = renamed.get(&item.key) {
                let paired = item.with_key(old_key.clone());
                if let Some(&was) = before.get(old_key) {
                    changes.push(Change::Changed { previous: was.clone(), next: paired.clone(), paired_by_hand: true });
                }
                rekeyed.push(paired);
                continue;
            }
            rekeyed.push(item.clone());
            match before.get(&item.key) {
                None => changes.push(Change::Added { next: item.clone() }),
                Some(&was) if was.content_digest() == item.content_digest() => {
                    changes.push(Change::Unchanged { previous: was.clone(), next: item.clone() });
                }
                Some(&was) => {
                    changes.push(Change::Changed { previous: was.clone(), next: item.clone(), paired_by_hand: false });
                }
            }
        }
        for item in previous {
            if !after.contains_key(&item.key) && !claimed.contains(&item.key) {
                changes.push(Change::Removed { previous: item.clone() });
            }
        }
        Ok(VersionPairing { changes, next: rekeyed })
    }
}

fn index(items: &[ChecklistItem]) -> Result<BTreeMap<&ItemKey, &ChecklistItem>, Defect> {
    let mut by_key = BTreeMap::new();
    for item in items {
        if by_key.insert(&item.key, item).is_some() {
            return Err(Defect(format!("A version holds one item per key; ItemKey[value={}] twice", item.key.value())));
        }
    }
    Ok(by_key)
}

/// An item as the importer saw it — its row — rather than a key they never saw.
fn describe(key: &ItemKey, items: &BTreeMap<&ItemKey, &ChecklistItem>) -> String {
    items
        .get(key)
        .map_or_else(|| "an item that does not exist".to_owned(), |item| format!("the item on row {}", item.row))
}
