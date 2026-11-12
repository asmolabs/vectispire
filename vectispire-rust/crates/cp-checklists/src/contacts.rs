//! `ContactProfiles`: the profiles a template's contact column names — the people a line is to be asked of, as
//! roles ("PO", "BA", "Arch") — which a project links to its accounts (decision 0044).
//!
//! Read from the cells, never from a list written here: every value the column holds is a profile but `AUTO`, which
//! marks a line Vectispire measures. One cell may name several, split on `/`; each part is compared without case or
//! spacing, and shown as first written.

use vectispire_domain::java;

use crate::text;

/// The column's marker for a line Vectispire measures, compared like a profile's key.
pub const AUTOMATIC: &str = "AUTO";

/// Within `t_checklist_contact.profile`: a contact cell holds at most 255 characters.
pub const MAX_KEY: usize = crate::item::ChecklistItem::MAX_CONTACT;

/// A profile: the key a link is stored and compared by, and the words a screen shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The label normalised and upper-cased.
    pub key: String,
    /// The first spelling the column used.
    pub label: String,
}

/// The profiles one contact cell names, in its order; none for a blank cell or `AUTO`.
pub fn of(contact: Option<&str>) -> Vec<Profile> {
    let Some(contact) = contact else { return Vec::new() };
    let mut named: Vec<Profile> = Vec::new();
    for part in contact.split('/') {
        let label = text::normalize(Some(part));
        if label.is_empty() {
            continue;
        }
        let key = key_of(Some(&label));
        if key != AUTOMATIC && !named.iter().any(|profile| profile.key == key) {
            named.push(Profile { key, label });
        }
    }
    named
}

/// Every profile the cells name, each once, in the order the column first names it.
pub fn of_all<'a>(contacts: impl IntoIterator<Item = &'a str>) -> Vec<Profile> {
    let mut named: Vec<Profile> = Vec::new();
    for contact in contacts {
        for profile in of(Some(contact)) {
            if !named.iter().any(|known| known.key == profile.key) {
                named.push(profile);
            }
        }
    }
    named
}

/// The keys one contact cell names — what a reminder groups a line under.
pub fn keys_of(contact: &str) -> Vec<String> {
    of(Some(contact)).into_iter().map(|profile| profile.key).collect()
}

/// The key of a profile as a person or a route names it; empty for a blank name, and for one holding a `/`.
pub fn key_of(name: Option<&str>) -> String {
    let normalized = text::normalize(name);
    if normalized.is_empty() || normalized.contains('/') {
        return String::new();
    }
    java::to_upper_root(&normalized)
}
