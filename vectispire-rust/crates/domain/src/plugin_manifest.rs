//! What a plugin manifest's rules say of a value another module names a plugin by.

use crate::bounded_text::Refused;
use crate::java;

/// `ManifestRules.MAX_ID`.
pub const MAX_ID: usize = 40;

/// `PluginManifest.requireId`: lowercase letters, digits and inner hyphens, 2 to [`MAX_ID`] characters — the id
/// enters every issue's fingerprint and is never renamed.
pub fn require_id(id: Option<&str>) -> Result<&str, Refused> {
    let id = id.unwrap_or("");
    let length = java::utf16_len(id);
    if !(2..=MAX_ID).contains(&length) {
        return Err(Refused(format!("A plugin id is 2 to {MAX_ID} characters.")));
    }
    let last = id.chars().count().saturating_sub(1);
    for (index, c) in id.chars().enumerate() {
        let alphanumeric = c.is_ascii_lowercase() || c.is_ascii_digit();
        let edge = index == 0 || index == last;
        if !alphanumeric && (edge || c != '-') {
            return Err(Refused(
                "A plugin id is lowercase letters, digits and inner hyphens: it enters every issue's fingerprint and is \
                 never renamed."
                    .to_owned(),
            ));
        }
    }
    Ok(id)
}
