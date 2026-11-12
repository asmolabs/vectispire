//! `ChecklistText`: the one normalisation a template's words go through before they identify or fingerprint an
//! item.
//!
//! **A data contract, like an issue's fingerprint.** An item's key and its content digest are computed over this
//! form and stored; change a step and every stored key stops matching the one computed for the same words, so the
//! next version pairs nothing — every answer carried across it becomes a new line to answer from scratch.
//!
//! What it absorbs is what a workbook changes without anybody changing the words: NFKC; every run of whitespace,
//! separator or control character (Java's `[\p{javaWhitespace}\p{Z}\p{Cc}]+`) as one space; format characters
//! (`\p{Cf}`) removed; the ends stripped as `String.strip` strips. It keeps case.

use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;
use vectispire_domain::java;

/// The normalised form; `None` reads as the empty string, the same as a blank cell.
pub fn normalize(value: Option<&str>) -> String {
    let Some(value) = value else { return String::new() };
    let mut out = String::with_capacity(value.len());
    let mut in_space = false;
    for c in value.nfkc() {
        // Removed before the spaces are joined, as Java's two `replaceAll` run: "a\u{200b} b" is one space.
        if get_general_category(c) == GeneralCategory::Format {
            continue;
        }
        if is_space(c) {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c);
            in_space = false;
        }
    }
    java::strip(&out).to_owned()
}

/// `[\p{javaWhitespace}\p{Z}\p{Cc}]` — the separators and the controls: every character `Character.isWhitespace`
/// takes is one or the other, so Java's first class adds nothing to the two after it.
fn is_space(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::SpaceSeparator
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::Control
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_java_whitespace_is_a_separator_or_a_control() {
        for c in (0..=0x10_ffff).filter_map(char::from_u32) {
            assert!(!java::is_whitespace(c) || is_space(c), "{:04X}", u32::from(c));
        }
    }
}
