//! `Language`: what a census counts in a tree, what a SAST rule set reads and what a plugin manifest declares — one
//! vocabulary, in the enum's order, which is the order a set of them is written in.

use crate::java;

/// The wire names, in the enum's order.
pub const LANGUAGES: [&str; 24] = [
    "apex",
    "bash",
    "c",
    "clojure",
    "csharp",
    "dockerfile",
    "elixir",
    "go",
    "html",
    "java",
    "javascript",
    "json",
    "kotlin",
    "ocaml",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "solidity",
    "swift",
    "terraform",
    "typescript",
    "yaml",
];

/// One language, ordered as the enum orders it — a `BTreeSet<Language>` is Java's `EnumSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Language(u8);

impl Language {
    /// Every language, in the enum's order.
    pub fn all() -> impl Iterator<Item = Language> {
        (0..LANGUAGES.len()).filter_map(|index| u8::try_from(index).ok()).map(Language)
    }

    pub fn wire_name(self) -> &'static str {
        LANGUAGES.get(usize::from(self.0)).copied().unwrap_or("")
    }

    /// `Language.fromWireName`: trimmed as `String.trim` trims, lowered under `Locale.ROOT`, one of the wire names.
    pub fn from_wire_name(value: &str) -> Option<Language> {
        let normalized = java::to_lower_root(java::trim(value));
        Language::all().find(|language| language.wire_name() == normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_language_is_read_as_java_reads_it_and_ordered_as_the_enum() {
        assert_eq!(Language::from_wire_name(" Java ").map(Language::wire_name), Some("java"));
        assert_eq!(Language::from_wire_name("\u{a0}java"), None, "String.trim keeps a no-break space");
        assert!(Language::from_wire_name("go") < Language::from_wire_name("yaml"));
        assert_eq!(Language::all().count(), LANGUAGES.len());
    }
}
