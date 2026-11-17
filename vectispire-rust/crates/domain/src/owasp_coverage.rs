//! Where this product's findings land in the OWASP Top 10, by rule — Java's `OwaspCoverage`.
//!
//! This first part is the placement alone: the categories, the types placed by rule, and the one
//! type that declares its category on the issue. The backlog's `owasp_category` filter places with
//! it, and so do the grid and the weekly flows, so the list a figure opens holds what the figure
//! counted. Comparing the issue's `owasp_category` column alone — what the port did before — put a
//! vulnerability nowhere (it is A06 with no column) and counted a plugin's self-declared category.

use crate::finding_type::FindingType;

/// The 2021 edition, in the standard's order: the order a questionnaire reads the grid in.
pub const CATEGORIES: [(&str, &str); 10] = [
    ("A01", "Broken Access Control"),
    ("A02", "Cryptographic Failures"),
    ("A03", "Injection"),
    ("A04", "Insecure Design"),
    ("A05", "Security Misconfiguration"),
    ("A06", "Vulnerable and Outdated Components"),
    ("A07", "Identification and Authentication Failures"),
    ("A08", "Software and Data Integrity Failures"),
    ("A09", "Security Logging and Monitoring Failures"),
    ("A10", "Server-Side Request Forgery"),
];

/// The finding types that place a finding in a category, by rule — Java's `BY_TYPE`.
const BY_TYPE: &[(FindingType, &str)] = &[
    (FindingType::Iac, "A05"),
    (FindingType::Vulnerability, "A06"),
    (FindingType::Eol, "A06"),
    (FindingType::Secret, "A07"),
];

/// The one type whose findings carry their category on the issue rather than in the type: code
/// analysis. A plugin's or an import's finding carrying a category is not placed.
pub const DECLARES_ITS_CATEGORY: FindingType = FindingType::Sast;

/// Whether `code` (already upper-cased) is one of the ten.
pub fn is_category(code: &str) -> bool {
    CATEGORIES.iter().any(|(known, _)| *known == code)
}

/// The ten codes, in order.
pub fn codes() -> impl Iterator<Item = &'static str> {
    CATEGORIES.iter().map(|(code, _)| *code)
}

/// The category a finding of this type belongs to, or nothing when no rule places it.
pub fn category_of(type_: FindingType) -> Option<&'static str> {
    BY_TYPE.iter().find(|(placed, _)| *placed == type_).map(|(_, category)| *category)
}

/// The wire names of the types placed in this category, sorted — empty for one only code analysis reaches.
pub fn types_placed_in(category: &str) -> Vec<&'static str> {
    let mut types: Vec<&'static str> =
        BY_TYPE.iter().filter(|(_, placed)| *placed == category).map(|(type_, _)| type_.wire_name()).collect();
    types.sort_unstable();
    types
}

/// The wire names of the types placed somewhere, sorted.
pub fn types_placed_anywhere() -> Vec<&'static str> {
    let mut types: Vec<&'static str> = BY_TYPE.iter().map(|(type_, _)| type_.wire_name()).collect();
    types.sort_unstable();
    types.dedup();
    types
}

/// Where in the Top 10 a backlog query asks an issue to be placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwaspPlacement {
    /// In one category, `A01`…`A10`.
    In(String),
    /// In any of the ten.
    Anywhere,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_types_are_placed_as_java_places_them() {
        assert_eq!(types_placed_in("A06"), vec!["eol", "vulnerability"]);
        assert_eq!(types_placed_in("A05"), vec!["iac"]);
        assert_eq!(types_placed_in("A07"), vec!["secret"]);
        assert!(types_placed_in("A03").is_empty(), "only code analysis reaches injection");
        assert_eq!(types_placed_anywhere(), vec!["eol", "iac", "secret", "vulnerability"]);
        assert_eq!(category_of(FindingType::Sast), None);
        assert_eq!(category_of(FindingType::Plugin), None);
    }

    #[test]
    fn the_ten_are_in_the_standards_order() {
        assert_eq!(codes().collect::<Vec<_>>(), ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]);
        assert!(is_category("A10"));
        assert!(!is_category("A11"));
    }
}
