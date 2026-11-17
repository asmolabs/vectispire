//! The OWASP Top 10 2021 category a CWE belongs to, by the standard's own lists — Java's `OwaspCwe`.
//!
//! **Not the guess `OwaspCoverage` refuses**: a CWE is the weakness the rule's author declared, and OWASP publishes for
//! each category the list of CWEs it maps ("List of Mapped CWEs", `github.com/OWASP/Top10` at `3a31f353`). Used only
//! where the rule declared no 2021 category of its own. Each list's length is the "CWEs Mapped" its page states.
//!
//! **One CWE appears in two lists**: CWE-259, hard-coded password, under A02 and A07. A02's page counts 29 and lists
//! 30, A07's counts 22 with it — so it is A07's, where a hard-coded secret (CWE-798) is filed too.
//!
//! **One difference from Java, named rather than hidden**: `java.util.regex`'s `\b` counts a non-spacing mark that
//! follows a letter or digit as part of the word, so `CWE-89` followed by a combining accent is no match there; the
//! ASCII boundary here, which `owasp_tag` uses for the same reason, matches it. Telling the two apart needs the
//! Unicode general category, which this crate — linked by the agent — does not carry. `reference/compliance/cwe.json`
//! holds the case, and the Rust test names it.

use std::sync::LazyLock;

use regex::Regex;

/// Category → its CWEs, in the standard's order. CWE-259 is under A07 only (see above).
const LISTS: [(&str, &[i32]); 10] = [
    (
        "A01",
        &[
            22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548,
            552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275,
        ],
    ),
    (
        "A02",
        &[
            261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347,
            523, 720, 757, 759, 760, 780, 818, 916,
        ],
    ),
    (
        "A03",
        &[
            20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184,
            470, 471, 564, 610, 643, 644, 652, 917,
        ],
    ),
    (
        "A04",
        &[
            73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501,
            522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173,
        ],
    ),
    ("A05", &[2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174]),
    ("A06", &[937, 1035, 1104]),
    (
        "A07",
        &[
            255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940,
            1216,
        ],
    ),
    ("A08", &[345, 353, 426, 494, 502, 565, 784, 829, 830, 915]),
    ("A09", &[117, 223, 532, 778]),
    ("A10", &[918]),
];

/// `\bCWE-(\d+)\b`, case-insensitive: ASCII boundaries and digits, as `java.util.regex` reads them since JDK 19, and
/// the letters spelt out because the domain's regex has no Unicode case folding to ask for.
static CWE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"(?-u:\b)[Cc][Ww][Ee]-([0-9]+)(?-u:\b)").expect("a fixed pattern")
});

/// The 2021 category of one CWE number, or nothing for a CWE no list names — `categoryOf`.
pub fn category_of(cwe: i32) -> Option<&'static str> {
    LISTS.iter().find(|(_, cwes)| cwes.contains(&cwe)).map(|(category, _)| *category)
}

/// The category of the first CWE in a declaration that maps to one — `categoryOfDeclaration`, on the form the
/// upstream rules write (`"CWE-89: Improper Neutralization…"`). The first, as `owasp_tag` takes the first category:
/// one finding, one category. A number no `int` holds names nothing, as `Integer.parseInt` refuses it.
pub fn category_of_declaration(declaration: &str) -> Option<&'static str> {
    CWE.captures_iter(declaration)
        .filter_map(|found| found.get(1))
        .filter_map(|digits| digits.as_str().parse::<i32>().ok())
        .find_map(category_of)
}

/// How many CWEs the table maps to one category — what `OwaspCweTest` holds to each page's figure.
pub fn mapped_to(category: &str) -> usize {
    LISTS.iter().filter(|(listed, _)| *listed == category).map(|(_, cwes)| cwes.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_category_maps_as_many_cwes_as_its_page_says_and_none_twice() {
        let stated = [
            ("A01", 34),
            ("A02", 29),
            ("A03", 33),
            ("A04", 40),
            ("A05", 20),
            ("A06", 3),
            ("A07", 22),
            ("A08", 10),
            ("A09", 4),
            ("A10", 1),
        ];
        for (category, count) in stated {
            assert_eq!(mapped_to(category), count, "{category}");
        }
        let mut every: Vec<i32> = LISTS.iter().flat_map(|(_, cwes)| cwes.iter().copied()).collect();
        let total = every.len();
        every.sort_unstable();
        every.dedup();
        assert_eq!(every.len(), total, "a CWE in two lists would count a finding twice");
    }

    #[test]
    fn the_hard_coded_password_is_a07_s() {
        assert_eq!(category_of(259), Some("A07"));
        assert_eq!(category_of(798), Some("A07"));
        assert_eq!(category_of_declaration("CWE-1078, then CWE-22"), Some("A01"));
        assert_eq!(category_of_declaration("ACWE-89"), None);
        assert_eq!(category_of_declaration("CWE-99999999999"), None);
    }
}
