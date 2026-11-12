//! `MavenVersion` and `MavenVersionRange`: a Maven version ordered as `ComparableVersion` in `maven-artifact` 3.9
//! orders it, and the range syntax a checklist's component rule allows versions with.
//!
//! **The order judges a line.** `[1.0,2.0)` admitting `2.0-RC1` wrongly passes a line on a build nobody released, so
//! the qualifiers are ranked exactly as Maven ranks them, and held to Java's answers in `reference/checklists/`
//! (every pair of a few hundred versions): `alpha < beta < milestone < rc = cr < snapshot < "" = ga = final = release
//! < sp`, an unknown qualifier after them all, a number after any qualifier at its place, trailing zeros and release
//! qualifiers dropped. A number is any run of `Character.isDigit` characters — `１.０` is `1.0` — compared by value,
//! however long.

use std::cmp::Ordering;
use std::fmt;

use crate::bounded_text::{Refused, clip};
use crate::java;

/// A version as Maven orders it; displayed as it was written.
#[derive(Debug, Clone)]
pub struct MavenVersion {
    written: String,
    items: Vec<Item>,
}

#[derive(Debug, Clone)]
enum Item {
    /// Its decimal digits, ASCII, without leading zeros: `""` is zero.
    Int(String),
    Str(String),
    List(Vec<Item>),
}

const QUALIFIERS: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];
/// `String.valueOf(QUALIFIERS.indexOf(""))`.
const RELEASE: &str = "5";

impl MavenVersion {
    /// `MavenVersion.of`: parsed from the version stripped (`String.strip`).
    pub fn of(version: &str) -> MavenVersion {
        MavenVersion { written: version.to_owned(), items: parse(java::strip(version)) }
    }
}

impl fmt::Display for MavenVersion {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.written)
    }
}

impl PartialEq for MavenVersion {
    fn eq(&self, other: &MavenVersion) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for MavenVersion {}

impl PartialOrd for MavenVersion {
    fn partial_cmp(&self, other: &MavenVersion) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MavenVersion {
    fn cmp(&self, other: &MavenVersion) -> Ordering {
        compare_lists(&self.items, &other.items)
    }
}

// ------------------------------------------------------------------ parsing

/// The lists as `parse` builds them: Java nests mutable lists and normalises each once the version is read,
/// innermost first. Here they live in an arena, in the order they were opened, and each item names a list by its
/// index there; normalising in reverse order of opening is the stack's order.
enum Built {
    Int(String),
    Str(String),
    List(usize),
}

fn parse(version: &str) -> Vec<Item> {
    let lower: Vec<char> = java::to_lower_root(version).chars().collect();
    let mut lists: Vec<Vec<Built>> = vec![Vec::new()];
    let mut list = 0usize;
    let mut digit = false;
    let mut start = 0usize;
    let text = |from: usize, to: usize| -> String { lower.get(from..to).unwrap_or_default().iter().collect() };
    let open = |lists: &mut Vec<Vec<Built>>, parent: usize| -> usize {
        lists.push(Vec::new());
        let sub = lists.len().saturating_sub(1);
        if let Some(items) = lists.get_mut(parent) {
            items.push(Built::List(sub));
        }
        sub
    };
    let add = |lists: &mut Vec<Vec<Built>>, at: usize, item: Built| {
        if let Some(items) = lists.get_mut(at) {
            items.push(item);
        }
    };
    for (index, &c) in lower.iter().enumerate() {
        if c == '.' {
            add(&mut lists, list, if index == start { zero() } else { item(digit, &text(start, index)) });
            start = index.saturating_add(1);
        } else if c == '-' {
            add(&mut lists, list, if index == start { zero() } else { item(digit, &text(start, index)) });
            start = index.saturating_add(1);
            list = open(&mut lists, list);
        } else if java::digit(c).is_some() {
            if !digit && index > start {
                // The same for a qualifier a digit follows: 1.0.0.M1 is 1-milestone-1, not 1.0.0.milestone-1.
                if lists.get(list).is_some_and(|items| !items.is_empty()) {
                    list = open(&mut lists, list);
                }
                add(&mut lists, list, Built::Str(string_item(&text(start, index), true)));
                start = index;
                list = open(&mut lists, list);
            }
            digit = true;
        } else {
            if digit && index > start {
                add(&mut lists, list, item(true, &text(start, index)));
                start = index;
                list = open(&mut lists, list);
            }
            digit = false;
        }
    }
    if lower.len() > start {
        // A qualifier after a dot reads as after a dash: 1.0.0.X1 < 1.0.0-X2.
        if !digit && lists.get(list).is_some_and(|items| !items.is_empty()) {
            list = open(&mut lists, list);
        }
        add(&mut lists, list, item(digit, &text(start, lower.len())));
    }
    let mut built: Vec<Option<Vec<Item>>> = (0..lists.len()).map(|_| None).collect();
    for index in (0..lists.len()).rev() {
        let items = std::mem::take(lists.get_mut(index).unwrap_or(&mut Vec::new()));
        let mut finished: Vec<Item> = items
            .into_iter()
            .map(|item| match item {
                Built::Int(digits) => Item::Int(digits),
                Built::Str(text) => Item::Str(text),
                // Opened after this one, so already normalised.
                Built::List(sub) => Item::List(built.get_mut(sub).and_then(Option::take).unwrap_or_default()),
            })
            .collect();
        normalize(&mut finished);
        if let Some(slot) = built.get_mut(index) {
            *slot = Some(finished);
        }
    }
    built.into_iter().next().flatten().unwrap_or_default()
}

fn zero() -> Built {
    Built::Int(String::new())
}

fn item(digit: bool, text: &str) -> Built {
    if digit {
        // `new BigInteger(text)`: every character a decimal digit of some script, read by its value.
        let digits: String =
            text.chars().filter_map(java::digit).filter_map(|value| char::from_digit(value, 10)).collect();
        Built::Int(digits.trim_start_matches('0').to_owned())
    } else {
        Built::Str(string_item(text, false))
    }
}

/// `new StringItem(value, followedByDigit)`: a lone `a`, `b` or `m` before a digit is its qualifier, then the
/// aliases.
fn string_item(value: &str, followed_by_digit: bool) -> String {
    let value = if followed_by_digit && java::utf16_len(value) == 1 {
        match value {
            "a" => "alpha",
            "b" => "beta",
            "m" => "milestone",
            other => other,
        }
    } else {
        value
    };
    match value {
        "ga" | "final" | "release" => String::new(),
        "cr" => "rc".to_owned(),
        other => other.to_owned(),
    }
}

/// Trailing zeros and release qualifiers dropped, up to the first item that is neither nor a list.
fn normalize(items: &mut Vec<Item>) {
    let mut index = items.len();
    while index > 0 {
        index = index.saturating_sub(1);
        let Some(last) = items.get(index) else { break };
        if is_null(last) {
            items.remove(index);
        } else if !matches!(last, Item::List(_)) {
            break;
        }
    }
}

// ------------------------------------------------------------------ ordering

fn comparable(qualifier: &str) -> String {
    QUALIFIERS
        .iter()
        .position(|known| *known == qualifier)
        .map_or_else(|| format!("{}-{qualifier}", QUALIFIERS.len()), |index| index.to_string())
}

fn is_null(item: &Item) -> bool {
    match item {
        Item::Int(digits) => digits.is_empty(),
        Item::Str(text) => comparable(text) == RELEASE,
        Item::List(items) => items.is_empty(),
    }
}

/// An item against an absent one: what a shorter version has where this one goes on.
fn compare_to_absent(item: &Item) -> Ordering {
    match item {
        Item::Int(digits) => {
            if digits.is_empty() {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        Item::Str(text) => java::compare_utf16(&comparable(text), RELEASE),
        // Every item against absence, not the first alone (MNG-6964): 1-0.1 is after 1.
        Item::List(items) => {
            items.iter().map(compare_to_absent).find(|order| *order != Ordering::Equal).unwrap_or(Ordering::Equal)
        }
    }
}

fn compare(left: &Item, right: &Item) -> Ordering {
    match (left, right) {
        (Item::Int(a), Item::Int(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
        (Item::Int(_), _) => Ordering::Greater,
        (Item::Str(_), Item::Int(_) | Item::List(_)) => Ordering::Less,
        (Item::Str(a), Item::Str(b)) => java::compare_utf16(&comparable(a), &comparable(b)),
        (Item::List(_), Item::Int(_)) => Ordering::Less,
        (Item::List(_), Item::Str(_)) => Ordering::Greater,
        (Item::List(a), Item::List(b)) => compare_lists(a, b),
    }
}

fn compare_lists(left: &[Item], right: &[Item]) -> Ordering {
    let mut left = left.iter();
    let mut right = right.iter();
    loop {
        let order = match (left.next(), right.next()) {
            (None, None) => return Ordering::Equal,
            (Some(l), None) => compare_to_absent(l),
            (None, Some(r)) => compare_to_absent(r).reverse(),
            (Some(l), Some(r)) => compare(l, r),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
}

// ------------------------------------------------------------------ ranges

/// A Maven version range — `[1.17,2.0)`, `[1.17.7]`, `(,2.0)`, `[1.0,1.2],[1.5,)` — and whether a version is in it.
///
/// What Maven refuses is refused, in words; so is what Maven reads and nobody means — a range that admits no
/// version, an unbounded side behind a square bracket, a bare version (Maven's "this, or anything").
#[derive(Debug, Clone)]
pub struct MavenVersionRange {
    written: String,
    restrictions: Vec<Restriction>,
}

#[derive(Debug, Clone)]
struct Restriction {
    lower: Option<MavenVersion>,
    lower_inclusive: bool,
    upper: Option<MavenVersion>,
    upper_inclusive: bool,
}

impl Restriction {
    fn contains(&self, version: &MavenVersion) -> bool {
        if let Some(lower) = &self.lower {
            let order = version.cmp(lower);
            if order == Ordering::Less || order == Ordering::Equal && !self.lower_inclusive {
                return false;
            }
        }
        if let Some(upper) = &self.upper {
            let order = version.cmp(upper);
            return order == Ordering::Less || order == Ordering::Equal && self.upper_inclusive;
        }
        true
    }
}

impl MavenVersionRange {
    /// Whether the text is written as a range: it opens, once stripped, with a bracket or a parenthesis.
    pub fn looks_like_range(spec: Option<&str>) -> bool {
        let text = java::strip(spec.unwrap_or(""));
        text.starts_with('[') || text.starts_with('(')
    }

    /// The range, or a refusal saying what is wrong with it.
    pub fn parse(spec: Option<&str>) -> Result<MavenVersionRange, Refused> {
        let text = java::strip(spec.unwrap_or(""));
        if !MavenVersionRange::looks_like_range(Some(text)) {
            return Err(refused(text, "a range opens with [ or ("));
        }
        let mut restrictions: Vec<Restriction> = Vec::new();
        let mut rest = text;
        while rest.starts_with('[') || rest.starts_with('(') {
            let close = first_close(rest).ok_or_else(|| refused(text, "a range closes with ] or )"))?;
            let restriction = restriction(text, rest.get(..=close).unwrap_or(""))?;
            if let Some(previous) = restrictions.last() {
                let (Some(upper), Some(lower)) = (&previous.upper, &restriction.lower) else {
                    return Err(refused(
                        text,
                        "its ranges overlap — an unbounded side can only be the first range's lower or the last one's \
                         upper",
                    ));
                };
                let order = upper.cmp(lower);
                if order == Ordering::Greater
                    || order == Ordering::Equal && previous.upper_inclusive && restriction.lower_inclusive
                {
                    return Err(refused(
                        text,
                        "its ranges overlap or are out of order — write them from the lowest up",
                    ));
                }
            }
            restrictions.push(restriction);
            rest = java::strip(rest.get(close.saturating_add(1)..).unwrap_or(""));
            if let Some(after) = rest.strip_prefix(',') {
                rest = java::strip(after);
                if rest.is_empty() {
                    return Err(refused(text, "a comma between ranges is followed by another range"));
                }
            }
        }
        if !rest.is_empty() {
            return Err(refused(
                text,
                &format!(
                    "\"{}\" follows the ranges — a version allowed on its own is a separate entry of the list",
                    clip(Some(rest), 40).unwrap_or("")
                ),
            ));
        }
        Ok(MavenVersionRange { written: text.to_owned(), restrictions })
    }

    /// The range when the text is one, `None` otherwise — never a refusal: for text stored before.
    pub fn read(spec: Option<&str>) -> Option<MavenVersionRange> {
        if !MavenVersionRange::looks_like_range(spec) {
            return None;
        }
        MavenVersionRange::parse(spec).ok()
    }

    pub fn contains(&self, version: &str) -> bool {
        let candidate = MavenVersion::of(version);
        self.restrictions.iter().any(|restriction| restriction.contains(&candidate))
    }
}

impl fmt::Display for MavenVersionRange {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.written)
    }
}

fn first_close(text: &str) -> Option<usize> {
    match (text.find(']'), text.find(')')) {
        (None, round) => round,
        (square, None) => square,
        (Some(square), Some(round)) => Some(square.min(round)),
    }
}

fn restriction(whole: &str, spec: &str) -> Result<Restriction, Refused> {
    let lower_inclusive = spec.starts_with('[');
    let upper_inclusive = spec.ends_with(']');
    // Both ends are one ASCII byte: the bracket that opened it and the one `first_close` found.
    let inner = java::strip(spec.get(1..spec.len().saturating_sub(1)).unwrap_or(""));
    let Some(comma) = inner.find(',') else {
        if !lower_inclusive || !upper_inclusive {
            return Err(refused(whole, "a single version is written in square brackets, [1.0]"));
        }
        let only = bound(whole, inner)?.ok_or_else(|| refused(whole, "[] names no version"))?;
        return Ok(Restriction {
            lower: Some(only.clone()),
            lower_inclusive: true,
            upper: Some(only),
            upper_inclusive: true,
        });
    };
    let lower = bound(whole, inner.get(..comma).unwrap_or(""))?;
    let upper = bound(whole, inner.get(comma.saturating_add(1)..).unwrap_or(""))?;
    if lower.is_none() && lower_inclusive || upper.is_none() && upper_inclusive {
        return Err(refused(whole, "an unbounded side is written with a parenthesis, (,2.0) or [1.0,)"));
    }
    if lower.is_none() && upper.is_none() {
        return Err(refused(
            whole,
            "it bounds nothing and admits every version — bind component_present to ask for the package whatever its \
             version",
        ));
    }
    if let (Some(low), Some(high)) = (&lower, &upper) {
        let order = low.cmp(high);
        if order == Ordering::Greater {
            return Err(refused(whole, &format!("its lower bound {low} is above its upper bound {high}")));
        }
        if order == Ordering::Equal && !(lower_inclusive && upper_inclusive) {
            return Err(refused(whole, &format!("it admits no version — one version is written [{low}]")));
        }
    }
    Ok(Restriction { lower, lower_inclusive, upper, upper_inclusive })
}

fn bound(whole: &str, text: &str) -> Result<Option<MavenVersion>, Refused> {
    let bound = java::strip(text);
    if bound.is_empty() {
        return Ok(None);
    }
    if bound
        .chars()
        .any(|c| matches!(c, ',' | '[' | ']' | '(' | ')') || java::is_whitespace(c) || java::is_iso_control(c))
    {
        return Err(refused(whole, &format!("\"{}\" is not a version", clip(Some(bound), 40).unwrap_or(""))));
    }
    Ok(Some(MavenVersion::of(bound)))
}

fn refused(spec: &str, why: &str) -> Refused {
    Refused(format!("The version range \"{}\" does not read: {why}.", clip(Some(spec), 60).unwrap_or("")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ascending(versions: &[&str]) {
        for (low, lower) in versions.iter().enumerate() {
            for higher in versions.iter().skip(low + 1) {
                assert_eq!(
                    MavenVersion::of(lower).cmp(&MavenVersion::of(higher)),
                    Ordering::Less,
                    "{lower} < {higher}"
                );
                assert_eq!(
                    MavenVersion::of(higher).cmp(&MavenVersion::of(lower)),
                    Ordering::Greater,
                    "{higher} > {lower}"
                );
            }
        }
    }

    #[test]
    fn qualifiers_and_numbers_are_ordered_as_maven_orders_them() {
        ascending(&["1-alpha2", "1-beta-2", "1-m2", "1-rc", "1-SNAPSHOT", "1", "1-sp", "1-abc", "1-1", "1-123"]);
        ascending(&["2.0", "2.0.a", "2-1", "2.0.2", "2.1.0", "2.1-a", "2.1b", "2.1-1", "2.2", "2.123", "11"]);
        assert_eq!(MavenVersion::of("1.9").cmp(&MavenVersion::of("1.10")), Ordering::Less, "not a string sort");
    }

    #[test]
    fn trailing_zeros_aliases_and_shorthands_are_one_version() {
        for same in ["1.0", "1.0.0", "1-0", "1.ga", "1-final", "1.0.0.RELEASE", "１.０"] {
            assert_eq!(MavenVersion::of("1"), MavenVersion::of(same), "{same}");
        }
        assert_eq!(MavenVersion::of("1.0.0.M1"), MavenVersion::of("1-milestone-1"));
        assert_eq!(MavenVersion::of("12345678901234567890"), MavenVersion::of("12345678901234567890.0"));
    }

    #[test]
    fn a_range_admits_by_the_order_and_refuses_what_nobody_means() {
        let range = MavenVersionRange::parse(Some("[1.17,2.0)")).unwrap();
        assert!(range.contains("1.17") && range.contains("1.99") && range.contains("2.0-SNAPSHOT"));
        assert!(!range.contains("2.0") && !range.contains("1.17-rc1"));
        for refused in ["(,)", "[,2.0)", "(1.0)", "(1.0,1.0)", "1.0", "[1.0,1.5],[1.2,2.0]", "[1.0,1.2],"] {
            assert!(MavenVersionRange::parse(Some(refused)).is_err(), "{refused}");
        }
    }
}
