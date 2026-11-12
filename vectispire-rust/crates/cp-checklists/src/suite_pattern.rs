//! `SuitePattern`: a test-suite rule's glob over a suite's whole name — `*` any run, `?` one character, every other
//! character itself. Matched by hand, never handed to a regex engine a crafted pattern could make backtrack for
//! minutes: this walk backtracks to the last star only. **Over UTF-16 units**, as Java's `charAt` walks: `?` is one
//! unit, so an astral character is two of them.

#[derive(Debug, Clone)]
pub struct SuitePattern {
    pattern: Vec<u16>,
}

impl SuitePattern {
    pub fn of(pattern: &str) -> SuitePattern {
        SuitePattern { pattern: pattern.encode_utf16().collect() }
    }

    pub fn matches(&self, name: Option<&str>) -> bool {
        let Some(name) = name else { return false };
        let name: Vec<u16> = name.encode_utf16().collect();
        star_match(&self.pattern, &name, Some(u16::from(b'?')))
    }
}

/// The greedy walk with a single backtrack point, `one` (when given) matching any one unit. A pattern's `*` is a star
/// before it is a character: tried as a literal first, a leading `*` was spent on a name's own and `*a` did not match
/// `*xa` (fixed on the Java side first).
pub(crate) fn star_match(pattern: &[u16], text: &[u16], one: Option<u16>) -> bool {
    let star_unit = u16::from(b'*');
    let mut p = 0usize;
    let mut n = 0usize;
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    while let Some(&c) = text.get(n) {
        let at = pattern.get(p).copied();
        if at == Some(star_unit) {
            star = Some(p);
            p = p.saturating_add(1);
            resume = n;
        } else if at.is_some_and(|unit| Some(unit) == one || unit == c) {
            p = p.saturating_add(1);
            n = n.saturating_add(1);
        } else if let Some(at_star) = star {
            p = at_star.saturating_add(1);
            resume = resume.saturating_add(1);
            n = resume;
        } else {
            return false;
        }
    }
    while pattern.get(p) == Some(&star_unit) {
        p = p.saturating_add(1);
    }
    p == pattern.len()
}
