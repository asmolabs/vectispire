//! `BoundedText`: a string held to the column it goes into, **counted in UTF-16 units** as Java counts it.
//!
//! MySQL and PostgreSQL measure a `varchar(n)` in characters; an astral character is two units here, so
//! anything accepted fits — and two hundred emoji are refused by a 255 column they would have fitted,
//! which is the direction to be wrong in. Rust's `len()` counts bytes and `chars().count()` characters;
//! either would accept or cut where Java does not.

use crate::java;

/// The ceiling for free text in a `text` column: 16,000 units is at most 48,000 UTF-8 bytes, inside
/// MySQL's 65,535-byte `TEXT`, and the two engines are deployed interchangeably.
pub const TEXT_MAX: usize = 16_000;

/// The ceiling for a list route's free-text search: the longest column any of them reads.
pub const SEARCH_MAX: usize = 500;

/// `BoundedText.clip`: at most `max` UTF-16 units, cut on a character boundary; `None` stays `None`.
///
/// For what a machine reports about itself — a purl, a hostname — where refusing would lose a whole scan
/// over one display field. **Never splits a surrogate pair**: the lone high surrogate left behind is not a
/// character in any encoding, and PostgreSQL refuses the row it is in. An astral character straddling the
/// limit is dropped whole, so the result may be one unit short of `max`.
pub fn clip(value: Option<&str>, max: usize) -> Option<&str> {
    let value = value?;
    let mut units = 0usize;
    for (offset, c) in value.char_indices() {
        let end = units.saturating_add(c.len_utf16());
        if end > max {
            return value.get(..offset);
        }
        units = end;
    }
    Some(value)
}

/// `BoundedText.tooLong`: the refusal when `value` is longer than `max` units, in Java's sentence —
/// `<what> is longer than <max> characters.` — and `None` when it fits or is absent.
pub fn too_long(value: Option<&str>, max: usize, what: &str) -> Option<String> {
    value.filter(|value| java::utf16_len(value) > max).map(|_| format!("{what} is longer than {max} characters."))
}
