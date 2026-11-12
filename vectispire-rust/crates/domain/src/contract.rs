//! The agent protocol's contract number, and the range of them the control plane serves — `AgentContract`.
//!
//! **A range, `OLDEST_SERVED` to `CURRENT`**, because decision 0043 §2 promises the control plane serves the agent of
//! the previous minor: control plane and agents roll at different moments, and a refusal in that window stops every
//! scan. A change the previous agent would not understand is made in two releases — the first raises [`CURRENT`] and
//! keeps [`OLDEST_SERVED`], handing each agent the form its announced number reads; the next raises
//! [`OLDEST_SERVED`] and deletes the old form. Never both in one release: 0.11.0 sealed credentials in an envelope
//! 0.10 agents could not open and left the number where it was, so the old agent was accepted and then failed on its
//! work.
//!
//! An agent newer than the control plane is refused too: the supported order is the control plane first, then its
//! agents. A Rust agent that is not on the Java agent's number is not a second implementation of one protocol, it is
//! a second protocol.

use crate::java;

/// The contract this build speaks, and the one its agent announces.
pub const CURRENT: u32 = 1;

/// The oldest contract the control plane still serves. Equal to [`CURRENT`] until a change makes the two differ, and
/// never raised in the release that moves [`CURRENT`].
pub const OLDEST_SERVED: u32 = 1;

/// [`CURRENT`] as the hello carries it: a string on the wire, compared as a number.
pub const VERSION: &str = "1";

/// The number an agent announced, or `None` when it is no contract number at all: trimmed as `String.trim` trims
/// (control characters too, not a no-break space), then `[1-9][0-9]{0,8}` — no sign, no leading zero, no fraction,
/// ASCII digits only. "1.1" and "01" are not contracts anybody announced.
pub fn parse(announced: Option<&str>) -> Option<u32> {
    let trimmed = java::trim(announced?);
    let bytes = trimmed.as_bytes();
    let well_formed = (1..=9).contains(&bytes.len())
        && bytes.first().is_some_and(|first| (b'1'..=b'9').contains(first))
        && bytes.iter().all(u8::is_ascii_digit);
    if well_formed { trimmed.parse().ok() } else { None }
}

/// Whether this contract is one the control plane serves: **within the range and nothing looser**. "Same major" or
/// "anything up to ours" moves the question elsewhere: every number below [`OLDEST_SERVED`] is a form whose code was
/// deleted.
pub fn is_compatible(announced: Option<&str>) -> bool {
    parse(announced).is_some_and(|number| (OLDEST_SERVED..=CURRENT).contains(&number))
}

/// The range in words, for a refusal: "1", or "1 to 2".
pub fn served() -> String {
    if OLDEST_SERVED == CURRENT { VERSION.to_owned() } else { format!("{OLDEST_SERVED} to {CURRENT}") }
}

/// What an operator does about an agent outside the range — two different fixes, so two sentences.
pub fn remedy(announced: Option<&str>) -> &'static str {
    if parse(announced).is_some_and(|number| number > CURRENT) {
        "Upgrade the control plane first, then its agents."
    } else {
        "Update the agent."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_number_is_read_as_java_reads_it() {
        assert_eq!(VERSION, CURRENT.to_string());
        assert_eq!(parse(Some("\u{0}1\u{1f}")), Some(1));
        assert_eq!(parse(Some("999999999")), Some(999_999_999));
        for refused in ["01", "1.0", "", "+1", "-1", "\u{a0}1", "\u{661}", "1000000000"] {
            assert_eq!(parse(Some(refused)), None, "{refused:?}");
        }
        assert_eq!(parse(None), None);
    }

    #[test]
    fn the_range_is_served_and_nothing_else() {
        assert!(is_compatible(Some(VERSION)));
        assert!(!is_compatible(Some(&CURRENT.saturating_add(1).to_string())));
        assert!(!is_compatible(Some(&OLDEST_SERVED.saturating_sub(1).to_string())));
        assert_eq!(
            remedy(Some(&CURRENT.saturating_add(1).to_string())),
            "Upgrade the control plane first, then its agents."
        );
        assert_eq!(remedy(Some("0")), "Update the agent.");
        assert_eq!(remedy(None), "Update the agent.");
        assert_eq!(served(), "1");
    }
}
