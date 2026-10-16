//! How many scans an agent runs at once — `AgentConcurrency`.
//!
//! Set on the agent's row by an administrator, stated by the control plane in the hello's answer and on
//! every claim's, and enforced on both sides: the control plane hands out no more, and the agent does
//! not poll for work it has no room for.

/// The fewest scans an agent runs at once.
pub const MIN: u32 = 1;
/// The most: beyond it one machine's Docker daemon, not the agent, is the bottleneck.
pub const MAX: u32 = 16;
/// What an agent runs when nothing says otherwise — one, as before the limit existed.
pub const DEFAULT: u32 = 1;

/// The header a claim's answer states the agent's current limit in — on a 204 too, which has no body.
pub const HEADER: &str = "X-Vectispire-Max-Concurrent";

/// A stored or stated limit as it applies: [`DEFAULT`] below [`MIN`] or absent, at most [`MAX`].
pub fn effective(stated: Option<i64>) -> u32 {
    match stated {
        Some(limit) if limit >= i64::from(MIN) => limit.min(i64::from(MAX)) as u32,
        _ => DEFAULT,
    }
}

/// The header's limit, or `None` when there is none or it is not a number — an older control plane,
/// which never applied a limit either; the agent then keeps what it had.
pub fn parse(header: Option<&str>) -> Option<u32> {
    let text = header?.trim();
    if text.is_empty() {
        return None;
    }
    // `Integer.parseInt`: an optional sign, decimal digits, nothing else, within 32 bits.
    text.parse::<i32>().ok().map(|limit| effective(Some(i64::from(limit))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_is_read_and_held_within_its_bounds_as_the_java_side_holds_it() {
        assert_eq!(parse(Some(" 3 ")), Some(3));
        assert_eq!(parse(Some("0")), Some(DEFAULT));
        assert_eq!(parse(Some("-2")), Some(DEFAULT));
        assert_eq!(parse(Some("40")), Some(MAX));
        assert_eq!(parse(Some("+4")), Some(4));
        assert_eq!(parse(Some("three")), None);
        assert_eq!(parse(Some("99999999999")), None, "beyond 32 bits is unreadable, as for parseInt");
        assert_eq!(parse(Some("")), None);
        assert_eq!(parse(None), None);
        assert_eq!(effective(None), DEFAULT);
    }
}
