//! A session's rules — `common.domain.auth.Sessions`, word for word where the words are behaviour.
//!
//! The properties the design exists for: **revocable** (a session is a row; deleting it logs out, on every
//! device), **expiring** (an absolute lifetime bounds what a stolen token allows, an idle one closes forgotten
//! sessions), **opaque** (32 random bytes, nothing to decode), and **not stored** (the store holds the token's
//! SHA-256, never the token: a dump of `t_session` hands over no live session).

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use vectispire_domain::secret::Secret;

use super::text::{is_java_regex_space, java_trim};

/// 32 bytes of entropy: 43 characters in base64url, nothing to escape.
const TOKEN_BYTES: usize = 32;

/// How long a single sign-on hand-off may wait to be exchanged — the cookie's own lifetime.
pub const HANDOFF_LIFETIME: Duration = Duration::seconds(60);

/// `vectispire.session.absolute-lifetime` and `vectispire.session.idle-lifetime`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPolicy {
    /// The ceiling, whatever happens.
    pub absolute_lifetime: Duration,
    /// Past this much silence the session closes even with lifetime left.
    pub idle_lifetime: Duration,
}

impl Default for SessionPolicy {
    /// `Sessions.Policy.DEFAULT`, and `application.yaml`'s defaults: twelve hours, sixty minutes.
    fn default() -> SessionPolicy {
        SessionPolicy { absolute_lifetime: Duration::hours(12), idle_lifetime: Duration::minutes(60) }
    }
}

/// The two causes of closure are told apart because the operator tuning the durations needs to know which one is
/// actually closing their users' sessions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Expired,
    Idle,
}

/// A token as it is handed out, and as it is stored. There is no function that produces a token alone, so the wrong
/// one cannot be stored by accident.
#[derive(Debug)]
pub struct IssuedToken {
    /// Goes to the client and is never written down.
    pub token: Secret,
    /// Written down; cannot be turned back into the token.
    pub hash: String,
}

/// Mints a session token.
///
/// **SHA-256 and not Argon2id, deliberately**: the token is 32 bytes from the operating system's generator, with no
/// dictionary to walk; a memory-hard derivation would buy nothing and be paid on every authenticated request. What
/// the hash buys is the one property at stake: whoever reads the table reads verifiers, not credentials.
pub fn issue() -> IssuedToken {
    let mut material = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut material);
    let token = base64_url(&material);
    material.iter_mut().for_each(|byte| *byte = 0);
    let hash = hash_of(&token);
    IssuedToken { token: Secret::new(token), hash }
}

/// `Base64.getUrlEncoder().withoutPadding()`.
pub(crate) fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The stored form of a token somebody just presented: `Digests.sha256Hex`, lower-case hex of the UTF-8 bytes.
///
/// The lookup that follows is an equality on the primary key, not a constant-time comparison, and does not need to
/// be: what the engine compares is the hash of what the caller sent, which the caller already knows in full.
pub fn hash_of(presented: &str) -> String {
    hex(&Sha256::digest(presented.as_bytes()))
}

/// The stored form of a single sign-on hand-off token, under its own prefix so the bearer route cannot find it.
pub fn handoff_hash_of(presented: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"handoff:");
    digest.update(presented.as_bytes());
    hex(&digest.finalize())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// `instant + duration`, at the far future when it would overflow — a lifetime too long to end is one that has not
/// ended (Java's `Instant.plus` would throw instead; no configuration reaches it).
fn plus(instant: OffsetDateTime, duration: Duration) -> OffsetDateTime {
    instant.checked_add(duration).unwrap_or(OffsetDateTime::new_utc(time::Date::MAX, time::Time::MIDNIGHT))
}

/// `Sessions.stateOf`: expired once `now` reaches `created + absolute`, idle once it reaches `last_seen + idle`.
pub fn state_of(
    created_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    now: OffsetDateTime,
    policy: &SessionPolicy,
) -> SessionState {
    if now >= plus(created_at, policy.absolute_lifetime) {
        return SessionState::Expired;
    }
    if now >= plus(last_seen_at, policy.idle_lifetime) {
        return SessionState::Idle;
    }
    SessionState::Active
}

pub fn is_active(
    created_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    now: OffsetDateTime,
    policy: &SessionPolicy,
) -> bool {
    state_of(created_at, last_seen_at, now, policy) == SessionState::Active
}

/// `Sessions.shouldRecordActivity`: activity is written at a grain of a sixtieth of the idle window, never finer than
/// a second.
///
/// The error goes the safe way: unwritten activity makes the session look older than it is, so it expires possibly a
/// little early and never late. One write per request onto one row was a fight between a screen's parallel calls.
pub fn should_record_activity(last_seen_at: OffsetDateTime, now: OffsetDateTime, policy: &SessionPolicy) -> bool {
    // `Duration.dividedBy(60)`: nanoseconds divided, truncated toward zero.
    let grain = Duration::nanoseconds_i128(policy.idle_lifetime.whole_nanoseconds().checked_div(60).unwrap_or(0));
    let grain = if grain < Duration::SECOND { Duration::SECOND } else { grain };
    now >= plus(last_seen_at, grain)
}

/// `Sessions.bearerToken`: the token of a header that is exactly `Bearer <token>` once trimmed, empty otherwise.
///
/// Stricter than the API-key path on purpose, and the two must not be confused: the scheme is spelt `Bearer` with
/// one space, and the token holds none of Java's `\s` (space, tab, line feed, vertical tab, form feed, carriage
/// return). Telling "absent", "malformed" and "unknown" apart would inform somebody probing.
pub fn bearer_token(header: Option<&str>) -> Option<&str> {
    let token = java_trim(header?).strip_prefix("Bearer ")?;
    is_session_token_shape(token).then_some(token)
}

/// What the `(\S+)` of `^Bearer (\S+)$` admits: at least one character, none of Java's regex `\s`.
pub fn is_session_token_shape(token: &str) -> bool {
    !token.is_empty() && !token.chars().any(is_java_regex_space)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).unwrap()
    }

    #[test]
    fn a_token_is_43_url_safe_characters_and_never_the_same_twice() {
        let first = issue();
        let second = issue();
        assert_eq!(first.token.expose().len(), 43);
        assert!(first.token.expose().bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(first.token.expose(), second.token.expose());
        assert_eq!(first.hash.len(), 64);
        assert_eq!(first.hash, hash_of(first.token.expose()));
        assert_ne!(hash_of(&first.hash), first.hash, "the stored value is not a credential");
    }

    #[test]
    fn the_absolute_lifetime_and_the_idle_window_close_a_session_apart() {
        let policy = SessionPolicy::default();
        let now = at("2026-08-10T08:00:00Z");
        assert_eq!(state_of(now, now, now, &policy), SessionState::Active);
        assert_eq!(state_of(now - Duration::hours(12), now, now, &policy), SessionState::Expired);
        assert_eq!(state_of(now - Duration::hours(2), now - Duration::minutes(60), now, &policy), SessionState::Idle);
        assert_eq!(
            state_of(now - Duration::hours(2), now - Duration::minutes(60) + Duration::nanoseconds(1), now, &policy),
            SessionState::Active
        );
    }

    #[test]
    fn activity_is_recorded_at_a_sixtieth_of_the_window_and_never_finer_than_a_second() {
        let policy = SessionPolicy::default();
        let seen = at("2026-09-04T10:00:00Z");
        assert!(!should_record_activity(seen, seen + Duration::milliseconds(40), &policy));
        assert!(!should_record_activity(seen, seen + Duration::seconds(59), &policy));
        assert!(should_record_activity(seen, seen + Duration::seconds(60), &policy));
        let strict = SessionPolicy { absolute_lifetime: Duration::hours(1), idle_lifetime: Duration::seconds(30) };
        assert!(!should_record_activity(seen, seen + Duration::milliseconds(500), &strict));
        assert!(should_record_activity(seen, seen + Duration::seconds(1), &strict));
    }

    #[test]
    fn the_session_header_is_exactly_bearer_space_token() {
        assert_eq!(bearer_token(Some("Bearer abc123")), Some("abc123"));
        assert_eq!(bearer_token(Some("  Bearer abc123 \u{1}")), Some("abc123"));
        for refused in ["", "   ", "abc123", "bearer abc123", "Bearer ", "Bearer a b", "Basic abc123", "Bearer  abc"] {
            assert_eq!(bearer_token(Some(refused)), None, "{refused:?}");
        }
        assert_eq!(bearer_token(None), None);
    }

    #[test]
    fn the_hand_off_is_hashed_apart_from_a_session() {
        assert_ne!(handoff_hash_of("x"), hash_of("x"));
        assert_eq!(handoff_hash_of("x"), hash_of("handoff:x"));
    }
}
