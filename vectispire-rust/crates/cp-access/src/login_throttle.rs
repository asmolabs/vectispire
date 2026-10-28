//! `LoginThrottle`: how many failures a sign-in may absorb, and under which keys they are counted.
//!
//! **Two independent counters, and both have to pass.** Per user only, and anybody locks a colleague out; per client
//! only, and a spread attacker tries as many passwords as they like against one account. The window slides, and the
//! check comes before any password comparison, so a locked account costs no hashing.
//!
//! The keys are rows of `t_login_attempt` and `t_rate_window`, written by whichever control plane served the attempt:
//! a name folded differently here would start a fresh budget on the day of the switch, and a different fold for a
//! spelling the collation equates would reopen the existence oracle [`user_key`] closes. Held to
//! `reference/sign-in/`, which `SignInReferenceSetTest` writes.

use time::{Duration, OffsetDateTime};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use vectispire_cp_http::address::client_bucket;
use vectispire_domain::java;

pub const MAX_ATTEMPTS_PER_USER: usize = 5;
pub const MAX_ATTEMPTS_PER_CLIENT: usize = 20;
pub const WINDOW: Duration = Duration::minutes(15);

/// Wrong second-factor codes an account may absorb per window, across challenges: a challenge dies after three, and
/// the password brings a fresh one, so only a counter that survives the password bounds the guessing.
pub const MAX_SECOND_FACTOR_FAILURES: usize = 5;

/// `LoginThrottle.Decision`: allowed, or how long to wait — [`Duration::ZERO`] when allowed, never under a second
/// otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub retry_after: Duration,
}

/// `LoginThrottle.decide(Attempts, now)`: both counters against their limits; the longer wait wins.
pub fn decide(user: &[OffsetDateTime], client: &[OffsetDateTime], now: OffsetDateTime) -> Decision {
    let user = wait_for(user, MAX_ATTEMPTS_PER_USER, now);
    let client = wait_for(client, MAX_ATTEMPTS_PER_CLIENT, now);
    decision(if user >= client { user } else { client })
}

/// `LoginThrottle.decide(List, limit, now)`: one counter alone, against its own limit (at least one: Java has no
/// answer for none, its `orElseThrow` finding no failure to wait for).
pub fn decide_one(attempts: &[OffsetDateTime], limit: usize, now: OffsetDateTime) -> Decision {
    decision(wait_for(attempts, limit, now))
}

fn decision(retry_after: Duration) -> Decision {
    Decision { allowed: retry_after.is_zero(), retry_after }
}

/// The wait until the counter drops back under `limit`: from the oldest failure still inside the window — never less
/// than a second, since announcing zero to a caller still blocked makes it retry at once and fail again.
fn wait_for(attempts: &[OffsetDateTime], limit: usize, now: OffsetDateTime) -> Duration {
    let in_window = within_window(attempts, now);
    if in_window.len() < limit {
        return Duration::ZERO;
    }
    let Some(earliest) = in_window.into_iter().min() else {
        return Duration::ZERO;
    };
    // In nanoseconds, which an `i128` holds for any two instants `time` can represent.
    let nanos = earliest
        .unix_timestamp_nanos()
        .saturating_add(WINDOW.whole_nanoseconds())
        .saturating_sub(now.unix_timestamp_nanos());
    let remaining = Duration::new(
        i64::try_from(nanos.div_euclid(NANOS_PER_SECOND)).unwrap_or(i64::MAX),
        i32::try_from(nanos.rem_euclid(NANOS_PER_SECOND)).unwrap_or(0),
    );
    remaining.max(Duration::SECOND)
}

const NANOS_PER_SECOND: i128 = 1_000_000_000;

/// `LoginThrottle.withinWindow`: the failures strictly after `now - WINDOW` — one exactly at the cutoff has left.
pub fn within_window(attempts: &[OffsetDateTime], now: OffsetDateTime) -> Vec<OffsetDateTime> {
    let cutoff = now.saturating_sub(WINDOW);
    attempts.iter().copied().filter(|&attempt| cutoff < attempt).collect()
}

/// `LoginThrottle.userKey`: the key failures against a typed name are counted under, for an account that exists and
/// for one that does not.
///
/// Trimmed (`String.trim`), decomposed for compatibility (NFKD), every mark (`\p{M}`) dropped, upper- then
/// lower-cased in the root locale — so `ß` and `ẞ`'s lower case meet `ss` only through the upper case — and the
/// letters MySQL's `utf8mb4_0900_ai_ci` equates with others and no decomposition takes apart replaced, as
/// `CollationFoldDatabaseTest` measured them on the server.
pub fn user_key(username: &str) -> String {
    let folded: String = java::trim(username).nfkd().filter(|&c| !is_combining_mark(c)).collect();
    let lower = java::to_lower_root(&folded.to_uppercase());
    let mut key = String::with_capacity(lower.len().saturating_add(11));
    key.push_str("login:user:");
    for c in lower.chars() {
        match collation_letter(c) {
            Some(replacement) => key.push_str(replacement),
            None => key.push(c),
        }
    }
    key
}

/// `LoginThrottle.COLLATION_LETTERS`.
fn collation_letter(c: char) -> Option<&'static str> {
    Some(match c {
        'æ' => "ae",
        'œ' => "oe",
        'ø' => "o",
        'ł' => "l",
        'đ' => "d",
        'ð' => "d",
        'ħ' => "h",
        'ŀ' => "l",
        '·' => "",
        _ => return None,
    })
}

/// `LoginThrottle.accountKey`: the key for an account that exists, which every spelling reaching it shares.
pub fn account_key(account_id: i64) -> String {
    format!("login:account:{account_id}")
}

/// `LoginThrottle.secondFactorKey`: wrong second-factor codes, per account.
pub fn second_factor_key(account_id: i64) -> String {
    format!("login:mfa:{account_id}")
}

/// `LoginThrottle.clientKey`: namespaced apart from the user keys, an IPv6 client counted on its /64. Java is handed
/// `String.valueOf(address)`, so an absent address is the text `null` by the time it gets here.
pub fn client_key(client_id: &str) -> String {
    format!("login:client:{}", client_bucket(client_id))
}
