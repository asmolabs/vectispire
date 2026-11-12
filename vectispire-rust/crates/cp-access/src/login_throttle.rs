//! `LoginThrottle`: how many failures a sign-in may absorb, and under which keys they are counted.
//!
//! **Three counters, and all have to pass**: an account (or a typed name) from one client, the same from every client,
//! and one client across every account. Each alone has a hole another closes. The window slides, and the check comes
//! before any password comparison, so a locked account costs no hashing.
//!
//! The keys are rows of `t_login_attempt` and `t_rate_window`, written by whichever control plane served the attempt:
//! a name folded differently here would start a fresh budget on the day of the switch, and a different fold for a
//! spelling the collation equates would reopen the existence oracle [`user_key`] closes. Held to
//! `reference/sign-in/`, which `SignInReferenceSetTest` writes.

use time::{Duration, OffsetDateTime};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use vectispire_cp_http::address::client_bucket;
use vectispire_domain::fingerprint::sha256_fields;
use vectispire_domain::java;

/// Failures against one account, or one typed name, **from one client**: the owner's mistypes, and a guesser working
/// from one place. Keyed per client, five failures lock out only the client that sent them — one counter shared by
/// every client let anyone who knew a name keep its owner out.
pub const MAX_ATTEMPTS_PER_USER: usize = 5;
/// Failures against one account, or one typed name, from **every** client — ten times higher, against a guess spread
/// across machines. A budget and not a lock ([`SignInLimits`]): past it, a client the account has signed in from, or
/// one sending the second factor with the password, still goes on to be verified.
pub const MAX_ATTEMPTS_PER_ACCOUNT: usize = 50;
pub const MAX_ATTEMPTS_PER_CLIENT: usize = 20;
pub const WINDOW: Duration = Duration::minutes(15);

/// `SignInLimits`: the ceilings `vectispire.sign-in.*` sets, the shipped ones by default. A zero ceiling or retention
/// reads as the shipped value where the settings are read (cp-runtime's loader), as Java's compact constructor does: a
/// ceiling of zero would refuse every sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignInLimits {
    pub failures_per_account_from_client: usize,
    pub failures_per_account: usize,
    pub failures_per_client: usize,
    /// How long a client that signed in to an account stays known to it.
    pub known_client_retention: Duration,
}

/// `SignInLimits.DEFAULT_KNOWN_CLIENT_RETENTION`: a person who signs in once a month from the office keeps their
/// exemption.
pub const DEFAULT_KNOWN_CLIENT_RETENTION: Duration = Duration::days(30);

impl Default for SignInLimits {
    fn default() -> SignInLimits {
        SignInLimits {
            failures_per_account_from_client: MAX_ATTEMPTS_PER_USER,
            failures_per_account: MAX_ATTEMPTS_PER_ACCOUNT,
            failures_per_client: MAX_ATTEMPTS_PER_CLIENT,
            known_client_retention: DEFAULT_KNOWN_CLIENT_RETENTION,
        }
    }
}

impl SignInLimits {
    /// The compact constructor's rule: zero is the shipped value, for each ceiling and the retention alike.
    pub fn new(
        failures_per_account_from_client: usize,
        failures_per_account: usize,
        failures_per_client: usize,
        known_client_retention: Duration,
    ) -> SignInLimits {
        let shipped = SignInLimits::default();
        let or = |value: usize, default: usize| if value > 0 { value } else { default };
        SignInLimits {
            failures_per_account_from_client: or(
                failures_per_account_from_client,
                shipped.failures_per_account_from_client,
            ),
            failures_per_account: or(failures_per_account, shipped.failures_per_account),
            failures_per_client: or(failures_per_client, shipped.failures_per_client),
            known_client_retention: if known_client_retention.is_positive() {
                known_client_retention
            } else {
                shipped.known_client_retention
            },
        }
    }
}

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

/// `LoginThrottle.accountKey(long, String)`: the account's failures from one client — see [`MAX_ATTEMPTS_PER_USER`].
pub fn account_key_from_client(account_id: i64, client_id: &str) -> String {
    from_client(&account_key(account_id), client_id)
}

/// `LoginThrottle.userKey(String, String)`: the typed name's failures from one client, beside
/// [`account_key_from_client`] for the reason [`user_key`] sits beside [`account_key`] — which counters an attempt
/// meets must not depend on whether the account exists.
pub fn user_key_from_client(username: &str, client_id: &str) -> String {
    from_client(&user_key(username), client_id)
}

/// A counter narrowed to one client bucket, as a digest: the typed name is the caller's and has no length the column
/// knows, and the bucket adds to it.
fn from_client(key: &str, client_id: &str) -> String {
    format!("login:from-client:{}", sha256_fields(&[Some(key), Some(&client_bucket(client_id))]))
}

/// `LoginThrottle.knownClientKey`: a client that has signed in to an account, which the account's budget across every
/// client does not refuse. "Client" is the counters' client — the address as the trusted proxies resolve it, or its
/// /64 — and not a cookie the caller would be free to send or not. A digest, so the table holding it does not also
/// record where every account signs in from.
pub fn known_client_key(account_id: i64, client_id: &str) -> String {
    sha256_fields(&[Some("login:known-client"), Some(&account_id.to_string()), Some(&client_bucket(client_id))])
}

/// The key asked of the known clients when no account answers to the name — `AuthService.isKnownClient`'s
/// `Digests.sha256Fields("login:no-account", username, ipAddress)`: the question is a query, and asked only when the
/// account exists it would time the answer to "does it exist". The address as given, not its bucket, as Java has it.
pub fn no_account_key(username: Option<&str>, ip_address: &str) -> String {
    // `String.valueOf(username)`: an absent name is the text `null`.
    sha256_fields(&[Some("login:no-account"), Some(username.unwrap_or("null")), Some(ip_address)])
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
