//! The outbox's retry policy — Java's `OutboxRetry` (vectispire-common): exponential backoff, capped, then
//! abandonment. Every value is held to `reference/outbox/relay.json`'s `constants` and `backoff`.
//!
//! **Abandoned, not deleted.** A message nobody will ever receive is what an operator has to be able to find: it stays,
//! `failed`, with its last error.

use time::{Duration, OffsetDateTime};

/// Eight attempts over a widening window: about four hours in total. (Java's comments speak of twelve in two places;
/// the constant is eight, and the constant is what runs.)
pub const MAX_ATTEMPTS: i32 = 8;

pub const BASE_BACKOFF: Duration = Duration::seconds(60);
pub const MAX_BACKOFF: Duration = Duration::hours(1);

/// How many messages one pass sends: maintenance does other work too, and a burst of two hundred webhooks would starve
/// it.
pub const MAX_PER_PASS: u32 = 20;

/// How long a claimed message is withheld from the other instances. It must outlast one delivery and the write that
/// settles it by a wide margin, and it is also how long a message waits when its claimant dies mid-delivery: it falls
/// due again rather than staying claimed for ever.
pub const CLAIM_WINDOW: Duration = Duration::minutes(5);

/// Delivered messages are kept a week, so "did it go out?" has an answer.
pub const SENT_RETENTION: Duration = Duration::days(7);

/// How long an error is kept, in UTF-16 units as Java's `substring` counts: a proxy's HTML page is not worth a
/// kilobyte per attempt.
const MAX_ERROR_LENGTH: usize = 500;

/// `60 s, 120 s, 240 s…` capped at one hour, from the attempt count rather than stored, so the policy can change
/// without rows carrying an older version's schedule.
pub fn backoff(attempts: i32) -> Duration {
    if attempts <= 0 {
        return BASE_BACKOFF;
    }
    // A shift capped at 20, not a power: on a corrupted counter an unbounded shift wraps to a negative delay and the
    // message is retried at once, for ever.
    let exponent = attempts.saturating_sub(1).min(20);
    let computed = BASE_BACKOFF.saturating_mul(1_i32 << exponent);
    if computed > MAX_BACKOFF { MAX_BACKOFF } else { computed }
}

/// The outcome of a failed attempt: `None` is abandonment, `Some` another chance at that instant.
pub fn next_attempt_at(attempts: i32, now: OffsetDateTime) -> Option<OffsetDateTime> {
    if is_abandoned(attempts) { None } else { Some(now.saturating_add(backoff(attempts))) }
}

pub fn is_abandoned(attempts: i32) -> bool {
    attempts >= MAX_ATTEMPTS
}

/// The error as `last_error` keeps it: `Kind: message`, `null` for a message there is not — Java's
/// `getClass().getSimpleName() + ": " + getMessage()` — cut at 500 UTF-16 units.
///
/// **Cut as Java cuts.** `substring` counts UTF-16 units and may split a surrogate pair; the drivers then write the
/// lone half as `?` (`String.getBytes(UTF_8)`), and that `?` is what the row holds. A Rust string cannot hold the half,
/// so the `?` is written here, and the row is the same.
pub fn recordable_error(kind: &str, message: Option<&str>) -> String {
    let value = format!("{kind}: {}", message.unwrap_or("null"));
    let mut out = String::with_capacity(value.len().min(MAX_ERROR_LENGTH * 3));
    let mut units: usize = 0;
    for c in value.chars() {
        let width = c.len_utf16();
        if units.saturating_add(width) > MAX_ERROR_LENGTH {
            if units < MAX_ERROR_LENGTH {
                out.push('?');
            }
            return out;
        }
        units = units.saturating_add(width);
        out.push(c);
    }
    out
}
