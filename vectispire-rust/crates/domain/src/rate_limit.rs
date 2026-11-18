//! `RateLimit` and `LinkHeader` (`common.domain.net`): what an answer says about a rate limit, and where a listing's
//! next page is (decision 0037 §3 — rate limits are honoured, never raced).
//!
//! **A 403 is not always a refusal**: GitHub answers a spent limit 403 with `X-RateLimit-Remaining: 0` or a
//! `Retry-After`. A 403 carrying none of those is the forge refusing the token something, and reading it as a limit
//! would wait on a refusal that never lifts. **Which header sets the wait, in order**: `Retry-After` (seconds, or an
//! HTTP date), `X-RateLimit-Reset` (epoch seconds), `RateLimit-Reset` (epoch seconds or a delay, told apart by size).

use crate::instant::Instant;

/// A value below this is a delay in seconds, above it an instant in epoch seconds (2001-09-09).
const EPOCH_THRESHOLD: i64 = 1_000_000_000;

/// `RateLimit.limited`: whether this answer is a rate limit rather than a refusal or a failure. `header` gives the
/// answer's first value of a header, by lower-case name.
pub fn limited<'a>(status: u16, header: impl Fn(&str) -> Option<&'a str>) -> bool {
    if status == 429 {
        return true;
    }
    if status != 403 {
        return false;
    }
    header("retry-after").is_some()
        || header("x-ratelimit-remaining").is_some_and(|value| crate::java::trim(value) == "0")
        || header("ratelimit-remaining").is_some_and(|value| crate::java::trim(value) == "0")
}

/// `RateLimit.waitOf`: how long the answer asks the caller to wait from `now`, in whole seconds and nanoseconds as a
/// `Duration`; never negative, `None` when no header names a wait.
pub fn wait_of<'a>(header: impl Fn(&str) -> Option<&'a str>, now: Instant) -> Option<std::time::Duration> {
    if let Some(wait) = header("retry-after").and_then(|value| retry_after(crate::java::trim(value), now)) {
        return Some(wait);
    }
    if let Some(wait) = header("x-ratelimit-reset").and_then(|value| epoch(crate::java::trim(value), now)) {
        return Some(wait);
    }
    let value = crate::java::trim(header("ratelimit-reset")?);
    let number = number(value)?;
    if number >= EPOCH_THRESHOLD { epoch(value, now) } else { Some(seconds(number)) }
}

fn retry_after(value: &str, now: Instant) -> Option<std::time::Duration> {
    if let Some(n) = number(value) {
        return Some(seconds(n));
    }
    rfc_1123(value).map(|at| between(now, at))
}

fn epoch(value: &str, now: Instant) -> Option<std::time::Duration> {
    number(value).map(|n| between(now, Instant::of_epoch_second(n)))
}

fn number(value: &str) -> Option<i64> {
    if value.is_empty() || value.len() > 18 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn seconds(n: i64) -> std::time::Duration {
    std::time::Duration::from_secs(u64::try_from(n).unwrap_or(0))
}

/// `Duration.between(now, at)`, clamped at zero.
fn between(now: Instant, at: Instant) -> std::time::Duration {
    if at <= now {
        return std::time::Duration::ZERO;
    }
    let after = std::time::Duration::new(u64::try_from(at.epoch_second).unwrap_or(0), at.nano);
    let before = std::time::Duration::new(u64::try_from(now.epoch_second).unwrap_or(0), now.nano);
    after.saturating_sub(before)
}

/// `DateTimeFormatter.RFC_1123_DATE_TIME`: `[EEE, ]d MMM yyyy HH:mm[:ss] (GMT|±HHMM)`.
pub fn rfc_1123(value: &str) -> Option<Instant> {
    let rest = match value.split_once(", ") {
        Some((day, rest)) if ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].contains(&day) => rest,
        Some(_) => return None,
        None => value,
    };
    let parts: Vec<&str> = rest.split(' ').collect();
    let [day, month, year, time, zone] = parts.as_slice() else {
        return None;
    };
    let day: u32 = (1..=2).contains(&day.len()).then(|| day.parse().ok()).flatten()?;
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let month = u32::try_from(MONTHS.iter().position(|m| m == month)?.checked_add(1)?).ok()?;
    let year: i64 =
        (year.len() == 4 && year.bytes().all(|b| b.is_ascii_digit())).then(|| year.parse().ok()).flatten()?;
    let fields: Vec<&str> = time.split(':').collect();
    let two = |text: &str| -> Option<u32> {
        (text.len() == 2 && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok()).flatten()
    };
    let (hour, minute, second) = match fields.as_slice() {
        [h, m] => (two(h)?, two(m)?, 0),
        [h, m, s] => (two(h)?, two(m)?, two(s)?),
        _ => return None,
    };
    let offset = offset_seconds(zone, &["GMT"])?;
    if hour > 23 || minute > 59 || second > 59 || day == 0 || day > 31 {
        return None;
    }
    Instant::of_utc(year, month, day, hour, minute, second)?.plus_seconds(offset.checked_neg()?)
}

/// The offset in seconds a zone names: one of `names` (UTC), or `±HHMM`.
pub(crate) fn offset_seconds(zone: &str, names: &[&str]) -> Option<i64> {
    if names.contains(&zone) {
        return Some(0);
    }
    let (sign, digits) =
        if let Some(digits) = zone.strip_prefix('+') { (1i64, digits) } else { (-1i64, zone.strip_prefix('-')?) };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (hours, minutes) = digits.split_at_checked(2)?;
    let (hours, minutes): (i64, i64) = (hours.parse().ok()?, minutes.parse().ok()?);
    if hours > 18 || minutes > 59 {
        return None;
    }
    hours.checked_mul(3600)?.checked_add(minutes.checked_mul(60)?)?.checked_mul(sign)
}

/// `LinkHeader.target`: the target of the first link whose `rel` names `relation`, as written (possibly relative),
/// read character by character — a GitLab keyset cursor carries commas and semicolons.
pub fn link_target(header: Option<&str>, relation: &str) -> Option<String> {
    let header = header.filter(|header| !crate::java::is_blank(header))?;
    let wanted = crate::java::to_lower_root(relation);
    let mut rest = header;
    loop {
        let (_, after_open) = rest.split_once('<')?;
        let (target, after_close) = after_open.split_once('>')?;
        let target = crate::java::trim(target);
        let (parameters, next) = parameters_of(after_close);
        if relations(parameters).contains(&format!(" {wanted} ")) && !target.is_empty() {
            return Some(target.to_owned());
        }
        rest = next;
    }
}

/// The parameters up to the next link — a `<` outside quotes — and what follows them.
fn parameters_of(text: &str) -> (&str, &str) {
    let mut quoted = false;
    for (offset, c) in text.char_indices() {
        if c == '"' {
            quoted = !quoted;
        } else if c == '<' && !quoted {
            return text.split_at_checked(offset).unwrap_or((text, ""));
        }
    }
    (text, "")
}

/// The `rel` parameter's types, lower case, each surrounded by spaces: `" next last "`.
fn relations(parameters: &str) -> String {
    let mut types = String::from(" ");
    for parameter in parameters.split(';') {
        let trimmed = crate::java::trim(parameter);
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        if !crate::java::trim(name).eq_ignore_ascii_case("rel") {
            continue;
        }
        let mut value = crate::java::trim(value);
        if !value.starts_with('"')
            && let Some((before, _)) = value.rsplit_once(',')
        {
            value = before;
        }
        if let Some(inner) = value.strip_prefix('"') {
            value = inner.split_once('"').map_or(inner, |(quoted, _)| quoted);
        }
        for kind in crate::java::trim(value).split(char::is_whitespace).filter(|kind| !kind.is_empty()) {
            types.push_str(&crate::java::to_lower_root(kind));
            types.push(' ');
        }
    }
    types
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<&'a str> {
        move |name| pairs.iter().find(|(key, _)| *key == name).map(|(_, value)| *value)
    }

    const NOW: Instant = Instant { epoch_second: 1_800_000_000, nano: 500 };

    #[test]
    fn a_403_is_a_limit_only_with_the_limit_headers() {
        assert!(limited(429, headers(&[])));
        assert!(!limited(403, headers(&[])));
        assert!(limited(403, headers(&[("x-ratelimit-remaining", " 0 ")])));
        assert!(limited(403, headers(&[("retry-after", "x")])));
        assert!(!limited(403, headers(&[("x-ratelimit-remaining", "12")])));
        assert!(!limited(500, headers(&[("retry-after", "1")])));
    }

    #[test]
    fn the_wait_by_header_in_order() {
        let s = std::time::Duration::from_secs;
        assert_eq!(wait_of(headers(&[("retry-after", "30"), ("x-ratelimit-reset", "1")]), NOW), Some(s(30)));
        assert_eq!(
            wait_of(headers(&[("x-ratelimit-reset", "1800000060")]), NOW),
            Some(std::time::Duration::new(59, 999_999_500))
        );
        assert_eq!(wait_of(headers(&[("x-ratelimit-reset", "1")]), NOW), Some(s(0)));
        assert_eq!(wait_of(headers(&[("ratelimit-reset", "45")]), NOW), Some(s(45)));
        assert_eq!(wait_of(headers(&[("ratelimit-reset", "1800000010")]), NOW).map(|d| d.as_secs()), Some(9));
        assert_eq!(wait_of(headers(&[("retry-after", "soon")]), NOW), None);
        let at = Instant::of_utc(2027, 1, 15, 8, 0, 0).unwrap();
        assert_eq!(wait_of(headers(&[("retry-after", "Fri, 15 Jan 2027 08:00:10 GMT")]), at), Some(s(10)));
    }

    #[test]
    fn rfc_1123_dates() {
        assert_eq!(rfc_1123("Tue, 3 Jun 2008 11:05:30 GMT"), Instant::of_utc(2008, 6, 3, 11, 5, 30));
        assert_eq!(rfc_1123("3 Jun 2008 11:05:30 +0200"), Instant::of_utc(2008, 6, 3, 9, 5, 30));
        assert_eq!(rfc_1123("Tue, 3 June 2008 11:05:30 GMT"), None);
    }

    #[test]
    fn link_headers_with_cursors_that_carry_commas() {
        let header = r#"<https://g.example/api/v4/projects?cursor=a,b;c&per_page=100>; rel="next", <https://g.example/x>; rel="first last""#;
        assert_eq!(
            link_target(Some(header), "NEXT").as_deref(),
            Some("https://g.example/api/v4/projects?cursor=a,b;c&per_page=100")
        );
        assert_eq!(link_target(Some(header), "last").as_deref(), Some("https://g.example/x"));
        assert_eq!(link_target(Some("<a>; rel=prev"), "next"), None);
        assert_eq!(link_target(Some("<a>; rel=next, <b>; rel=last"), "next").as_deref(), Some("a"));
        assert_eq!(link_target(Some("<>; rel=next"), "next"), None);
        assert_eq!(link_target(None, "next"), None);
    }
}
