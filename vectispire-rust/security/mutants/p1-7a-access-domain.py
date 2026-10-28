#!/usr/bin/env python3
"""Mutation check of the access port's first stage (Phase 1, the pure half of task 1.3 and TeamRules for 1.7): TOTP
codes and Base32 in cp-access's totp, the sign-in throttle's window and keys in login_throttle, TeamRules in the
domain, and cp-http's client_bucket read as InetAddress.ofLiteral reads an address — held to reference/sign-in/ and
reference/teams/. See README.md.
"""
import sys

import _runner

S = ["-p", "vectispire-cp-access", "--test", "sign_in_reference_set"]
TL = ["-p", "vectispire-cp-access", "--lib", "totp"]
ST = [S, TL]
TR = ["-p", "vectispire-domain", "--test", "teams_reference_set"]
TOTP = "crates/cp-access/src/totp.rs"
LT = "crates/cp-access/src/login_throttle.rs"
TEAMS = "crates/domain/src/team_rules.rs"
ADDR = "crates/cp-http/src/address.rs"

# Equivalent, and removed: the code's length check in `matching_step` (Java's too) — a string of any other length is
# never equal to a six-digit code, so the comparison refuses it anyway; counting it in bytes rather than UTF-16 units
# differs only for a non-ASCII string, which no code equals either. `client_bucket`'s blank check — a blank address is
# not a literal and is kept as it came by the fallback as well. The room for an IPv4 tail in an IPv6 literal (`j + 4 <=
# 16`) — a tail with no room overflows the sixteen bytes and is refused by the final length. `ipv6_literal`'s
# `length > 2` before taking brackets off — `[]` without them is empty, which no literal is. An IPv6 group's sixteen-bit
# bound — a group past it is refused by the `u16` it is written into.
MUTANTS = [
    ("totp code trimmed as String.trim", TOTP, "let cleaned = java::trim(submitted);", "let cleaned = submitted.trim();", S),
    ("totp empty key matches nothing", TOTP, "    if key.is_empty() {\n        return None;\n    }\n    let current", "    let current", ST),
    ("totp empty key no code", TOTP, "(!key.is_empty()).then(", "true.then(", ST),
    ("totp window one step back", TOTP, "[current.saturating_sub(1), current,", "[current, current,", S),
    ("totp window one step on", TOTP, "current, current.saturating_add(1)]", "current, current]", S),
    ("totp step toward zero", TOTP, "instant.unix_timestamp().wrapping_div(TIME_STEP_SECONDS)", "instant.unix_timestamp().div_euclid(TIME_STEP_SECONDS)", S),
    ("totp truncation sign bit", TOTP, "[next() & 0x7f, next(), next(), next()]", "[next(), next(), next(), next()]", S),
    ("totp truncation offset nibble", TOTP, "usize::from(last & 0x0f)", "usize::from(last & 0x07)", S),
    ("base32 root upper case", TOTP, "text.to_uppercase().chars()", "text.to_ascii_uppercase().chars()", S),
    ("base32 last group written", TOTP, "    if bits > 0 {\n        out.push(letter(", "    if false {\n        out.push(letter(", S),
    ("uri space as plus", TOTP, "            b' ' => out.push('+'),\n", "", S),
    ("uri star kept", TOTP, "b'.' | b'-' | b'*' | b'_'", "b'.' | b'-' | b'_'", S),
    ("throttle cutoff strict", LT, "cutoff < attempt", "cutoff <= attempt", S),
    ("throttle limit reached", LT, "if in_window.len() < limit {", "if in_window.len() <= limit {", S),
    ("throttle oldest failure", LT, "in_window.into_iter().min()", "in_window.into_iter().max()", S),
    ("throttle at least a second", LT, "remaining.max(Duration::SECOND)", "remaining", S),
    ("throttle longer wait wins", LT, "if user >= client { user } else { client }", "user", S),
    ("user key String.trim", LT, "java::trim(username).nfkd()", "username.trim().nfkd()", S),
    ("user key compatibility decomposition", LT, "java::trim(username).nfkd()", "java::trim(username).nfd()", S),
    ("user key marks dropped", LT, ".nfkd().filter(|&c| !is_combining_mark(c)).collect()", ".nfkd().collect()", S),
    ("user key upper before lower", LT, "java::to_lower_root(&folded.to_uppercase())", "java::to_lower_root(&folded)", S),
    ("user key collation letters", LT, "        'ø' => \"o\",\n", "", S),
    ("client key bucketed", LT, "client_bucket(client_id))", "client_id)", S),
    ("team name String.trim", TEAMS, "let trimmed = java::trim(name.unwrap_or(\"\"));", "let trimmed = name.unwrap_or(\"\").trim();", TR),
    ("team name UTF-16 length", TEAMS, "java::utf16_len(trimmed) > MAX_NAME_LENGTH", "trimmed.len() > MAX_NAME_LENGTH", TR),
    ("team description clipped", TEAMS, "bounded_text::clip(Some(trimmed), MAX_DESCRIPTION_LENGTH).map(str::to_owned)", "Some(trimmed.to_owned())", TR),
    ("team kind String.trim", TEAMS, "java::to_lower_root(java::trim(kind.unwrap_or(\"\")))", "java::to_lower_root(kind.unwrap_or(\"\").trim())", TR),
    ("team kind null named", TEAMS, "kind.unwrap_or(\"null\")", "kind.unwrap_or(\"\")", TR),
    ("bucket String.trim", ADDR, "let trimmed = java::trim(address);", "let trimmed = address.trim();", S),
    ("ipv4 fifteen characters", ADDR, "java::utf16_len(text) > 15", "java::utf16_len(text) > 16", S),
    ("ipv4 four parts", ADDR, "if new_part || bytes.len() == 3 {", "if new_part || bytes.len() == 4 {", S),
    ("ipv4 leading part a byte", ADDR, "bytes.push(u8::try_from(value).ok()?);", "bytes.push(u8::try_from(value & 0xff).ok()?);", S),
    ("ipv4 last part bound", ADDR, "value >= 1u64.checked_shl(", "value > 1u64.checked_shl(", S),
    ("ipv6 brackets taken off", ADDR, "Some(inner) if java::utf16_len(text) > 2 => inner,", "Some(inner) if false => inner,", S),
    ("ipv6 zone numeric", ADDR, "if zone.is_some_and(|zone| !numeric_zone(zone)) {", "if false {", S),
    ("ipv6 zone int bound", ADDR, ".try_fold(0i32, |value, c| value.checked_mul(10)?.checked_add(i32::try_from(c.to_digit(10)?).ok()?))", ".try_fold(0i64, |value, c| value.checked_mul(10)?.checked_add(i64::from(c.to_digit(10)?)))", S),
    ("ipv6 mapped with zone refused", ADDR, "Some(v4) if zone.is_none() => Some(IpAddr::V4(v4)),", "Some(v4) => Some(IpAddr::V4(v4)),", S),
    ("ipv6 mapped is ipv4", ADDR, "match address.to_ipv4_mapped() {", "match None::<std::net::Ipv4Addr> {", S),
    ("ipv6 trailing percent", ADDR, "|| (literal.ends_with('%') && literal.find('%') == literal.len().checked_sub(1))", "", S),
    ("ipv6 leading colon doubled", ADDR, "if literal.chars().nth(1) != Some(':') {", "if false {", S),
    ("ipv6 one gap", ADDR, "                if gap.is_some() {\n                    return None;\n                }\n", "", S),
    ("ipv6 no trailing colon", ADDR, "} else if position == chars.len() || out.len() > 14 {", "} else if out.len() > 14 {", S),
    ("ipv6 ipv4 tail three dots", ADDR, "if tail.matches('.').count() != 3 {", "if tail.matches('.').count() > 3 {", S),
    ("ipv6 gap needs room", ADDR, "        if out.len() == 16 {\n            return None;\n        }\n", "", S),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=600))
