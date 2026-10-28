#!/usr/bin/env python3
"""Mutation check of Phase 4 task 4.2, first stage: the SIEM domain in crates/domain/src/siem (the catalogue and the
placement of every audit operation, the CEF escapes and field order, the syslog header and framing, the endpoint
reader — a webhook's port, a numeric host as `Inet4Address.ofLiteral` reads it —, the severity minimum, the triage
signals, the collector CA and the PEM and X.509 reading under it, a pasted bundle read whole),
TriageStatus moved to the domain, the calendar on Instant, and
cp-audit's guards between the audit vocabulary and the SIEM's. See README.md.
"""
import sys

import _runner

T = ["-p", "vectispire-domain", "--test", "siem", "--test", "siem_reference_set"]
A = ["-p", "vectispire-cp-audit", "--test", "siem_vocabulary"]
TS = ["-p", "vectispire-domain", "--lib", "triage_status"]
IN = ["-p", "vectispire-domain", "--lib", "instant"]
CA = ["-p", "vectispire-domain", "--test", "collector_ca"]
X = ["-p", "vectispire-domain", "--lib", "x509"]
CAX = [CA, X]
EL = [T, ["-p", "vectispire-domain", "--lib", "siem::endpoint"]]
EP = "crates/domain/src/siem/endpoint.rs"

# Equivalent, and removed: BER's indefinite length is refused by the shortest-form check as a length of zero, so
# no separate guard exists for it; after a `\#` prefix `leading` is zero, so no prefix test guards the leading
# spaces; reading every value of a single-valued RDN is reading its first. `java_uri` resetting the port when a
# server authority falls back to a registry one is Java's, and unreachable: the port is the last thing read, so
# nothing fails after it. An empty part of an IPv4 literal is refused by the parse of its digits as well, and a single
# part's 32-bit bound by the `u32` the last part is written into.
MUTANTS = [
    ("cef '=' escaped in values", "crates/domain/src/siem/cef.rs", "            '=' => out.push_str(\"\\\\=\"),\n", "", T),
    ("cef '|' escaped in header", "crates/domain/src/siem/cef.rs", "            '|' => out.push_str(\"\\\\|\"),\n", "", T),
    ("cef CR escaped in values", "crates/domain/src/siem/cef.rs", "            '\\r' => out.push_str(\"\\\\r\"),\n", "", T),
    ("cef controls neutralised", "crates/domain/src/siem/cef.rs", "matches!(c, '\\u{0}'..='\\u{1f}' | '\\u{7f}'..='\\u{9f}' | '\\u{2028}' | '\\u{2029}')", "matches!(c, '\\u{0}'..='\\u{1f}')", T),
    ("cef key ASCII only", "crates/domain/src/siem/cef.rs", "b.is_ascii_alphanumeric())", "b.is_ascii_alphanumeric() || b >= 0x80)", T),
    ("cef key empty refused", "crates/domain/src/siem/cef.rs", "if key.is_empty() || !key", "if !key", T),
    ("cef LinkedHashMap put in place", "crates/domain/src/siem/cef.rs", "        Some((_, existing)) => value.clone_into(existing),", "        Some(_) => fields.push((key.to_owned(), value.to_owned())),", T),
    ("cef blank (isBlank) not empty", "crates/domain/src/siem/cef.rs", "    fn put_present(mut self, key: &str, value: Option<&str>) -> Self {\n        if let Some(value) = value.filter(|value| !java::is_blank(value))", "    fn put_present(mut self, key: &str, value: Option<&str>) -> Self {\n        if let Some(value) = value.filter(|value| !value.trim().is_empty())", T),
    ("cef fixed severity refused", "crates/domain/src/siem/cef.rs", "        } else if self.refused.is_none() {", "        } else if false {", T),
    ("cef severity range", "crates/domain/src/siem/cef.rs", ".filter(|severity| *severity <= 10)", ".filter(|severity| *severity <= 11)", T),
    ("syslog header token printable", "crates/domain/src/siem/syslog.rs", "('!'..='~').contains(c)", "(' '..='~').contains(c)", T),
    ("syslog hostname cap", "crates/domain/src/siem/syslog.rs", ".take(max_length)", ".take(max_length.saturating_add(1))", T),
    ("syslog band 9", "crates/domain/src/siem/syslog.rs", "        9.. => 2,", "        10.. => 2,", T),
    ("syslog octet count bytes", "crates/domain/src/siem/syslog.rs", "format!(\"{} \", message.len())", "format!(\"{} \", message.chars().count())", T),
    ("syslog event severity not type", "crates/domain/src/siem/syslog.rs", "priority(event.cef_severity())", "priority(event.event_type().cef_severity())", T),
    ("endpoint mapped v4 refused", "crates/domain/src/siem/endpoint.rs", ".is_ok_and(|parsed| parsed.to_ipv4_mapped().is_none())", ".is_ok()", T),
    ("endpoint numeric scope bound", "crates/domain/src/siem/endpoint.rs", " || scope.parse::<i32>().is_err())", ")", T),
    ("endpoint label length", "crates/domain/src/siem/endpoint.rs", "label.len() <= 63", "label.len() <= 64", T),
    ("endpoint ascii only host", "crates/domain/src/siem/endpoint.rs", "alphanumeric_ends && label.len()", "true && label.len()", T),
    ("endpoint port >= 1", "crates/domain/src/siem/endpoint.rs", ".filter(|port| *port >= 1)", "", T),
    ("endpoint port ascii digits", "crates/domain/src/siem/endpoint.rs", "!text.bytes().all(|b| b.is_ascii_digit())", "false", T),
    ("endpoint no path", "crates/domain/src/siem/endpoint.rs", "if value.contains('/') {", "if value.contains(\"://\") {", T),
    ("endpoint java trim", "crates/domain/src/siem/endpoint.rs", "let value = java::trim(endpoint.unwrap_or(\"\"));", "let value = endpoint.unwrap_or(\"\").trim();", T),
    ("endpoint webhook host required", "crates/domain/src/siem/endpoint.rs", "uri.host.as_deref().is_none_or(java::is_blank)", "false", T),
    ("webhook port 0 accepted", EP, "port == 0 || port > 65_535", "port > 65_535", T),
    ("webhook port 65536 accepted", EP, "port == 0 || port > 65_535", "port == 0 || port > 65_536", T),
    ("uri port not read", "crates/domain/src/repository_url.rs", "self.port = Some(self.substring(p, q).parse::<i32>().map_err(|_| Syntax)?);", "self.substring(p, q).parse::<i32>().map_err(|_| Syntax)?;", T),
    ("numeric host not checked", EP, " || (is_numeric(host) && !is_ipv4_literal(host))", "", T),
    ("numeric host digits only", EP, "b.is_ascii_digit() || b == b'.')", "b.is_ascii_digit())", T),
    ("numeric host trailing dot kept", EP, "ipv4_of_literal(host.strip_suffix('.').unwrap_or(host))", "ipv4_of_literal(host)", T),
    ("ipv4 fifteen characters", EP, "java::utf16_len(text) > 15", "java::utf16_len(text) > 16", EL),
    ("ipv4 four parts", EP, "if leading.len() > 3 {", "if leading.len() > 4 {", EL),
    ("ipv4 leading part a byte", EP, "*byte = u8::try_from(value(part)?).ok()?;", "*byte = u8::try_from(value(part)? & 0xff).ok()?;", EL),
    ("ipv4 two parts 24 bits", EP, "1 => 1 << 24,", "1 => 1 << 25,", EL),
    ("ipv4 three parts 16 bits", EP, "2 => 1 << 16,", "2 => 1 << 17,", EL),
    ("ipv4 four parts 8 bits", EP, "_ => 1 << 8,", "_ => 1 << 9,", EL),
    ("ipv4 bound exclusive", EP, "if last >= bound {", "if last > bound {", EL),
    ("ipv4 last part fills the bytes left", EP, ".zip(tail).skip(leading.len())", ".zip(tail)", EL),
    ("pasted damaged marker accepted", "crates/domain/src/pinned_ca.rs", "if read.pem.to_ascii_lowercase().matches(\"-----begin\").count() > read.anchors.len() {", "if false {", CA),
    ("pasted every bundle refused", "crates/domain/src/pinned_ca.rs", "if read.pem.to_ascii_lowercase().matches(\"-----begin\").count() > read.anchors.len() {", "if read.pem.to_ascii_lowercase().matches(\"-----begin\").count() >= read.anchors.len() {", CA),
    ("pasted marker with its space", "crates/domain/src/pinned_ca.rs", "if read.pem.to_ascii_lowercase().matches(\"-----begin\").count() > read.anchors.len() {", "if read.pem.to_ascii_lowercase().matches(\"-----begin \").count() > read.anchors.len() {", CA),
    ("pasted marker in capitals only", "crates/domain/src/pinned_ca.rs", "if read.pem.to_ascii_lowercase().matches(\"-----begin\").count() > read.anchors.len() {", "if read.pem.matches(\"-----BEGIN\").count() > read.anchors.len() {", CA),
    ("collector paste read leniently", "crates/domain/src/siem/collector_ca.rs", "PinnedCa::parse_pasted(pem, now, &SUBJECT)", "PinnedCa::parse(pem, now, &SUBJECT)", CA),
    ("filter ping bypass", "crates/domain/src/siem/severity_filter.rs", "    if event.event_type() == SecurityEventType::PingTest {\n        return true;\n    }\n", "", T),
    ("filter unreadable sends all", "crates/domain/src/siem/severity_filter.rs", ".is_none_or(|floor|", ".is_some_and(|floor|", T),
    ("filter event severity", "crates/domain/src/siem/severity_filter.rs", "event.cef_severity() >= floor", "event.event_type().cef_severity() >= floor", T),
    ("filter high floor", "crates/domain/src/siem/severity_filter.rs", "Severity::High => Some(7)", "Severity::High => Some(8)", T),
    ("triage request answered", "crates/domain/src/siem/triage_signals.rs", "        return Some(if answers_a_request {", "        return Some(if false {", T),
    ("triage pending stays quiet", "crates/domain/src/siem/triage_signals.rs", "(answers_a_request && after != TriageStatus::PendingApproval)", "answers_a_request", T),
    ("catalogue signature id", "crates/domain/src/siem/event_type.rs", "\"VECTI-SEC-029\"", "\"VECTI-SEC-001\"", T),
    ("catalogue follows issue", "crates/domain/src/siem/event_type.rs", "6, Detected, true;", "6, Detected;", T),
    ("issue severity critical 8", "crates/domain/src/siem/event_type.rs", "Severity::Critical => 8,", "Severity::Critical => 9,", T),
    ("placement one mapping", "crates/domain/src/siem/event_type.rs", "(\"CHECKLIST_RETURNED\", E::ChecklistSignOffRefused),", "(\"CHECKLIST_RETURNED\", E::ChecklistSignedOff),", T),
    ("operation unplaced", "crates/domain/src/siem/event_type.rs", "    \"CHECKLIST_REMINDER_SENT\",\n", "", A),
    ("stray placed name", "crates/domain/src/siem/event_type.rs", "    \"LOGIN_SUCCESS\",\n", "    \"LOGIN_SUCCESS\",\n    \"LOGIN_SUCESS\",\n", A),
    ("signal names an event", "crates/domain/src/siem/event_type.rs", "AccessGrantChanged = \"ACCESS_GRANT_CHANGED\"", "AccessGrantChanged = \"ACCESS_GRANTS_CHANGED\"", A),
    ("triage status java trim", "crates/domain/src/triage_status.rs", "java::to_lower_root(java::trim(value))", "java::to_lower_root(value.trim())", TS),
    ("instant civil", "crates/domain/src/instant.rs", ".checked_add(if month <= 2 { 1 } else { 0 })?", ".checked_add(0)?", IN),
    ("bundle length in characters", "crates/domain/src/pinned_ca.rs", "let length = java::utf16_len(value);", "let length = value.chars().count();", CA),
    ("nine certificates accepted", "crates/domain/src/pinned_ca.rs", "if anchors.len() == MAX_CERTIFICATES {", "if anchors.len() > MAX_CERTIFICATES {", CA),
    ("a known type that does not decode is something other", "crates/domain/src/pinned_ca.rs", " || x509::read_whole(&der).is_none()", "", CA),
    ("any type is something other", "crates/domain/src/pinned_ca.rs", "!OTHER_KNOWN_TYPES.contains(&kind.as_str()) || ", "", CA),
    ("X509 CERTIFICATE not a certificate", "crates/domain/src/pinned_ca.rs", "&[\"CERTIFICATE\", \"X509 CERTIFICATE\"]", "&[\"CERTIFICATE\"]", CA),
    ("expired is after the instant", "crates/domain/src/pinned_ca.rs", "if now >= anchor.not_after {", "if now > anchor.not_after {", CA),
    ("not-yet-valid never refused", "crates/domain/src/pinned_ca.rs", "if now < anchor.not_before {", "if false {", CA),
    ("lone CR ends no line", "crates/domain/src/pinned_ca.rs", "rest.find(['\\n', '\\r'])", "rest.find('\\n')", CA),
    ("headers read as Base64", "crates/domain/src/pinned_ca.rs", "        if line.contains(':') {\n            // A header (`Proc-Type: …`): read and set aside.\n            continue;\n        }\n", "", CA),
    ("a broken BEGIN is unreadable", "crates/domain/src/pinned_ca.rs", "    if tail != \"-----\" {\n        return None;\n    }", "    if tail != \"-----\" {\n        return Some(None);\n    }", CA),
    ("whole text not trimmed", "crates/domain/src/pinned_ca.rs", "let value = java::trim(pem.unwrap_or(\"\"));", "let value = pem.unwrap_or(\"\");", CA),
    ("base64 lines not trimmed", "crates/domain/src/pinned_ca.rs", "body.push_str(java::trim(line));", "body.push_str(line);", CA),
    ("an END line found anywhere", "crates/domain/src/pinned_ca.rs", "if line.starts_with(&end_marker) {", "if line.contains(&end_marker) {", CA),
    ("dates checked before the CA flag", "crates/domain/src/pinned_ca.rs", "    let Some(name) = certificate.subject() else { return Ok(None) };\n", "    let Some(name) = certificate.subject() else { return Ok(None) };\n    if certificate.not_after().is_none() {\n        return Ok(None);\n    }\n    if name.contains(\"Odd\") {\n        return Ok(None);\n    }\n", CA),
    ("no constraints is a CA", "crates/domain/src/x509.rs", "let Some(value) = self.extension(BASIC_CONSTRAINTS) else { return Some(false) };", "let Some(value) = self.extension(BASIC_CONSTRAINTS) else { return Some(true) };", CAX),
    ("keyCertSign not asked of a wide usage", "crates/domain/src/x509.rs", "[first, ..] => first & 0x04 != 0,", "[first, ..] => first & 0x04 != 0 && false,", CAX),
    ("last octet not masked", "crates/domain/src/x509.rs", "[only] => only & 0x04 != 0 && unused <= 2,", "[only] => only & 0x04 != 0,", X),
    ("v1 extras allowed", "crates/domain/src/x509.rs", "if version == 1 && !extras.is_empty() {", "if false {", X),
    ("v2 extensions allowed", "crates/domain/src/x509.rs", "0xa3 if version != 2 =>", "0xa3 =>", X),
    ("empty issuer allowed", "crates/domain/src/x509.rs", "        if name(fields.next())?.is_empty() {\n            return None;\n        }", "        name(fields.next())?;", X),
    ("repeated extension allowed", "crates/domain/src/x509.rs", "        if read.iter().any(|(known, _)| *known == id.value) {\n            return None;\n        }\n", "", X),
    ("non-minimal length read", "crates/domain/src/x509.rs", "        if length < 0x80 {\n            return None;\n        }\n", "", X),
    ("UTC pivot at 49", "crates/domain/src/x509.rs", "if year < 50 {", "if year < 49 {", CAX),
    ("symbols: E unnamed", "crates/domain/src/x509.rs", "(\"1.2.840.113549.1.9.1\", \"E\"),", "", CA),
    ("BMP read as Latin-1", "crates/domain/src/x509.rs", "0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x19 | 0x1a | 0x1b =>", "0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x19 | 0x1a | 0x1b | 0x1e =>", CA),
    ("bit string hex lower-case", "crates/domain/src/x509.rs", "format!(\"\\\\#{}\", hex(value.encoded, true))", "format!(\"\\\\#{}\", hex(value.encoded, false))", CA),
    ("no hash escape", "crates/domain/src/x509.rs", "if text.starts_with('#') { format!(\"\\\\{text}\") } else { text }", "text", CA),
    ("trailing spaces kept", "crates/domain/src/x509.rs", "|| index >= trailing_from", "", CAX),
    ("multi-valued joined by comma", "crates/domain/src/x509.rs", "rendered.push(parts.join(\"+\"));", "rendered.push(parts.join(\",\"));", CA),
    ("arcs over 40 not split", "crates/domain/src/x509.rs", "40..80 => (1, arc.checked_sub(40)?),", "40..80 => (2, arc.checked_sub(80)?),", X),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=600))
