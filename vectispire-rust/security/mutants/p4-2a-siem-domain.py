#!/usr/bin/env python3
"""Mutation check of Phase 4 task 4.2, first stage: the SIEM domain in crates/domain/src/siem (the catalogue and the
placement of every audit operation, the CEF escapes and field order, the syslog header and framing, the endpoint
reader, the severity minimum, the triage signals), TriageStatus moved to the domain, the calendar on Instant, and
cp-audit's guards between the audit vocabulary and the SIEM's. See README.md.
"""
import sys

import _runner

T = ["-p", "vectispire-domain", "--test", "siem", "--test", "siem_reference_set"]
A = ["-p", "vectispire-cp-audit", "--test", "siem_vocabulary"]
TS = ["-p", "vectispire-domain", "--lib", "triage_status"]
IN = ["-p", "vectispire-domain", "--lib", "instant"]

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
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=600))
