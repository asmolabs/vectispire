#!/usr/bin/env python3
"""Mutation check of Phase 4 task 4.2, second stage: the SIEM module's services in crates/cp-siem — what is queued and
when (the minimum, the export switched off or without an endpoint, the writer's signal, the connection test and the stop
notice never queued, the 1,024-unit cut and its `?`, the audit fallback, the chain's alarm), the queued payload as Java
writes and reads it, the delivery's gone-or-retried answers and the CA checked current, every check of the save (the
endpoint's length and storage, the header's protocol, characters, length, encryption and context, the moved endpoint,
the CA's protocol, paste reading and removal), the stop notice and whom it reaches, the connection test's outcomes, the
private switch, the webhook's header and statuses, and the syslog transport (no checked address, the datagram ceiling,
octet counting, a pin replacing the trust, the name verified, the runtime bundle, the deadline). See README.md.

The engine suite replays `reference/siem/module.json` on MySQL and PostgreSQL, so most mutants are killed by Java's own
answer for the case they break.
"""
import sys

import _runner

E = ["-p", "vectispire-cp-siem", "--test", "engines"]
TR = ["-p", "vectispire-cp-siem", "--test", "transport"]
EV = "crates/cp-siem/src/events.rs"
DL = "crates/cp-siem/src/delivery.rs"
CF = "crates/cp-siem/src/config.rs"
SE = "crates/cp-siem/src/internal/sender.rs"
SY = "crates/cp-siem/src/internal/syslog.rs"

# Equivalent, and removed: `QueuedEvent::to_event` replacing an `externalId` the row already holds in place is what
# `CefEvent::new` does anyway (a key given twice keeps its first place and its last value, as `LinkedHashMap.put`), so
# appending a second one leaves the same event. The listener's error leaving `recorded_in_transaction` cannot be told
# from a swallowed one by any test: the audit log writes the entry either way (on PostgreSQL the failed statement aborts
# the transaction and the entry is written again alone; on MySQL it commits) — the property is `cp-audit`'s.
MUTANTS = [
    # ---- events ----
    ("stop notice queued", EV, "SecurityEventType::PingTest | SecurityEventType::SiemExportStopped)", "SecurityEventType::PingTest)", E),
    ("ping queued", EV, "SecurityEventType::PingTest | SecurityEventType::SiemExportStopped)", "SecurityEventType::SiemExportStopped)", E),
    ("a disabled export queues", EV, "let exporting = config.enabled && config.endpoint", "let exporting = config.endpoint", E),
    ("a blank endpoint queues", EV, "config.endpoint.as_deref().is_some_and(|endpoint| !java::is_blank(endpoint));", "config.endpoint.as_deref().is_some();", E),
    ("the minimum ignored", EV, "if !exporting || !severity_filter::admits(event, Some(&config.min_severity)) {", "if !exporting {", E),
    ("the writer's signal ignored", EV, "        Some(signal) => match SecurityEventType::from_wire_name(signal.0) {", "        Some(signal) => match SecurityEventType::from_wire_name(signal.0).filter(|_| false) {", E),
    ("a cut pair dropped, not ?", EV, "                kept.push('?');\n", "", E),
    ("message bound 1023", EV, "pub const MAX_MESSAGE_LENGTH: usize = 1_024;", "pub const MAX_MESSAGE_LENGTH: usize = 1_023;", E),
    ("legacy severity not the type's", EV, "unwrap_or_else(|| i32::from(known.cef_severity()))", "unwrap_or(5)", E),
    ("epoch milli truncated", EV, "epoch_second: milliseconds.div_euclid(1_000)", "epoch_second: milliseconds.wrapping_div(1_000)", E),
    ("members not camelCase", EV, "#[serde(rename_all = \"camelCase\")]", "#[serde(rename_all = \"snake_case\")]", E),
    ("fallback publishes nothing", EV, "                self.publish(&event).await;\n", "                let _ = &event;\n", E),
    ("chain alarm not published", EV, "                Ok(event) => self.publish(&event).await,", "                Ok(event) => drop(event),", E),
    # ---- delivery ----
    ("disabled delivered", DL, "            .filter(|config| config.enabled)\n", "", E),
    ("blank endpoint delivered", DL, "            .filter(|config| config.endpoint.as_deref().is_some_and(|endpoint| !java::is_blank(endpoint)))\n", "", E),
    ("unknown protocol retried", DL, "ok_or_else(|| {\n            DeliveryError::Gone(format!(", "ok_or_else(|| {\n            DeliveryError::failed(\"IllegalStateException\", format!(", E),
    ("unusable endpoint retried", DL, "DeliveryError::Gone(format!(\"the stored SIEM endpoint is unusable", "DeliveryError::failed(\"IllegalArgumentException\", format!(\"the stored SIEM endpoint is unusable", E),
    ("lapsed CA trusted", DL, "CollectorCa::parse(Some(stored), instant(self.clock.now()))", "CollectorCa::read(Some(stored))", E),
    ("CA read for every protocol", DL, "stored.filter(|pem| protocol == SiemProtocol::SyslogTls && !java::is_blank(pem))", "stored.filter(|pem| !java::is_blank(pem))", E),
    ("header sent over syslog", DL, "let header: Option<Secret> = if protocol.carries_headers() {", "let header: Option<Secret> = if true {", E),
    # ---- the save ----
    ("endpoint length untrimmed", CF, "bounded_text::within(java::trim(text), MAX_ENDPOINT_LENGTH", "bounded_text::within(text, MAX_ENDPOINT_LENGTH", E),
    ("endpoint stored untrimmed", CF, "row.endpoint = endpoint_text.map(|text| java::trim(text).to_owned());", "row.endpoint = endpoint_text.map(str::to_owned);", E),
    ("enabled without endpoint", CF, "} else if update.enabled {", "} else if false {", E),
    ("header kept for syslog", CF, "            if !protocol.carries_headers() {", "            if false {", E),
    ("header any character", CF, "if !header.chars().all(|c| (' '..'\\u{7f}').contains(&c)) {", "if header.contains('\\n') {", E),
    ("header 1501", CF, "pub const MAX_AUTH_HEADER_LENGTH: usize = 1_500;", "pub const MAX_AUTH_HEADER_LENGTH: usize = 1_501;", E),
    ("CA accepted for another protocol", CF, "if ca_given.is_some() && protocol != SiemProtocol::SyslogTls {", "if false {", E),
    ("paste read leniently", CF, "Some(pem) => Some(CollectorCa::parse_pasted(Some(pem), instant(now)).map_err(invalid)?),", "Some(pem) => Some(CollectorCa::parse(Some(pem), instant(now)).map_err(invalid)?),", E),
    ("moved endpoint keeps header", CF, "if previous != next && header_given.is_none() {", "if previous != next && false {", E),
    ("blank header replaces", CF, "let header_given = update.auth_header.as_ref().filter(|header| !java::is_blank(header.expose()));", "let header_given = update.auth_header.as_ref();", E),
    ("header stored clear", CF, "row.auth_header = Some(self.encryption.encrypt(java::trim(header.expose()), AUTH_HEADER_CONTEXT).await?);", "row.auth_header = Some(java::trim(header.expose()).to_owned());", E),
    ("header context", CF, "pub const AUTH_HEADER_CONTEXT: &str = \"siem_config:auth_header\";", "pub const AUTH_HEADER_CONTEXT: &str = \"siem_config:header\";", E),
    ("CA kept off TLS", CF, "if protocol != SiemProtocol::SyslogTls || update.tls_ca_pem", "if update.tls_ca_pem", E),
    ("blank CA keeps", CF, "if protocol != SiemProtocol::SyslogTls || update.tls_ca_pem.as_deref().is_some_and(java::is_blank) {", "if protocol != SiemProtocol::SyslogTls {", E),
    ("redirect untold", CF, "leaving.filter(|previous| !row.enabled || !previous.same_destination_as(&row))", "leaving.filter(|_| !row.enabled)", E),
    ("same text other protocol stays", CF, "        self.protocol.name() == row.protocol\n            && row", "        row", E),
    ("lapsed CA told", CF, "            Some(pem) => match CollectorCa::parse(Some(pem), instant(self.now())) {", "            Some(pem) => match CollectorCa::read(Some(pem)) {", E),
    ("stale header sent over syslog", CF, "row.auth_header.as_deref().filter(|_| protocol.carries_headers())", "row.auth_header.as_deref()", E),
    ("notice words swapped", CF, "        let message = if redirected {", "        let message = if !redirected {", E),
    # ---- the connection test ----
    ("test endpoint required", CF, "if endpoint_text.is_none_or(java::is_blank) {", "if endpoint_text.is_none() {", E),
    ("test sends header over syslog", CF, "let header = auth_header.filter(|_| parsed.carries_headers());", "let header = auth_header;", E),
    ("stored CA read as a paste", CF, "                let read = if tls_ca_pem.is_some() {", "                let read = if true {", E),
    ("status 200 for syslog", CF, "status_code: if parsed.carries_headers() { 200 } else { 0 },", "status_code: 200,", E),
    ("policy outcome said as a failure", CF, "                TestResult::refused(REFUSED_BY_POLICY)", "                TestResult::refused(NOT_DELIVERED)", E),
    ("minimum by ASCII case", CF, "java::compare_ignore_case(candidate, trimmed).is_eq()", "candidate.eq_ignore_ascii_case(trimmed)", E),
    ("blank protocol refused", CF, "let protocol = match update.protocol.as_deref().filter(|value| !java::is_blank(value)) {", "let protocol = match update.protocol.as_deref() {", E),
    # ---- the sender ----
    ("private allowed ignored", SE, "Ok(true) => Ok(OutboundPolicy::InternalAllowed),", "Ok(true) => Ok(OutboundPolicy::PublicOnly),", TR),
    ("private refused ignored", SE, "Ok(false) => Ok(OutboundPolicy::PublicOnly),", "Ok(false) => Ok(OutboundPolicy::InternalAllowed),", TR),
    ("blank header sent", SE, "if let Some(header) = header.filter(|header| !java::is_blank(header.expose())) {", "if let Some(header) = header {", TR),
    ("a redirect accepted", SE, "if answer.status / 100 != 2 {", "if answer.status >= 400 {", TR),
    ("429 not rate-limited", SE, "let rate_limited = answer.status == 429", "let rate_limited = answer.status == 430", TR),
    # ---- syslog ----
    ("no address resolved again", SY, "        if destination.addresses.is_empty() {", "        if false {", TR),
    ("datagram at the limit refused", SY, "if payload.len() > MAX_DATAGRAM {", "if payload.len() >= MAX_DATAGRAM {", TR),
    ("stream unframed", SY, "write_frame(stream, &syslog::octet_counted(message), timeout, label).await", "write_frame(stream, message.as_bytes(), timeout, label).await", TR),
    ("pin joins the runtime", SY, "Some(ca) => Arc::new(pinned_roots(ca, label)?),", "Some(ca) => {\n                        let mut roots = (*self.runtime).clone();\n                        roots.roots.extend(pinned_roots(ca, label)?.roots);\n                        Arc::new(roots)\n                    }", TR),
    ("pin ignored", SY, "Some(ca) => Arc::new(pinned_roots(ca, label)?),", "Some(_) => self.runtime.clone(),", TR),
    ("name not the one written", SY, "let name = ServerName::try_from(destination.host.clone())", "let name = ServerName::try_from(\"collector.test\".to_owned())", TR),
    ("bundle not read", SY, "let (added, _) = roots.add_parsable_certificates(certificates);", "let (added, _) = (certificates.len(), ());", TR),
    ("no deadline", SY, "    match tokio::time::timeout(timeout, exchange).await {", "    match Ok::<_, ()>(exchange.await) {", TR),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=300))
