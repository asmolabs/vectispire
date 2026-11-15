#!/usr/bin/env python3
"""Mutation check of the platform port's second stage: the settings catalog and save's routes (crates/cp-platform/src/web/settings.rs), the two narrow parts of tickets and ai a save runs (crates/cp-platform/src/seams.rs, held to reference/platform/settings-save.json on a database), and the binary's composition of the settings screen (crates/cp-app). See README.md.

Not mutants:
- `settings_screen::compose`'s registry replaced by a fresh `Integrations` over the same database — equivalent: the
  registry is its table, and the save neither asks nor answers "in use".
- `GuardedAiDestination::stored_url`'s default for an empty stored URL dropped — equivalent while the catalog's default
  of both URLs is the provider's default address: `Settings::get` already answers it for a key with no row, and a row
  stored empty is cleared by the save's own check on a blank URL.
"""
import sys

import _runner

SEAMS = "crates/cp-platform/src/seams.rs"
WEB = "crates/cp-platform/src/web/settings.rs"
SCREEN = "crates/cp-app/src/settings_screen.rs"
REGISTRY = "crates/cp-app/src/registry.rs"
REFERENCE = ["-p", "vectispire-cp-platform", "--test", "save_reference"]
UNITS = ["-p", "vectispire-cp-platform", "--lib", "settings"]
CONTRACT = ["-p", "vectispire-cp-platform", "--test", "contract"]
COMPOSITION = ["-p", "vectispire-cp-app", "--test", "settings_composition"]
PARTITION = ["-p", "vectispire-cp-app", "--test", "route_authorization"]

MUTANTS = [
    # ── tickets' CA pinning ──
    ("the CA's dates not read", SEAMS, "PinnedCa::parse_pasted(Some(pem), instant(self.clock.now()), &TRACKER_CA)", "PinnedCa::read(Some(pem), &TRACKER_CA)", REFERENCE),
    ("the collector's words for the tracker's", SEAMS, 'Subject { field: "The tracker CA", server: "the tracker" }', 'Subject { field: "The collector CA", server: "the collector" }', REFERENCE),
    # ── ai's destination guard ──
    ("the acknowledgement lets nothing through", SEAMS, "            if after.allow_remote {\n                return Ok(None);", "            if false {\n                return Ok(None);", REFERENCE),
    ("a cleared URL judged as typed", SEAMS, "let url = if vectispire_cp_settings::types::is_blank(&url) { default.to_owned() } else { url };", "let url = url;", REFERENCE),
    ("the provider read as typed", SEAMS, 'let openai = java_trim(after.provider).to_lowercase() == "openai";', 'let openai = after.provider == "openai";', REFERENCE),
    ("an internal destination allowed, not required", SEAMS, "OutboundPolicy::InternalRequired", "OutboundPolicy::InternalAllowed", REFERENCE),
    ("the refusal not naming the provider", SEAMS, 'let label = format!("{display} URL");', 'let label = "URL".to_owned();', REFERENCE),
    ("the acceptor's name kept untrimmed", SEAMS, "Setting::AiReviewRiskAcknowledgedBy, java_trim(by)", "Setting::AiReviewRiskAcknowledgedBy, by", REFERENCE),
    ("the acceptance's instant in seconds", SEAMS, "&vectispire_cp_audit::iso_instant(at)", "&at.unix_timestamp().to_string()", REFERENCE),
    ("the acceptor kept when the switch goes off", SEAMS, '            self.settings.set(tx, Setting::AiReviewRiskAcknowledgedBy, "").await?;\n', "", REFERENCE),
    # ── the routes ──
    ("a repeated key keeps its first value", WEB, "Some(pair) => pair.1 = value,", "Some(_) => {}", UNITS),
    ("a number's text through a double", WEB, "Some(_) => Ok(Some(raw.to_owned())),", 'Some(_) => Ok(Some(serde_json::from_str::<serde_json::Value>(raw).map_err(|_| "x")?.to_string())),', UNITS),
    ("a container read as text", WEB, "Some(b'{' | b'[') | None => Err(", "None => Err(", UNITS),
    ("an access denial answered by the handler", WEB, "AdministrationError::AccessDenied(reason) => vectispire_cp_http::chain::denied(reason),", "AdministrationError::AccessDenied(reason) => Problem::handler(StatusCode::FORBIDDEN, reason).into_response(),", UNITS),
    ("any role administrative", WEB, "administrative: account.role.is_some_and(|role| role.is_administrative()),", "administrative: account.role.is_some(),", UNITS),
    ("an administrator governs the platform", WEB, "governs_platform: account.role.is_some_and(|role| role.governs_platform()),", "governs_platform: account.role.is_some_and(|role| role.is_administrative()),", UNITS),
    ("the save open to every account", WEB, "Route::put(SETTINGS).requires(Access::SecurityLead)", "Route::put(SETTINGS).requires(Access::Account)", CONTRACT),
    # ── the binary's composition ──
    ("four-eyes asked of nobody", SCREEN, "Box::pin(async move { Ok(self.0.any_active().await?) })", "Box::pin(async move { Ok(true) })", COMPOSITION),
    ("a fresh guard in place of the process's", SCREEN, "GuardedAiDestination::new(Settings::new(db.clone()), guard)", "GuardedAiDestination::new(Settings::new(db.clone()), OutboundUrlGuard::new(Vec::new()))", COMPOSITION),
    ("the settings routes not registered", REGISTRY, "    list.extend(vectispire_cp_platform::settings_routes(platform.settings));\n", "", PARTITION),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
