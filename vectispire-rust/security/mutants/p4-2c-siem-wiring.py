#!/usr/bin/env python3
"""Mutation check of Phase 4 task 4.2, third stage: the SIEM routes and the module's place in the binary — the routes'
markers, the unconfigured answer and the refusals' statuses, `RequestActors`' fallback, the composition (the handler in
the outbox's registry, the listener in the audit log, the chain-broken listener, the guard built at start handed to the
sender), and the emitters wired through `cp_outbox::SecurityEvents`: the issues' leak and deadline, the gate's refusal
together with its verdict or apart, and never for a pass. See README.md.
"""
import sys

import _runner

COMPOSED = ["-p", "vectispire-cp-app", "--test", "siem_composition"]
MAINT = ["-p", "vectispire-cp-app", "--test", "maintenance_composition"]
CONTRACT = ["-p", "vectispire-cp-siem", "--test", "contract"]
SIEM = ["-p", "vectispire-cp-siem", "--lib"]
ACCESS = ["-p", "vectispire-cp-access", "--lib", "actors"]
ISSUES = ["-p", "vectispire-cp-issues", "--lib"]
GATE = ["-p", "vectispire-cp-gate", "--lib", "persistence"]
CA = "crates/cp-app/src/siem.rs"
MT = "crates/cp-app/src/maintenance.rs"
WEB = "crates/cp-siem/src/web/mod.rs"
ACT = "crates/cp-access/src/security/actors.rs"
SYNC = "crates/cp-issues/src/sync.rs"
SLA = "crates/cp-issues/src/sla.rs"
SIG = "crates/cp-issues/src/signals.rs"
GS = "crates/cp-gate/src/service.rs"

MUTANTS = [
    # ---- the composition ----
    ("handler not registered", MT, "AgentResultAuditDelivery::new(audit)), siem.delivery.clone()],", "AgentResultAuditDelivery::new(audit))],", [MAINT, COMPOSED]),
    ("listener not in the audit log", CA, "pub fn audit_listeners(siem: &Siem) -> Vec<Arc<dyn vectispire_cp_audit::Listener>> {\n    vec![siem.events.clone()]", "pub fn audit_listeners(siem: &Siem) -> Vec<Arc<dyn vectispire_cp_audit::Listener>> {\n    let _ = siem;\n    Vec::new()", COMPOSED),
    ("chain alarm not heard", CA, "pub fn chain_broken_listeners(siem: &Siem) -> Vec<Arc<dyn vectispire_cp_audit::ChainBrokenListener>> {\n    vec![siem.events.clone()]", "pub fn chain_broken_listeners(siem: &Siem) -> Vec<Arc<dyn vectispire_cp_audit::ChainBrokenListener>> {\n    let _ = siem;\n    Vec::new()", COMPOSED),
    ("start's guard not the sender's", CA, "        setup.guard,\n        PinnedHttpSender", "        OutboundUrlGuard::new(Vec::new()),\n        PinnedHttpSender", COMPOSED),
    # ---- the routes ----
    ("save open to governance read", WEB, "Route::put(CONFIG).requires(Access::SecurityLead)", "Route::put(CONFIG).requires(Access::GovernanceRead)", CONTRACT),
    ("test open to governance read", WEB, "Route::post(TEST).requires(Access::SecurityLead)", "Route::post(TEST).requires(Access::GovernanceRead)", CONTRACT),
    ("unconfigured minimum", WEB, "            min_severity: \"HIGH\".to_owned(),\n            tls_ca_pem: None,", "            min_severity: \"LOW\".to_owned(),\n            tls_ca_pem: None,", SIEM),
    ("missing key a 400", WEB, "Problem::handler(StatusCode::PRECONDITION_FAILED, EncryptionError::MissingKey.to_string())", "Problem::handler(StatusCode::BAD_REQUEST, EncryptionError::MissingKey.to_string())", SIEM),
    ("actor without fallback", ACT, "principal.actor().unwrap_or_else(|| fallback.to_owned())", "principal.actor().unwrap_or_default()", ACCESS),
    # ---- the issues' emitters ----
    ("a medium secret is a leak", SIG, "Severity::of(Some(severity)).is_at_least(Severity::High)", "Severity::of(Some(severity)).is_at_least(Severity::Medium)", ISSUES),
    ("leak not raised", SYNC, "            events.raise(tx, &event).await.map_err(|failed| IssueError::Store(failed.to_string()))?;\n", "            let _ = event;\n", ISSUES),
    ("deadline not raised", SLA, "                self.events.raise(&mut tx, &event).await.map_err(|failed| IssueError::Store(failed.to_string()))?;\n", "                let _ = event;\n", ISSUES),
    ("deadline dated when noticed", SLA, "                    breach.first_seen_at.saturating_add(window),", "                    now,", ISSUES),
    # ---- the gate's emitter ----
    ("refusal not raised with its verdict", GS, "            self.events.raise(&mut tx, event).await?;", "            let _ = event;", GATE),
    ("refusal not raised apart", GS, "            self.events.raise_apart(event).await;", "            let _ = event;", GATE),
    ("a pass raises", GS, "let refusal = if decision.verdict.passed { None } else { self.refusal(target, decision, caller) };", "let refusal = self.refusal(target, decision, caller);", GATE),
    ("verdict lost when the event fails", GS, "        if let Err(failed) = self.record_alone(target, decision, caller).await {", "        if let Err(failed) = Err::<(), &str>(\"skipped\") {", GATE),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=600))
