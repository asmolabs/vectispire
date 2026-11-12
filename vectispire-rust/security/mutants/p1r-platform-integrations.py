#!/usr/bin/env python3
"""Mutation check of the recovery plan's Phase 1, integrations (decision 0040): the registry (crates/cp-settings), the
SIEM transports as integrations (crates/cp-siem), the outbox's held delivery (crates/cp-outbox) and the governor's
routes (crates/cp-platform). The registry's and the SIEM's suites run on a database (Docker). See README.md.
"""
import sys

import _runner

ST = "crates/cp-settings/src/integrations.rs"
SC, SD, SU = "crates/cp-siem/src/config.rs", "crates/cp-siem/src/delivery.rs", "crates/cp-siem/src/internal/in_use.rs"
OL = "crates/cp-outbox/src/lib.rs"
PW = "crates/cp-platform/src/web/integrations.rs"
TS = ["-p", "vectispire-cp-settings", "--test", "integrations"]
TSIEM = ["-p", "vectispire-cp-siem", "--test", "engines"]
TO = ["-p", "vectispire-cp-outbox", "--test", "relay"]
TP = ["-p", "vectispire-cp-platform", "--lib"]

MUTANTS = [
    # ── the registry ──
    ("an absent row enabled", ST, "enabled: row.is_some_and(|row| row.enabled),", "enabled: row.is_none_or(|row| row.enabled),", TS),
    ("nothing is in use", ST, "                        if let Some(using) = using {", "                        if let Some(using) = using.filter(|_| false) {", TS),
    ("in use asked on enabling too", ST, "                if !enabled && current {", "                if current {", TS),
    ("a hold that holds nothing", ST, "            Some(true) => Ok(()),\n            _ => Err(IntegrationsError::Disabled(integration)),", "            _ => Ok(()),", TS),
    ("the absent key switched off writes", ST, "            None => return Ok(Switched { integration: IntegrationView::of(integration, None), changed: false }),", "            None => return Ok(Switched { integration: IntegrationView::of(integration, None), changed: true }),", TS),
    # ── the SIEM's transports ──
    ("an enabled save not asked", SC, "        if update.enabled {\n            self.integrations.require_enabled(transport).await?;\n        }", "", TSIEM),
    ("the test not asked", SC, "        self.integrations.require_enabled(Integration::of_siem(parsed)).await?;", "", TSIEM),
    ("the stop notice over a disabled transport", SC, "            Ok(true) => {}\n            Ok(false) => {", "            Ok(_) => {}\n            #[allow(unreachable_patterns)]\n            Ok(false) => {", TSIEM),
    ("a disabled transport delivers", SD, "        if !enabled {\n            return Err(DeliveryError::Held(", "        if false {\n            return Err(DeliveryError::Held(", TSIEM),
    ("a disabled export in use", SU, "                .filter(|(enabled, _)| *enabled)", "", TSIEM),
    # ── the outbox ──
    ("a hold counted", OL, "self.store.record_attempt(message.id, message.attempts, Some(&reason), PENDING, Some(next)).await?;", "self.store.record_attempt(message.id, attempts, Some(&reason), PENDING, Some(next)).await?;", TO),
    ("a hold abandoned", OL, "self.store.record_attempt(message.id, message.attempts, Some(&reason), PENDING, Some(next)).await?;", "self.store.record_attempt(message.id, message.attempts, Some(&reason), FAILED, None).await?;", TO),
    # ── the governor's route ──
    ("null read as off", PW, "            None | Some(Value::Null) => Ok(None),", "            None | Some(Value::Null) => Ok(Some(false)),", TP),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS))
