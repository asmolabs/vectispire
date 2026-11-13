#!/usr/bin/env python3
"""Mutation check of the recovery plan's Phase 1, access and settings catch-up to Java 1.0: the derivation bound (cp-access
derivations, passwords, the sign-in, the password change and the MFA enrolment taking their attempt back), the
password asked again at MFA enrolment, the e-mail address of an account the directory writes and SCIM's lowered role,
the settings save's integrations, held channels and secret administrator-only keys, the AI endpoint check, and
cp-app's composition of `vectispire.sign-in.*`. See README.md.

Not mutants: the users' statements' new column (`scim_lowered_from` in `update_row`) — a checked statement changed
without its cache does not compile, so the mutant proves nothing; `tests/engines.rs` reads the column back on a real
server. The risk acknowledgement written in the save's transaction rather than after it — no test can see the
difference without a failure injected between the two writes.
"""
import sys

import _runner

DERIV = "crates/cp-access/src/derivations.rs"
PW = "crates/cp-access/src/passwords.rs"
ACC = "crates/cp-access/src/accounts.rs"
RULES = "crates/cp-access/src/account_rules.rs"
SIGN = "crates/cp-access/src/sign_in.rs"
SF = "crates/cp-access/src/second_factor.rs"
SCIM = "crates/cp-access/src/scim.rs"
SET = "crates/cp-platform/src/settings.rs"
APP = "crates/cp-app/src/access.rs"

D = ["-p", "vectispire-cp-access", "--test", "derivations"]
DL = ["-p", "vectispire-cp-access", "--lib", "derivations"]
FLOW = ["-p", "vectispire-cp-access", "--test", "sign_in_flow"]
SVC = ["-p", "vectispire-cp-access", "--test", "service"]
SCIMT = ["-p", "vectispire-cp-access", "--test", "scim_on_both_engines"]
PLAT = ["-p", "vectispire-cp-platform", "--test", "engines"]
APPT = ["-p", "vectispire-cp-app", "--test", "access_composition"]

MUTANTS = [
    # ── the bound on derivations ──
    ("a derivation waits as long as it takes", DERIV, "tokio::time::timeout(self.wait, self.permits.acquire())", "tokio::time::timeout(Duration::from_secs(30), self.permits.acquire())", D),
    ("retry after at least a second", DERIV, "self.wait.max(Duration::from_secs(1))", "self.wait", [D, DL]),
    ("an unset bound is the shipped one", DERIV, "if permits > 0 { permits } else { DerivationGate::default_permits() }", "permits", DL),
    ("at least two permits", DERIV, "let by_processors = processors.max(2);", "let by_processors = processors;", DL),
    ("a quarter of the memory", DERIV, ".checked_div(MEMORY_SHARE_DIVISOR)", ".checked_div(1)", DL),
    ("the wait in the refusal's body", DERIV, '.with("retryAfterSeconds", seconds)', "", D),
    ("verify under the bound", PW, "Some(prepared) => crate::derivations::gate().run(move || prepared.matches()).await,", "Some(prepared) => Ok(prepared.matches()),", D),
    ("hash under the bound", PW, "crate::derivations::gate().run(|| hash(password)).await", "Ok(hash(password))", D),
    ("the sign-in's derivation bounded", ACC, "let matches = passwords::verify_bounded(password, Some(against)).await?;", "let matches = passwords::verify(password, Some(against));", D),
    ("a saturated sign-in takes its rows back", SIGN, "                self.throttle().release(&throttle).await?;\n                return Err(saturated.into());", "                return Err(saturated.into());", D),
    ("a saturated password check takes its reservation back", ACC, "            attempts.release(held).await?;\n            Err(saturated.into())", "            Err(saturated.into())", D),
    # ── MFA enrolment asks the password ──
    ("enrolment on a wrong password", SF, "        if !matches {", "        if false {", FLOW),
    ("enrolment past the budget", SF, "        let attempt = self.throttle.reserve_password(user.id, ip_address).await?;\n        if !attempt.admitted() {", "        let attempt = self.throttle.reserve_password(user.id, ip_address).await?;\n        if false {", FLOW),
    ("enrolment clears this client's failures", SF, "        self.throttle.clear_password_failures(user.id, ip_address).await?;\n", "", FLOW),
    # ── the e-mail address and the directory ──
    ("the directory's address changed", ACC, "        if user.scim_managed {", "        if false {", SVC),
    ("the address it holds is no change", ACC, "        if email == user.email {\n            return Ok(None);\n        }\n", "", SVC),
    ("another account's address", ACC, "            && self.store.email_taken(email, account_id).await?", "            && false", SVC),
    ("an address read as one", ACC, "        refuse_if(account_rules::validate_email(Some(email)))?;\n", "", SVC),
    ("a format character is no address", RULES, "            | G::Format\n", "", SVC),
    ("a domain with a dot", RULES, " && dotted\n", "\n", SVC),
    ("a role set lifts the lowering", ACC, "        if change.role.is_some()\n            && let Some(lowered)", "        if false\n            && let Some(lowered)", SVC),
    ("the lowered role recorded", SCIM, "            user.scim_lowered_from = Some(previous_role.clone());\n", "", SCIMT),
    ("a lowered account not bound", SCIM, "            if let Some(lowered) = &user.scim_lowered_from\n                && !link_privileged", "            if let Some(lowered) = &user.scim_lowered_from\n                && false", SCIMT),
    # ── the settings save and the AI endpoint ──
    ("a secret administrator-only key unchanged", SET, "&& (setting.is_secret() || value != self.settings.get(setting).await?)", "&& (value != self.settings.get(setting).await?)", PLAT),
    ("the Ollama address's own sentence", SET, "None if setting == Setting::AiReviewOllamaUrl => format!(", "None if false => format!(", PLAT),
    ("a disabled tracker chosen", SET, '            self.require_enabled(integration("tracker", chosen)?).await?;\n', "", PLAT),
    ("the tracker it has sent back", SET, "            && Some(chosen) != tracker(&self.settings.get(setting).await?)\n", "\n", PLAT),
    ("the AI provider moves", SET, "if provider_moves || review_turns_on {", "if review_turns_on {", PLAT),
    ("review turned on", SET, "if provider_moves || review_turns_on {", "if provider_moves {", PLAT),
    ("review already on", SET, "            && !self.settings.is_enabled(Setting::AiReviewEnabled).await?;", ";", PLAT),
    ("the channels held", SET, "            self.integrations.hold_enabled(&mut tx, channel).await.map_err(refused_by_registry)?;\n", "", PLAT),
    ("a switch off configures nothing", SET, '                    && value != "false"\n', "", PLAT),
    ("a secret channel is never compared", SET, "&& (setting.is_secret() || value != java_trim(&self.settings.get(setting).await?))", "&& (value != java_trim(&self.settings.get(setting).await?))", PLAT),
    ("the endpoint named to an administrator", SET, "let named = caller.is_some_and(|caller| caller.administrative);", "let named = caller.is_some();", PLAT),
    ("the endpoint check's refusal says AI is unavailable", SET, "lead: AI_UNAVAILABLE }", 'lead: "" }', PLAT),
    # ── the composition ──
    ("the bound put in force", APP, "    derivations::bound(derivation_gate(settings));\n", "", APPT),
    ("the limits from the settings", APP, "    let limits = sign_in_limits(settings);", "    let limits = SignInLimits::default();", APPT),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
