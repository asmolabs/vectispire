#!/usr/bin/env python3
"""Mutation check of the access port's second stage (Phase 1, task 1.3's services): the sign-in throttle's
reservations, AuthService.login, AuthenticationFlowService (sign-in, the second factor's challenge, the hand-off),
TotpService, SignInMethodPolicy, RateWindows and SessionCleanupService in cp-access — held to AuthServiceTest,
TotpServiceTest, MfaChallengeIsSharedTest, AuthenticationCeilingsTest and RateWindowsIntegrationTest, case by case.
See README.md.
"""
import sys

import _runner

UNIT = ["-p", "vectispire-cp-access", "--test", "sign_in_flow"]
ENGINES = ["-p", "vectispire-cp-access", "--test", "sign_in_on_both_engines"]
LIB = ["-p", "vectispire-cp-access", "--lib", "second_factor"]
BOTH = [UNIT, ENGINES]
TH = "crates/cp-access/src/throttle.rs"
SI = "crates/cp-access/src/sign_in.rs"
SF = "crates/cp-access/src/second_factor.rs"
RW = "crates/cp-access/src/rate_windows.rs"
SC = "crates/cp-access/src/session_cleanup.rs"
AT = "crates/cp-access/src/persistence/sign_in/attempts.rs"

# Equivalent, and removed:
# - `release`'s guard on an empty reservation: the store answers 0 for no id without a statement, as Java skips one.
# - the throttle's `now - WINDOW` lower bound on the rows read: `decide_one` keeps only the failures inside the window
#   again, so a wider read counts the same.
# - `verify`'s `java::is_blank` before the trim: a code that is blank only by Java's wider whitespace (U+2003) survives
#   `String.trim`, is not six units long, and is no backup code either — `false` both ways.
# - the code's six-unit length check before the TOTP: `matching_step` measures the same length and refuses the rest.
# Not mutated: the SQL texts, whose change has no entry in the offline cache and does not compile — except MySQL's
# hand-built `in (…)`, which is below. The read-back default after `countAttempt` (a challenge discarded between the
# count and the read, `MAX_MFA_ATTEMPTS + 1`) is only reachable by a race the fakes cannot stage; Java's test does not
# stage it either.
MUTANTS = [
    # ── the throttle
    ("reservation counts its own rows", TH, ".filter(|row| !own.contains(&row.id))", ".filter(|_| true)", UNIT),
    ("strictest ceiling ignored", TH, "if retry_after > wait {", "if false {", UNIT),
    ("first refusal wins, not the strictest", TH, "if retry_after > wait {", "if wait.is_zero() {", UNIT),
    ("refused reservation keeps its rows", TH, "        if !reservation.admitted() {\n            self.release(&reservation).await?;\n        }\n", "", BOTH),
    ("second factor's ceiling", TH, "second_factor_key(account_id), MAX_SECOND_FACTOR_FAILURES)]", "second_factor_key(account_id), MAX_ATTEMPTS_PER_USER + 1)]", BOTH),
    ("password's ceiling", TH, "account_key(account_id), MAX_ATTEMPTS_PER_USER)]", "account_key(account_id), MAX_ATTEMPTS_PER_USER + 1)]", BOTH),
    ("password cleared under another key", TH, "self.store.delete_attempts_by_key(&login_throttle::account_key(account_id)).await?;", "self.store.delete_attempts_by_key(&login_throttle::second_factor_key(account_id)).await?;", UNIT),
    ("wait rounded up", TH, "u64::try_from(self.retry_after.whole_seconds()).unwrap_or(0)", "u64::try_from(self.retry_after.whole_seconds() + 1).unwrap_or(0)", UNIT),
    # ── AuthService.login
    ("account counter dropped", SI, "            ceilings.push((login_throttle::account_key(found.id), MAX_ATTEMPTS_PER_USER));\n", "", UNIT),
    ("name counter dropped", SI, "        ceilings.push((name_key, MAX_ATTEMPTS_PER_USER));\n", "", UNIT),
    ("client counter at the user's ceiling", SI, "ceilings.push((client_key.clone(), MAX_ATTEMPTS_PER_CLIENT));", "ceilings.push((client_key.clone(), MAX_ATTEMPTS_PER_CLIENT + 1));", UNIT),
    ("absent address not String.valueOf", SI, 'request.ip_address.unwrap_or("null")', 'request.ip_address.unwrap_or("")', UNIT),
    ("throttle after the derivation", SI, "        if !throttle.admitted() {\n            // Refused before any hashing", "        if false {\n            // Refused before any hashing", BOTH),
    ("throttled login loses its signal", SI, '                    Some("SIGN_IN_THROTTLED"),', "                    None,", UNIT),
    ("failure's description", SI, '"Login failed".to_owned()', '"Login failed: wrong password".to_owned()', UNIT),
    ("success keeps its own rows", SI, "        self.throttle().release(&throttle).await?;\n", "", BOTH),
    ("success clears the address too", SI, ".filter(|(key, _)| *key != client_key)", ".filter(|_| true)", BOTH),
    ("success clears nothing", SI, ".filter(|(key, _)| *key != client_key)", ".filter(|_| false)", BOTH),
    ("no rehash", SI, "        self.accounts.rehash_if_stale(&found, Some(request.password)).await;\n", "", BOTH),
    ("session before the second factor", SI, "        if found.mfa_enabled {\n            // **No session yet**", "        if false {\n            // **No session yet**", UNIT),
    # ── AuthenticationFlowService.signIn
    ("password door ignored", SI, "        if !self.methods.password_allowed() {", "        if false {", UNIT),
    ("login's entry rebuilt without its signal", SI, "                ..result.audit\n", "                signal: None,\n                ..result.audit\n", UNIT),
    ("challenge issued to a locked factor", SI, "                if !locked.is_zero() {", "                if false {", UNIT),
    ("challenge stored under its token", SI, "token_hash: hash_of(token),", "token_hash: token.to_owned(),", BOTH),
    ("challenge cap off by one", SI, ">= MAX_MFA_CHALLENGES {", "> MAX_MFA_CHALLENGES {", UNIT),
    ("no sweep before the count", SI, "        self.store.delete_expired_challenges(now).await?;\n", "", UNIT),
    ("challenge lifetime", SI, "Duration::seconds(300);", "Duration::seconds(301);", UNIT),
    ("password door with no provider closed", SI, "password: password_requested || !single_sign_on", "password: password_requested", UNIT),
    ("provider's default label", SI, "unwrap_or_else(|| DEFAULT_PROVIDER_LABEL.to_owned())", "unwrap_or_default()", UNIT),
    # ── AuthenticationFlowService.verify
    ("challenge alive at its expiry's edge refused", SI, "if self.clock.now() <= challenge.expires_at =>", "if self.clock.now() < challenge.expires_at =>", UNIT),
    ("challenge never expires", SI, "if self.clock.now() <= challenge.expires_at =>", "if true =>", UNIT),
    ("deactivated account verified", SI, "find_by_id(challenge.user_id).await?.filter(|user| user.is_active)", "find_by_id(challenge.user_id).await?", UNIT),
    ("deactivated account's challenge kept", SI, "            self.store.discard_challenge(&key).await?;\n            return Ok(Verification::AccountMissing);", "            return Ok(Verification::AccountMissing);", UNIT),
    ("presentation not counted", SI, "        self.store.count_challenge_attempt(&key).await?;\n", "", BOTH),
    ("fourth presentation admitted", SI, "if presented > MAX_MFA_ATTEMPTS {", "if presented > MAX_MFA_ATTEMPTS + 1 {", UNIT),
    ("third presentation refused", SI, "if presented > MAX_MFA_ATTEMPTS {", "if presented >= MAX_MFA_ATTEMPTS {", UNIT),
    ("throttled challenge kept", SI, "            self.store.discard_challenge(&key).await?;\n            return Ok(Verification::Throttled(attempt.retry_after));", "            return Ok(Verification::Throttled(attempt.retry_after));", UNIT),
    ("account's budget not asked", SI, "        let attempt = self.throttle().reserve_second_factor(user.id).await?;\n        if !attempt.admitted() {", "        let attempt = self.throttle().reserve_second_factor(user.id).await?;\n        if false {", BOTH),
    ("challenge outlives its last try", SI, "let exhausted = presented >= MAX_MFA_ATTEMPTS;", "let exhausted = presented > MAX_MFA_ATTEMPTS;", BOTH),
    ("lock not signalled", SI, "(exhausted || account_locked).then_some", "exhausted.then_some", UNIT),
    ("right code keeps the challenge", SI, "        self.store.discard_challenge(&key).await?;\n        self.throttle().clear_second_factor_failures(user.id).await?;", "        self.throttle().clear_second_factor_failures(user.id).await?;", UNIT),
    ("right code keeps the budget", SI, "        self.store.discard_challenge(&key).await?;\n        self.throttle().clear_second_factor_failures(user.id).await?;", "        self.store.discard_challenge(&key).await?;", UNIT),
    ("session with the verifying request's agent", SI, "challenge.user_agent.as_deref(), challenge.ip_address.as_deref()", "user_agent, ip_address", UNIT),
    # ── exchange
    ("deactivated hand-off not revoked", SI, "            self.sessions.revoke(&handoff).await?;\n", "", UNIT),
    # ── TotpService
    ("enrolling over an active factor", SF, "        if user.mfa_enabled {\n            return Err(SecondFactorError::InvalidInput(ALREADY_ENABLED));", "        if false {\n            return Err(SecondFactorError::InvalidInput(ALREADY_ENABLED));", BOTH),
    ("secret sealed under the codes' context", SF, "self.seal.seal(secret, &secret_context(user.id))", "self.seal.seal(secret, &backup_context(user.id))", BOTH),
    ("codes sealed under the secret's context", SF, "self.seal.seal(serialized.expose(), &backup_context(user.id))", "self.seal.seal(serialized.expose(), &secret_context(user.id))", BOTH),
    ("codes joined otherwise", SF, 'let serialized = Secret::new(codes.join(","));', 'let serialized = Secret::new(codes.join(";"));', UNIT),
    ("enrolment's step not spent", SF, "last_step: step, at: now", "last_step: step - 1, at: now", BOTH),
    ("context prefix", "crates/cp-crypto/src/lib.rs", 'format!("user:totp_secret:{user_id}")', 'format!("user:totp:{user_id}")', [LIB, ENGINES]),
    ("codes' context prefix", "crates/cp-crypto/src/lib.rs", 'format!("user:backup_codes:{user_id}")', 'format!("user:backup:{user_id}")', [LIB, ENGINES]),
    ("disable without the budget", SF, "        if !attempt.admitted() {\n            return Err(SecondFactorError::Locked", "        if false {\n            return Err(SecondFactorError::Locked", BOTH),
    ("disable keeps the budget", SF, "        self.throttle.clear_second_factor_failures(user.id).await?;\n", "", UNIT),
    ("disabled factor verifies", SF, "if !user.mfa_enabled || java::is_blank(code) {", "if java::is_blank(code) {", UNIT),
    ("code not trimmed", SF, "let cleaned = java::trim(code);", "let cleaned = code;", UNIT),
    ("replayed step accepted", SF, "&& self.store.advance_totp_step(user.id, step).await? == 1", "&& self.store.advance_totp_step(user.id, step).await? <= 1", BOTH),
    ("backup code spent twice", SF, "self.clock.now()).await? != 1 {", "self.clock.now()).await? > 1 {", BOTH),
    ("backup code's signal", SF, 'Some("MFA_BACKUP_CODE_USED"),', "None,", UNIT),
    ("enrolment not clamped", SF, "without_second_factor: accounts.min(without)", "without_second_factor: without", UNIT),
    # ── RateWindows
    ("window number not floored", RW, "let number = millis.div_euclid(length);", "let number = millis.checked_div(length).unwrap_or(0);", UNIT),
    ("subject not digested", RW, 'sha256_hex(subject.unwrap_or(""))', 'subject.unwrap_or("").to_owned()', UNIT),
    ("ceiling exclusive", RW, "if i64::from(hits) <= ceiling =>", "if i64::from(hits) < ceiling =>", BOTH),
    ("wait not until the window closes", RW, "u64::try_from(until_closed).unwrap_or(0)", "0", UNIT),
    ("lost insert not counted", RW, "            self.windows.increment(key).await?;\n        }\n        Ok(self.windows.hits_of", "        }\n        Ok(self.windows.hits_of", BOTH),
    ("database failure refuses", RW, "                    limit.key()\n                );\n                Outcome { admitted: true,", "                    limit.key()\n                );\n                Outcome { admitted: false,", UNIT),
    # ── SessionCleanupService
    ("attempts kept one window only", SC, "WINDOW.whole_seconds().saturating_mul(2)", "WINDOW.whole_seconds()", BOTH),
    ("a failed purge fails the tick", SC, "    outcome.unwrap_or_else(|failed| {\n        tracing::warn!(\"{what} skipped: {failed}\");\n        0\n    })", "    outcome.unwrap()", UNIT),
    ("abandoned challenges kept", SC, "challenges: skipped(self.store.delete_expired_challenges(self.clock.now()).await, \"MFA challenge purge\"),", "challenges: 0,", ENGINES),
    # ── MySQL's hand-built `in (…)`
    ("one placeholder for every id", AT, 'let marks = vec!["?"; ids.len()].join(", ");', 'let marks = vec!["?"; 1].join(", ");', ENGINES),
    ("challenge user agent clipped", SI, "vectispire_domain::bounded_text::clip(attempt.user_agent, USER_AGENT_MAX)\n                    .map(str::to_owned)", "attempt.user_agent.map(str::to_owned)", ENGINES + ["a_user_agent_past_the_column"]),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
