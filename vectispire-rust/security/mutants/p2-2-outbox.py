#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.2: cp-outbox (the retry policy, the stamped payload, the registry and its
coverage against Java's, the relay, the two maintenance tasks and the relay guard, the statements on both engines)
and the binary's composition of it. The engine mutants start a MySQL and a PostgreSQL each. See README.md.
"""
import sys

import _runner

S = "crates/cp-outbox/src/"
RETRY, PAY, DEL, LIB, TASKS = S + "retry.rs", S + "payload.rs", S + "delivery.rs", S + "lib.rs", S + "internal/mod.rs"
PMY, PPG = S + "persistence/mysql.rs", S + "persistence/postgres.rs"

T = ["-p", "vectispire-cp-outbox", "--test", "reference", "--test", "relay"]
ENG = ["-p", "vectispire-cp-outbox", "--test", "engines"]
APP = ["-p", "vectispire-cp-app", "--test", "maintenance_composition"]

MUTANTS = [
    # ── the policy ──
    ("nine attempts", RETRY, "pub const MAX_ATTEMPTS: i32 = 8;", "pub const MAX_ATTEMPTS: i32 = 9;", T),
    ("a thirty-second base", RETRY, "pub const BASE_BACKOFF: Duration = Duration::seconds(60);", "pub const BASE_BACKOFF: Duration = Duration::seconds(30);", T),
    ("a two-hour cap", RETRY, "pub const MAX_BACKOFF: Duration = Duration::hours(1);", "pub const MAX_BACKOFF: Duration = Duration::hours(2);", T),
    ("twenty-one per pass", RETRY, "pub const MAX_PER_PASS: u32 = 20;", "pub const MAX_PER_PASS: u32 = 21;", T),
    ("a four-minute claim", RETRY, "pub const CLAIM_WINDOW: Duration = Duration::minutes(5);", "pub const CLAIM_WINDOW: Duration = Duration::minutes(4);", T),
    ("eight days kept", RETRY, "pub const SENT_RETENTION: Duration = Duration::days(7);", "pub const SENT_RETENTION: Duration = Duration::days(8);", T),
    ("zero attempts shifted", RETRY, "    if attempts <= 0 {\n        return BASE_BACKOFF;", "    if attempts < 0 {\n        return BASE_BACKOFF;", T),
    ("the shift uncapped", RETRY, "let exponent = attempts.saturating_sub(1).min(20);", "let exponent = attempts.saturating_sub(1);", T),
    ("the delay uncapped", RETRY, "if computed > MAX_BACKOFF { MAX_BACKOFF } else { computed }", "computed", T),
    ("the first retry doubled", RETRY, "let exponent = attempts.saturating_sub(1).min(20);", "let exponent = attempts.min(20);", T),
    ("an abandoned message rescheduled", RETRY, "if is_abandoned(attempts) { None } else { Some(now.saturating_add(backoff(attempts))) }", "Some(now.saturating_add(backoff(attempts)))", T),
    ("abandoned one attempt late", RETRY, "attempts >= MAX_ATTEMPTS", "attempts > MAX_ATTEMPTS", T),
    ("a missing message empty", RETRY, 'message.unwrap_or("null")', 'message.unwrap_or("")', T),
    ("the prefix without its space", RETRY, 'format!("{kind}: {}"', 'format!("{kind}:{}"', T),
    ("errors cut one unit later", RETRY, "const MAX_ERROR_LENGTH: usize = 500;", "const MAX_ERROR_LENGTH: usize = 501;", T),
    ("a character that fits cut", RETRY, "if units.saturating_add(width) > MAX_ERROR_LENGTH {", "if units.saturating_add(width) >= MAX_ERROR_LENGTH {", T),
    ("errors cut in characters", RETRY, "let width = c.len_utf16();", "let width = 1;", T),
    ("a split pair dropped", RETRY, "                out.push('?');\n", "", T),
    ("a full error given a ?", RETRY, "if units < MAX_ERROR_LENGTH {", "if true {", T),
    # ── the stamped payload ──
    ("no message id", PAY, '    members.insert("message_id".to_owned(), Value::String(id.to_string()));\n', "", T),
    ("the message id misnamed", PAY, 'members.insert("message_id".to_owned()', 'members.insert("messageId".to_owned()', T),
    ("control characters in lower case", PAY, 'return write!(writer, "\\\\u{byte:04X}")', 'return write!(writer, "\\\\u{byte:04x}")', T),
    ("an array accepted", PAY, 'Value::Array(_) => return Err(PayloadError::NotAnObject("an array")),', 'Value::Array(_) => Map::new(),', T),
    # ── the registry and the coverage ──
    ("a handler never routes", DEL, ".find(|handler| handler.message_type() == message_type)", ".find(|handler| handler.message_type() == message_type && false)", T),
    ("a channel routes any type", DEL, ".find(|channel| channel.message_type() == message_type)", ".find(|_| true)", T),
    ("the last channel of a type routes", DEL, "            .iter()\n            .find(|channel|", "            .iter()\n            .rev()\n            .find(|channel|", T),
    ("missing handlers not seen", DEL, "missing_handlers: difference(&handlers, &java.handlers),", "missing_handlers: Vec::new(),", T + APP),
    ("missing channels not seen", DEL, "missing_channels: difference(&channels, &java.channels),", "missing_channels: Vec::new(),", T),
    ("extra handlers not seen", DEL, "extra_handlers: difference(&java.handlers, &handlers),", "extra_handlers: Vec::new(),", T),
    ("extra channels not seen", DEL, "extra_channels: difference(&java.channels, &channels),", "extra_channels: Vec::new(),", T),
    ("missing handlers ignored", DEL, "        self.missing_handlers.is_empty()\n            && ", "        ", T),
    ("missing channels ignored", DEL, "            && self.missing_channels.is_empty()\n", "", T),
    ("extra handlers ignored", DEL, "            && self.extra_handlers.is_empty()\n", "", T),
    ("extra channels ignored", DEL, "            && self.extra_channels.is_empty()\n", "", T),
    # ── the relay ──
    ("the clock at the nanosecond", LIB, "now.replace_microsecond(now.microsecond()).unwrap_or(now)", "now", T),
    ("due rows of another status", LIB, "self.store.find_due(PENDING, at, limit)", "self.store.find_due(SENT, at, limit)", T),
    ("the claim ignored", LIB, "self.store.claim(message.id, PENDING, at, at.saturating_add(retry::CLAIM_WINDOW)).await? == 0", "self.store.claim(message.id, PENDING, at, at.saturating_add(retry::CLAIM_WINDOW)).await? == 2", T),
    ("a claim without its window", LIB, "self.store.claim(message.id, PENDING, at, at.saturating_add(retry::CLAIM_WINDOW))", "self.store.claim(message.id, PENDING, at, at)", T),
    ("the attempt not counted", LIB, "let attempts = message.attempts.wrapping_add(1);", "let attempts = message.attempts;", T),
    ("a delivery marked with the wrong status", LIB, "self.store.mark_sent(message.id, attempts, SENT, at)", "self.store.mark_sent(message.id, attempts, PENDING, at)", T),
    ("a delivery not counted", LIB, "                    result.sent = result.sent.saturating_add(1);\n", "", T),
    ("a gone destination retried", LIB, "self.store.record_attempt(message.id, attempts, Some(&reason), FAILED, None)", "self.store.record_attempt(message.id, attempts, Some(&reason), PENDING, None)", T),
    ("a gone reason prefixed", LIB, "Err(DeliveryError::Gone(reason)) => {\n", "Err(DeliveryError::Gone(gone)) => {\n                    let reason = retry::recordable_error(\"GoneDestinationException\", Some(&gone));\n", T),
    ("a gone message counted as failed", LIB, "                    tracing::error!(\"Outbox message {} abandoned: {reason}\", message.id);\n                    result.abandoned = result.abandoned.saturating_add(1);", "                    tracing::error!(\"Outbox message {} abandoned: {reason}\", message.id);\n                    result.failed = result.failed.saturating_add(1);", T),
    ("an abandonment counted as a failure", LIB, "                        result.abandoned = result.abandoned.saturating_add(1);\n                    } else {", "                        result.failed = result.failed.saturating_add(1);\n                    } else {", T),
    ("a failure never abandoned", LIB, "let status = if abandoned { FAILED } else { PENDING };", "let status = PENDING;", T),
    ("a failure without its next attempt", LIB, "let next = retry::next_attempt_at(attempts, at);", "let next = None;", T),
    ("a failure's reason uncut", LIB, "let reason = retry::recordable_error(kind, text);", "let reason = format!(\"{kind}: {}\", text.unwrap_or(\"null\"));", T),
    ("the unknown type's reason reworded", LIB, 'format!("No channel handles outbox type {}", message.message_type)', 'format!("No handler for outbox type {}", message.message_type)', T),
    ("a panic ends the pass", LIB, "AssertUnwindSafe(delivery).catch_unwind().await.unwrap_or_else(|panic| {", "Ok::<_, Box<dyn std::any::Any + Send>>(delivery.await).unwrap_or_else(|panic| {", T),
    ("a panic's text lost", LIB, "                .downcast_ref::<&str>()\n                .map(|text| (*text).to_owned())", "                .downcast_ref::<u8>()\n                .map(|text| text.to_string())", T),
    ("everything sent pruned", LIB, "self.store.delete_sent_before(SENT, self.now().saturating_sub(retry::SENT_RETENTION))", "self.store.delete_sent_before(SENT, self.now())", T),
    ("the pending pruned", LIB, "self.store.delete_sent_before(SENT,", "self.store.delete_sent_before(PENDING,", T),
    ("a row written as sent", LIB, "            status: PENDING,\n            attempts: 0,", "            status: SENT,\n            attempts: 0,", T),
    ("a row written tried", LIB, "            status: PENDING,\n            attempts: 0,", "            status: PENDING,\n            attempts: 1,", T),
    ("enqueue returns another id", LIB, "        Ok(message.id)\n", "        Ok(Uuid::new_v4())\n", ENG),
    # ── the tasks and the guard ──
    ("never held", TASKS, "        !self.coverage.is_complete()\n", "        false\n", T + APP),
    ("a held relay relays", TASKS, "                return Ok(());\n", "", T),
    ("a smaller batch", TASKS, "self.outbox.relay(retry::MAX_PER_PASS).await?;", "self.outbox.relay(10).await?;", T),
    ("the purge task purges nothing", TASKS, "let delivered = self.outbox.prune_sent().await?;", "let delivered = 0_u64;", T),
    ("the relay in the purge's slot", TASKS, "        Sequence::NotificationRelay\n", "        Sequence::SentMessages\n", T + APP),
    ("the purge in the relay's slot", TASKS, "        Sequence::SentMessages\n", "        Sequence::NotificationRelay\n", T + APP),
    # ── the statements ──
    ("a claim at its own window (MySQL)", PMY, "        status,\n        UtcInstant(at),\n    )", "        status,\n        UtcInstant(until),\n    )", ENG),
    ("a claim at its own window (PostgreSQL)", PPG, "        status,\n        UtcInstant(at) as _,\n    )", "        status,\n        UtcInstant(until) as _,\n    )", ENG),
    ("one more due row (MySQL)", PMY, "        UtcInstant(at),\n        limit,", "        UtcInstant(at),\n        limit + 1,", ENG),
    ("one more due row (PostgreSQL)", PPG, "i64::from(limit),", "i64::from(limit) + 1,", ENG),
    ("no team written (MySQL)", PMY, "        message.team_id,\n        message.status,", "        None::<i64>,\n        message.status,", ENG),
    ("no team written (PostgreSQL)", PPG, "        message.team_id,\n        message.status,", "        None::<i64>,\n        message.status,", ENG),
    ("a retry not scheduled (MySQL)", PMY, "        status,\n        next_attempt_at.map(UtcInstant),", "        status,\n        None::<UtcInstant>,", ENG),
    ("a retry not scheduled (PostgreSQL)", PPG, "        next_attempt_at.map(UtcInstant) as _,", "        None::<UtcInstant> as _,", ENG),
    ("pruned at the wrong instant (MySQL)", PMY, "        status,\n        UtcInstant(cutoff),", "        status,\n        UtcInstant(cutoff + time::Duration::days(1)),", ENG),
    ("pruned at the wrong instant (PostgreSQL)", PPG, "        UtcInstant(cutoff) as _,", "        UtcInstant(cutoff + time::Duration::days(1)) as _,", ENG),
]

# Equivalent, removed from the list with the reason:
# - the shift's cap at 30 instead of 20: from 7 on the doubled delay is past the one-hour cap either way, and
#   1 << 30 times sixty seconds does not overflow, so every attempt count gets the same delay.
# - the Solidus escape: serde_json never asks its formatter for one; `/` is written raw on both sides.
# - the relay task's `told` flag (the warning written once): a log line, not observable by the store or the result.
# - the held run's `Ok(())` versus an error: the turn logs either and goes on; the store sees nothing in both cases,
#   which is what the tests hold.


if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
