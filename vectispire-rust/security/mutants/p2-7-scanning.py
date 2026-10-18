#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.7: cp-scanning (the claim's conditions — the take, the limit counted behind the
agent's lock, the paged exclusion, the wait — the attempts and their sentences, the leader lease, the scheduler and
retention, the dispatcher's sealing and its refusals, the result's write, the routes' visibility) and the domain rules
it reads (`schedules`: isDue, the SplitMix slot, runsAtLeastEvery; `scan_queue`: afterFailure). The engine mutants
start a MySQL or a PostgreSQL. See README.md.

No mutant changes a statement's text: a statement is its offline cache's key, and a changed one does not compile
offline — the conditions in SQL are held by the engine suite instead (and removed below with that reason).
"""
import sys

import _runner

S = "crates/cp-scanning/src/"
Q, L, DISP, SCHED, RET, TRIG, QUERY, VIEWS, PURGE, WEB, INT = (
    S + "internal/queue.rs", S + "internal/leader.rs", S + "dispatcher.rs", S + "scheduler.rs", S + "retention.rs",
    S + "trigger.rs", S + "query.rs", S + "views.rs", S + "purge.rs", S + "web/mod.rs", S + "internal/mod.rs",
)
SCH, SQ, INST = "crates/domain/src/schedules.rs", "crates/domain/src/scan_queue.rs", "crates/domain/src/instant.rs"

PG = ["-p", "vectispire-cp-scanning", "--test", "engines", "on_postgresql"]
MY = ["-p", "vectispire-cp-scanning", "--test", "engines", "on_mysql"]
REF = ["-p", "vectispire-cp-scanning", "--test", "reference"]
RT = ["-p", "vectispire-cp-scanning", "--test", "routes"]
UNIT = ["-p", "vectispire-cp-scanning", "--lib"]
DOM = ["-p", "vectispire-domain", "--test", "scanning_reference_set"]
DOMU = ["-p", "vectispire-domain", "--lib"]

MUTANTS = [
    # ── the claim ──
    ("a take that lost counts as taken", Q, "            Ok(1) => tx.commit().await.is_ok(),", "            Ok(_) => tx.commit().await.is_ok(),", PG),
    ("the count behind the lock is skipped", Q, "        if persistence::count_held(tx, worker, SCANNING, claimed_at).await? >= limit {\n            return Ok(Taken::Full);", "        if false {\n            return Ok(Taken::Full);", PG),
    ("no lock before the count", Q, "        if !self.agents.lock_for_claim(tx, agent, claimed_at).await? {\n            return Ok(Taken::Full);\n        }\n", "", PG),
    ("a deleted agent still claims", Q, "        if !self.agents.lock_for_claim(tx, agent, claimed_at).await? {", "        if self.agents.lock_for_claim(tx, agent, claimed_at).await? && false {", PG),
    ("a lost take is the end of the claim", Q, "                Taken::Lost => {}", "                Taken::Lost => return Ok(AgentClaim { scan: None, kept }),", PG),
    ("the take ignores a lost row", Q, "            if persistence::take(tx, *candidate, PENDING, SCANNING, worker, claimed_at, lease_expires_at).await? == 1 {", "            if persistence::take(tx, *candidate, PENDING, SCANNING, worker, claimed_at, lease_expires_at).await? <= 1 {", PG),
    ("an excluding agent takes an excluded repository", Q, "                if row.repo_id.is_none_or(|repository| !excluded.contains(&repository)) {", "                if row.repo_id.is_none_or(|_| true) {", PG),
    ("an excluding agent leaves image scans", Q, "                if row.repo_id.is_none_or(|repository| !excluded.contains(&repository)) {", "                if row.repo_id.is_some_and(|repository| !excluded.contains(&repository)) {", PG),
    ("kept is never told", Q, "                kept = true;\n", "", PG),
    ("the walk stops at the first page", Q, "            if rows.len() < PAGE {\n                break;\n            }", "            if rows.len() <= PAGE {\n                break;\n            }", PG),
    ("the next page restarts at the first", Q, "            after = rows.last().map(|last| (last.created_at, last.id));", "            after = None;", PG),
    ("the exclusion is never asked", Q, "            let excluded = if repositories.is_empty() {", "            let excluded = if true {", PG),
    # ── attempts ──
    ("another worker's report is applied", Q, "scan.status == SCANNING && scan.claimed_by.as_deref() == Some(worker) && scan.attempts == attempt", "scan.status == SCANNING && scan.attempts == attempt", PG),
    ("a retried scan is failed", Q, "        let to = if abandoned.retried() { PENDING } else { FAILED };", "        let to = FAILED;", PG),
    ("the reason is stored whole", Q, "        let sentence = truncate(&reason(&abandoned));", "        let sentence = reason(&abandoned);", UNIT + PG),
    ("a lapse exhausted is requeued", Q, "                        FAILED,\n                        Some(LEASE_EXHAUSTED_MESSAGE),", "                        PENDING,\n                        Some(LEASE_EXHAUSTED_MESSAGE),", PG),
    ("a lapse waits for nothing", Q, "                        PENDING,\n                        None,\n                        Some(offset(not_before)),", "                        PENDING,\n                        None,\n                        None,", PG),
    ("a reason cut a unit late", Q, "        if units + width > length {", "        if units + width > length + 1 {", UNIT),
    ("a cut pair leaves no ?", Q, "            if units < length {\n                kept.push('?');", "            if false {\n                kept.push('?');", UNIT),
    ("a permanent failure retries", SQ, "    if kind == FailureKind::Permanent {\n        return Next::Fail { permanent: true };", "    if false {\n        return Next::Fail { permanent: true };", DOM),
    ("the last attempt retries", SQ, "    attempts >= policy.max_attempts", "    attempts > policy.max_attempts", DOM),
    ("the first attempt waits the second delay", SQ, "usize::try_from(attempt.max(1)).unwrap_or(1)", "usize::try_from(attempt.max(2)).unwrap_or(1)", DOM),
    ("past the list waits the first delay", SQ, ".min(delays.len()).saturating_sub(1)", ".min(1).saturating_sub(1)", DOM),
    ("no delays wait the lease", SQ, "    if delays.is_empty() {\n        return Duration::ZERO;", "    if delays.is_empty() {\n        return policy.lease;", DOM),
    ("an instant's fraction never carries", INST, "let (carry, nano) = if total >= 1_000_000_000 { (1, total - 1_000_000_000) } else { (0, total) };", "let (carry, nano) = if total > 1_000_000_000 { (1, total - 1_000_000_000) } else { (0, total) };", DOMU),
    # ── the leader lease ──
    ("a live lease is stolen", L, "        if !mine && !expired {", "        if !mine && false {", PG),
    ("an expiry at the instant is live", L, "        let expired = lease.expires_at.is_none_or(|expiry| expiry <= at);", "        let expired = lease.expires_at.is_none_or(|expiry| expiry < at);", PG),
    ("a takeover ignores what was read", L, "                    persistence::take_over_from(&mut tx, name, holder, expires_at, at, previous, expiry).await", "                    persistence::renew_leadership(&mut tx, name, holder, expires_at, at).await", PG),
    ("a lost insert wins", L, "            Err(_) => {\n                let _ = tx.rollback().await;\n                false\n            }", "            Err(_) => {\n                let _ = tx.rollback().await;\n                true\n            }", PG),
    ("a stale lease has a holder", L, "            (Some(holder), Some(expiry)) if expiry > at => Some(holder),", "            (Some(holder), Some(_)) => Some(holder),", PG),
    ("the scheduler ticks without the lease", SCHED, "        if !self.hold_leadership(at).await {\n            return 0;", "        if false {\n            return 0;", PG),
    ("an unreachable lease is believed held", SCHED, "                tracing::warn!(error = %failure, \"Scheduling lease unreachable — tick skipped.\");\n                false", "                tracing::warn!(error = %failure, \"Scheduling lease unreachable — tick skipped.\");\n                true", PG),
    # ── the scheduler ──
    ("a target under way is queued again", SCHED, "        if under_way > 0 {\n            return Ok(0);", "        if under_way > 1 {\n            return Ok(0);", PG),
    ("the stamp is skipped", SCHED, "        self.targets.stamp_scheduled(tx, target, at).await.map_err(|failure| StoreError(Box::new(failure)))?;\n", "", PG),
    ("the default interval read in days", SCHED, "            Ok(days) => i64::from(days).saturating_mul(24 * 60),", "            Ok(days) => i64::from(days),", PG),
    ("images are not scheduled", SCHED, "                    if due_container(container, default_minutes, now) {", "                    if false {", PG),
    ("a manual target is due", SCH, "    match target.mode() {\n        Mode::Manual => false,", "    match target.mode() {\n        Mode::Manual => true,", DOM),
    ("an interval due a second late", SCH, "Some(last) => last.plus_seconds(interval_seconds).is_some_and(|due| now >= due),", "Some(last) => last.plus_seconds(interval_seconds).is_some_and(|due| now > due),", [DOM, DOMU]),
    ("a never-scheduled interval waits", SCH, "    if interval_seconds <= 0 {\n        return false;\n    }\n    match last {\n        None => true,", "    if interval_seconds <= 0 {\n        return false;\n    }\n    match last {\n        None => false,", DOM),
    ("no default schedules everything", SCH, "    if default_seconds <= 0 {", "    if default_seconds < 0 {", DOM),
    ("the default's slot is reached late", SCH, "        Some(last) => last < latest_slot(target, default_seconds, now),", "        Some(last) => last <= latest_slot(target, default_seconds, now),", [DOM, DOMU]),
    ("repository and image share a slot", SCH, "        ScanTarget::Container(id) => id.wrapping_mul(2).wrapping_add(1),", "        ScanTarget::Container(id) => id.wrapping_mul(2),", DOM),
    ("SplitMix's first shift", SCH, "    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);", "    z = (z ^ (z >> 31)).wrapping_mul(0xbf58_476d_1ce4_e5b9);", DOM),
    ("SplitMix's last step", SCH, "    (z ^ (z >> 31)) as i64", "    z as i64", DOM),
    ("SplitMix's golden ratio", SCH, "    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);", "    z = z.wrapping_add(0x9e37_79b9_7f4a_7c16);", DOM),
    ("an interval below a second divides by zero's twin", SCH, "    mix(seed).rem_euclid(interval_seconds.max(1))", "    mix(seed).rem_euclid(interval_seconds.max(2))", DOM),
    ("the slot counted from now, not the offset", SCH, "        seconds.wrapping_sub(seconds.wrapping_sub(offset(target, interval_seconds)).rem_euclid(period)),", "        seconds.wrapping_sub(seconds.rem_euclid(period)),", DOM),
    ("a broken expression fires once", SCH, "        None => cron.next_after(now).is_some(),", "        None => true,", DOM),
    ("a cron occurrence due a second late", SCH, "        Some(last) => cron.next_after(last).is_some_and(|next| next <= now),", "        Some(last) => cron.next_after(last).is_some_and(|next| next < now),", [DOM, DOMU]),
    ("a cron scheduled from now", SCH, "        Some(last) => cron.next_after(last).is_some_and(|next| next <= now),", "        Some(_) => cron.next_after(now).is_some_and(|next| next <= now),", DOM),
    ("an unusable expression reads as an interval", SCH, "    } else if !matches!(cron, Stored::Absent) {", "    } else if matches!(cron, Stored::Parsed(_)) {", DOM),
    ("the cadence believes the next gap only", SCH, "        if nanos_between(from, next) > period_nanos {\n            return false;\n        }", "        if false {\n            return false;\n        }", DOM),
    ("the cadence's horizon is two periods alone", SCH, "now.plus_seconds(span.max(SIXTY_TWO_DAYS))", "now.plus_seconds(span)", [DOM, DOMU]),
    ("an interval longer than the period passes", SCH, "    period_seconds > 0 && interval_seconds > 0 && interval_seconds <= period_seconds", "    period_seconds > 0 && interval_seconds > 0", DOM),
    ("a manual target runs often enough", SCH, "    match in_force.mode {\n        Mode::Manual => false,", "    match in_force.mode {\n        Mode::Manual => true,", DOM),
    # ── retention ──
    ("the keep window ignored", RET, "            keep_per_target: u32::try_from(keep).unwrap_or(0),", "            keep_per_target: 0,", PG),
    ("the age limit read in seconds", RET, "max_age: Duration::from_secs(u64::try_from(days).unwrap_or(0).saturating_mul(86_400)),", "max_age: Duration::from_secs(u64::try_from(days).unwrap_or(0)),", PG),
    # ── the trigger, the purge, the figures ──
    ("a waiting scan is stacked", TRIG, "            if persistence::count_of_repository(&mut tx, \"pending\", repository.id).await? > 0 {", "            if persistence::count_of_repository(&mut tx, \"pending\", repository.id).await? > 1 {", PG),
    ("an image scan without its branch", TRIG, "            branch: IMAGE_BRANCH.to_owned(),", "            branch: String::new(),", PG),
    ("the purge keeps the findings", PURGE, "                persistence::delete_findings_of_scans(tx, batch).await?;", "                let _ = batch;", PG),
    ("the latest scan forgets its status", INT, "LatestScan { id: row.scan_id, status: row.status, created_at: row.created_at, error: row.error },", "LatestScan { id: row.scan_id, status: String::new(), created_at: row.created_at, error: row.error },", PG),
    ("an unrecorded census read as none", S + "catalog.rs", "                if let Some(languages) = detected_languages::read(column.as_deref()) {\n                    detected.insert(repository, languages);\n                }", "                detected.insert(repository, detected_languages::read(column.as_deref()).unwrap_or_default());", PG),
    # ── the dispatcher ──
    ("a delegated agent without a sealing key is handed credentials", DISP, "    !agent.mode().delivers_credentials() || agent.sealing_public_key.as_deref().is_some_and(is_usable_sealing_key)", "    true", REF),
    ("a local agent is excluded", DISP, "    !agent.mode().delivers_credentials() || agent.sealing_public_key.as_deref().is_some_and(is_usable_sealing_key)", "    agent.sealing_public_key.as_deref().is_some_and(is_usable_sealing_key)", REF),
    ("a full agent is told about a key", DISP, "            if claim.kept && self.queue.count_held(&worker).await.map_err(ClaimError::Failed)? < limit {", "            if claim.kept {", REF),
    ("a kept agent is told nothing", DISP, "            if claim.kept && self.queue.count_held(&worker).await.map_err(ClaimError::Failed)? < limit {", "            if false {", REF),
    ("the withheld sentence ignores the pin", DISP, "not_pinned: agent.signing_public_key.as_deref().is_none_or(vectispire_domain::java::is_blank),", "not_pinned: true,", REF),
    ("a key added since the selection is not refunded", DISP, "            if let Err(failure) = self.queue.requeue_refunded(scan.id, worker).await {\n                return Delivery::Failed(TaskFailure::transient(failure));\n            }\n", "", REF),
    ("a key leaves for an unproved sealing key", DISP, "let Some(sealing_key) = agent.sealing_public_key.as_deref().filter(|key| is_usable_sealing_key(key)) else {", "let Some(sealing_key) = agent.sealing_public_key.as_deref().or(Some(\"\")) else {", REF),
    ("the token sealed as a deployment key", DISP, "            let context = SealContext::https_token(https.host.as_deref(), https.username.as_deref());", "            let context = SealContext::deployment_key();", REF),
    ("the token sealed without its user", DISP, "            let context = SealContext::https_token(https.host.as_deref(), https.username.as_deref());", "            let context = SealContext::https_token(https.host.as_deref(), None);", REF),
    ("the key sealed as a token", DISP, "            match vectispire_crypto::seal(sealing_key, key.expose(), &SealContext::deployment_key()) {", "            match vectispire_crypto::seal(sealing_key, key.expose(), &SealContext::https_token(None, None)) {", REF),
    ("the credential's delivery is not audited", DISP, "        self.record_credential_sent(agent, scan.id, \"sealed for the agent's verified sealing key\").await;\n", "", REF),
    ("a local agent's token is decrypted", DISP, "        if let (Some(token_id), true) = (repository.https_token_id, deliver_credentials) {", "        if let (Some(token_id), _) = (repository.https_token_id, deliver_credentials) {", REF),
    ("a local agent's key is decrypted", DISP, "        if let (Some(key_id), true) = (repository.ssh_key_id, deliver_credentials) {", "        if let (Some(key_id), _) = (repository.ssh_key_id, deliver_credentials) {", REF),
    ("an unreadable token is sent empty", DISP, "            if secret.state() == SecretState::Unreadable {\n                return Err(TaskFailure::refused(format!(\n                    \"The HTTPS token", "            if false {\n                return Err(TaskFailure::refused(format!(\n                    \"The HTTPS token", REF),
    ("an ambiguous URL is dispatched", DISP, "        if let Some(reason) = repository_url::validate(&repository.url) {", "        if let Some(reason) = None::<String> {", REF),
    ("the allow-list is not checked again", DISP, "        if !self.allowed_hosts.permits(&repository.url) {", "        if false {", REF),
    ("a blank branch is sent blank", DISP, "        let branch = if vectispire_domain::java::is_blank(&scan.branch) {", "        let branch = if scan.branch.is_empty() {", REF),
    ("SAST languages recorded without SAST", DISP, "        let column = if steps.contains(&Step::Sast) {", "        let column = if true {", REF),
    ("SAST always on", DISP, "        if self.sast.sast_enabled().await.map_err(TaskFailure::transient)? {", "        if true {", REF),
    ("a refusal retries", DISP, "        TaskFailure { message: message.into(), kind: FailureKind::Permanent }", "        TaskFailure { message: message.into(), kind: FailureKind::Transient }", REF),
    ("a failure reason is not scrubbed", DISP, "        let reason = failure_reason::scrub(&failure.message, secrets);", "        let reason = { let _ = secrets; failure.message.clone() };", PG),
    ("the retry's instant keeps its fraction", DISP, "                epoch_second: not_before.epoch_second,\n                nano: 0,", "                epoch_second: not_before.epoch_second,\n                nano: not_before.nano,", REF),
    ("the worker's room counts the agents' scans", DISP, "        let held = i32::try_from(self.queue.count_held(worker).await?).unwrap_or(i32::MAX);", "        let held = 1;", PG),
    ("a scan taken over is run anyway", DISP, "        if !self.queue.renew_lease(scan.id, worker).await? {", "        if !self.queue.renew_lease(scan.id, worker).await? && false {", PG),
    ("a scan that examined nothing is completed", DISP, "    let nothing_examined = artifacts.observed_nothing() && !artifacts.failures.is_empty();", "    let nothing_examined = false;", PG),
    ("a clean scan is failed", DISP, "    let nothing_examined = artifacts.observed_nothing() && !artifacts.failures.is_empty();", "    let nothing_examined = artifacts.observed_nothing();", PG),
    ("a stolen scan's result is written", DISP, "        if !self.queue.hold_for_write(tx, scan_id, worker).await? {\n            return Ok(false);", "        if !self.queue.hold_for_write(tx, scan_id, worker).await? && false {\n            return Ok(false);", PG),
    ("the SBOM stored as sent", DISP, "    Ok(vectispire_domain::wire::to_wire_string(&tree))", "    let _ = tree;\n    Ok(raw.to_owned())", PG),
    ("the failures not summarised", DISP, "        error: failure_summary(artifacts)?,", "        error: None,", PG),
    ("a project absent blanks the columns", DISP, "        project: artifacts.project.as_ref().map(|project| (project.kind.clone(), project.version.clone())),", "        project: Some(artifacts.project.as_ref().map_or((None, None), |project| (project.kind.clone(), project.version.clone()))),", PG),
    # ── the reads and the routes ──
    ("a restricted history reads the estate", QUERY, "            Visibility::Everything => {\n                let mut tx = persistence::read(&self.db).await?;", "            _ => {\n                let mut tx = persistence::read(&self.db).await?;", RT),
    ("a hidden scan's detail is served", QUERY, "    Ok(rows::require_visible_scan(scan, ScanView::target, allowed)?)", "    Ok(rows::require_visible_scan(scan, ScanView::target, &Visibility::Everything)?)", RT),
    ("an image scan of a restricted reader is its repository's", VIEWS, "            (None, Some(id)) => Some(ScanTarget::Container(id)),", "            (None, Some(_)) => None,", RT),
    ("the history's offset ignored", QUERY, "            Visibility::Only(targets) => self.within(targets, repo, container, window).await?,", "            Visibility::Only(targets) => self.within(targets, repo, container, ListWindow { limit: window.limit, offset: 0 }).await?,", RT),
    ("an unresolved allowance read as everything", WEB, "    scope.map_err(|_| Box::new(refuse(method, uri, ScanError::unexpected(NoAllowance))))", "    Ok(scope.unwrap_or_else(|_| Allowance::everything()))", RT),
    ("no SBOM answered empty", QUERY, "        read?.ok_or_else(|| ScanError::NotFound(NO_SBOM.to_owned()))", "        Ok(read?.unwrap_or_default())", RT),
    ("examined types unsorted", WEB, "                names.sort_unstable();\n                names\n", "                names\n", RT),
    ("an unknown language is kept", VIEWS, "    LANGUAGES.iter().copied().find(|language| *language == normalized)", "    LANGUAGES.iter().copied().find(|language| *language == normalized).or(Some(\"unknown\"))", REF),
    ("a null plugin outcome is no outcome", VIEWS, "                Value::Null => return Err(NullOutcome),", "                Value::Null => return Ok(Vec::new()),", REF),
    ("a decimal finding count refuses the column", VIEWS, "                    Some(Some(decimal.trunc() as i32))", "                    None", REF),
]

# Equivalent, removed from the list with the reason:
# - the built-in worker's stop at its limit (`>=` read `>`), its stop on an empty queue, and a claim of zero: one more
#   turn asks for `limit - claimed` scans, zero, and takes none; only statements are spent, which nothing observes.
# - the unlocked count before an agent's claim (`>=` read `>`): it decides nothing, the count behind the agent's lock is
#   repeated before any take ("concurrent polls of one agent", "the count waits for a concurrent take").
# - `kept |=` read `kept =`: a later attempt walks the same excluded rows the earlier one did — nothing in between takes
#   a scan the agent is kept from — so it is kept again.
# - the attempt in `abandon`'s read of the row: the release's statement repeats the condition ("a failure report ends
#   its attempt only" forces the window), so dropping it from the read changes no row.
# - a disabled retention policy's early return: `RetentionPolicy::prunable` answers none for a disabled policy itself.
# - the identifier no column hands out, bound for an empty batch of a restricted history: Java needed it because
#   `in ()` is not valid everywhere; an empty array or JSON list selects nothing on both engines either way.
# - the conditions inside the statements (`status = ?`, the wait in the take's `where`, the owner and the attempt in a
#   release, the lapse in the reclaim's, the holder and the expiry in a takeover): a statement's text is its offline
#   cache's key, so a mutated statement does not compile offline. Each is held by an engine case that forces it:
#   "the take repeats the wait", "a failure report ends its attempt only", "a deposed worker…", "a renewal beats a
#   stale reclaim", "the write fences the reclaim", the leader election's eight claimants.
# - `NoExclusion::excludes_nothing` and `Excluding`'s default: the walk with an exclusion that excludes nothing finds the
#   same first candidate the one-row read finds; only the cost differs.
# - the read-only transaction of a candidate read (`persistence::read` versus `write`): a read either way.
# - `json_ids`/`json_strings` formatting: serde's and the join's text are the same JSON for integers and strings.
# - `log_abandoned`'s and the reclaim's log lines: nothing reads them.
# - `IngestionStandIn`, `BundledRules`, `NoPlugins`, `AgentsStandIn`: placeholders the composition replaces, held by the
#   composition test and the claims' reference cases.

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=1200))
