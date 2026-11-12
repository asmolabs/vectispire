#!/usr/bin/env python3
"""Mutation check of the access port's administration services (Phase 1, stage 2b): GrantTargets, an account's grants
(AccountAdministrationService.targets / replaceTargets), TeamAdministrationService and TeamChannels,
ApiKeyAdministrationService, AccountNames and AccountDirectory in cp-access, and the targets module's answers to
GrantableTargets' new questions — held to GrantTargetsTest, GrantTargetsRoutesTest, TeamVisibilityTest,
AccountInputRoutesTest and ApiKeyIntegrationRoutesTest, case by case. See README.md.
"""
import sys

import _runner

LIB = ["-p", "vectispire-cp-access", "--lib"]
ENGINES = ["-p", "vectispire-cp-access", "--test", "administration_on_both_engines"]
TARGETS = ["-p", "vectispire-cp-targets", "--test", "engines"]
GT = "crates/cp-access/src/internal/grant_targets.rs"
AT = "crates/cp-access/src/account_targets.rs"
TM = "crates/cp-access/src/teams.rs"
AK = "crates/cp-access/src/api_key_administration.rs"
AN = "crates/cp-access/src/account_names.rs"
TA = "crates/cp-targets/src/internal/mod.rs"

# Equivalent, and removed:
# - a team's deletion deleting its members, grants and channel explicitly: the schema cascades on both engines (V6/V7,
#   MySQL's since V19), so removing any one of the three statements leaves the same rows. Java's reason for the explicit
#   delete — a cascade an engine does not honour — no longer has an engine to occur on; kept, as Java keeps it.
# - `names` de-duplicating the ids before the lookups: the answer is a map, a second lookup re-inserts the same pair.
# - the list's tie-break on the identifier: two teams' names cannot compare equal ignoring case — the creation and the
#   rename refuse it — so the tie-break orders nothing a database built by these services holds.
# Not mutated: the SQL texts, whose change has no entry in the offline cache and does not compile.
MUTANTS = [
    # ── GrantTargets
    ("held grant not kept", GT, "    if held(&normalized, id) {", "    if false {", [LIB, ENGINES]),
    ("held asked with the kind as sent", GT, "    if held(&normalized, id) {", '    if held(kind.unwrap_or(""), id) {', LIB),
    ("project not checked", GT, "KIND_PROJECT => targets.project_exists(id).await?,", "KIND_PROJECT => true,", LIB),
    ("granter's visibility ignored", GT, "Ok(targets.exists(target).await? && granter.permits(target))", "Ok(targets.exists(target).await?)", [LIB, ENGINES]),
    ("existence not asked", GT, "Ok(targets.exists(target).await? && granter.permits(target))", "Ok(granter.permits(target))", [LIB, ENGINES]),
    ("refusal's sentence", GT, 'format!("No {normalized} with id {id}.")', 'format!("No {normalized} {id}.")', LIB),
    # ── an account's grants
    ("account's repeats not collapsed", AT, "            if !wanted.contains(&grant) {\n                wanted.push(grant);\n            }", "            wanted.push(grant);", ENGINES),
    ("account's grants added to, not replaced", AT, "        store::delete_user_targets(&mut tx, id).await?;\n", "", ENGINES),
    ("no grant said as a count", AT, 'if wanted.is_empty() { "none".to_owned() }', 'if false { "none".to_owned() }', ENGINES),
    ("absent account listed", AT, "        require_account(&mut tx, id).await?;\n        let grants", "        let grants", ENGINES),
    # ── teams
    ("list in byte order", TM, "java::compare_ignore_case(&left.name, &right.name)", "left.name.cmp(&right.name)", ENGINES),
    ("own name taken", TM, "Some(existing) if Some(existing.id) != allowed =>", "Some(existing) if existing.id != 0 =>", ENGINES),
    ("another's name free", TM, "Some(existing) if Some(existing.id) != allowed =>", "Some(existing) if allowed.is_none() && existing.id != 0 =>", ENGINES),
    ("team's target repeats kept", TM, "            if !wanted.contains(&grant) {\n                wanted.push(grant);\n            }", "            wanted.push(grant);", ENGINES),
    ("members' repeats kept", TM, "            if !wanted.contains(user_id) {", "            if true {", ENGINES),
    ("unknown member skipped to the insert", TM, "        if !unknown.is_empty() {", "        if false {", ENGINES),
    ("membership's origin", TM, 'pub const ORIGIN_MANUAL: &str = "manual";', 'pub const ORIGIN_MANUAL: &str = "scim";', ENGINES),
    ("deletion's sentence", TM, "({members} member(s), {owned} target(s))", "({owned} member(s), {members} target(s))", ENGINES),
    ("team's grants added to, not replaced", TM, "        store::delete_team_targets(&mut tx, id).await?;\n        for grant in &wanted {", "        for grant in &wanted {", ENGINES),
    ("URL not trimmed", TM, 'java::trim(requested_url.unwrap_or("")).to_owned()', 'requested_url.unwrap_or("").to_owned()', ENGINES),
    ("width checked after the guard", TM, '            bounded_text::within(&url, MAX_WEBHOOK_URL_LENGTH, "The webhook URL")\n                .map_err(|refused| AdminError::InvalidInput(refused.0))?;\n', "", ENGINES),
    ("private always allowed", TM, "let policy = if self.policy.private_destinations_allowed().await? {", "let policy = if true {", ENGINES),
    ("private never allowed", TM, "let policy = if self.policy.private_destinations_allowed().await? {", "let policy = if false {", ENGINES),
    ("guard not asked", TM, "tokio::task::spawn_blocking(move || guard.validate(&checked, policy, WEBHOOK_LABEL))", "tokio::task::spawn_blocking(move || Ok::<String, vectispire_cp_outbound::UnsafeUrl>(checked))", ENGINES, [("let policy = if", "let _policy = if"), ("let guard = self.outbound.clone();", "let _guard = self.outbound.clone();")]),
    ("channel not replaced", TM, "            store::delete_webhook(&mut tx, id).await?;\n            store::insert_webhook", "            store::insert_webhook", ENGINES),
    ("removed channel reported", TM, "Ok(TeamView::of(&team, members, owned, !url.is_empty()))", "Ok(TeamView::of(&team, members, owned, true))", ENGINES),
    ("every team has a channel", TM, ".filter(|team| team_ids.contains(team))", ".filter(|_| true)", ENGINES),
    # ── API keys
    ("governor's key revoked by anyone", AK, "if let Some(refusal) = refuse_governor_administration(acting, owner, None) {", "if let Some(refusal) = None::<String> {", ENGINES),
    ("expired only after its expiry", AK, "expires <= as_of", "expires < as_of", ENGINES),
    ("inactive owner named", AK, "                    .filter(|account| account.is_active)\n", "", ENGINES),
    ("deleted target blank", AK, 'Some(found.map_or_else(|| format!("{kind} {id} (deleted)"), str::to_owned))', "found.map(str::to_owned)", [LIB, ENGINES]),
    ("trailing empty scopes kept", AK, "    while pieces.last().is_some_and(String::is_empty) {", "    while false {", LIB),
    # ── AccountNames, AccountDirectory
    ("dot first in the domain", AN, "c == '.' && dot > 0 &&", "c == '.' &&", LIB),
    ("dot last in the domain", AN, "dot.saturating_add(1) < run.len()", "dot.saturating_add(1) <= run.len()", LIB),
    ("own address printed", AN, "holds_address(name) || email.is_some_and(", "holds_address(name) && email.is_some_and(", LIB),
    ("inactive contact", AN, ".iter().filter(|user| user.is_active).map(UserView::of)", ".iter().map(UserView::of)", ENGINES),
    # ── the targets module's answers
    ("project named as gone", TA, "KIND_PROJECT => projects.get(&grant.id).cloned().unwrap_or_else(|| naming::DELETED.to_owned()),", "KIND_PROJECT => naming::DELETED.to_owned(),", TARGETS),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
