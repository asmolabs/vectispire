#!/usr/bin/env python3
"""Mutation check of the access port's SCIM provisioning (Phase 1, stage 2c): ScimProvisioningService in cp-access
(`scim.rs`) and its pure rules in the domain (`scim.rs`, `java::read_long`) — held to ScimUsersRoutesTest,
ScimGroupsRoutesTest, ScimPagingRoutesTest and ScimUsersControllerTest case by case on both engines, to the
transactions (a statement refused half-way leaves nothing written), and to reference/access/scim/, which
ScimReferenceSetTest writes from the Java service. See README.md.
"""
import sys

import _runner

REFERENCE = ["-p", "vectispire-domain", "--test", "scim_reference_set"]
ENGINES = ["-p", "vectispire-cp-access", "--test", "scim_on_both_engines"]
DS = "crates/domain/src/scim.rs"
JV = "crates/domain/src/java.rs"
SC = "crates/cp-access/src/scim.rs"

# Equivalent, and not listed:
# - an account's deletion closing its sessions, and a group's deleting its members, grants and channel explicitly: the
#   schema cascades each of them on both engines (t_session since V5, t_team_* since V6/V7, MySQL's since V19), so
#   removing one statement leaves the same rows. Kept, as the team administration keeps them (p1-7c says the same).
# - `member_value_text` answering nothing for a container, and `""` for `null`: either way the value is blank, and a
#   blank value names nobody (`member_ref`).
# - `read_long`'s sign: a magnitude past i64 and its negation are both refused by `i64::try_from`.
# Not mutated: the SQL texts, whose change has no entry in the offline cache and does not compile — the `for update`
# of an account's read among them.
MUTANTS = [
    # ── the filter, the page, the member, the removal path (the reference set)
    ("trailing text after the value", DS, "'\"' => return chars.as_str().is_empty().then_some((is_user_name, value)),",
     "'\"' => return Some((is_user_name, value)),", REFERENCE),
    ("an escaped line terminator", DS, ".filter(|&c| !is_line_terminator(c))?", ".filter(|&c| !is_line_terminator(c) || true)?", REFERENCE),
    ("Unicode white space between the words", DS, "text.trim_start_matches([' ', '\\t', '\\n', '\\u{b}', '\\u{c}', '\\r'])",
     "text.trim_start_matches(char::is_whitespace)", REFERENCE),
    ("attribute and operator in their case only", DS, "if head.eq_ignore_ascii_case(word)", "if head == word", REFERENCE),
    ("username filter not lowered", DS, "UserFilter::UserName(java::to_lower_root(&value))", "UserFilter::UserName(value)", REFERENCE),
    ("blank filter refused", DS, "filter.filter(|filter| !java::is_blank(filter))", "filter.filter(|filter| !filter.is_empty())", REFERENCE),
    ("refusal quotes more", DS, "const QUOTED_FILTER: usize = 200;", "const QUOTED_FILTER: usize = 201;", REFERENCE),
    ("start below one kept", DS, "start.max(1)", "start.max(0)", REFERENCE),
    ("count unbounded", DS, "count.clamp(0, MAX_COUNT)", "count.clamp(0, i32::MAX)", REFERENCE),
    ("start counted from zero", DS, "usize::try_from(start_index.saturating_sub(1))", "usize::try_from(start_index)", REFERENCE),
    ("Rust's integer grammar", DS, "Some(match java::read_long(trimmed) {", "Some(match trimmed.parse::<i64>().ok() {", REFERENCE),
    ("member name not lowered", DS, "None => MemberRef::UserName(java::to_lower_root(trimmed)),",
     "None => MemberRef::UserName(trimmed.to_owned()),", REFERENCE),
    ("removal prefix in any case", DS, "if path.starts_with(PREFIX) {", "if path.to_lowercase().starts_with(PREFIX) {", REFERENCE),
    ("long s is not s", DS, " || (c == '\\u{17f}' && expected == 's')", "", REFERENCE),
    ("quote before a final terminator kept", DS, '["", "\\r\\n", "\\n", "\\r", "\\u{85}", "\\u{2028}", "\\u{2029}"]', '[""]', REFERENCE),
    ("plus is no sign", JV, "if !matches!(first, '-' | '+') {", "if first != '-' {", REFERENCE),
    # ── what the directory may not do
    ("administrative account provisionable", SC, "if Role::of(Some(&user.role)).is_some_and(Role::administers) {", "if false {", ENGINES),
    ("global-scope role granted", SC, "Some(role) if role.administers() || role.has_global_security_scope() =>",
     "Some(role) if role.administers() =>", ENGINES),
    ("held role is a grant", SC, "        Some(role) if role.name() == unchanged => Ok(unchanged.to_owned()),\n", "", ENGINES),
    ("absent role demotes", SC, "        None => Ok(unchanged.to_owned()),", "        None => Ok(Role::User.name().to_owned()),", ENGINES),
    ("role read as typed", SC, "Role::of(Some(&java::to_upper_root(java::trim(requested))))", "Role::of(Some(java::trim(requested)))", ENGINES),
    ("rebinding allowed", SC, "Some(bound) if *bound != external_id => {", "Some(bound) if false && *bound != external_id => {", ENGINES),
    ("second factor bound", SC, "            if user.mfa_enabled {", "            if false {", ENGINES),
    ("only administrators privileged", SC, ".is_none_or(privileged) && !link_privileged {", ".is_none_or(Role::administers) && !link_privileged {", ENGINES),
    ("privileged linking ignored", SC, ".is_none_or(privileged) && !link_privileged {", ".is_none_or(privileged) {", ENGINES),
    ("unreadable role bindable", SC, ".is_none_or(privileged) && !link_privileged {", ".is_some_and(privileged) && !link_privileged {", ENGINES),
    ("triage approver bindable", SC, "\n        || role.can_approve_triage()", "", ENGINES),
    ("global scope bindable", SC, "\n        || role.has_global_security_scope()\n", "\n", ENGINES),
    ("bound subject inserted", SC, "&& store::account_bound_to(&mut tx, subject).await?.is_some()\n",
     "&& store::account_bound_to(&mut tx, subject).await?.is_some_and(|_| false)\n", ENGINES),
    ("bound subject bound again", SC, "store::account_bound_to(&mut tx, subject).await?.is_some_and(|other| other.id != id)",
     "store::account_bound_to(&mut tx, subject).await?.is_some_and(|other| other.id == id)", ENGINES),
    ("column one wider", SC, "const IDENTITY_COLUMN: usize = 255;", "const IDENTITY_COLUMN: usize = 256;", ENGINES),
    ("patched display name unbounded", SC, "user.display_name = bounded(Some(name), \"displayName\")?;", "user.display_name = Some(name.clone());", ENGINES),
    # ── accounts
    ("username kept as typed", SC, "java::to_lower_root(java::trim(attributes.user_name.as_deref().unwrap_or(\"\")))",
     "java::trim(attributes.user_name.as_deref().unwrap_or(\"\")).to_owned()", ENGINES),
    ("taken username inserted", SC, "if store::account_named(&mut tx, &username).await?.is_some() {", "if false {", ENGINES),
    ("provisioned inactive", SC, "is_active: attributes.active.unwrap_or(true),", "is_active: attributes.active.unwrap_or(false),", ENGINES),
    ("absent active deactivates", SC, "let now_active = attributes.active.unwrap_or(true);", "let now_active = attributes.active.unwrap_or(false);", ENGINES),
    ("role change keeps the sessions", SC, "if role != previous_role && now_active {\n            store::delete_sessions(&mut tx, id).await?;\n",
     "if role != previous_role && now_active {\n", ENGINES),
    ("deactivation keeps the sessions", SC, "} else if was_active && !now_active {\n            store::delete_sessions(&mut tx, id).await?;\n",
     "} else if was_active && !now_active {\n", ENGINES),
    ("account committed before its sessions", SC, "store::update_account(&mut tx, &user).await?;\n\n        let description",
     "store::update_account(&mut tx, &user).await?;\n        teams::commit(tx).await?;\n        let mut tx = teams::write(&self.db).await?;\n\n        let description", ENGINES),
    ("patched deactivation keeps the sessions", SC, "        if deactivated {\n            store::delete_sessions(&mut tx, id).await?;",
     "        if false {\n            store::delete_sessions(&mut tx, id).await?;", ENGINES),
    ("every patch recorded", SC, "        if deactivated {\n            self.record(", "        if true {\n            self.record(", ENGINES),
    ("patch path in its case", SC, "let path = java::to_lower_root(operation.path.as_deref().unwrap_or(\"\"));",
     "let path = operation.path.as_deref().unwrap_or(\"\").to_owned();", ENGINES),
    ("entry attributed to the caller", SC, "username: Some(username.to_owned()),", "username: actor.username.clone(),", ENGINES),
    ("users never cut", SC, "Ok(Page::of(found, start_index, count)", "Ok(Page::of(found, None, None)", ENGINES),
    ("subject filter by name", SC, "store::account_bound_to(&mut tx, &subject).await?.into_iter().collect()",
     "store::account_named(&mut tx, &subject).await?.into_iter().collect()", ENGINES),
    # ── groups
    ("groups never cut", SC, "Page::of(teams::teams(&mut tx).await?, start_index, count)", "Page::of(teams::teams(&mut tx).await?, None, None)", ENGINES),
    ("listed groups without members", SC, "by_team.remove(&team.id).unwrap_or_default()", "Vec::new()", ENGINES),
    ("own name taken", SC, "Ok(teams::team_named(tx, name).await?.is_some_and(|other| other.id != id))",
     "Ok(teams::team_named(tx, name).await?.is_some())", ENGINES),
    ("another's name free", SC, "Ok(teams::team_named(tx, name).await?.is_some_and(|other| other.id != id))",
     "Ok(teams::team_named(tx, name).await?.is_some_and(|other| other.id == id))", ENGINES),
    ("blank name renames", SC, "Some(requested) if !java::is_blank(requested) =>", "Some(requested) =>", ENGINES),
    ("refused rename commits", SC, "                        return Ok(GroupChange::NameTaken);\n                    }\n                    team.name = rename;",
     "                        teams::commit(tx).await?;\n                        return Ok(GroupChange::NameTaken);\n                    }\n                    team.name = rename;", ENGINES),
    ("members committed before the newcomers", SC, "teams::delete_members(&mut tx, id).await?;\n        for value in member_values",
     "teams::delete_members(&mut tx, id).await?;\n        teams::commit(tx).await?;\n        let mut tx = teams::write(&self.db).await?;\n        for value in member_values", ENGINES),
    ("replace read as add", SC, "let replacement = if kind == \"replace\" { member_replacement_of(operation)? } else { None };",
     "let replacement: Option<&[Value]> = None;", ENGINES),
    ("add replaces", SC, "if kind == \"replace\" { member_replacement_of", "if kind == \"replace\" || kind == \"add\" { member_replacement_of", ENGINES),
    ("unlisted members stay", SC, "    for user_id in current.iter().filter(|user_id| !listed.contains(user_id)) {\n        store::delete_member(tx, team_id, *user_id).await?;\n    }\n",
     "", ENGINES),
    ("kept member re-marked", SC, "for user_id in listed.iter().filter(|user_id| !current.contains(user_id)) {", "for user_id in listed.iter() {", ENGINES),
    ("members not a list read as none", SC, "_ => Err(ScimError::InvalidInput(\"Group members must be a list.\".to_owned())),", "_ => Ok(None),", ENGINES),
    ("display name not a string ignored", SC, "_ => Err(ScimError::InvalidInput(\"Group displayName must be a string.\".to_owned())),", "_ => Ok(None),", ENGINES),
    ("removal of everybody ignored", SC, "Removal::Everyone => {\n                        teams::delete_members(&mut tx, id).await?;\n                    }",
     "Removal::Everyone => {}", ENGINES),
    ("removal of one ignored", SC, "store::delete_member(&mut tx, id, user_id).await?;", "let _ = user_id;", ENGINES),
    ("unknown identifier joins", SC, "Some(MemberRef::Id(id)) => teams::account(tx, id).await?.map(|account| account.id),",
     "Some(MemberRef::Id(id)) => Some(id),", ENGINES),
    ("membership's origin", SC, 'pub const ORIGIN_SCIM: &str = "scim";', 'pub const ORIGIN_SCIM: &str = "manual";', ENGINES),
    ("created team's description", SC, 'const CREATED_VIA_SCIM: &str = "Created via SCIM";', 'const CREATED_VIA_SCIM: &str = "Created by SCIM";', ENGINES),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
