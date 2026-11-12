#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.6: cp-targets (the visibility each service applies, the routes' answers on it, a
deletion's order and its revocations, the identity guard and its keying, the schedule, the clone credentials and their
secrets, the forms' refusals, the request readers), the principal's restriction in cp-http and cp-access, access's
TargetGrants, and the domain rules the module reads. The engine mutants start a MySQL and a PostgreSQL each. See
README.md.
"""
import sys

import _runner

S = "crates/cp-targets/src/"
REPO, CONT, SOL, TREE, CRED = S + "repositories.rs", S + "containers.rs", S + "solutions.rs", S + "tree.rs", S + "credentials.rs"
DEL, IDN, SCHED, WEB, READ, JSON = S + "deletion.rs", S + "identity.rs", S + "schedule.rs", S + "web/mod.rs", S + "web/read.rs", S + "web/json.rs"
PERS = S + "persistence/mod.rs"
SEC, CREDS, GRANTS = "crates/cp-access/src/security/mod.rs", "crates/cp-access/src/internal/credentials/mod.rs", "crates/cp-access/src/target_grants.rs"
PGR = "crates/cp-access/src/persistence/target_grants.rs"
D = "crates/domain/src/"

ENG = ["-p", "vectispire-cp-targets", "--test", "engines"]
RT = ["-p", "vectispire-cp-targets", "--test", "routes"]
RU = ["-p", "vectispire-cp-targets", "--test", "rules"]
UNIT = ["-p", "vectispire-cp-targets", "--lib"]
ACC = ["-p", "vectispire-cp-access", "--lib"]
ACCE = ["-p", "vectispire-cp-access", "--test", "credentials_on_both_engines"]
DOM = ["-p", "vectispire-domain", "--test", "targets_reference_set"]

MUTANTS = [
    # ── visibility: every service refuses what its caller cannot see ──
    ("a listing reads every repository", REPO, "persistence::visible_repositories(&self.db, allowed)", "persistence::visible_repositories(&self.db, &Visibility::Everything)", ENG),
    ("a listing reads every image", CONT, "persistence::visible_containers(&self.db, allowed)", "persistence::visible_containers(&self.db, &Visibility::Everything)", ENG),
    ("an update of a hidden repository", REPO, "let mut row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Repository(id), allowed)?;", "let mut row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Repository(id), &Visibility::Everything)?;", ENG),
    ("a scan of a hidden repository", REPO, "        let row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Repository(id), allowed)?;\n        let view = RepositoryView::from(&row);", "        let row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Repository(id), &Visibility::Everything)?;\n        let view = RepositoryView::from(&row);", ENG + RT),
    ("a deletion of a hidden repository", REPO, "let row = vectispire_cp_access::rows::require_visible_repository(found, id, allowed)?;", "let row = vectispire_cp_access::rows::require_visible_repository(found, id, &Visibility::Everything)?;", ENG),
    ("an update of a hidden image", CONT, "let mut row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Container(id), allowed)?;", "let mut row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Container(id), &Visibility::Everything)?;", ENG),
    ("a scan of a hidden image", CONT, "        let row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Container(id), allowed)?;\n        let view = ContainerView::from(&row);", "        let row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Container(id), &Visibility::Everything)?;\n        let view = ContainerView::from(&row);", ENG + RT),
    ("a deletion of a hidden image", CONT, ".filter(|_| allowed.permits(ScanTarget::Container(id)))", ".filter(|_| true)", ENG),
    ("a hidden repository filed", SOL, "            let repository = rows::require_visible_repository(found, repository_id, allowed)?;\n            if repository.project_id == Some(project_id) {", "            let repository = rows::require_visible_repository(found, repository_id, &Visibility::Everything)?;\n            if repository.project_id == Some(project_id) {", ENG),
    ("a hidden repository removed", SOL, "            let repository = rows::require_visible_repository(found, repository_id, allowed)?;\n            if repository.project_id != Some(project_id) {", "            let repository = rows::require_visible_repository(found, repository_id, &Visibility::Everything)?;\n            if repository.project_id != Some(project_id) {", ENG),
    ("a hidden image filed", SOL, "            let container = rows::require_visible_row(found, ScanTarget::Container(container_id), allowed)?;\n            if container.project_id == Some(project_id) {", "            let container = rows::require_visible_row(found, ScanTarget::Container(container_id), &Visibility::Everything)?;\n            if container.project_id == Some(project_id) {", ENG),
    ("a hidden image removed", SOL, "            let container = rows::require_visible_row(found, ScanTarget::Container(container_id), allowed)?;\n            if container.project_id != Some(project_id) {", "            let container = rows::require_visible_row(found, ScanTarget::Container(container_id), &Visibility::Everything)?;\n            if container.project_id != Some(project_id) {", ENG),
    ("a project moved by a restricted caller", SOL, "if !matches!(allowed, Visibility::Everything) {", "if false {", ENG),
    ("a twin named to a caller who cannot see it", REPO, "if !allowed.permits(ScanTarget::Repository(existing.id)) {", "if false {", UNIT + ENG),
    ("a hidden project's detail", TREE, "        let Some(project) = project else {\n            return Err(TargetError::not_found(rows::PROJECT_NOT_FOUND));\n        };\n        let seen: BTreeSet<ScanTarget> = scope.visible.iter().copied().collect();", "        let Some(project) = project else {\n            return Err(TargetError::not_found(rows::PROJECT_NOT_FOUND));\n        };\n        let seen: BTreeSet<ScanTarget> = filed.iter().copied().collect();", ENG),
    ("the tree shows a hidden project", TREE, "                everything\n                    || allowance.granted_projects.contains(&project.id)", "                true\n                    || allowance.granted_projects.contains(&project.id)", ENG + RT),
    ("the tree counts a hidden repository", TREE, "all_repositories.iter().filter(|row| visibility.permits(ScanTarget::Repository(row.id))).collect();", "all_repositories.iter().collect();", ENG + RT),
    ("a granted project not shown", TREE, "                    || allowance.granted_projects.contains(&project.id)\n", "", ENG),
    ("a partial project read whole", TREE, "        partial: count(visible.len().saturating_add(visible_containers.len())) < filed,", "        partial: false,", ENG),
    ("an unresolved allowance read as everything", WEB, "    scope.map_err(|_| Box::new(problem(&call.method, &call.path, TargetError::unexpected(NoAllowance)).into_response()))", "    Ok(scope.unwrap_or_else(|_| Allowance::everything()))", RT),
    # ── the principal's restriction ──
    ("a key's repository read as everything", SEC, "        Restriction::Target(vectispire_domain::ScanTarget::Repository(id)) => {\n            Visibility::only([ScanTarget::Repository(id)])\n        }", "        Restriction::Target(vectispire_domain::ScanTarget::Repository(_)) => Visibility::everything(),", ACC + RT),
    ("a key of no known kind sees everything", SEC, "        Restriction::Nothing => Visibility::only([]),", "        Restriction::Nothing => Visibility::everything(),", ACC),
    ("an unreadable role read as the stored one", SEC, "role: principal.grounds.stored_role.clone().unwrap_or_default(),", 'role: principal.grounds.stored_role.clone().unwrap_or_else(|| "ADMIN".to_owned()),', ACC),
    ("a key's restriction lost on resolution", CREDS, "            restriction: restriction_of_visibility(&self.credential_restriction()),", "            restriction: Restriction::None,", ACCE),
    ("a two-target restriction widened", CREDS, "            _ => Restriction::Nothing,", "            _ => Restriction::None,", ACC),
    ("the account's id lost", CREDS, "            account_id: account.map(|account| account.id),", "            account_id: None,", ACCE),
    # ── a deletion: grants first, listeners by phase, the row last ──
    ("listeners in registration order", DEL, "        listeners.sort_by_key(|listener| listener.phase());\n", "", ENG + RU),
    ("grants left with the target", DEL, "    let revoked =\n        target_grants::revoke_all(tx, TargetPurge::kind(target), id).await.map_err(TargetError::unexpected)?;", "    let revoked = Revoked::default();", ENG),
    ("the purge skipped", DEL, "    registry.publish(tx, &TargetPurge::Deleted(target)).await.map_err(TargetError::Unexpected)?;\n", "", ENG),
    ("an image's grants revoked as a repository's", DEL, "            ScanTarget::Container(_) => vectispire_cp_access::visibility::KIND_CONTAINER,", "            ScanTarget::Container(_) => vectispire_cp_access::visibility::KIND_REPOSITORY,", ENG),
    ("a failing listener ignored", DEL, "            listener.purge(tx, purge).await?;", "            let _ = listener.purge(tx, purge).await;", ENG),
    ("the access change not signalled", DEL, "audit.record(if revoked.grants > 0 { deleted.signalling(ACCESS_GRANT_CHANGED) } else { deleted }).await;", "audit.record(deleted).await;", ENG),
    ("no entry per revoked key", DEL, "    for key in &revoked.keys {", "    for key in revoked.keys.iter().take(0) {", ENG),
    ("restricted keys left standing", GRANTS, "        target_grants::delete_key(tx, key.id).await?;\n", "", ENG),
    # ── the identity guard and its keying ──
    ("a raced twin not read back", REPO, "        match refusal.await {\n            Ok(Err(conflict)) => conflict,", "        match refusal.await {\n            Ok(Err(_)) => TargetError::from(failure),", ENG),
    ("a row takes no guard", REPO, "    row.identity_guard = if holds_guard { identity.map(RepositoryIdentity::guard) } else { None };", "    row.identity_guard = None;", ENG),
    ("an edit to another twin accepted", REPO, "        if identity != previous_identity\n", "        if false\n", ENG),
    ("the younger twin keyed", IDN, "                        guard: free.then_some(guard.as_str()),", "                        guard: Some(guard.as_str()),", ENG),
    ("a keyed twin counted as keyed", IDN, "Ok(Some(false)) => done.twins = done.twins.saturating_add(1),", "Ok(Some(false)) => done.keyed = done.keyed.saturating_add(1),", ENG),
    # ── the schedule ──
    ("manual only beside an interval", SCHED, "        if manual_only == Some(true) && names_schedule {", "        if false {", RU + RT),
    ("a negative interval accepted", SCHED, "if interval_minutes.is_some_and(|minutes| minutes < 0) {", "if false {", RU),
    ("an interval of zero kept", SCHED, "                Some(0) => None,\n", "", RU),
    ("manual only kept beside a new schedule", SCHED, "let manual = manual_only.unwrap_or(!names_schedule && self.manual_only);", "let manual = manual_only.unwrap_or(self.manual_only);", RU),
    ("an absent expression clears it", SCHED, "cron: if cron.is_none() { self.cron.clone() } else { expression },", "cron: expression,", RU),
    # ── the clone credentials ──
    ("a token stored under the key's context", CRED, "let ciphertext = self.encryption.encrypt(token, &git_token_context(&id.as_hyphenated().to_string())).await?;", "let ciphertext = self.encryption.encrypt(token, &private_key_context(&id.as_hyphenated().to_string())).await?;", ENG),
    ("a key stored under the token's context", CRED, "            self.encryption.encrypt(private_key, &private_key_context(&id.as_hyphenated().to_string())).await?;", "            self.encryption.encrypt(private_key, &git_token_context(&id.as_hyphenated().to_string())).await?;", ENG),
    ("a key's state read under another context", CRED, "            let context = private_key_context(&key.id.as_hyphenated().to_string());", "            let context = git_token_context(&key.id.as_hyphenated().to_string());", ENG),
    ("a token with white space accepted", CRED, "if token.chars().any(java::is_whitespace) {", "if false {", RT),
    ("anything accepted as a private key", CRED, "if !PRIVATE_KEY_HEADER.is_match(private_key) {", "if false {", RT),
    ("a token in use deleted", CRED, "            let in_use = persistence::count_by_https_token(&mut tx, id).await?;\n            if in_use > 0 {", "            let in_use = persistence::count_by_https_token(&mut tx, id).await?;\n            if in_use > 1 {", ENG),
    # ── the forms ──
    ("a credential in a URL accepted", REPO, "    if repository_url::carries_credential(url) {", "    if false {", ENG + RT),
    ("any host cloned", REPO, "        if self.allowed_hosts.permits(url) {", "        if true {", ENG),
    ("both credentials accepted", REPO, "    if row.https_token_id.is_some() && row.ssh_key_id.is_some() {", "    if false {", ENG),
    ("a token over SSH accepted", REPO, "        if !repository_url::is_https(&row.url) {", "        if false {", ENG),
    ("a token sent to another host", REPO, "        if !repository_url::has_host(&row.url, &host) {", "        if false {", ENG),
    ("a key over HTTPS accepted", REPO, "    if row.ssh_key_id.is_some() && repository_url::is_https(&row.url) {", "    if false {", ENG),
    ("the mask written over the stored URL", REPO, "            && !repository_url::is_masked_form_of(schedule::trim(Some(url)), &previous_url)", "", ENG),
    ("a solution still holding projects deleted", SOL, "            if held > 0 {", "            if held > 1 {", RT),
    ("a solution's name taken twice", SOL, "        Some(existing) if Some(existing.id) != this => {\n            Err(TargetError::conflict(format!(\"A solution named", "        Some(existing) if false => {\n            Err(TargetError::conflict(format!(\"A solution named", RT),
    ("a repository in another project removed", SOL, "            if repository.project_id != Some(project_id) {", "            if false {", RT),
    # ── the answers ──
    ("a stored URL shown with its credential", JSON, "            url: repository_url::redact(&repository.url),", "            url: repository.url.clone(),", RT),
    ("unknown languages answered as none", JSON, "            detected_languages: listed.detected_languages.as_ref().map(|languages| languages.iter().cloned().collect()),", "            detected_languages: Some(listed.detected_languages.clone().unwrap_or_default().into_iter().collect()),", RT),
    ("a number read as no text", READ, "            Some(Value::Number(number)) => Ok(Some(number.to_string())),\n            Some(Value::Bool(flag)) => Ok(Some(flag.to_string())),", "            Some(Value::Number(_)) => Ok(None),\n            Some(Value::Bool(flag)) => Ok(Some(flag.to_string())),", RT),
    ("a hexadecimal path variable read as decimal", READ, "        Some(digits) => (digits, 16),", "        Some(digits) => (digits, 10),", UNIT),
    ("a numeric string refused as a number", READ, "                java::parse_int(trimmed).map(Some).map_err(|_| unreadable())", "                Err(unreadable())", RT),
    # ── the domain rules ──
    ("the identity keeps its .git", D + "repository_url.rs", "    match stripped.strip_suffix(\".git\") {", "    match None::<&str> {", DOM),
    ("the identity keeps its case", D + "repository_url.rs", "    let lowered = crate::java::to_lower_root(path);", "    let lowered = path.to_owned();", DOM),
    ("a guard without its branch", D + "repository_identity.rs", "fingerprint::sha256_fields(&[Some(&self.repository), Some(&self.branch), Some(&self.sub_path)])", "fingerprint::sha256_fields(&[Some(&self.repository), Some(&self.sub_path)])", DOM),
    ("an SSH password not a credential", D + "repository_url.rs", "    !scheme.as_str().eq_ignore_ascii_case(\"ssh://\") || user.as_str().contains(':')", "    !scheme.as_str().eq_ignore_ascii_case(\"ssh://\")", DOM),
    ("the case-insensitive order by full mappings", D + "java.rs", "    if c == '\\u{130}' {\n        return 'i';\n    }\n", "", DOM),
    ("a required field kept blank", D + "bounded_text.rs", "    if trimmed.is_empty() {\n        return Err(Refused(format!(\"{what} is required.\")));", "    if false {\n        return Err(Refused(format!(\"{what} is required.\")));", DOM),
    ("an offset off the page accepted", D + "list_window.rs", "        if offset < 0 || offset.checked_rem(limit) != Some(0) {", "        if offset < 0 {", DOM),
    ("an unusable expression run on the interval", D + "schedules.rs", "    } else if !matches!(cron, Stored::Absent) {", "    } else if matches!(cron, Stored::Parsed(_)) {", DOM),
]

# Equivalent, removed from the list with the reason:
# - the solutions' and projects' administration refusing a caller whose allowance is not everything
#   (`require_everything`): only an administrator's session reaches those routes — no API key is accepted there — and
#   an administrator's allowance is everything in either mode, so no request can tell the check from its absence. It is
#   kept as the routes' answer on visibility, should who may call them ever change.
# - the duplicate check before the write: the unique index on the guard refuses the same row, and the refusal is read
#   back from the committed holder, so the answer is the same 409. The check saves a failed statement (and, on MySQL,
#   an identity value), which nothing observes.
# - the holder filter in `refuse_if_registered` (`Some(holder.id) != this`): the check runs only when the identity
#   changed, and a row whose identity changed cannot hold the new guard itself.
# - the agent keys' exclusion from the revocation (`owner_user_id is not null`): a statement's text is its offline
#   cache's key, so a mutated statement does not compile offline; the condition is held by the engine suite instead,
#   where no agent key is ever restricted to a target (`AgentKeys` issues them unrestricted).
# - `json_strings`' and `json_ids`' formatting: serde's and the join's text are the same JSON for integers and strings.
# - the read-only transaction of a listing's project names (`persistence::read` versus `write`): a read either way.
# - `ScanningStandIn`'s and `IssuesStandIn`'s answers: placeholders the composition replaces; their only observable is
#   the stand-in itself, held by the routes' answers.

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
