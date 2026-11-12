#!/usr/bin/env python3
"""Mutation check of Phase 1 task 1.6: cp-audit, cp-settings, cp-platform and cp-app's mirror adapter.
Each mutant must turn the owning crate's tests red. The `oracle` feature runs Java as the oracle: it needs
ORACLE_CLASSPATH_FILE in the environment (see README.md).
"""
import sys

import _runner

AUD, SET, PLAT, APP = "vectispire-cp-audit", "vectispire-cp-settings", "vectispire-cp-platform", "vectispire-cp-app"
A, T, P = "crates/cp-audit/src/", "crates/cp-settings/src/", "crates/cp-platform/src/"
ORACLE = ["--features", "oracle"]

M = [
    # --- cp-audit: the chain, the data contract
    ("instant rounded, not truncated", AUD, A + "chain.rs", "        utc.millisecond()\n", "        utc.millisecond() + u16::from(utc.microsecond() % 1000 >= 500)\n"),
    ("separator printable", AUD, A + "chain.rs", "            joined.push(SEPARATOR);", "            joined.push('|');"),
    ("field order", AUD, A + "chain.rs", "        entry.ip_address.as_deref(),\n        entry.user_agent.as_deref(),", "        entry.user_agent.as_deref(),\n        entry.ip_address.as_deref(),"),
    ("unchained row at the switchover alarms", AUD, A + "chain.rs", "if entry.entry.timestamp.is_some_and(|at| at > oldest) {", "if entry.entry.timestamp.is_some_and(|at| at >= oldest) {"),
    ("vanished predecessor ignored", AUD, A + "chain.rs", "            && !known.contains(previous)", "            && false"),
    ("own hash not checked", AUD, A + "chain.rs", "        if stored != entry_hash(&entry.entry) {", "        if stored.is_empty() {"),
    ("rebuild does not relink", AUD, A + "chain.rs", "            previous = Some(hash.clone());", ""),
    # --- cp-audit: writing
    ("dated at the head, not after it", AUD, A + "log.rs", "        Some(head) if candidate <= head.timestamp => {", "        Some(head) if candidate < head.timestamp => {"),
    ("instants not strictly increasing", AUD, A + "log.rs", "let next = |previous: i64| if candidate > previous { candidate } else { previous.saturating_add(1) };", "let next = |previous: i64| if candidate >= previous { candidate } else { previous };"),
    ("absent resource empty, not \"null\"", AUD, A + "log.rs", 'resource_id: truncate(entry.resource_id.as_deref().unwrap_or("null"), TEXT_COLUMN).to_owned(),', 'resource_id: truncate(entry.resource_id.as_deref().unwrap_or(""), TEXT_COLUMN).to_owned(),'),
    ("blank address kept", AUD, A + "log.rs", "ip_address: truncate_optional(blank_to_none(entry.ip_address.as_deref()), ADDRESS_COLUMN),", "ip_address: truncate_optional(entry.ip_address.as_deref(), ADDRESS_COLUMN),"),
    ("description not cut", AUD, A + "log.rs", "                .map(|text| truncate(text, TEXT_COLUMN).to_owned())", "                .map(str::to_owned)"),
    ("listeners not told in the transaction", AUD, A + "log.rs", "        if with_listeners {\n            for listener", "        if false {\n            for listener"),
    ("fallback does not tell the listeners", AUD, A + "log.rs", "                if !with_listeners {\n                    self.after_commit", "                if false {\n                    self.after_commit"),
    ("mirror as a set, not a multiset", AUD, A + "log.rs", "Some(remaining) if *remaining > 0 => *remaining = remaining.saturating_sub(1),", "Some(_) => {}"),
    ("chain head not locked", AUD, A + "log.rs", "        if !persistence::lock_chain(tx).await? {\n            return Err(AuditError::ChainHeadMissing);\n        }\n", ""),
    ("cut splits a pair", AUD, A + "text.rs", "        units = usize::saturating_add(units, c.len_utf16());", "        units = usize::saturating_add(units, 1);"),
    ("no-break space is blank", AUD, A + "text.rs", "        || (space_separator && !matches!(c, '\\u{a0}' | '\\u{2007}' | '\\u{202f}'))", "        || space_separator"),
    # --- cp-audit: reading
    ("deletion seen only by the chain", AUD, A + "query.rs", "let intact = result.broken.is_none() && mirror.missing_from_table == 0;", "let intact = result.broken.is_none();"),
    ("break not told to the SOC", AUD, A + "query.rs", "                listener.chain_broken(&event).await;", ""),
    ("page size unbounded", AUD, A + "query.rs", "let size = limit.clamp(1, MAX_PAGE_SIZE);", "let size = limit.max(1);"),
    ("offset not on a page boundary", AUD, A + "query.rs", "let applied = from.checked_div(size).map_or(0, |page| i64::from(page).saturating_mul(i64::from(size)));", "let applied = i64::from(from);"),
    ("search case-sensitive", AUD, A + "query.rs", 'pattern: term.map(|term| format!("%{}%", term.to_lowercase())),', 'pattern: term.map(|term| format!("%{term}%")),'),
    ("search unbounded", AUD, A + "query.rs", "    if trimmed.encode_utf16().count() > SEARCH_MAX {", "    if false {"),
    ("bundle instant always nine digits", AUD, A + "query.rs", "        if nanos.is_multiple_of(1_000_000) {", "        if false {"),
    ("bundle member order", AUD, A + "export.rs", '    member(&mut out, "userId", entry.user_id.as_deref(), false);\n    member(&mut out, "ipAddress", entry.ip_address.as_deref(), false);', '    member(&mut out, "ipAddress", entry.ip_address.as_deref(), false);\n    member(&mut out, "userId", entry.user_id.as_deref(), false);', ORACLE),
    # --- cp-settings
    ("cleared value comes back as the default", SET, T + "store.rs", "            Some(value) => value.unwrap_or_default(),", "            Some(value) => value.filter(|value| !value.is_empty()).unwrap_or_else(|| setting.default_value().to_owned()),"),
    ("unreadable int is zero", SET, T + "store.rs", "Ok(parse_int(&value).or_else(|| parse_int(setting.default_value())).unwrap_or_default())", "Ok(parse_int(&value).unwrap_or_default())"),
    ("insert-if-absent swallows any failure", SET, T + "store.rs", "                if persistence::find(&self.db, key).await?.is_some() {", "                if true {"),
    ("first install overwrites a choice", SET, T + "store.rs", "            if persistence::find_in(tx, setting.key()).await?.is_some() {\n                continue;\n            }\n", ""),
    ("catalog key through the internal door", SET, T + "store.rs", "        Some(_) => Err(SettingsError::CatalogKey(format!(\"{key} is a catalog setting, {how}.\"))),", "        Some(_) => Ok(()),"),
    ("version not trimmed", SET, T + "about.rs", "        Some(configured) => Some(java_trim(configured).to_owned()),", "        Some(configured) => Some(configured.to_owned()),"),
    ("blank brand kept", SET, T + "about.rs", "    match value.filter(|value| !is_blank(value)) {", "    match value.filter(|value| !value.is_empty()) {"),
    ("ssh user is a credential", SET, T + "rules.rs", "    !scheme.eq_ignore_ascii_case(\"ssh://\") || user.contains(':')", "    true"),
    # --- cp-platform
    ("secret shown to everyone", PLAT, P + "settings.rs", "(setting.is_secret() && !is_admin)", "(setting.is_secret() && false)"),
    ("credential shown to an administrator", PLAT, P + "settings.rs", "value: (!(setting.is_encrypted() || (setting.is_secret()", "value: (!(false || (setting.is_secret()"),
    ("values not trimmed", PLAT, P + "settings.rs", 'let value = java_trim(value.as_deref().unwrap_or("")).to_owned();', 'let value = value.as_deref().unwrap_or("").to_owned();'),
    ("acknowledgement settable from the wire", PLAT, P + "settings.rs", "        if matches!(setting, Setting::AiReviewRiskAcknowledgedBy | Setting::AiReviewRiskAcknowledgedAt) {", "        if matches!(setting, Setting::AiReviewRiskAcknowledgedBy) {"),
    ("governor-only for any administrator", PLAT, P + "settings.rs", "if setting.governor_only() && !writer.is_some_and(|writer| writer.governs_platform) {", "if setting.governor_only() && !writer.is_some_and(|writer| writer.administrative) {"),
    ("administrator-only even unchanged", PLAT, P + "settings.rs", "            && value != self.settings.get(setting).await?\n", ""),
    ("administrator-only for anyone", PLAT, P + "settings.rs", "            && !writer.is_some_and(|writer| writer.administrative)\n", "            && false\n"),
    ("four-eyes on without an approver", PLAT, P + "settings.rs", "        if !self.approvers.any_active().await.map_err(collaborator)? {", "        if false {"),
    ("four-eyes on without two publishers", PLAT, P + "settings.rs", "        if !self.approvers.two_can_publish_templates().await.map_err(collaborator)? {", "        if false {"),
    ("four-eyes on without two signers", PLAT, P + "settings.rs", "        if !self.approvers.two_can_sign_off_checklists().await.map_err(collaborator)? {", "        if false {"),
    ("credential stored in the clear", PLAT, P + "settings.rs", "        if setting.is_encrypted() {\n            return Err(AdministrationError::InvalidInput(format!(", "        if false {\n            return Err(AdministrationError::InvalidInput(format!("),
    ("value not validated", PLAT, P + "settings.rs", "        if let Some(problem) = setting.validate(Some(value)) {", "        if let Some(problem) = None::<String> {"),
    ("CA refused unchanged", PLAT, P + "settings.rs", "            && value != java_trim(&self.settings.get(setting).await?)\n", ""),
    ("expiry not a date", PLAT, P + "settings.rs", "if setting == Setting::TicketTokenExpiresOn && !value.is_empty() && !is_iso_local_date(value) {", "if setting == Setting::TicketTokenExpiresOn && value.is_empty() {"),
    ("GitHub project refused unchanged", PLAT, P + "settings.rs", "            && (provider_after != provider_now || project_after != project_now)\n", ""),
    ("blank GitHub project refused", PLAT, P + "settings.rs", "            && !vectispire_cp_settings::types::is_blank(project_after)\n", ""),
    ("withdrawal refused", PLAT, P + "settings.rs", "        if !withdraws_acknowledgement {", "        if true {"),
    ("AI judged on the stored state", PLAT, P + "settings.rs", "                openai_url: pending.get(&Setting::AiReviewOpenaiUrl).copied(),", "                openai_url: None,"),
    ("acknowledgement stamped on every save", PLAT, P + "settings.rs", "            && *switch != previous_acknowledgement\n", ""),
    ("acknowledgement anonymous", PLAT, P + "settings.rs", 'let by = writer.map_or("", |writer| writer.username.as_str());', 'let by = "";'),
    ("partial write on refusal", PLAT, P + "settings.rs", "            self.admit(setting, &value, writer).await?;\n            changes.push(Change { setting, value });", "            let refused = self.admit(setting, &value, writer).await;\n            if refused.is_ok() { let mut tx = self.db.begin(Mode::ReadWrite).await.map_err(|failure| AdministrationError::Storage(failure.into()))?; self.settings.set(&mut tx, setting, &value).await?; tx.commit().await.map_err(|failure| AdministrationError::Storage(failure.into()))?; }\n            refused?;\n            changes.push(Change { setting, value });"),
    ("security save not signalled", PLAT, P + "settings.rs", ".record(if changes.iter().any(|change| change.setting.governs_security()) {", ".record(if false {"),
    ("secret value in the entry", PLAT, P + "settings.rs", "    if change.setting.is_secret() {\n        return format!", "    if false {\n        return format!"),
    ("four-eyes described as a value", PLAT, P + "settings.rs", "    if change.setting == Setting::FourEyesApprovalRequired {\n        return format!(", "    if false {\n        return format!("),
    ("empty not named", PLAT, P + "settings.rs", 'if change.value.is_empty() { "(empty)" } else { &change.value }', '&change.value'),
    ("keys in another order", PLAT, P + "settings.rs", "keys: changes.iter().map(|change| change.setting.key()).collect::<Vec<_>>().join(\",\"),", "keys: changes.iter().rev().map(|change| change.setting.key()).collect::<Vec<_>>().join(\",\"),"),
    ("leap year wrong", PLAT, P + "forms.rs", "(year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)", "true"),
    ("plus with four digits", PLAT, P + "forms.rs", "        Some('+') => (5..=10).contains(&year.len()),", "        Some('+') => (4..=10).contains(&year.len()),"),
    ("dot-dot repository", PLAT, P + "forms.rs", "        && repository != \"..\";", ";"),
    # --- cp-app: the adapter
    ("adapter crosses two fields", APP, "crates/cp-app/src/audit_mirror.rs", "        user_id: entry.user_id.clone(),\n        ip_address: entry.ip_address.clone(),", "        user_id: entry.ip_address.clone(),\n        ip_address: entry.user_id.clone(),"),
    ("adapter says configured", APP, "crates/cp-app/src/audit_mirror.rs", "        self.0.is_configured()", "        true"),
]

MUTANTS = [(m[0], m[2], m[3], m[4], ["-p", m[1], *(m[5] if len(m) > 5 else [])]) for m in M]


if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=1500))
