#!/usr/bin/env python3
"""Mutation check of Phase 5, checklists stage 1a: the checklists vocabulary in crates/cp-checklists (the text an item's
key and digest are computed over, answers and their words, items and pairing, contacts, reminders, rules read in Java's
order and written in their canonical form, scopes and patterns, the evaluation and its evidence) and its shared part in
crates/domain (the facts, a forge's review reading, Maven's order and ranges, the plugin id, Instant read back). See
README.md.
"""
import sys

import _runner

R = ["-p", "vectispire-cp-checklists", "--test", "reference_set"]
L = ["-p", "vectispire-cp-checklists", "--lib"]
RL = [R, L]
IN = ["-p", "vectispire-domain", "--lib", "instant"]
MV = [R, ["-p", "vectispire-domain", "--lib", "maven_version"]]
C = "crates/cp-checklists/src/"
D = "crates/domain/src/"

# Equivalent, and removed: `ChecklistText`'s `\p{javaWhitespace}` — every character it holds is a separator or a
# control too, which `text.rs` now says and a test checks over every code point. The thresholds' failures added to the summary only on complete data — with data missing the
# outcome is `no_data` before the failures are read, so the guard on `unmet` cannot be told apart; the figure's own
# `met` carries the same condition and is mutated instead.
MUTANTS = [
    ("text format removed", C + "text.rs", "if get_general_category(c) == GeneralCategory::Format {", "if false {", R),
    ("text controls are spaces", C + "text.rs", "            | GeneralCategory::Control\n", "", R),
    ("text stripped", C + "text.rs", "    java::strip(&out).to_owned()", "    out", R),
    ("answer lowered", C + "answer.rs", "let normalized = java::to_lower_root(stripped);", "let normalized = stripped.to_owned();", R),
    ("answer words compared normalised", C + "answer.rs", "java::to_lower_root(&text::normalize(Some(left))) == java::to_lower_root(&text::normalize(Some(right)))", "left == right", R),
    ("answer n/a offered", C + "answer.rs", "if value == ChecklistAnswer::NotApplicable && !offered.offers_not_applicable() {", "if false {", R),
    ("answer comment required", C + "answer.rs", "if value.requires_comment() && comment.is_none() {", "if false {", R),
    ("author kind exact", C + "answer.rs", "AnswerAuthor::of_stored(stored) == Some(AnswerAuthor::System)", "stored.is_some_and(|kind| kind.eq_ignore_ascii_case(\"system\"))", R),
    ("item key lowered", C + "item.rs", "sha256_hex(&java::to_lower_root(&normalized))", "sha256_hex(&normalized)", R),
    ("item id ceiling", C + "item.rs", "if java::utf16_len(&normalized) > ItemKey::MAX_ID {", "if java::utf16_len(&normalized) >= ItemKey::MAX_ID {", R),
    ("item validity floor", C + "item.rs", "!(1..=EvidenceRequirement::MAX_VALIDITY_MONTHS).contains(months)", "!(0..=EvidenceRequirement::MAX_VALIDITY_MONTHS).contains(months)", R),
    ("item digest order", C + "item.rs", "            Some(&evidence),\n            Some(&rule),", "            Some(&rule),\n            Some(&evidence),", R),
    ("item words in utf-16", C + "item.rs", "    if java::utf16_len(kept) > max {", "    if kept.chars().count() > max {", R),
    ("pairing digest decides", C + "pairing.rs", "Some(&was) if was.content_digest() == item.content_digest() => {", "Some(&was) if was.key == item.key => {", R),
    ("pairing removed claimed", C + "pairing.rs", "if !after.contains_key(&item.key) && !claimed.contains(&item.key) {", "if !after.contains_key(&item.key) {", R),
    ("contacts auto excluded", C + "contacts.rs", "if key != AUTOMATIC && !named", "if !named", R),
    ("contacts key one profile", C + "contacts.rs", "if normalized.is_empty() || normalized.contains('/') {", "if normalized.is_empty() {", R),
    ("reminder cut", C + "reminder.rs", "clip(Some(&single), CONTROL_SHOWN.saturating_sub(1))", "clip(Some(&single), CONTROL_SHOWN)", R),
    ("reminder url slashes", C + "reminder.rs", "url.trim_end_matches('/')", "url", R),
    ("ratio four decimals", C + "decimal.rs", "if normalized.scale > SCALE {", "if normalized.scale > SCALE + 1 {", RL),
    ("ratio zero refused", C + "decimal.rs", " || !zero_allowed && ratio.signum() == 0", "", RL),
    ("ratio at least", C + "decimal.rs", ".saturating_mul(power) >= i128::from(self.unscaled)", ".saturating_mul(power) > i128::from(self.unscaled)", RL),
    ("rule keys of another kind refused", C + "rule.rs", "if !kind.allowed().contains(&name.as_str()) {", "if false {", R),
    ("rule age floor", C + "rule.rs", "    if !(1..=MAX_AGE_DAYS).contains(&max_age_days) {", "    if !(0..=MAX_AGE_DAYS).contains(&max_age_days) {", R),
    ("rule scopes sorted", C + "rule.rs", "            scopes.sort_by(|left, right| java::compare_utf16(&left.key(), &right.key()));\n", "", R),
    ("rule scope named twice", C + "rule.rs", "                if keys.contains(&key) {", "                if false {", R),
    ("rule findings threshold required", C + "rule.rs", "            if thresholds.is_empty() {\n                return Err(refused(", "            if false {\n                return Err(refused(", R),
    ("rule minimum tests floor", C + "rule.rs", "if !(1..=MAX_TESTS).contains(&minimum_tests) {", "if !(0..=MAX_TESTS).contains(&minimum_tests) {", R),
    ("rule stored not declared", C + "rule.rs", "        components.push(if stated {", "        components.push(if true {", R),
    ("rule branch whitespace", C + "rule.rs", "java::is_iso_control(c) || java::is_whitespace(c) || \"~^:?*[\\\\\".contains(c)", "java::is_iso_control(c) || \"~^:?*[\\\\\".contains(c)", R),
    ("rule one pattern keeps its key", C + "rule.rs", "[one] => node.insert(\"suitePattern\", Out::Text(one.clone())),", "[one] => node.insert(\"suitePatterns\", texts(std::slice::from_ref(one))),", R),
    ("rule empty thresholds not written", C + "rule.rs", "                if !thresholds.is_empty() {\n                    node.insert(\"thresholds\"", "                if true {\n                    node.insert(\"thresholds\"", R),
    ("rule threshold put in place", C + "rule.rs", "            Some(slot) => slot.1 = parsed,", "            Some(_) => thresholds.push((severity, parsed)),", R),
    ("rule utf-16 order", C + "rule.rs", "components.sort_by(|left, right| java::compare_utf16(&left.purl_prefix, &right.purl_prefix));", "components.sort_by(|left, right| left.purl_prefix.cmp(&right.purl_prefix));", R),
    ("scope built-in types", C + "tool_scope.rs", "                .filter(|kind| BUILT_IN_TYPES.contains(kind))\n", "", R),
    ("scope slug inner hyphens", C + "tool_scope.rs", "c == '-' && index != 0 && index != last", "c == '-'", R),
    ("scope tool ceiling", C + "tool_scope.rs", "java::utf16_len(&tool) > 100", "java::utf16_len(&tool) > 101", R),
    ("component boundary", C + "allowed_component.rs", "matches!(rest.chars().next(), None | Some('@' | '/' | '?' | '#'))", "true", R),
    ("component ranges maven only", C + "allowed_component.rs", "        self.maven()\n            && self", "        true\n            && self", R),
    ("component no version in prefix", C + "allowed_component.rs", "        || prefix.contains('@')\n", "", R),
    ("component versions utf-16 order", C + "allowed_component.rs", "sorted.sort_by(|left, right| java::compare_utf16(left, right));", "sorted.sort();", R),
    ("coverage dotted refused", C + "coverage_scope.rs", "if !pattern.contains('/') && pattern.contains('.') {", "if false {", R),
    ("coverage ** whole segments", C + "coverage_scope.rs", "if segment.contains(\"**\") && segment != \"**\" {", "if false {", R),
    ("coverage ** any segments", C + "coverage_scope.rs", "any |= *was;", "any = *was;", R),
    ("suite star first", C + "suite_pattern.rs", "        if at == Some(star_unit) {", "        if at == Some(star_unit) && !at.is_some_and(|unit| unit == c) {", R),
    ("suite one utf-16 unit", C + "suite_pattern.rs", "let name: Vec<u16> = name.encode_utf16().collect();", "let name: Vec<u16> = name.chars().map(|c| u16::try_from(u32::from(c)).unwrap_or(0)).collect();", R),
    ("evaluation edge of the age", C + "evaluation.rs", "if let Some(look) = newest.as_ref().filter(|look| look.at >= since) {\n                return examined(look.clone());\n            }\n            if scanned", "if let Some(look) = newest.as_ref().filter(|look| look.at > since) {\n                return examined(look.clone());\n            }\n            if scanned", R),
    ("evaluation newest run first", C + "evaluation.rs", "            within.sort_by_key(|run| std::cmp::Reverse(run.scan.at));\n", "", R),
    ("evaluation not applicable anywhere", C + "evaluation.rs", "        if everywhere_not_applicable {", "        if false {", R),
    ("evaluation unknown state open", C + "evaluation.rs", "if count.state == \"resolved\" {", "if count.state != \"open\" {", R),
    ("evaluation figure judged only complete", C + "evaluation.rs", "met: if complete { Some(failures.is_empty()) } else { None },", "met: Some(failures.is_empty()),", R),
    ("evaluation inventory absent", C + "evaluation.rs", "    listed.is_empty() && !matches!(facts", "    false && !matches!(facts", R),
    ("evaluation stated versions judge", C + "evaluation.rs", "if unmet.is_empty() && !unrecorded.is_empty() {", "if !unrecorded.is_empty() {", R),
    ("evaluation window", C + "evaluation.rs", ".filter(|change| change.merged_at >= from)", ".filter(|_| true)", R),
    ("evaluation headline first", C + "evaluation.rs", "if let Some(headline) = self.missing.iter().min().copied() {", "if let Some(headline) = self.missing.iter().max().copied() {", R),
    ("evaluation as of oldest", C + "evaluation.rs", "let as_of = self.looks.iter().min().copied();", "let as_of = self.looks.iter().max().copied();", R),
    ("evaluation sast reads every source language", C + "evaluation.rs", "    if !unread.is_empty() {\n        return ScopeState::Missing {", "    if false {\n        return ScopeState::Missing {", R),
    ("review settings prove", D + "checklists/review.rs", "self.required_approvals >= minimum_approvals && self.author_approval_prevented && self.direct_push_refused", "self.required_approvals >= minimum_approvals", R),
    ("review a source read or why", D + "checklists/review.rs", "if settings.is_some() == settings_unread.is_some() || history.is_some() == history_unread.is_some() {", "if false {", R),
    ("maven shorthand", D + "maven_version.rs", "            \"a\" => \"alpha\",", "            \"a\" => \"a\",", MV),
    ("maven lists skipped by normalize", D + "maven_version.rs", "        } else if !matches!(last, Item::List(_)) {", "        } else {", MV),
    ("maven numbers by value", D + "maven_version.rs", "a.len().cmp(&b.len()).then_with(|| a.cmp(b))", "a.cmp(b)", MV),
    ("maven ranges overlap", D + "maven_version.rs", "                    || order == Ordering::Equal && previous.upper_inclusive && restriction.lower_inclusive\n", "", MV),
    ("maven unbounded in parentheses", D + "maven_version.rs", "if lower.is_none() && lower_inclusive || upper.is_none() && upper_inclusive {", "if false {", MV),
    ("maven digits of any script", D + "maven_version.rs", "        } else if java::digit(c).is_some() {", "        } else if c.is_ascii_digit() {", MV),
    ("plugin id floor", D + "plugin_manifest.rs", "if !(2..=MAX_ID).contains(&length) {", "if !(1..=MAX_ID).contains(&length) {", R),
    ("instant fraction digits", D + "instant.rs", "Some(digits) if (1..=9).contains(&digits.len())", "Some(digits) if (1..=10).contains(&digits.len())", IN),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
