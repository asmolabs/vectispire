#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.4: the fingerprint and the target vocabulary in crates/domain (fingerprint, tool
keys, the clip, Java's string and number behaviours, the finding types and statuses, the dependency graph, the SBOM
and licence readings, retention) and the port of Spring's cron parser. See README.md.
"""
import sys

import _runner

S = "crates/domain/src/"
FP, TK, BT, JV, FT, ST, SS = S + "fingerprint.rs", S + "tool_keys.rs", S + "bounded_text.rs", S + "java.rs", S + "finding_type.rs", S + "scan_target.rs", S + "scan_status.rs"
DG, SB, RT, IN, CR = S + "dependency_graph.rs", S + "sbom.rs", S + "retention.rs", S + "instant.rs", S + "cron.rs"
T = ["-p", "vectispire-domain"]

MUTANTS = [
    # ── the fingerprint ──
    ("an empty purl is a purl", FP, "Some(purl) if !purl.is_empty() => Some(purl),", "Some(purl) => Some(purl),", T),
    ("the name wins over the purl", FP, "Some(purl) if !purl.is_empty() => Some(purl),", "Some(_) if false => None,", T),
    ("a bar separates the fields", FP, "hasher.update([0u8]);", "hasher.update([b'|']);", T),
    ("null is hashed as a word", FP, 'hasher.update(field.unwrap_or("").as_bytes());', 'hasher.update(field.unwrap_or("null").as_bytes());', T),
    ("upper-case hex", FP, '{byte:02x}', '{byte:02X}', T),
    ("any type is fingerprinted by tool", FP, "if !finding_type.tool_scoped() {", "if false {", T),
    ("an empty key is the only blank one", FP, "!crate::java::is_blank(key)", "!key.is_empty()", T),
    ("the tool key in the rule's place", FP, "identifier: rule_id,", "identifier: Some(tool_key),", T),
    # ── tool keys ──
    ("keys trimmed the Rust way", TK, 'crate::java::strip(value.unwrap_or(""))', 'value.unwrap_or("").trim()', T),
    ("tool names lowered the Unicode way", TK, "crate::java::to_lower_root(tool)", "tool.to_lowercase()", T),
    ("tool names keep their case", TK, "crate::java::to_lower_root(tool)", "tool.to_owned()", T),
    ("the tool is checked first", TK, 'let source = require(source_slug, "source")?;\n    let tool = require(tool_name, "tool name")?;',
     'let tool = require(tool_name, "tool name")?;\n    let source = require(source_slug, "source")?;', T),
    ("another plugin prefix", TK, 'pub const PLUGIN_PREFIX: &str = "plugin:";', 'pub const PLUGIN_PREFIX: &str = "plugin/";', T),
    # ── java ──
    ("U+001C-U+001F are not white space", JV, "'\\u{9}'..='\\u{d}' | '\\u{1c}'..='\\u{20}'", "'\\u{9}'..='\\u{d}' | '\\u{20}'", T),
    ("the figure space is white space", JV, "'\\u{2008}'..='\\u{200a}'\n", "'\\u{2007}'..='\\u{200a}'\n", T),
    ("trim is Unicode's", JV, "text.trim_matches(|c: char| c <= ' ')", "text.trim()", T),
    ("a lone surrogate is U+FFFD", JV, "unit.unwrap_or('?')", "unit.unwrap_or('\\u{fffd}')", T),
    ("eleven digits per run", JV, "filter(|&value| value < 10)", "filter(|&value| value <= 10)", T),
    ("fullwidth digits are not digits", JV, "0xABF0, 0xFF10,", "0xABF0, 0xFF11,", T),
    ("2147483648 is an int", JV, "let limit: i64 = if negative { 1 << 31 } else { (1 << 31) - 1 };", "let limit: i64 = 1 << 31;", T),
    ("a plus sign is refused", JV, "if first != '-' && first != '+' {", "if first != '-' {", T),
    ("a lone sign is a zero", JV, "        if chars.peek().is_none() {\n            return Err(NotAnInt::At(1));", "        if false {\n            return Err(NotAnInt::At(1));", T),
    ("a boolean's text is the default", JV, "Some(Value::Bool(flag)) => Some(flag.to_string()),", "Some(Value::Bool(_)) => default.map(str::to_owned),", T),
    ("a container's text is the default", JV, "Some(Value::Array(_) | Value::Object(_)) => Some(String::new()),", "Some(Value::Array(_) | Value::Object(_)) => default.map(str::to_owned),", T),
    ("final and medial sigma swapped", JV, "if sigma_is_final(&chars, index) { 'ς' } else { 'σ' }", "if sigma_is_final(&chars, index) { 'σ' } else { 'ς' }", T),
    ("the double quote breaks a word", JV, "'.' | '\\'' | '\"' => WordClass::MidBoth,", "'.' | '\\'' => WordClass::MidBoth,", T),
    ("a hyphen breaks a word", JV, "        '-'\n        | '_'\n", "        '_'\n", T),
    ("combining marks break a word", JV, "        '\\u{300}'..='\\u{36f}'\n        | '\\u{483}'", "        '\\u{483}'", T),
    ("a danda is a letter", JV, "'\\u{964}' | '\\u{965}' => WordClass::Danda,", "'\\u{964}' | '\\u{965}' => WordClass::Letter,", T),
    ("kana are letters", JV, "        | '\\u{3041}'..='\\u{30fe}'\n", "", T),
    ("no cased letter needed before", JV, "before.iter().any(|&c| is_cased(c)) && !after.iter()", "!after.iter()", T),
    ("title case is not cased", JV, "matches!(c, '\\u{1c5}' | '\\u{1c8}'", "matches!(c, '\\u{1c8}'", T),
    ("a word goes on after a danda", JV, "Some(WordClass::Letter) if !after_danda => WordClass::Letter,", "Some(WordClass::Letter) => WordClass::Letter,", T),
    ("mid marks join anything", JV, "Some(after) if joins && class_at(after) == Some(run) => cursor = after,", "Some(after) if class_at(after) == Some(run) => cursor = after,", T),
    # ── the vocabulary ──
    ("ai-review", FT, 'FindingType::AiReview => "ai_review",', 'FindingType::AiReview => "ai-review",', T),
    ("imports are not tool-scoped", FT, "matches!(self, FindingType::Plugin | FindingType::Imported)", "matches!(self, FindingType::Plugin)", T),
    ("quality gates on request", FT, "FindingType::Quality => GateParticipation::Never,", "FindingType::Quality => GateParticipation::OnRequest,", T),
    ("a type's wire name is trimmed", FT, "kind.wire_name() == value)", "kind.wire_name() == value.trim())", T),
    ("repository: prefix", ST, 'format!("repo:{id}")', 'format!("repository:{id}")', T),
    ("a status trimmed the Rust way", SS, "crate::java::trim(value?).to_lowercase()", "value?.trim().to_lowercase()", T),
    ("scanning is not in flight", SS, "matches!(self, ScanStatus::Pending | ScanStatus::Scanning)", "matches!(self, ScanStatus::Pending)", T),
    # ── the clip ──
    ("the clip stops one short", BT, "if end > max {", "if end >= max {", T),
    ("the clip counts characters", BT, "let end = units.saturating_add(c.len_utf16());", "let end = units.saturating_add(1);", T),
    ("too long in bytes", BT, "java::utf16_len(value) > max", "value.len() > max", T),
    # ── the dependency graph ──
    ("no edge is a graph", DG, "        if depended_upon.is_empty() {\n            return DependencyGraph::default();", "        if false {\n            return DependencyGraph::default();", T),
    ("an empty parent is an edge", DG, 'java::as_text(java::path(Some(relation), "parent"), None).filter(|p| !p.is_empty())', 'java::as_text(java::path(Some(relation), "parent"), None)', T),
    ("any relationship is an edge", DG, "== Some(DEPENDENCY_OF)", "!= None", T),
    ("the last duplicate wins", DG, "*graph.by_purl.entry(purl).or_insert(false) |= direct;", "graph.by_purl.insert(purl, direct);", T),
    ("an artifact without id is direct", DG, 'field("id", None).is_some_and(', 'field("id", None).is_none_or(', T),
    ("every purl counts as direct", DG, ".filter(|direct| **direct).count()", ".count()", T),
    ("the name alone matches", DG, "self.by_name_and_version.get(&key(name, version.unwrap_or(\"\")))", "self.by_name_and_version.iter().find(|(k, _)| k.starts_with(name)).map(|(_, v)| v)", T),
    # ── the SBOM ──
    ("fields untrimmed", SB, "Some(Value::String(value)) => Some(java::trim(value))", "Some(Value::String(value)) => Some(value.as_str())", T),
    ("plain licences trimmed", SB, "Value::String(license) => Some(license.clone()),", "Value::String(license) => Some(java::trim(license).to_owned()),", T),
    ("the expression before the value", SB, 'text(Some(entry), "value").or_else(|| text(Some(entry), "spdxExpression"))', 'text(Some(entry), "spdxExpression").or_else(|| text(Some(entry), "value"))', T),
    ("the distro keeps its case", SB, "Some(Distro { id: java::to_lower_root(&id), version, label })", "Some(Distro { id: id.clone(), version, label })", T),
    ("no label without a name", SB, "unwrap_or_else(|| id.clone());", "unwrap_or_default();", T),
    ("the blocklist keeps its case", SB, "java::trim(entry).to_uppercase()", "java::trim(entry).to_owned()", T),
    ("licences compared with their case", SB, "self.forbidden.contains(&license.to_uppercase())", "self.forbidden.contains(license.as_str())", T),
    # ── retention ──
    ("no age limit protects everything", RT, "cutoff.is_some_and(|cutoff| candidate.created_at > cutoff)", "cutoff.is_none_or(|cutoff| candidate.created_at > cutoff)", T),
    ("the cut-off itself is recent", RT, "candidate.created_at > cutoff", "candidate.created_at >= cutoff", T),
    ("both axes needed to enable", RT, "self.keep_per_target != UNLIMITED || !self.max_age.is_zero()", "self.keep_per_target != UNLIMITED && !self.max_age.is_zero()", T),
    ("a negative setting is kept", RT, "Ok(value) if value >= 0 => value,", "Ok(value) => value,", T),
    ("a setting is not trimmed", RT, "java::read_int(java::trim(raw))", "java::read_int(raw)", T),
    ("zero days purges evidence", RT, "if days <= 0 { None }", "if days < 0 { None }", T),
    ("a nanosecond borrow lost", IN, "None => (1, self.nano", "None => (0, self.nano", T),
    # ── cron: parsing ──
    ("a different weekly", CR, '("@weekly", "0 0 0 * * 0"),', '("@weekly", "0 0 0 * * 1"),', T),
    ("the Kelvin sign is not k", CR, "('\\u{212a}', 'k')", "('\\u{212a}', 'q')", T),
    ("macros compared in ASCII only", CR, "matches!((c, e), ('\\u{130}' | '\\u{131}', 'i')", "matches!((c, e), ('\\u{130}', 'i')", T),
    ("fields split on any white space", CR, ".split(' ').map(java::trim)", ".split_whitespace().map(java::trim)", T),
    ("tokens not trimmed", CR, ".split(' ').map(java::trim)", ".split(' ')", T),
    ("minutes refused before seconds", CR, "            let seconds = bits_field(seconds, Kind::Second)?;\n            let minutes = bits_field(minutes, Kind::Minute)?;",
     "            let minutes = bits_field(minutes, Kind::Minute)?;\n            let seconds = bits_field(seconds, Kind::Second)?;", T),
    ("names in lower case are not names", CR, "let mut value = value.to_uppercase();", "let mut value = value.to_owned();", T),
    ("0 stays 0 for Sunday", CR, "Field::Bits { kind, bits } if bits & 1 != 0 => Field::Bits { kind, bits: (bits | 1 << 7) & !1 },",
     "Field::Bits { kind, bits } if bits & 1 != 0 => Field::Bits { kind, bits },", T),
    ("? is not *", CR, 'bits_field(if value == "?" { "*" } else { value }, kind)', "bits_field(value, kind)", T),
    ("7 stays 7 as a minimum", CR, "if kind == Kind::DayOfWeek && min == 7 {", "if false {", T),
    ("a step without a range stops at its start", CR, "if !range_text.contains('-') {", "if false {", T),
    ("a zero step is a step", CR, "if delta <= 0 {", "if delta < 0 {", T),
    ("the step saturates", CR, "i = i.wrapping_add(delta);", "i = i.saturating_add(delta);", T),
    ("an empty range is a range", CR, "if min > max { Err(", "if min >= max { Err(", T),
    ("the field is not quoted", CR, "format!(\"{message} '{value}'\")", "message", T),
    ("0 is not a day", CR, "if (self == Kind::DayOfWeek && value == 0) || (min..=max).contains(&value) {", "if (min..=max).contains(&value) {", T),
    ("the day's range said plainly", CR, '"1 - 28/31".to_owned()', '"1 - 31".to_owned()', T),
    ("L-0 is an offset", CR, "if offset >= 0 {", "if offset > 0 {", T),
    ("LW is an offset", CR, 'let adjuster = if value == "LW" {', 'let adjuster = if false {', T),
    ("a Saturday moves forward", CR, "6 if day != 1 => temporal.plus_days(-1)?,", "6 if day != 1 => temporal.plus_days(1)?,", T),
    ("1W on a Saturday moves back", CR, "6 => temporal.plus_days(2)?,", "6 => temporal.plus_days(-1)?,", T),
    ("Monday the 3rd is not 1W", CR, "|| (weekday == 1 && day == 1 && current == 3)", "|| false", T),
    ("the last weekday overshoots", CR, "let difference = if difference > 0 { difference.checked_sub(7)? } else { difference };", "let difference = if difference > 0 { difference } else { difference };", T),
    ("one month to find the nth weekday", CR, "for _ in 0..12 {", "for _ in 0..1 {", T),
    ("a large ordinal does not wrap", CR, "ordinal.wrapping_sub(1).wrapping_mul(7)", "ordinal.saturating_sub(1).saturating_mul(7)", T),
    ("no rollback on the same day", CR, "if result.day == current.day { current } else { result.at_midnight() }", "result.at_midnight()", T),
    ("a Quartz result before the start stands", CR, "if result >= temporal {", "if true {", T),
    ("a rolled Quartz result keeps its time", CR, "Some(kind.reset(adjuster.adjust(rolled)?))", "adjuster.adjust(rolled)", T),
    ("a list takes its latest", CR, ".filter_map(|field| field.next_or_same(temporal)).min()", ".filter_map(|field| field.next_or_same(temporal)).max()", T),
    ("a missing day is reached directly", CR, "self.add_base(t, max.checked_sub(current)?.checked_add(1)?)", "self.with(t, max)", T),
    ("the month keeps its day on reset", CR, "Kind::Month => DateTime { day: 1, ..t.at_midnight() },", "Kind::Month => t.at_midnight(),", T),
    ("a weekday is set in place", CR, "Kind::DayOfWeek => t.plus_days(value.checked_sub(t.day_of_week())?),", "Kind::DayOfWeek => Some(t),", T),
    ("a month set keeps an impossible day", CR, "Some(DateTime { month, day: t.day.min(month_length(t.year, month)), ..t })", "Some(DateTime { month, ..t })", T),
    ("months added keep an impossible day", CR, "DateTime { year, month, day: self.day.min(month_length(year, month)), ..self }", "DateTime { year, month, ..self }", T),
    ("the epoch was a Friday", CR, "days.checked_add(3)", "days.checked_add(4)", T),
    ("ten attempts", CR, "const MAX_ATTEMPTS: u32 = 366;", "const MAX_ATTEMPTS: u32 = 10;", T),
    ("next is not strictly after", CR, ".plus_nanos(1)?;", ".plus_nanos(0)?;", T),
    ("the first round is the answer", CR, "            if result == temporal {\n                return result.to_instant();", "            if true {\n                return result.to_instant();", T),
    ("an empty expression is tokenised", CR, "        if expression.is_empty() {\n            return Err(InvalidCron(\"Expression must not be empty\"", "        if false {\n            return Err(InvalidCron(\"Expression must not be empty\"", T),
    ("characters after L read as a day", CR, "        if !value.ends_with('L') {", "        if false {", T),
    ("0 is not Sunday before L or #", CR, "let day = if day == 0 { 7 } else { day };", "let day = if day == 0 { 0 } else { day };", T),
    ("a zero ordinal is an ordinal", CR, "if ordinal <= 0 {", "if ordinal < 0 {", T),
    ("five fields with a wildcard second", CR, 'if fields.count() == 5 { format!("0 {trimmed}") }', 'if fields.count() == 5 { format!("* {trimmed}") }', T),
    ("blank the Rust way", CR, "match expression.filter(|e| !java::is_blank(e)) {", "match expression.filter(|e| !e.trim().is_empty()) {", T),
]

# Removed as indistinguishable from the original, each for its reason, not counted as killed:
# - "an array is a catalogue" (sbom::is_catalogue without `is_object()`): `java::path` already answers None for
#   anything but an object, so the check is Java's spelling and changes no answer.
# - "an unlimited window keeps nothing" (retention, without `keep_per_target != UNLIMITED`): UNLIMITED is 0 and
#   the rank is unsigned, so `rank < 0` is false either way — Java's guard reads the same.
# - "the search never gives up" (BitsCronField's own attempt limit): one field reaches a set bit within a year
#   of rolling (a month, a week, a day of a month), so its loop ends long before 366 rounds; the limit that
#   stops an impossible date is CronExpression's, whose mutant ("ten attempts") is killed.
# - "five fields counted on spaces only" (crontab::normalize splitting on ' ' instead of Java's \s): the counts
#   differ only when a tab or line break sits inside a token, and Spring then refuses that token whichever way
#   the fields were counted.



if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=300))
