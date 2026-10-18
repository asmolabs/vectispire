#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.11 (first part): the golden replay's comparison and normalisation in cp-contract
(`recorded`) — the oracle of the port. Every mutant below makes the comparison more lenient, or reads the recorder's
rules wider than they are; each must turn `tests/recorded.rs` (and the crate's unit tests) red. See README.md.
"""
import sys

import _runner

S = "crates/cp-contract/src/recorded/"
PH, RP, RW, DF = S + "placeholders.rs", S + "replay.rs", S + "rows.rs", S + "deferred.rs"

T = ["-p", "vectispire-cp-contract", "--test", "recorded", "--lib"]

MUTANTS = [
    # ── ordinals: one value per ordinal, one ordinal per value ──
    ("an ordinal rebound to another value", PH, "        if let Some(bound) = self.by_ordinal.get(&ordinal)\n            && bound != value\n", "        if let Some(bound) = self.by_ordinal.get(&ordinal)\n            && false && bound != value\n", T),
    ("a value taken by two ordinals", PH, "            && *other != ordinal\n", "            && false && *other != ordinal\n", T),
    ("ordinals not checked within one text", PH, "if *other_family == family && ((*other_n == n) != (*other_value == value)) {", "if false && *other_family == family && ((*other_n == n) != (*other_value == value)) {", T),
    ("a refused text binds half", PH, "            self.accept(found, text, &field, &mut proposed, &mut secrets, &mut owed)\n                .map_err(|why| format!(\"{actual:?} against {template:?}: {} {why}\", describe(found)))?;", "            if self.accept(found, text, &field, &mut proposed, &mut secrets, &mut owed).is_err() { continue; }", T),
    ("a UUID's case told apart", PH, "Placeholder::Uuid(n) => ordinal(Family::Uuid, *n, text.to_ascii_lowercase(), proposed),", "Placeholder::Uuid(n) => ordinal(Family::Uuid, *n, text.to_owned(), proposed),", T),
    ("long numbers not bound", PH, "Placeholder::Long(n) => ordinal(Family::Long, *n, text.to_owned(), proposed),", "Placeholder::Long(_) => Ok(()),", T),
    # ── identities ──
    ("an identity not pinned", PH, "            Placeholder::Id { table, rank: Some(rank) } => self.id_of(table, *rank)?.to_string(),\n            Placeholder::Secret(n)", "            Placeholder::Secret(n)", T),
    ("ranks counted from zero", PH, "self.starts.get(table)?.checked_add(rank)?.checked_sub(1)", "self.starts.get(table)?.checked_add(rank)", T),
    ("a prior id may be the test's", PH, "&& value < start {", "&& value <= start {", T),
    ("any number for an identity", PH, "            (Json::Str(template), Json::Num(text)) if integer_placeholder(template) => {", "            (Json::Str(_), Json::Num(_)) => {}\n            (Json::Str(template), Json::Num(text)) if integer_placeholder(template) => {", T),
    ("any placeholder may be a number", PH, "        [Segment::Placeholder(Placeholder::Id { .. } | Placeholder::Long(_) | Placeholder::ClockStep)]", "        [Segment::Placeholder(_)]", T),
    # ── secrets ──
    ("a secret's hash unchecked", PH, "            Placeholder::SecretHash(n) => self.minting.sha256_hex(self.bound(Family::Secret, *n)?),\n            _ => return None,", "            _ => return None,", T),
    ("an owed hash never checked", PH, "                    if !hash.eq_ignore_ascii_case(&wanted) {", "                    if false && !hash.eq_ignore_ascii_case(&wanted) {", T),
    ("an owed prefix never checked", PH, "                    if !value.starts_with(prefix.as_str()) {", "                    if false && !value.starts_with(prefix.as_str()) {", T),
    ("a secret already another's", PH, "                if let Some(other) = secrets_bound.and_then(|known| known.by_value.get(text)) {", "                if let Some(other) = secrets_bound.and_then(|known| known.by_value.get(text)).filter(|_| false) {", T),
    ("a bound secret not pinned", PH, "            Placeholder::Secret(n) => self.bound(Family::Secret, *n)?.to_owned(),\n", "", T),
    ("a key's prefix not pinned", PH, "            Placeholder::SecretPrefix(n) => self.bound(Family::Secret, *n)?.chars().take(12).collect(),\n", "", T),
    ("an API key minted as a token", PH, "            Some(SecretKind::ApiKey) => self.minting.api_key(),", "            Some(SecretKind::ApiKey) => self.minting.session_token(),", T),
    ("a prefix not a sign of an API key", PH, "                    kinds.insert(n, SecretKind::ApiKey);", "                    kinds.insert(n, SecretKind::Token);", T),
    # ── password hashes ──
    ("a secret's hash unverified", PH, "                Some(_) => Err(format!(\"does not hold secret {n}\")),", "                Some(_) => Ok(()),", T),
    ("an owed password never checked", PH, "                    if !self.verifies(value, &hash) {", "                    if false && !self.verifies(value, &hash) {", T),
    ("any text a password hash", PH, r'''Placeholder::PasswordHash(_) => r#"\$argon2(?:id|i|d)\$[^\s"]+|\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}"#,''', r'''Placeholder::PasswordHash(_) => r"[^\x00]*",''', T),
    # ── shapes and the window ──
    ("anything sealed", PH, 'Placeholder::Sealed => r"v2:[A-Za-z0-9+/_-]+=*",', 'Placeholder::Sealed => r".+",', T),
    ("a digest of any length", PH, 'Placeholder::Digest(_) => r"[0-9a-fA-F]{64}",', 'Placeholder::Digest(_) => r"[0-9a-fA-F]{32,128}",', T),
    ("a hash field's rule everywhere", PH, "shape(found, sole && field.contains(\"hash\")).to_owned()", "shape(found, true).to_owned()", T),
    ("a long number of any length", PH, 'Placeholder::Long(_) => r"[0-9]{12,19}",', 'Placeholder::Long(_) => r"[0-9]+",', T),
    ("an instant without its zone", PH, '(?::[0-9]{2}(?:[.,][0-9]{1,9})?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})"', '(?::[0-9]{2}(?:[.,][0-9]{1,9})?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?"', T),
    ("a datetime may be a date", PH, 'Placeholder::DateTime => r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:[.,][0-9]{1,9})?)?",', 'Placeholder::DateTime => r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:[.,][0-9]{1,9})?)?)?",', T),
    ("the window's end later", PH, "match (shift_years(today, -3), shift_years(today, 11)) {", "match (shift_years(today, -3), shift_years(today, 12)) {", T),
    ("the window's start earlier", PH, "match (shift_years(today, -3), shift_years(today, 11)) {", "match (shift_years(today, -4), shift_years(today, 11)) {", T),
    ("day 32", PH, "    if !(1..=31).contains(&day) {", "    if !(1..=32).contains(&day) {", T),
    ("a day not clamped to its month", PH, "    let Ok(date) = Date::from_calendar_date(year, month, day.min(month.length(year))) else {", "    let Ok(date) = Date::from_calendar_date(year, month, day) else {", T),
    ("a text without placeholders compared loosely", PH, "            return if template == actual { Ok(()) } else { Err(format!(\"{actual:?}, recorded {template:?}\")) };", "            return if template.eq_ignore_ascii_case(actual) { Ok(()) } else { Err(format!(\"{actual:?}, recorded {template:?}\")) };", T),
    ("the template not anchored", PH, "        let mut expression = String::from(\"^(?:\");", "        let mut expression = String::from(\"(?:\");", T),
    # ── documents ──
    ("an extra member allowed", PH, "                    if !left.iter().any(|(other, _)| other == name) {\n                        out.push(format!(\"{pointer}/{name}: {}, not recorded\", value.to_text()));", "                    if false && !left.iter().any(|(other, _)| other == name) {\n                        out.push(format!(\"{pointer}/{name}: {}, not recorded\", value.to_text()));", T),
    ("a missing member allowed", PH, "                        None => out.push(format!(\"{child}: absent, recorded {}\", value.to_text())),", "                        None => {}", T),
    ("arrays of another length", PH, "                if left.len() != right.len() {\n                    out.push(format!(\"{at}: {} elements, recorded {}\", right.len(), left.len()));\n                    return;\n                }\n", "", T),
    ("an answer's numbers by value", PH, "                    NumberText::Exact => left == right,", "                    NumberText::Exact => same_number(left, right),", T),
    ("a row's numbers by their sign", PH, "        if body == \"0\" { body } else { format!(\"{sign}{body}\") }", "        body", T),
    ("two booleans alike", PH, "            (Json::Bool(left), Json::Bool(right)) if left == right => {}", "            (Json::Bool(_), Json::Bool(_)) => {}", T),
    ("null for anything", PH, "            (Json::Null, Json::Null) => {}", "            (Json::Null, _) | (_, Json::Null) => {}", T),
    # ── headers ──
    ("a header of another count", RP, "        if wanted.len() != got.len() {\n            out.push(format!(\"header {name}: {got:?}, recorded {wanted:?}\"));\n            continue;\n        }\n", "", T),
    ("a header's value unchecked", RP, "            if let Err(why) = bindings.match_text(template, value, name) {\n                out.push(format!(\"header {name}: {why}\"));\n            }", "            let _ = (template, value);", T),
    ("an extra header allowed", RP, "        if !names.contains(&lower) && !TRANSPORT_HEADERS.contains(&lower.as_str()) {", "        if false && !names.contains(&lower) && !TRANSPORT_HEADERS.contains(&lower.as_str()) {", T),
    # ── rows ──
    ("rows of another count", RP, "            if wanted.len() != got.len() {\n                out.push(format!(\n                    \"{at}: {} row(s), recorded {} — made {}, recorded {}\",", "            if false && wanted.len() != got.len() {\n                out.push(format!(\n                    \"{at}: {} row(s), recorded {} — made {}, recorded {}\",", T),
    ("one made row for two recorded", RP, "                        if let Some(slot) = used.get_mut(candidate) {\n                            *slot = true;\n                        }\n", "", T),
    ("an unmatched row allowed", RP, "                if !matched {\n                    out.push(format!(", "                if false && !matched {\n                    out.push(format!(", T),
    ("an unrecorded table allowed", RP, "        if !recorded_tables.iter().any(|(other, _)| other == name) {", "        if false && !recorded_tables.iter().any(|(other, _)| other == name) {", T),
    ("a recorded table never compared", RP, "        let theirs = actual_tables.iter().find(|(other, _)| other == name).map(|(_, changes)| changes);\n        for kind in [\"inserted\", \"updated\", \"deleted\"] {", "        let theirs = actual_tables.iter().find(|(other, _)| other == name).map(|(_, changes)| changes);\n        for kind in [\"inserted\"] {", T),
    ("an instant moved is a change", PH, "    if from == to {\n        return true;\n    }\n    collapse(today, column, from) == collapse(today, column, to)", "    from == to", T),
    ("any two values alike", PH, "    if from == to {\n        return true;\n    }\n    collapse(today, column, from) == collapse(today, column, to)", "    let _ = (today, column, from, to);\n    true", T),
    ("a sealed value not collapsed", PH, '    let sealed = SEALED.replace_all(text, "«sealed»");', "    let sealed = std::borrow::Cow::Borrowed(text);", T),
    ("a date outside the window collapsed", PH, "            if !in_range {\n                whole.to_owned()\n            } else if", "            if false {\n                whole.to_owned()\n            } else if", T),
    ("a clock step not collapsed", PH, '    if column == "totp_last_step" || column == "totplaststep" {', '    if column == "never" {', T),
    ("the seconds printed when zero", RW, '    if seconds == "00" && grouped.is_empty() {', "    if false {", T),
    # ── the list ──
    ("a served recording that differs passes", DF, "                    Some(other) if !golden_line && route_line.is_none() => {", "                    Some(other) if false && !golden_line && route_line.is_none() => {", T),
    ("a listed recording that is green passes", DF, "                    Some(Outcome::Green) if golden_line => problems.push(format!(", "                    Some(Outcome::Green) if false && golden_line => problems.push(format!(", T),
    ("a route not served and not listed passes", DF, "                    if route_line.is_none() && !golden_line {", "                    if false && route_line.is_none() && !golden_line {", T),
    ("an unknown path not listed passes", DF, "                } else if !golden_line {\n                    problems.push(format!(\n                        \"{}: {} {} reaches no operation", "                } else if false && !golden_line {\n                    problems.push(format!(\n                        \"{}: {} {} reaches no operation", T),
    ("a stale route line kept", DF, "            None => problems.push(format!(\"route {} {} ({reason}): no recording needs this line\", route.0, route.1)),", "            None => {}", T),
    ("a stale golden line kept", DF, "        if !used_goldens.contains(name.as_str()) {", "        if false && !used_goldens.contains(name.as_str()) {", T),
    ("a stale outside line kept", DF, "        if !used_outside.contains(key) {", "        if false && !used_outside.contains(key) {", T),
    ("the list above its ceiling", DF, "        Ok(ceiling) if deferred.len() > ceiling => problems.push(format!(", "        Ok(ceiling) if false && deferred.len() > ceiling => problems.push(format!(", T),
    ("the ceiling never lowered", DF, "        Ok(ceiling) if deferred.len() < ceiling => problems.push(format!(", "        Ok(ceiling) if false && deferred.len() < ceiling => problems.push(format!(", T),
    ("a line listed twice", DF, "            if repeated {", "            if false && repeated {", T),
    ("a digest's case told apart", PH, "ordinal(Family::Digest, *n, text.to_ascii_lowercase(), proposed)", "ordinal(Family::Digest, *n, text.to_owned(), proposed)", T),
    ("the fixture's hash unverified", PH, 'Err("does not hold the fixture\'s passphrase".to_owned())', "Ok(())", T),
    ("an unknown hash may be the fixture's", PH, 'Err("holds the fixture\'s passphrase".to_owned())', "Ok(())", T),
    ("dates outside the window", PH, "if in_window(self.today, year, month, day) {", "if true || in_window(self.today, year, month, day) {", T),
    ("HTTP dates outside the window", PH, "if in_window(self.today, year, 1, 1) {", "if true || in_window(self.today, year, 1, 1) {", T),
    ("a one-time code anywhere", PH, "if ONE_TIME_CODE_FIELDS.contains(&field) {", "if true {", T),
    ("a row's fraction ignored", PH, "let fraction = fraction.trim_end_matches('0');", 'let fraction = "";', T),
    ("a recording the replay skipped passes", DF, 'problems.push(format!("{}: of a served route, and the replay did not run it", recording.name))', "()", T),
    ("a green route line kept", DF, "Some((total, green)) if outcomes.is_some() && total == green => problems", "Some((total, green)) if false && outcomes.is_some() && total == green => problems", T),
]

# Equivalent or out of reach, not in the list:
# - a table keyed by its identity compared as a set rather than in order: both lists are in id order and every row's
#   id is pinned by its rank, so a recorded row can match one made row only, the one at its own place — the set match
#   finds the same pairs. Kept ordered for the messages, which point at the row by its place.
# - an empty reason in deferred.txt: the line is trimmed before it is split on ` | `, so a reason of white space alone
#   leaves nothing to split and is refused as "no reason"; the separate check was removed as dead.
# - the `(?i:…)` around a pinned secret hash: `Minting::sha256_hex` writes lower case on both sides, so no answer can
#   tell the two apart.


if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
