#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.5: the protocol's server half (crates/protocol: jackson.rs, coerce.rs,
received.rs, server.rs, and the claim's writer added to wire.rs). See README.md.
"""
import sys

import _runner

S = "crates/protocol/src/"
J, C, R, V, W = S + "jackson.rs", S + "coerce.rs", S + "received.rs", S + "server.rs", S + "wire.rs"
T = ["-p", "vectispire-protocol", "--lib", "--test", "java_read_reference_set", "--test", "server_wire_reference_set"]
TM = ["-p", "vectispire-protocol", "--test", "memory"]

MUTANTS = [
    # ── the encoding, as ByteSourceJsonBootstrapper detects it ──
    ("no UTF-32 big-endian mark", J, "0x0000_FEFF => return Ok(Encoding::Utf32 { big_endian: true, skip: 4 }),", "", T),
    ("no UTF-16 mark", J, "0xFFFE => return Ok(Encoding::Utf16 { big_endian: false, skip: 2 }),", "", T),
    ("no UTF-8 mark", J, "_ if quad >> 8 == 0x00EF_BBBF => return Ok(Encoding::Utf8 { skip: 3 }),", "", T),
    ("UTF-8 mark kept", J, "return Ok(Encoding::Utf8 { skip: 3 })", "return Ok(Encoding::Utf8 { skip: 0 })", T),
    ("no UTF-32 without a mark", J, "if quad >> 8 == 0 {\n        Ok(Encoding::Utf32 { big_endian: true, skip: 0 })", "if false {\n        Ok(Encoding::Utf32 { big_endian: true, skip: 0 })", T),
    ("UTF-32 little-endian read big", J, "Ok(Encoding::Utf32 { big_endian: false, skip: 0 })", "Ok(Encoding::Utf32 { big_endian: true, skip: 0 })", T),
    ("no UTF-16 without a mark", J, "if first & 0xFF00 == 0 {", "if false {", T),
    ("UTF-16 little-endian without a mark read as UTF-8", J, "} else if first & 0x00FF == 0 {\n        Encoding::Utf16 { big_endian: false, skip: 0 }", "} else if false {\n        Encoding::Utf16 { big_endian: false, skip: 0 }", T),
    ("a stray high surrogate in UTF-16 keeps the next unit", J, "                Some(_) => {\n                    index = index.saturating_add(1);\n                    '\\u{FFFD}'", "                Some(_) => {\n                    '\\u{FFFD}'", T),
    ("UTF-32 past U+10FFFF accepted", J, "if code > 0x10_FFFF {", "if code > 0x7FFF_FFFF {", T),
    # ── the lexer: the first document, the limits ──
    ("trailing content read", J, "if self.mapper.trailing == Trailing::Refused {", "if true {", T),
    ("trailing content ignored by MVC", J, "if self.mapper.trailing == Trailing::Refused {", "if false {", T),
    ("an empty body accepted", J, 'return refused("No content to map due to end-of-input");', "return Ok(Cow::Borrowed(b\"null\"));", T),
    ("one level more", J, "if self.depth > self.mapper.depth {", "if self.depth > self.mapper.depth + 1 {", T),
    ("one level less", J, "if self.depth > self.mapper.depth {", "if self.depth >= self.mapper.depth {", T),
    ("Jackson 3 nests as deep as Jackson 2", J, "depth: 500, string: 100_000_000", "depth: 1_000, string: 100_000_000", T),
    ("strings one unit longer", J, "if !name && units > self.mapper.string {", "if !name && units > self.mapper.string + 1 {", T),
    ("names one unit longer", J, "if name && units > MAX_NAME_LENGTH {", "if name && units > MAX_NAME_LENGTH + 1 {", T),
    ("strings counted in bytes", J, 'units = units.saturating_add(count);', 'units = units.saturating_add(count + 1);', T),
    ("a decimal's exponent not counted", J, 'integer.saturating_add(fraction).saturating_add(exponent)', 'integer.saturating_add(fraction)', T),
    ("an integer one digit longer", J, "if length > MAX_NUMBER_LENGTH {", "if length > MAX_NUMBER_LENGTH + 1 {", T),
    ("leading zeros allowed", J, 'return refused("Invalid numeric value: Leading zeroes not allowed");', "", T),
    ("nullx is null", J, "if root && self.peek().is_some_and(", "if false && self.peek().is_some_and(", T),
    ("any escape accepted", J, "other => return refused(format!(\"Unrecognized character escape (code {other})\")),", "_ => None,", T),
    # ── surrogates, in values and in names ──
    ("a lone high escape left for serde", J, '                        clean = false;\n                    }\n                    break;', '                    }\n                    break;', T),
    ("a lone low escape left for serde", J, "                    if !high_escape {\n                        if name {\n                            return refused(\"Unexpected low surrogate in field name\");\n                        }\n                        clean = false;\n                    }", "                    if !high_escape {\n                        if name {\n                            return refused(\"Unexpected low surrogate in field name\");\n                        }\n                    }", T),
    ("a lone low escape in a name accepted", J, "                        if name {\n                            return refused(\"Unexpected low surrogate in field name\");\n                        }", "", T),
    ("two highs in a name accepted", J, "return refused(\"Broken surrogate pair in field name: expected low surrogate, got 0xD800\");", "clean = false;", T),
    ("a high then another escape in a name accepted", J, "return refused(\"Broken surrogate pair in field name: expected low surrogate\");", "clean = false;", T),
    ("a high then a raw character in a name accepted", J, '                            return refused(\n                                "Broken surrogate pair in field name: expected \'\\\\\' to start low surrogate",\n                            );', '                            clean = false;', T),
    ("the high escape forgotten", J, "                    high_escape = true;\n", "", T),
    ("a lone surrogate as U+FFFD", J, "for c in char::decode_utf16(units.iter().copied()).map(|unit| unit.unwrap_or('?')) {", "for c in char::decode_utf16(units.iter().copied()).map(|unit| unit.unwrap_or('\\u{FFFD}')) {", T),
    ("a rewritten quote unescaped", J, "            '\"' => out.extend_from_slice(b\"\\\\\\\"\"),\n", "", T),
    ("a rewritten control character raw", J, "            '\\u{0}'..='\\u{1F}' => out.extend_from_slice(format!(\"\\\\u{:04X}\", u32::from(c)).as_bytes()),\n", "", T),
    # ── Jackson's UTF-8 decoder ──
    ("five-byte leads accepted", J, "0xF0..=0xF7 => (3, u32::from(lead & 0x07)),", "0xF0..=0xFF => (3, u32::from(lead & 0x07)),", T),
    ("middle bytes unchecked", J, "if byte & 0xC0 != 0x80 {", "if false {", T),
    ("an encoded surrogate accepted", J, "if (0xD800..=0xDFFF).contains(&value) {", "if false {", T),
    ("an overlong two-byte form left for serde", J, "1 => (1, value >= 0x80),", "1 => (1, true),", T),
    ("an overlong three-byte form left for serde", J, "(1, value >= 0x800)", "(1, true)", T),
    ("past U+10FFFF left for serde", J, "_ => (2, (0x1_0000..=0x10_FFFF).contains(&value)),", "_ => (2, true),", T),
    ("the four-byte arithmetic standard", J, "let high = (0xD800 | (offset >> 10)) & 0xFFFF;", "let high = (0xD800 + (offset.max(0) >> 10)) & 0xFFFF;", T),
    # ── coercions ──
    ("a number's text normalised", C, "Shape::Number(token) => Ok(Some(token.to_owned())),", "Shape::Number(token) => Ok(Some(token.parse::<f64>().map(|n| n.to_string()).unwrap_or_default())),", T),
    ("a boolean is no text", C, "Shape::Bool(value) => Ok(Some(value.to_string())),\n        Shape::Number(token) => Ok(Some(token.to_owned())),", "Shape::Number(token) => Ok(Some(token.to_owned())),", T),
    ("a decimal int range unchecked", C, "if !(-2_147_483_648.0..=2_147_483_647.0).contains(&value) {", "if false {", T),
    ("a decimal int rounded", C, "Ok(Some(value.trunc() as i32))", "Ok(Some(value.round() as i32))", T),
    ("int text untrimmed", C, "            let trimmed = java::trim(&value);\n            if trimmed.is_empty() || trimmed == \"null\" {\n                return Ok(None);\n            }\n            java::read_int(trimmed)", "            let trimmed = value.as_ref();\n            if trimmed.is_empty() || trimmed == \"null\" {\n                return Ok(None);\n            }\n            java::read_int(trimmed)", T),
    ("the text null is an int", C, "            if trimmed.is_empty() || trimmed == \"null\" {\n                return Ok(None);\n            }\n            java::read_int(trimmed)", "            if trimmed.is_empty() {\n                return Ok(None);\n            }\n            java::read_int(trimmed)", T),
    ("ASCII digits only", C, '            java::read_int(trimmed).map(Some).map_err(|_| {', '            trimmed.parse::<i32>().map(Some).map_err(|_| {', T),
    ("a minus zero is true", C, "Ok(token.trim_start_matches('-').bytes().any(|b| b != b'0'))", "Ok(token != \"0\")", T),
    ("a decimal is a boolean", C, "Shape::Number(token) if is_integer(token) => Ok(token.trim_start_matches('-')", "Shape::Number(token) => Ok(token.trim_start_matches('-')", T),
    ("Title-case true refused", C, '"true" | "True" | "TRUE" => Ok(true),', '"true" | "TRUE" => Ok(true),', T),
    ("the text null refused as a boolean", C, '"false" | "False" | "FALSE" | "" | "null" => Ok(false),', '"false" | "False" | "FALSE" | "" => Ok(false),', T),
    ("boolean text untrimmed", C, "Shape::Text(value) => match java::trim(&value) {", "Shape::Text(value) => match value.as_ref() {", T),
    ("an enum index past the end", C, "usize::try_from(index).ok().filter(|&index| index < names.len()).map(Some).ok_or_else(|| unknown(token))", "usize::try_from(index).ok().map(Some).ok_or_else(|| unknown(token))", T),
    ("an enum name untrimmed", C, "            let trimmed = java::trim(&value);\n            if let Some(index) = names.iter().position(|name| *name == trimmed) {", "            let trimmed = value.as_ref();\n            if let Some(index) = names.iter().position(|name| *name == trimmed) {", T),
    ("an enum name in any case", C, "if let Some(index) = names.iter().position(|name| *name == trimmed) {", "if let Some(index) = names.iter().position(|name| name.eq_ignore_ascii_case(trimmed)) {", T),
    ("an enum index with a leading zero", C, "let leading_zero = trimmed.starts_with('0') && trimmed.len() > 1;", "let leading_zero = false;", T),
    ("no enum index as text", C, "            if digit_first\n", "            if false\n", T),
    ("a wire name in any case", C, "Shape::Text(value) => Ok(names.iter().position(|name| *name == value)),", "Shape::Text(value) => Ok(names.iter().position(|name| name.eq_ignore_ascii_case(&value))),", T),
    ("a wire name as an object", C, 'Shape::Object | Shape::Array => Err(Refused("Input mismatch reading Enum: expected a scalar".into())),', "Shape::Object | Shape::Array => Ok(None),", T),
    ("the first duplicate wins", C, "        if key == name {\n            found = Some(read(value)?);", "        if key == name && found.is_none() {\n            found = Some(read(value)?);", T),
    ("a long's decimal unchecked", C, "if !(i64::MIN as f64..=i64::MAX as f64).contains(&value) {", "if false {", T),
    ("a long's text untrimmed", C, "            let trimmed = java::trim(&value);\n            if trimmed.is_empty() || trimmed == \"null\" {\n                return Ok(None);\n            }\n            read_long(trimmed)", "            let trimmed = value.as_ref();\n            if trimmed.is_empty() || trimmed == \"null\" {\n                return Ok(None);\n            }\n            read_long(trimmed)", T),
    # ── durations ──
    ("a duration's blank is refused", C, "            if trimmed.is_empty() {\n                return Ok(None);\n            }\n            parse_duration(trimmed)", "            parse_duration(trimmed)", T),
    ("a duration's fraction rounded", C, "nanos = format!(\"{fraction:0<9}\").parse::<i128>().ok()?;", "nanos = format!(\"{fraction:0>9}\").parse::<i128>().ok()?;", T),
    ("a negative duration's fraction positive", C, "                    if number.starts_with('-') {\n                        nanos = nanos.wrapping_neg();\n                    }", '', T),
    ("ten fraction digits", C, "if fraction.len() > 9 {", "if fraction.len() > 10 {", T),
    ("a bare T accepted", C, "        if hours.is_none() && minutes.is_none() && seconds.is_none() {\n            return None;\n        }\n    }", "    }", T),
    ("a duration never negated", C, "if negate { duration.negated() } else { Some(duration) }", "Some(duration)", T),
    ("weeks of days", C, "checked_add(days.unwrap_or(0).checked_mul(86_400)?)?;", "checked_add(days.unwrap_or(0).checked_mul(604_800)?)?;", T),
    ("decimal seconds without wrap", C, "let signed = |magnitude: u64| if negative { magnitude.wrapping_neg() } else { magnitude };", "let signed = |magnitude: u64| if negative { magnitude.wrapping_neg() } else { magnitude.min(i64::MAX as u64) };", T),
    ("decimal nanos rounded up", C, "let nanos = signed(low_bits(9)).wrapping_sub(seconds.wrapping_mul(1_000_000_000));", "let nanos = signed(low_bits(9) + 1).wrapping_sub(seconds.wrapping_mul(1_000_000_000));", T),
    ("negative nanos not carried", C, "nanos: u32::try_from(nano_adjustment.rem_euclid(NANOS)).ok()?,", "nanos: u32::try_from((nano_adjustment % NANOS).abs()).ok()?,", T),
    # ── the result, step by step ──
    ("an SBOM null present", R, "            .filter(|raw| raw.get() != \"null\")\n", "", T),
    ("absent steps empty", R, "dependencies: coerce::last(&members, \"dependencies\", |raw| findings(raw, dependency))?.flatten(),", "dependencies: Some(coerce::last(&members, \"dependencies\", |raw| findings(raw, dependency))?.flatten().unwrap_or_default()),", T),
    ("API contracts flattened", R, "api_contracts: coerce::last(&members, \"apiContracts\", |raw| findings(raw, contract))?.flatten(),", "api_contracts: coerce::last(&members, \"apiContracts\", |raw| findings(raw, contract))?.flatten().filter(|list| !list.is_empty()),", T),
    ("a null finding dropped", R, "        .collect::<Result<Vec<_>, _>>()\n        .map(Some)\n}", "        .collect::<Result<Vec<_>, _>>()\n        .map(|items| Some(items.into_iter().filter(Option::is_some).collect()))\n}", T),
    ("null languages kept", R, "        if let Some(name) = coerce::text(element)? {\n            names.insert(name);\n        }", "        names.insert(coerce::text(element)?.unwrap_or_default());", T),
    ("no observation from a produced plugin", R, "            && !self.plugins.iter().any(|step| matches!(step, ReceivedStep::Produced { .. }))", "", T),
    ("observed nothing without SAST", R, "            && self.sast.is_none()\n            && !self.plugins", "            && !self.plugins", T),
    ("the method left as sent", R, "let method = text(&m, \"method\")?.map(|method| method.to_uppercase());", "let method = text(&m, \"method\")?;", T),
    ("a blank path kept", R, "        Some(path) if java::is_blank(&path) => \"/\".to_owned(),\n", "", T),
    ("a relative path kept", R, "        Some(path) => format!(\"/{path}\"),", "        Some(path) => path,", T),
    ("visibility absent left null-ish", R, ".unwrap_or(ApiVisibility::Unknown);", ".unwrap_or(ApiVisibility::Public);", T),
    ("declared paths null refused", R, "let Some(elements) = coerce::list(raw, \"java.util.ArrayList\")? else { return Ok(Vec::new()) };\n        elements.into_iter().map(coerce::text)", "let elements = coerce::list(raw, \"java.util.ArrayList\")?.ok_or_else(|| Refused(String::new()))?;\n        elements.into_iter().map(coerce::text)", T),
    ("the last state is the type", R, "let state = m.iter().find(|(key, _)| key == \"state\").map(|(_, value)| *value);", "let state = m.iter().rev().find(|(key, _)| key == \"state\").map(|(_, value)| *value);", T),
    ("no wrapper form", R, "            Shape::Array => wrapped(element)?,", "            Shape::Array => return Err(Refused(String::new())),", T),
    ("a wrapper without its value refused", R, "let Some(value) = elements.next() else { return Ok(None) };", "let Some(value) = elements.next() else { return Err(Refused(String::new())) };", T),
    ("a wrapper's third element read past", R, '    if elements.next().is_some() {\n        return Err(Refused(\n            "Unexpected token, expected END_ARRAY', '    if false {\n        return Err(Refused(\n            "Unexpected token, expected END_ARRAY', T),
    ("a null plugin step kept", R, "            Shape::Null => None,\n            Shape::Object => {", "            Shape::Null => Some(ReceivedStep::Absent { plugin_id: None, manifest_digest: None, reason: None }),\n            Shape::Object => {", T),
    ("produced without findings is empty", R, '                    ReceivedStep::Absent {\n                        plugin_id,\n                        manifest_digest,\n                        reason: Some(PRODUCED_WITHOUT_FINDINGS.to_owned()),\n                    }', '                    ReceivedStep::Produced { plugin_id, manifest_digest, tool_name: None, tool_version: None, findings: Vec::new(), signature }', T),
    ("languages in the order sent", R, "let indices: BTreeSet<usize> = indices.into_iter().collect();", "let indices: Vec<usize> = indices.into_iter().collect();", T),
    ("a language untrimmed", R, "let normalized = java::to_lower_root(java::trim(&name));", "let normalized = java::to_lower_root(&name);", T),
    ("a null language accepted", R, '    let name = coerce::text(raw)?\n        .ok_or_else(|| Refused("Cannot construct instance of PluginStep$NotApplicable: null language".into()))?;', '    let name = coerce::text(raw)?.unwrap_or_else(|| "java".into());', T),
    ("an unknown wire name refused", C, "Shape::Text(value) => Ok(names.iter().position(|name| *name == value)),", "Shape::Text(value) => names.iter().position(|name| *name == value).map(Some).ok_or_else(|| Refused(String::new())),", T),
    ("the root's null refused", R, "let Some(members) = coerce::root(text, \"ScanArtifacts\")? else { return Err(Unreadable::Null) };", "let Some(members) = coerce::root(text, \"ScanArtifacts\")? else { return Err(Unreadable::Refused(String::new())) };", T),
    ("a rewritten SBOM copied", R, "Ok(Received { sbom: sbom.map(|at| cut(document, at)).transpose()?.map(Cow::Owned), ..read })", "Ok(Received { sbom: sbom.map(|at| cut(document.clone(), at)).transpose()?.map(Cow::Owned), ..read })", TM),
    ("a borrowed SBOM copied", R, "            Cow::Borrowed(document) => read_document(document),", "            Cow::Borrowed(document) => read_document(document).map(Received::into_owned),", T),
    # ── the server's bodies ──
    ("control characters in lower case", V, 'CharEscape::AsciiControl(byte) => return write!(writer, "\\\\u{:04X}", byte),', 'CharEscape::AsciiControl(byte) => return write!(writer, "\\\\u{:04x}", byte),', T),
    ("milliseconds always", V, "        if nano.is_multiple_of(1_000_000) {", "        if true {", T),
    ("microseconds written as nanoseconds", V, "        } else if nano.is_multiple_of(1_000) {", "        } else if false {", T),
    ("a whole second with a fraction", V, "    if nano > 0 {", "    if nano >= 0 {", T),
    ("before the epoch read forwards", V, "let second_of_day = instant.epoch_second.rem_euclid(Instant::SECONDS_PER_DAY);", "let second_of_day = instant.epoch_second % Instant::SECONDS_PER_DAY;", T),
    ("the contract untrimmed", V, "announced.is_some_and(|announced| java::trim(announced) == contract::VERSION)", "announced.is_some_and(|announced| announced == contract::VERSION)", T),
    ("the contract trimmed as Rust trims", V, "announced.is_some_and(|announced| java::trim(announced) == contract::VERSION)", "announced.is_some_and(|announced| announced.trim() == contract::VERSION)", T),
    ("an empty contract named as sent", V, 'let announced = announced.filter(|announced| !announced.is_empty()).unwrap_or("unknown");', 'let announced = announced.unwrap_or("unknown");', T),
    ("a failure report's attempt 0 accepted", V, "let attempt = attempt.filter(|&attempt| attempt >= 1).ok_or_else(unreadable)?;", "let attempt = attempt.filter(|&attempt| attempt >= 0).ok_or_else(unreadable)?;", T),
    ("a failure kind in its case", V, 'Some(value) if java::to_lower_root(java::trim(value)) == "permanent" => FailureKind::Permanent,', 'Some(value) if value == "permanent" => FailureKind::Permanent,', T),
    ("the hello read by Jackson 2", V, "        let document = jackson::prepare(body, jackson::SPRING_MVC)?;\n        let text = std::str::from_utf8(&document).map_err(|error| Refused(error.to_string()))?;\n        let Some(m) = coerce::root(text, \"HelloRequest\")?", "        let document = jackson::prepare(body, jackson::CONTROL_PLANE)?;\n        let text = std::str::from_utf8(&document).map_err(|error| Refused(error.to_string()))?;\n        let Some(m) = coerce::root(text, \"HelloRequest\")?", T),
    ("the failure report read by Jackson 3", V, "let document = jackson::prepare(body, jackson::CONTROL_PLANE)?;", "let document = jackson::prepare(body, jackson::SPRING_MVC)?;", T),
    ("the generation as an int", V, 'generation: coerce::last(&m, "generation", coerce::boxed_long)?.flatten(),', 'generation: coerce::last(&m, "generation", coerce::boxed_int)?.flatten().map(i64::from),', T),
    ("a zero generation usable", V, "self.generation.is_some_and(|generation| generation > 0)", "self.generation.is_some_and(|generation| generation >= 0)", T),
    ("the not-pinned sentence", V, "No signing key is pinned for agent", "No signing key pinned for agent", T),
    ("the disabled status", V, 'refusal(401, format!("Agent \\"{agent}\\" is disabled."))', 'refusal(403, format!("Agent \\"{agent}\\" is disabled."))', T),
    ("the hello's id after its name", V, "    pub id: Option<Uuid>,\n    pub name: Option<String>,", "    pub name: Option<String>,\n    pub id: Option<Uuid>,", T),
    ("retryAt left out when absent", V, 'answer.serialize_field("retryAt", &self.retry_at.map(iso_instant))?;', 'if let Some(at) = self.retry_at { answer.serialize_field("retryAt", &iso_instant(at))?; }', T),
    # ── the claim's writer ──
    ("the sealed key left out", W, "fn sealed<S: Serializer>(value: &Option<Secret>, serializer: S) -> Result<S::Ok, S::Error> {\n    value.as_ref().map(Secret::expose).serialize(serializer)", "fn sealed<S: Serializer>(value: &Option<Secret>, serializer: S) -> Result<S::Ok, S::Error> {\n    value.as_ref().map(|_| \"\").serialize(serializer)", T),
    ("steps in another order", W, "pub enum Step {\n    Dependencies,\n    Secrets,", "pub enum Step {\n    Secrets,\n    Dependencies,", T),
    ("the claim written by serde's own escapes", V, "        write(self)\n    }\n}\n\n/// Whether the hello's contract number", "        serde_json::to_string(self)\n    }\n}\n\n/// Whether the hello's contract number", T),
]

# Equivalent, removed from the list with the reason:
# - "a stray high surrogate in UTF-16 at the end" (`None => '\u{FFFD}'` → anything): a high surrogate at the very
#   end of a body is inside or after the document; inside, the string never closes and the body is refused either
#   way; after it, Jackson never reads it.
# - the UTF-16 reversed mark (U+FFFE → U+FFFD): outside a string both are refused; inside, both are text that never
#   reaches a field the reference set reads back — and the case a Java body could pin is not one an agent writes.
# - "a huge exponent not zero" (`DecimalUtils`' `scale < -63` shortcut): such a number is a multiple of 10^64, so of
#   2^64, and the low 64 bits of its seconds and nanoseconds are zero without the shortcut too.
# - "the four-byte low unit wrong": a four-byte form's high unit is itself a low surrogate (DC00–DFBF, or FFC0 and up
#   for an overlong form), so its low unit never pairs with anything and is `?` whatever its value.
# - "a raw control character accepted" (the arm narrowed to NUL): a byte below 0x20 that leaves it falls to the
#   multi-byte arm, which refuses it as an invalid UTF-8 start byte — the body is refused either way, worded otherwise.
# - `Refused`'s messages: the routes do not echo them; only "refused or not" is pinned.


if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
