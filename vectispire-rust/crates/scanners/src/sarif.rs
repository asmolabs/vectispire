//! A SARIF 2.1.0 log, read with the guards every document from outside this process gets — `SarifReport`,
//! `SarifPaths` and `SarifFinding`.
//!
//! **A plugin's report is written by code somebody else wrote**, after reading a repository somebody else wrote.
//! So: a size ceiling checked before a byte is parsed; no expansion (nesting capped at 64, a string at a million
//! characters, a number at a hundred digits, twenty runs, a hundred thousand results, a key given twice refused);
//! no link (external property files, a location outside the analysed tree). **Absent is not empty, here too**: a
//! run with no `results` did not compute any, an empty array found nothing (decision 0007).
//!
//! **A data contract**: the rule id and the normalised path enter the fingerprint of every plugin issue. Every rule
//! here is held to `reference/plugins/sarif/` — the Java reader's answers. Where Jackson refuses the JSON itself,
//! its own words follow "not readable JSON:" and are not reproduced; the refusal is.

use crate::jackson;
use crate::output::{children, index, path};
use serde::Serialize;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fmt;
use vectispire_domain::Severity;
use vectispire_domain::java;

const MAX_DEPTH: usize = 64;
const MAX_STRING: usize = 1_000_000;
/// Jackson's default for a property name (`StreamReadConstraints.DEFAULT_MAX_NAME_LEN`).
const MAX_NAME: usize = 50_000;
const MAX_NUMBER: usize = 100;
const MAX_RUNS: usize = 20;
const MAX_RESULTS: usize = 100_000;
const MAX_RULE_ID: usize = 1_000;
/// `SarifReport.MAX_TOOL_NAME`.
pub const MAX_TOOL_NAME: usize = 100;

/// Why a document was refused — `InvalidSarifException`, its message meant for the producer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidSarif(pub String);

/// The prefix of a refusal whose detail is the JSON parser's own.
pub const NOT_READABLE_JSON: &str = "The SARIF document is not readable JSON: ";

fn invalid(message: impl Into<String>) -> InvalidSarif {
    InvalidSarif(message.into())
}

/// One result, reduced to what Vectispire keeps — `SarifFinding`, in its wire form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifFinding {
    /// Fingerprint material, whole.
    pub rule_id: String,
    pub severity: Severity,
    /// Relative to the analysed tree, normalised — fingerprint material; `None` for a result naming no file.
    pub file: Option<String>,
    pub line: Option<i32>,
    pub message: Option<String>,
}

/// One run — `SarifReport.Run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub tool_name: String,
    pub tool_version: Option<String>,
    /// False when an invocation says `executionSuccessful: false`.
    pub successful: bool,
    /// `None` when the run carries no `results`: it did not compute any.
    pub results: Option<Vec<SarifFinding>>,
}

/// `SarifReport.read`.
///
/// `absolute_roots`: the absolute directories standing for the analysed tree — `/repo/source` for a plugin.
pub fn read(document: &[u8], max_bytes: u64, absolute_roots: &[&str]) -> Result<Vec<Run>, InvalidSarif> {
    if document.is_empty() {
        return Err(invalid("The SARIF document is empty."));
    }
    if u64::try_from(document.len()).map_or(true, |length| length > max_bytes) {
        return Err(invalid(format!("The SARIF document is larger than the {max_bytes} bytes accepted.")));
    }
    let root = parse(document)?;
    let Some(Value::Object(root)) = root else {
        return Err(invalid("A SARIF document is a JSON object."));
    };
    let version = root.get("version");
    if jackson_text(version).as_deref() != Some("2.1.0") {
        return Err(invalid(format!(
            "Only SARIF 2.1.0 is read; this document says version \"{}\".",
            jackson::as_text(version, "")
        )));
    }
    if present(root.get("inlineExternalProperties")) {
        return Err(invalid("The SARIF document refers to external properties; they are not followed."));
    }
    let Some(Value::Array(runs)) = root.get("runs") else {
        return Err(invalid("A SARIF document carries a \"runs\" array."));
    };
    if runs.len() > MAX_RUNS {
        return Err(invalid(format!("The SARIF document carries more than {MAX_RUNS} runs.")));
    }
    let mut budget = MAX_RESULTS;
    runs.iter().map(|each| run(each, absolute_roots, &mut budget)).collect()
}

/// `asText(null)`: a scalar's text, `None` for null or absent.
fn jackson_text(node: Option<&Value>) -> Option<String> {
    match node {
        None | Some(Value::Null) => None,
        other => Some(jackson::as_text(other, "")),
    }
}

/// `present`: there, not null, and not an empty object or array.
fn present(node: Option<&Value>) -> bool {
    match node {
        None | Some(Value::Null) => false,
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(members)) => !members.is_empty(),
        Some(_) => true,
    }
}

fn has_control(value: &str) -> bool {
    value.chars().any(java::is_iso_control)
}

/// `text(node, field)`: a textual member, stripped, `None` when absent, not text, or blank.
fn text(node: Option<&Value>, field: &str) -> Option<String> {
    match path(node, field) {
        Some(Value::String(value)) => Some(java::strip(value)).filter(|value| !value.is_empty()).map(str::to_owned),
        _ => None,
    }
}

fn run(run: &Value, roots: &[&str], budget: &mut usize) -> Result<Run, InvalidSarif> {
    if !run.is_object() {
        return Err(invalid("A SARIF run is a JSON object."));
    }
    let run = Some(run);
    if present(path(run, "externalPropertyFileReferences")) {
        return Err(invalid("A SARIF run refers to external property files; they are not followed."));
    }
    let driver = path(path(run, "tool"), "driver");
    let tool_name = match path(driver, "name") {
        Some(Value::String(name)) => java::strip(name).to_owned(),
        _ => String::new(),
    };
    if tool_name.is_empty() {
        return Err(invalid("A SARIF run names no tool (tool.driver.name)."));
    }
    if java::utf16_len(&tool_name) > MAX_TOOL_NAME || has_control(&tool_name) {
        return Err(invalid(format!(
            "The tool name of a SARIF run is longer than {MAX_TOOL_NAME} characters or carries a control character."
        )));
    }
    let tool_version = text(driver, "semanticVersion").or_else(|| text(driver, "version"));
    let successful = !children(path(run, "invocations"))
        .into_iter()
        .any(|invocation| matches!(path(Some(invocation), "executionSuccessful"), Some(Value::Bool(false))));

    let results = match path(run, "results") {
        None | Some(Value::Null) => return Ok(Run { tool_name, tool_version, successful, results: None }),
        Some(Value::Array(results)) => results,
        Some(_) => return Err(invalid("The \"results\" of a SARIF run are an array.")),
    };
    *budget = budget
        .checked_sub(results.len())
        .ok_or_else(|| invalid(format!("The SARIF document carries more than {MAX_RESULTS} results.")))?;

    let rules = Rules::of(path(driver, "rules"));
    let mut findings = Vec::with_capacity(results.len());
    for (position, result) in results.iter().enumerate() {
        if let Some(found) = finding(result, &rules, roots, position)? {
            findings.push(found);
        }
    }
    Ok(Run { tool_name, tool_version, successful, results: Some(findings) })
}

/// A result as a finding, or `None` for one SARIF itself says is not a finding.
fn finding(result: &Value, rules: &Rules<'_>, roots: &[&str], position: usize) -> Result<Option<SarifFinding>, InvalidSarif> {
    if !result.is_object() {
        return Err(invalid(format!("Result {position} is not a JSON object.")));
    }
    let result = Some(result);
    // `pass` and `notApplicable` are the tool saying there is nothing here.
    let kind = jackson::as_text(path(result, "kind"), "fail");
    if kind == "pass" || kind == "notApplicable" {
        return Ok(None);
    }
    // A suppression the producer accepted — the default status — is a decision already taken where the report was
    // made; importing it as open would undo it here, with nobody's name on it.
    let accepted = children(path(result, "suppressions"))
        .into_iter()
        .any(|suppression| jackson::as_text(path(Some(suppression), "status"), "accepted") == "accepted");
    if accepted {
        return Ok(None);
    }

    let rule = rules.rule_of(result);
    let rule_id = text(result, "ruleId")
        .or_else(|| text(path(result, "rule"), "id"))
        .or_else(|| text(rule, "id"))
        .ok_or_else(|| {
            invalid(format!(
                "Result {position} names no rule: without one it has no identity across runs, and every run would \
                 open it again."
            ))
        })?;
    if java::utf16_len(&rule_id) > MAX_RULE_ID || has_control(&rule_id) {
        return Err(invalid(format!(
            "Result {position} has a rule identifier longer than {MAX_RULE_ID} characters or carrying a control \
             character."
        )));
    }

    let location = path(index(path(result, "locations"), 0), "physicalLocation");
    let uri = jackson_text(path(path(location, "artifactLocation"), "uri"));
    let file = normalize(uri.as_deref(), roots)?;
    let line = start_line(path(path(location, "region"), "startLine"));
    let message = text(path(result, "message"), "text")
        .or_else(|| text(path(rule, "shortDescription"), "text"))
        .or_else(|| text(path(rule, "fullDescription"), "text"));

    Ok(Some(SarifFinding { rule_id, severity: severity(result, rule), file, line, message }))
}

/// `canConvertToInt() && asInt() > 0`: an integral number within `int`, or a floating one within its range
/// (truncated); text and every other node is no line.
fn start_line(node: Option<&Value>) -> Option<i32> {
    let Some(Value::Number(number)) = node else { return None };
    let line = if let Some(integer) = number.as_i64() {
        i32::try_from(integer).ok()?
    } else if number.is_u64() {
        return None;
    } else {
        let float = number.as_f64()?;
        if !(f64::from(i32::MIN)..=f64::from(i32::MAX)).contains(&float) {
            return None;
        }
        jackson::as_int(node, 0)
    };
    (line > 0).then_some(line)
}

/// `SarifReport.severity`: `security-severity` first (the CVSS-scale score in a result's or a rule's
/// properties), then the SARIF level of the result, then of the rule's default configuration, `warning` by default.
fn severity(result: Option<&Value>, rule: Option<&Value>) -> Severity {
    let score = score(path(path(result, "properties"), "security-severity"))
        .or_else(|| score(path(path(rule, "properties"), "security-severity")));
    if let Some(value) = score {
        return if value >= 9.0 {
            Severity::Critical
        } else if value >= 7.0 {
            Severity::High
        } else if value >= 4.0 {
            Severity::Medium
        } else {
            Severity::Low
        };
    }
    let level = text(result, "level")
        .or_else(|| text(path(rule, "defaultConfiguration"), "level"))
        .unwrap_or_else(|| "warning".to_owned());
    match java::to_lower_root(&level).as_str() {
        "error" => Severity::High,
        "note" | "none" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn score(node: Option<&Value>) -> Option<f64> {
    let parsed = match node {
        Some(Value::Number(number)) => number.as_f64()?,
        Some(Value::String(text)) => java::parse_double(java::strip(text))?,
        _ => return None,
    };
    (parsed.is_finite() && (0.0..=10.0).contains(&parsed)).then_some(parsed)
}

/// The driver's rules, by index and by identifier (the first one of an identifier wins).
struct Rules<'a> {
    by_index: Vec<&'a Value>,
    by_id: HashMap<String, &'a Value>,
}

impl<'a> Rules<'a> {
    fn of(rules: Option<&'a Value>) -> Rules<'a> {
        let by_index = children(rules);
        let mut by_id = HashMap::new();
        for rule in &by_index {
            if let Some(id) = text(Some(rule), "id") {
                by_id.entry(id).or_insert(*rule);
            }
        }
        Rules { by_index, by_id }
    }

    fn rule_of(&self, result: Option<&Value>) -> Option<&'a Value> {
        let index = match path(result, "ruleIndex") {
            Some(value) if is_int(value) => Some(value),
            _ => path(path(result, "rule"), "index"),
        };
        if let Some(found) = index
            .filter(|value| is_int(value))
            .and_then(Value::as_i64)
            .and_then(|at| usize::try_from(at).ok())
            .and_then(|at| self.by_index.get(at))
        {
            return Some(*found);
        }
        text(result, "ruleId").and_then(|id| self.by_id.get(&id).copied())
    }
}

/// `isInt()`: an integral number Jackson keeps as an `int`.
fn is_int(value: &Value) -> bool {
    value.as_i64().is_some_and(|integer| i32::try_from(integer).is_ok())
}

// -------------------------------------------------------------------------------------------------------------
// The JSON itself, read under Jackson's constraints.

/// The first JSON value of the document, `None` when it holds none; refused as Jackson refuses it, and refused
/// when anything but white space follows.
fn parse(document: &[u8]) -> Result<Option<Value>, InvalidSarif> {
    // Jackson's byte bootstrapper skips a UTF-8 byte-order mark.
    let document = document.strip_prefix(b"\xef\xbb\xbf").unwrap_or(document);
    refuse_long_numbers(document)?;
    let mut values = serde_json::Deserializer::from_slice(document).into_iter::<serde::de::IgnoredAny>();
    let end = match values.next() {
        None => return Ok(None),
        Some(Err(error)) => return Err(unreadable(&error.to_string())),
        Some(Ok(_)) => values.byte_offset(),
    };
    let (first, rest) = document.split_at_checked(end).ok_or_else(|| unreadable("truncated"))?;
    let mut deserializer = serde_json::Deserializer::from_slice(first);
    let value = Limited { depth: 0 }.deserialize(&mut deserializer).map_err(|error| unreadable(&error.to_string()))?;
    match next_token(rest) {
        Next::End => Ok(Some(value)),
        Next::Token => Err(invalid("The SARIF document carries content after its end.")),
        Next::Unreadable => Err(unreadable("unexpected content after the document")),
    }
}

fn unreadable(detail: &str) -> InvalidSarif {
    let line = detail.lines().next().unwrap_or("no detail");
    invalid(format!("{NOT_READABLE_JSON}{line}"))
}

enum Next {
    End,
    Token,
    Unreadable,
}

fn is_json_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// What Jackson's `nextToken` makes of what follows the first value: nothing, another token (which it reads lazily
/// — an object, an array, a string are not read past their first character), or a malformed one.
fn next_token(rest: &[u8]) -> Next {
    let start = rest.iter().position(|byte| !is_json_space(*byte));
    let Some(token) = start.and_then(|start| rest.get(start..)) else { return Next::End };
    match token.first() {
        Some(b'{' | b'[' | b'"') => Next::Token,
        Some(b'-' | b'0'..=b'9') => {
            let length = token.iter().position(|byte| !matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'));
            let (number, after) = token.split_at(length.unwrap_or(token.len()));
            let well_formed = serde_json::from_slice::<serde::de::IgnoredAny>(number).is_ok();
            // A root-level value is followed by white space or nothing.
            if well_formed && after.first().is_none_or(|byte| is_json_space(*byte)) { Next::Token } else { Next::Unreadable }
        }
        _ => {
            for literal in [&b"true"[..], b"false", b"null"] {
                if let Some(after) = token.strip_prefix(literal) {
                    let identifier = after.first().is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'));
                    return if identifier { Next::Unreadable } else { Next::Token };
                }
            }
            Next::Unreadable
        }
    }
}

/// Jackson's constraints that must hold before `serde_json` reads a byte: **nesting past 64**, and a number token of
/// more than a hundred digits. The workspace builds `serde_json` with `unbounded_depth` (Jackson reads deeper than
/// its default 128), so nothing else stops a document of a million `[` from recursing until the stack is gone.
/// Scanned up to the end of the first value, which is what Jackson reads under its constraints.
fn refuse_long_numbers(document: &[u8]) -> Result<(), InvalidSarif> {
    let mut in_string = false;
    let mut escaped = false;
    let mut digits = 0usize;
    let mut depth = 0usize;
    for byte in document {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        if byte.is_ascii_digit() {
            digits = digits.saturating_add(1);
            if digits > MAX_NUMBER {
                return Err(unreadable("Number value length exceeds the maximum allowed"));
            }
            continue;
        }
        if matches!(byte, b'.' | b'e' | b'E' | b'+' | b'-') {
            continue;
        }
        digits = 0;
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth = depth.saturating_add(1);
                if depth > MAX_DEPTH {
                    return Err(unreadable("Document nesting depth exceeds the maximum allowed"));
                }
            }
            b']' | b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Builds the tree while refusing what Jackson's constraints refuse: nesting past 64, a key twice in an object, a
/// string past a million characters, a name past fifty thousand.
struct Limited {
    depth: usize,
}

impl Limited {
    fn deeper<E: serde::de::Error>(&self) -> Result<Limited, E> {
        let depth = self.depth.checked_add(1).filter(|depth| *depth <= MAX_DEPTH);
        depth.map(|depth| Limited { depth }).ok_or_else(|| E::custom("Document nesting depth exceeds the maximum allowed"))
    }
}

impl<'de> DeserializeSeed<'de> for Limited {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Limited {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        if java::utf16_len(value) > MAX_STRING {
            return Err(E::custom("String value length exceeds the maximum allowed"));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let deeper = self.deeper()?;
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Limited { depth: deeper.depth })? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let deeper = self.deeper()?;
        let mut members = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if java::utf16_len(&key) > MAX_NAME {
                return Err(serde::de::Error::custom("Name length exceeds the maximum allowed"));
            }
            if members.contains_key(&key) {
                return Err(serde::de::Error::custom(format!("Duplicate field '{key}'")));
            }
            let value = map.next_value_seed(Limited { depth: deeper.depth })?;
            members.insert(key, value);
        }
        Ok(Value::Object(members))
    }
}

// -------------------------------------------------------------------------------------------------------------
// Paths — `SarifPaths`.

const REFUSED_LINK: &str = "names a location outside the analysed tree";

/// `SarifPaths.normalize`: the location as a path inside the analysed tree, `None` for one that names no file.
///
/// `%XX` decoded as UTF-8, `\` a separator, `file:` stripped and any other scheme refused, an absolute path only
/// under one of `roots` (removed), empty and `.` segments dropped, `..` refused — and with it the whole document,
/// since keeping the rest would make it read as the complete report.
pub fn normalize(uri: Option<&str>, roots: &[&str]) -> Result<Option<String>, InvalidSarif> {
    let Some(uri) = uri.filter(|uri| !java::is_blank(uri)) else { return Ok(None) };
    let decoded = decode(java::strip(uri))?.replace('\\', "/");
    if has_control(&decoded) {
        return Err(invalid("A result location carries a control character."));
    }
    let mut path = decoded.as_str();
    if let Some(colon) = scheme_end(path) {
        let (scheme, rest) = path.split_at(colon);
        if java::to_lower_root(scheme) != "file" {
            return Err(invalid(format!("A result {REFUSED_LINK}: {}.", shorten(uri))));
        }
        path = rest.get(1..).unwrap_or("");
        if let Some(authority) = path.strip_prefix("//") {
            // `file://host/path`: only an empty host names this machine's path.
            let (host, after) = match authority.find('/') {
                Some(slash) => authority.split_at(slash),
                None => (authority, "/"),
            };
            if !host.is_empty() && !host.eq_ignore_ascii_case("localhost") {
                return Err(invalid(format!("A result {REFUSED_LINK}: {}.", shorten(uri))));
            }
            path = after;
        }
    }
    let relative = if path.starts_with('/') { under_a_root(path, roots, uri)? } else { path };
    let mut kept = Vec::new();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return Err(invalid(format!("A result {REFUSED_LINK} (a \"..\" segment): {}.", shorten(uri))));
        }
        kept.push(segment);
    }
    Ok((!kept.is_empty()).then(|| kept.join("/")))
}

fn under_a_root<'a>(absolute: &'a str, roots: &[&str], uri: &str) -> Result<&'a str, InvalidSarif> {
    for root in roots {
        if absolute == *root {
            return Ok("");
        }
        if let Some(rest) = absolute.strip_prefix(root).and_then(|rest| rest.strip_prefix('/')) {
            return Ok(rest);
        }
    }
    Err(invalid(format!(
        "A result {REFUSED_LINK} (an absolute path): {}. Report paths relative to the analysed directory.",
        shorten(uri)
    )))
}

/// The index of a URI scheme's colon: a letter first, then letters, digits, `+ - .`.
fn scheme_end(value: &str) -> Option<usize> {
    for (position, c) in value.char_indices() {
        if c == ':' {
            return Some(position).filter(|position| *position > 0);
        }
        let allowed = c.is_ascii_alphabetic() || (position > 0 && (c.is_ascii_digit() || matches!(c, '+' | '-' | '.')));
        if !allowed {
            return None;
        }
    }
    None
}

/// `%XX` escapes as UTF-8, strictly: a broken escape or invalid UTF-8 is refused, not guessed.
fn decode(value: &str) -> Result<String, InvalidSarif> {
    if !value.contains('%') {
        return Ok(value.to_owned());
    }
    let broken = || invalid("A result location carries a broken %-escape.");
    let mut out = String::with_capacity(value.len());
    let mut bytes = Vec::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let high = chars.next().and_then(hex_digit).ok_or_else(broken)?;
            let low = chars.next().and_then(hex_digit).ok_or_else(broken)?;
            bytes.push(high.checked_mul(16).and_then(|high| high.checked_add(low)).ok_or_else(broken)?);
        } else {
            flush(&mut bytes, &mut out)?;
            out.push(c);
        }
    }
    flush(&mut bytes, &mut out)?;
    Ok(out)
}

/// `Character.digit(c, 16)` for the forms a URI carries.
fn hex_digit(c: char) -> Option<u8> {
    c.to_digit(16).and_then(|digit| u8::try_from(digit).ok())
}

fn flush(bytes: &mut Vec<u8>, out: &mut String) -> Result<(), InvalidSarif> {
    if bytes.is_empty() {
        return Ok(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("A result location's %-escapes are not UTF-8."))?;
    out.push_str(text);
    bytes.clear();
    Ok(())
}

/// The first 120 UTF-16 units and an ellipsis, as Java shortens a quoted value.
fn shorten(value: &str) -> String {
    if java::utf16_len(value) <= 120 {
        return value.to_owned();
    }
    let mut units = 0usize;
    let kept: String = value
        .chars()
        .take_while(|c| {
            units = units.saturating_add(c.len_utf16());
            units <= 120
        })
        .collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_with_content_after_it_is_told_from_one_that_is_not_json() {
        let doc = br#"{"version":"2.1.0","runs":[]}"#;
        assert!(read(doc, 1000, &[]).unwrap().is_empty());
        let after = |tail: &str| [&doc[..], tail.as_bytes()].concat();
        for token in [" {}", " []", " \"x", " 1", "\n-2.5e3", " true", " null]"] {
            assert_eq!(read(&after(token), 1000, &[]).unwrap_err().0, "The SARIF document carries content after its end.");
        }
        for garbage in [" x", " ]", " 1x", " truex", " ,"] {
            assert!(read(&after(garbage), 1000, &[]).unwrap_err().0.starts_with(NOT_READABLE_JSON), "{garbage}");
        }
    }
}
