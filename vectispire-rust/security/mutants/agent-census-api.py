#!/usr/bin/env python3
"""Mutation check of the agent's workspace stream: the census, the project manifest and the API discovery, which read
the audited repository in the agent's own process — links refused, bounds kept, the JDK's parser limits and Jackson's
held, a failed discovery failed rather than empty, and the Java decoding of what the repository wrote. See README.md.

Killed by `vectispire-scanners`' unit tests and its reference set (`tests/workspace_reference_set.rs`, the trees of
`reference/workspace/` answered by Java), and `vectispire-domain`'s language tests. No database, no Docker.
"""
import sys

import _runner

SOURCE_FILES = "crates/scanners/src/source_files.rs"
WALK = "crates/scanners/src/walk.rs"
CENSUS = "crates/scanners/src/census.rs"
LANGUAGE = "crates/domain/src/language.rs"
MANIFEST = "crates/scanners/src/manifest.rs"
POM = "crates/scanners/src/pom.rs"
PROPERTIES = "crates/scanners/src/properties.rs"
JSON = "crates/scanners/src/jackson_tree.rs"
API = "crates/scanners/src/api_discovery.rs"

SCANNERS = ["-p", "vectispire-scanners", "--lib", "--test", "workspace_reference_set"]
DOMAIN = ["-p", "vectispire-domain", "--lib", "language"]

MUTANTS = [
    # The reads of the tree.
    ("a link read as a file", SOURCE_FILES,
     "metadata.file_type().is_file() && metadata.len() <= MAX_BYTES", "metadata.len() <= MAX_BYTES", SCANNERS),
    ("an encoded surrogate replaced three times", SOURCE_FILES,
     "(Some(char::from_u32(value).unwrap_or('\\u{FFFD}')), 3)", "(None, 1)", SCANNERS),
    ("a link followed by the walk", WALK, "let metadata = entry.metadata();",
     "let metadata = std::fs::metadata(&path);", SCANNERS),
    ("a skipped subtree entered", WALK, "if visit == Visit::Continue {", "if visit != Visit::Terminate {", SCANNERS),

    # The census.
    ("node_modules counted", CENSUS, 'const SKIPPED: [&str; 2] = [".git", "node_modules"];',
     'const SKIPPED: [&str; 2] = [".git", ".none"];', SCANNERS),
    ("the root skipped by its own name", CENSUS, "if dir != self.root && name", "if true && name", SCANNERS),
    ("a link counted", CENSUS, "if metadata.file_type().is_file()\n", "if !metadata.file_type().is_dir()\n", SCANNERS),
    ("an exhausted walk called complete", CENSUS,
     "            self.complete = false;\n            return Visit::Terminate;", "            return Visit::Terminate;",
     SCANNERS),
    ("an unreadable directory proves an absence", CENSUS,
     "        self.complete = false;\n        Ok(Visit::Continue)", "        Ok(Visit::Continue)", SCANNERS),
    ("an incomplete census recorded", CENSUS, "self.complete.then(|| self.found.iter()", "Some(self.found.iter()",
     SCANNERS),
    ("an incomplete census trusted for a plugin", CENSUS, "!self.complete || declared", "declared", SCANNERS),
    ("the census's deadline ignored", CENSUS,
     "let late = self.give_up_at.is_some_and(|give_up_at| (self.clock)() > give_up_at);", "let late = false;", SCANNERS),
    ("no early stop", CENSUS, "if !self.wanted.is_empty() && self.wanted.is_subset(&self.found) {", "if false {",
     SCANNERS),
    ("an early stop on an empty wish", CENSUS, "if !self.wanted.is_empty() && self.wanted.is_subset", "if self.wanted.is_subset",
     SCANNERS),
    ("Dockerfile.<anything> not a Dockerfile", LANGUAGE, 'lower.starts_with("dockerfile.")', "false", DOMAIN),

    # The manifest.
    ("a linked manifest read", MANIFEST, "source_files::is_regular_file(&manifest).then(", "manifest.exists().then(",
     SCANNERS),
    ("package.json before pom.xml", MANIFEST,
     '    ("pom.xml", "maven", maven),\n    ("build.gradle.kts", "gradle", gradle),\n    ("build.gradle", "gradle", gradle),\n'
     '    ("package.json", "npm", npm),',
     '    ("package.json", "npm", npm),\n    ("build.gradle.kts", "gradle", gradle),\n    ("build.gradle", "gradle", gradle),\n'
     '    ("pom.xml", "maven", maven),', SCANNERS),
    ("an overlong version kept", MANIFEST, "java::utf16_len(trimmed) <= MAX_VERSION", "true", SCANNERS),
    ("a version's length in characters", MANIFEST, "java::utf16_len(trimmed) <= MAX_VERSION",
     "trimmed.chars().count() <= MAX_VERSION", SCANNERS),
    ("the first version of the file", MANIFEST,
     'in_project_table = stripped == "[project]" || stripped == "[tool.poetry]";', "in_project_table = true;", SCANNERS),
    ("an empty quoted version matched", MANIFEST, ".filter(|value| !value.is_empty())", "", SCANNERS),
    ("an undeclared entity resolved", POM, '"quot" => Ok(\'"\'),\n            _ => Err(Malformed),',
     '"quot" => Ok(\'"\'),\n            _ => Ok(\'?\'),', SCANNERS),
    ("elements nested past the JDK's depth", POM, "if depth > MAX_DEPTH {", "if false {", SCANNERS),
    ("attributes past the JDK's limit", POM, "if attributes.len() > MAX_ATTRIBUTES {", "if false {", SCANNERS),
    ("names past the JDK's limit", POM, "if length > MAX_NAME {", "if false {", SCANNERS),
    ("a dependency's version taken", POM, "let parent_is_root = self.stack.len() == 1;",
     "let parent_is_root = !self.stack.is_empty();", SCANNERS),
    ("a mismatched end tag accepted", POM, "if self.stack.last() != Some(&name) {", "if false {", SCANNERS),
    ("a duplicate attribute accepted", POM, "if attributes.contains(&attribute) {", "if false {", SCANNERS),
    ("line ends kept", POM, "        self.normalize_line_ends();\n", "", SCANNERS),
    ("an unknown encoding read as ASCII", POM,
     "} else if (ASCII.contains(&upper.as_str()) || ASCII_COMPATIBLE.contains(&upper.as_str())) && bytes.is_ascii() {",
     "} else if bytes.is_ascii() {", SCANNERS),
    ("text after the root accepted", POM, "if self.peek().is_some() { Err(Malformed) } else { Ok(()) }", "Ok(())", SCANNERS),
    ("`--` inside a comment accepted", POM, "return if self.eat(\">\") { Ok(()) } else { Err(Malformed) };", "return Ok(());",
     SCANNERS),
    ("a comment continued", PROPERTIES, "if line.is_empty() && (c == u16::from(b'#') || c == u16::from(b'!')) {",
     "if false {", SCANNERS),
    ("a malformed \\u escape tolerated", PROPERTIES, ".ok_or(Malformed)?;\n                    value = value.wrapping_shl(4) | digit;",
     ".unwrap_or(0);\n                    value = value.wrapping_shl(4) | digit;", SCANNERS),
    ("a continuation not joined", PROPERTIES, "if !preceding_backslash {\n                return Some(line);",
     "if true {\n                return Some(line);", SCANNERS),

    # Jackson's limits and leniencies.
    ("nesting past Jackson's depth", JSON, "if stack.len() >= MAX_DEPTH {", "if false {", SCANNERS),
    ("a number past Jackson's length", JSON, "if digits > MAX_NUMBER_DIGITS {", "if false {", SCANNERS),
    ("a name past Jackson's length", JSON, "if length > MAX_NAME_LENGTH {", "if false {", SCANNERS),
    ("leading zeroes accepted", JSON, "if leading_zero && integer > 1 {", "if false {", SCANNERS),
    ("an encoded surrogate accepted", JSON, '3 if (0xD800..=0xDFFF).contains(&value) => Err(Refused("an encoded surrogate")),\n',
     "", SCANNERS),
    ("a root number glued to garbage", JSON, "if matches!(root, Node::Number(_)) && !matches!", "if false && !matches!",
     SCANNERS),
    ("the first of duplicate names kept", JSON, "Some(member) => member.1 = value,", "Some(_) => {}", SCANNERS),
    ("-0 written as is", JSON, 'if raw == "-0" { "0".to_owned() } else { raw.to_owned() }', "raw.to_owned()", SCANNERS),
    ("a byte-order mark not skipped", JSON, "bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {\n        return Ok(Source::Utf8(rest));",
     "bytes.strip_prefix(&[0xEF, 0xBB, 0xBF, 0x00]) {\n        return Ok(Source::Utf8(rest));", SCANNERS),

    # The API discovery.
    ("vendor/ read", API, '    "vendor",\n', '    "vendorx",\n', SCANNERS),
    ("a top-level test* directory read", API, '|| relative.starts_with("test")\n', "\n", SCANNERS),
    ("a .spec.ts read", API, '|| lower.ends_with(".spec.ts")\n', "\n", SCANNERS),
    ("the list before merging unbounded", API, "if self.endpoints.len() > self.ceiling.saturating_mul(2) {", "if false {",
     SCANNERS),
    ("a contract past the ceiling accepted", API,
     ".find(|contract| usize::try_from(contract.endpoints_count).unwrap_or(0) > ceiling)", ".find(|_| false)", SCANNERS),
    ("the merged list past the ceiling accepted", API, "if adjusted.len() > ceiling {", "if false {", SCANNERS),
    ("duplicates kept", API, 'if seen.insert(format!("{}:{}", endpoint.method, endpoint.path)) {',
     'if seen.insert(format!("{}:{}", endpoint.method, endpoint.path)) || true {', SCANNERS),
    ("an ingress prefix without its slash ignored", API,
     "let without = slash > 0 && path.get(..slash).is_some_and(|prefix| public_paths.contains(prefix));",
     "let without = false;", SCANNERS),
    ("any manifest's paths taken for an ingress", API,
     'if !content.contains("kind: Ingress") && !content.contains("kind: \\"Ingress\\"") {', "if false {", SCANNERS),
    ("the discovery's deadline ignored", API,
     "if give_up_at.is_some_and(|give_up_at| clock() > give_up_at) { Err(timed_out(deadline)) } else { Ok(()) }",
     "Ok(())", SCANNERS),
    ("a missing tree walked", API, "if !std::fs::metadata(root).is_ok_and(|metadata| metadata.is_dir()) {", "if false {",
     SCANNERS),
    ("an unwalkable tree found empty", API,
     "    fn visit_file_failed(&mut self, _: &Path, _: std::io::Error) -> Result<Visit, Failed> {\n"
     "        Err(Failed(WALK_FAILED.to_owned()))",
     "    fn visit_file_failed(&mut self, _: &Path, _: std::io::Error) -> Result<Visit, Failed> {\n"
     "        Ok(Visit::Continue)", SCANNERS),
    ("a class-level guard ignored", API,
     "let class_auth = header.is_some_and(|header| CLASS_GUARDS.iter().any(|guard| header.contains(guard)));",
     "let class_auth = false;", SCANNERS),
    ("comments read as code", API, "let units = strip_comments(raw);",
     "let units: Vec<u16> = raw.encode_utf16().collect();", SCANNERS),
    ("half the context read back", API, "const BEFORE: usize = 500;", "const BEFORE: usize = 250;", SCANNERS),
    ("the health probes not known public", API, '|| path.starts_with("/actuator/health")\n', "\n", SCANNERS),
    ("`security: []` in JSON not public", API,
     "let explicitly_public =\n                    matches!(security, Some(security @ Node::Array(_)) if security.is_empty_container());",
     "let explicitly_public = false;", SCANNERS),
    ("a YAML top-level key not ending the paths", API, "if YAML_TOP_LEVEL_KEY.is_match(line) {", "if false {", SCANNERS),
    ("@login_required after a Flask route ignored", API,
     "around(index.checked_sub(1)) || around(index.checked_add(1))", "around(index.checked_sub(1))", SCANNERS),
]

# Not listed, each equivalent on its own:
# - the size bound read before the open (`metadata.len() <= MAX_BYTES`) and the one enforced while reading
#   (`take(MAX_BYTES + 1)`, then `> MAX_BYTES`): each holds without the other unless the file grows in between, which
#   no test arranges; likewise `O_NOFOLLOW` behind the metadata's link check, and the discovery's own `is_readable`
#   behind `read_text`'s. They are kept because the race is real.
# - a listing that breaks off mid-directory (`post_visit_directory` with an error): no file system a test can build
#   makes `readdir` fail after it opened.
# - `gradle.properties` absent or a link: `read_bytes` answers nothing for both, which reads as no version either way.
# - the DOCTYPE: nothing in the reader declares one, so it is refused as any unknown markup is; there is no line of
#   its own to break.

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
