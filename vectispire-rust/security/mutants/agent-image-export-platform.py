#!/usr/bin/env python3
"""Mutation check of the image exported for its platform (branch fix/agent-image-export-platform, 2026-11-27): the save
names the platform, and the archive is checked against it whatever the daemon. Each mutant must turn
`crates/container/tests/image_platform_reference_set.rs` (Java's answers) or `image_export.rs` red. See README.md.

What a missed guard costs: the arm64 variant of an image inventoried and matched as the amd64 one production deploys,
recorded as the image's — or an archive nobody checked handed to the cataloguer. `image_export.rs`'s last test needs
Docker and pulls Alpine 3.20.3 by its index digest.
"""
import sys

import _runner

A = "crates/container/src/image_archive.rs"
R = "crates/container/src/runner.rs"
REFERENCE = ["-p", "vectispire-container", "--test", "image_platform_reference_set"]
EXPORT = ["-p", "vectispire-container", "--test", "image_export"]

MUTANTS = [
    # The platform rules, against Java's answers.
    ("any variant admitted", A, "&& (self.variant.is_empty() || self.variant == found.variant)", "", REFERENCE),
    ("any operating system admitted", A, "        self.os == found.os\n            && ", "        ", REFERENCE),
    ("one image of the platform enough", A, "if found.iter().all(|image| asked.admits(image)) {",
     "if found.iter().any(|image| asked.admits(image)) {", REFERENCE),
    ("arm64's v8 kept", A, 'if variant == "8" || variant == "v8" {', "if false {", REFERENCE),
    ("any character in a component", A,
     "part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')", "true", REFERENCE),
    ("a blank platform read as one", A, "if vectispire_domain::java::is_blank(platform) {",
     "if platform.is_empty() {", REFERENCE),
    ("a byte-order mark refused", A, 'bytes.strip_prefix(b"\\xEF\\xBB\\xBF").unwrap_or(bytes)', "bytes", REFERENCE),
    # The tar reader, against Java's archives.
    ("the checksum not checked", A, "if checksum(&header) != number(field(&header, 148, 8))? {",
     "if number(field(&header, 148, 8)).is_err() {", REFERENCE),
    ("a PAX path ignored", A, "                if path.is_some() {\n                    pending_name = path;",
     "                if false {\n                    pending_name = path;", REFERENCE),
    ("a PAX size ignored", A, "                if pax_size.is_some() {\n                    pending_size = pax_size;",
     "                if false {\n                    pending_size = pax_size;", REFERENCE),
    ("the ustar prefix ignored", A, "        if !prefix.is_empty() {\n            return",
     "        if false {\n            return", REFERENCE),
    ("a GNU header's bytes read as a prefix", A, 'if field(header, 257, 6) == b"ustar\\0" {',
     'if field(header, 257, 5) == b"ustar" {', REFERENCE),
    ("a directory read as the file", A, "let regular = kind == b'0' || kind == 0;", "let regular = true;", REFERENCE),
    ("no limit on an entry", A, "if entry_size > limit as u64 {", "if false {", REFERENCE),
    ("./ not ignored", A, '    name.strip_prefix("./").unwrap_or(name)', "    name", REFERENCE),
    ("a skip past the end", A, "Some(there) if there <= end =>", "Some(there) =>", REFERENCE),
    # The export itself, against a stub daemon and the real one.
    ("the save without its platform", R, "self.save(reference, asked.as_ref())", "self.save(reference, None)", EXPORT),
    ("the archive not checked", R,
     "        let refusal = image_archive::refusal(reference, platform, &asked, |name, limit| {\n"
     "            image_archive::entry(destination, name, limit)\n        });",
     "        let _ = (&asked, platform);\n        let refusal: Option<String> = None;", EXPORT),
    ("a refused archive left behind", R,
     "                let _ = std::fs::remove_file(destination);\n                Err(ExportError::Platform(refusal))",
     "                Err(ExportError::Platform(refusal))", EXPORT),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=600, description=__doc__))
