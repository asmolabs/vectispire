//! `unsafe` is forbidden, once, with one exception that has a reason.
//!
//! The plan's §6.1: `unsafe_code = "forbid"` in every control-plane crate, and the only `unsafe` in the
//! workspace is libgit2's two process-wide calls in the agent's `git` crate, which `edges.toml` names with
//! their file and their count. The workspace lint is `deny`, so that the exception can be allowed where it is
//! made; this is the check that the exception stays one: it reads the sources, so an `unsafe` block, function,
//! impl, trait or `extern` block anywhere else — in a test, in a build script, inside a macro's tokens — fails,
//! whatever lint level the crate was made to carry.

use crate::graph::Workspace;
use crate::model::{Config, Kind};
use crate::source::read_package;

/// Every violation, and how many files were read.
pub fn check(config: &Config, workspace: &Workspace) -> (Vec<String>, usize) {
    let mut violations = Vec::new();
    let mut read = 0;
    for package in workspace.members() {
        let kind = config.classify(&package.name);
        let (files, errors) = read_package(&package.dir, &["src", "tests", "benches", "examples", "build.rs"]);
        read += files.len();
        violations.extend(errors.into_iter().map(|error| format!("{}: unreadable: {error}", package.name)));

        for file in &files {
            if file.facts.unsafes.is_empty() {
                continue;
            }
            let allowed = config
                .settings
                .unsafe_allowed
                .iter()
                .find(|allowed| allowed.krate == package.name && allowed.file == file.rel);
            match allowed {
                Some(allowed) if file.facts.unsafes.len() <= allowed.max => {}
                Some(allowed) => violations.push(format!(
                    "{}: {}: {} uses of `unsafe`, and edges.toml allows {} here: the exception stays what it was written for",
                    package.name,
                    file.rel,
                    file.facts.unsafes.len(),
                    allowed.max
                )),
                None => {
                    for line in &file.facts.unsafes {
                        violations.push(format!("{}: {}:{line}: `unsafe` outside the documented exception", package.name, file.rel));
                    }
                }
            }
        }

        // A control-plane crate carries the prohibition itself, not by way of a workspace lint someone can relax.
        if matches!(kind, Kind::Module(_) | Kind::Infrastructure(_) | Kind::UnknownControlPlane) {
            for file in &files {
                let is_root = file.rel == "src/lib.rs"
                    || file.rel == "src/main.rs"
                    || (file.rel.starts_with("src/bin/") && file.rel.matches('/').count() == 2);
                if is_root && !file.facts.forbids_unsafe {
                    violations.push(format!("{}: {} lacks `#![forbid(unsafe_code)]`", package.name, file.rel));
                }
            }
        }
    }
    violations.sort();
    (violations, read)
}
