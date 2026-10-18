//! `cp-contract` — the one command of the crate.
//!
//! `replay-plan <dir>` reads every recording the Java suite's recorder wrote under `<dir>` (`recorded::format`) and
//! holds `golden/deferred.txt` to it: exit 0 when every recording of a route not served, or outside the contract, is
//! covered by a line and no line is stale, 1 when a recording cannot be read, 3 otherwise, 2 on a bad command line.
//! The recordings of served routes are replayed by each module's `golden` test (`scripts/replay-goldens.sh`).
//!
//! `allowlist-write` writes `reference/not-yet-ported.txt` and its ceiling for a router that serves
//! nothing: every documented route. It is run **once**, when the document moves (`refresh.sh`), and
//! never to make a check pass — the list only shrinks.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use std::collections::BTreeSet;

use vectispire_cp_contract::recorded::deferred::{CEILING, Deferred, check_list, coverage, listed};
use vectispire_cp_contract::recorded::format::Recording;
use vectispire_cp_contract::{Allowlist, Document};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("allowlist-write") => write_allowlist(),
        Some("summary") => summary(),
        Some("replay-plan") => replay_plan(arguments.get(1).map(String::as_str)),
        _ => {
            err("usage: cp-contract allowlist-write | summary | replay-plan <golden dir>\n");
            ExitCode::from(2)
        }
    }
}

fn write_allowlist() -> ExitCode {
    let document = Document::embedded();
    let nothing: Vec<vectispire_cp_contract::RouteDecl> = Vec::new();
    let text = Allowlist::text_for(&document, &nothing);
    let count = text.lines().filter(|line| !line.starts_with('#') && !line.trim().is_empty()).count();
    let reference = Path::new(env!("CARGO_MANIFEST_DIR")).join("reference");
    let written = std::fs::write(reference.join("not-yet-ported.txt"), text)
        .and_then(|()| std::fs::write(reference.join("not-yet-ported.ceiling"), format!("{count}\n")));
    match written {
        Ok(()) => {
            out(&format!("{count} routes written to {}\n", reference.join("not-yet-ported.txt").display()));
            ExitCode::SUCCESS
        }
        Err(error) => {
            err(&format!("cannot write the allowlist: {error}\n"));
            ExitCode::FAILURE
        }
    }
}

fn replay_plan(dir: Option<&str>) -> ExitCode {
    let Some(dir) = dir else {
        err("usage: cp-contract replay-plan <golden dir>\n");
        return ExitCode::from(2);
    };
    let recording = match Recording::open(Path::new(dir)) {
        Ok(recording) => recording,
        Err(error) => {
            err(&format!("cannot read the recording: {error}\n"));
            return ExitCode::FAILURE;
        }
    };
    let document = Document::embedded();
    let not_ported = Allowlist::embedded();
    // Served is what has left the list of routes not ported: the contract's view, whichever crate serves it.
    let served: BTreeSet<(String, String)> =
        document.routes().into_iter().filter(|route| !not_ported.entries().contains(route)).collect();
    let all = match listed(&recording, &document, &served) {
        Ok(all) => all,
        Err(error) => {
            err(&format!("cannot read the recording: {error}\n"));
            return ExitCode::FAILURE;
        }
    };
    if all.is_empty() {
        err(&format!("{dir} holds no recording: a plan of nothing would pass whatever the recorder did\n"));
        return ExitCode::FAILURE;
    }
    let owed = all.iter().filter(|listed| listed.served).count();
    let outside = all.iter().filter(|listed| listed.route.is_none()).count();
    out(&format!(
        "{} recordings of passed tests; {owed} of served routes, owed a replay; {outside} outside the contract; {} of routes not served\n",
        all.len(),
        all.len().saturating_sub(owed).saturating_sub(outside)
    ));
    let deferred = Deferred::embedded();
    let mut problems = check_list(&deferred, &document, CEILING);
    problems.extend(coverage(&deferred, &all, None));
    if problems.is_empty() {
        return ExitCode::SUCCESS;
    }
    for problem in &problems {
        err(&format!("  {problem}\n"));
    }
    err("golden/deferred.txt does not account for every recording that is not replayed\n");
    ExitCode::from(3)
}

fn summary() -> ExitCode {
    let document = Document::embedded();
    let allowlist = Allowlist::embedded();
    out(&format!(
        "openapi {} — {} operations; {} not ported yet (ceiling {})\n",
        document.version(),
        document.operations().len(),
        allowlist.entries().len(),
        allowlist.ceiling()
    ));
    ExitCode::SUCCESS
}

/// What the command says on stdout. A closed pipe is not a failure of the command, so the write's result
/// is dropped; the print macros are denied workspace-wide (`Cargo.toml`).
fn out(text: &str) {
    drop(std::io::stdout().lock().write_all(text.as_bytes()));
}

/// The same on stderr.
fn err(text: &str) {
    drop(std::io::stderr().lock().write_all(text.as_bytes()));
}
