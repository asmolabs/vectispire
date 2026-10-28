//! `cp-contract` — the one command of the crate.
//!
//! `replay-plan <dir>` reads every recording the Java suite's recorder wrote under `<dir>` (`recorded::format`) and
//! holds `golden/deferred/` to it: exit 0 when every recording of a route not served, or outside the contract, is
//! covered by a line and no line is stale, 1 when a recording cannot be read, 3 otherwise, 2 on a bad command line.
//! The recordings of served routes are replayed by each module's `golden` test (`scripts/replay-goldens.sh`).
//!
//! `summary` prints the document's operations and the routes not ported yet, in total and per module file.
//!
//! There is no command that writes the list of routes not ported: it was written once, and when the document moves
//! (`reference/refresh.sh`) a new operation is added by hand to its module's file — which module is a fact of the
//! Java side the document does not carry.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use std::collections::BTreeSet;

use vectispire_cp_contract::recorded::deferred::{Deferred, check_list, coverage, listed};
use vectispire_cp_contract::recorded::format::Recording;
use vectispire_cp_contract::{Allowlist, Document};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("summary") => summary(),
        Some("replay-plan") => replay_plan(arguments.get(1).map(String::as_str)),
        _ => {
            err("usage: cp-contract summary | replay-plan <golden dir>\n");
            ExitCode::from(2)
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
    let not_ported = Allowlist::committed();
    if let Some(problem) = not_ported_problem(&document, &not_ported) {
        err(&problem);
        return ExitCode::FAILURE;
    }
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
    let deferred = Deferred::committed();
    let files: Vec<String> = deferred.files.iter().map(|(label, lines, _)| format!("{label} {lines}")).collect();
    out(&format!("golden/deferred/ holds {} lines: {}\n", deferred.len(), files.join(", ")));
    let mut problems = check_list(&deferred, &document);
    problems.extend(coverage(&deferred, &all, None));
    if problems.is_empty() {
        return ExitCode::SUCCESS;
    }
    for problem in &problems {
        err(&format!("  {problem}\n"));
    }
    err("golden/deferred/ does not account for every recording that is not replayed\n");
    ExitCode::from(3)
}

fn summary() -> ExitCode {
    let document = Document::embedded();
    let allowlist = Allowlist::committed();
    if let Some(problem) = not_ported_problem(&document, &allowlist) {
        err(&problem);
        return ExitCode::FAILURE;
    }
    let files: Vec<String> = allowlist.files().iter().map(|(label, entries, _)| format!("{label} {entries}")).collect();
    out(&format!(
        "openapi {} — {} operations; {} not ported yet (ceilings {}): {}\n",
        document.version(),
        document.operations().len(),
        allowlist.entries().len(),
        allowlist.ceiling(),
        files.join(", ")
    ));
    ExitCode::SUCCESS
}

/// The list of routes not ported, read: a file without its ceiling, a malformed line or an unreadable directory would
/// make "served" mean "not listed because the list could not be read".
fn not_ported_problem(document: &Document, list: &Allowlist) -> Option<String> {
    let nothing: BTreeSet<(String, String)> = BTreeSet::new();
    let problems: Vec<String> = vectispire_cp_contract::check_partition(document, &nothing, list)
        .into_iter()
        .filter(|finding| {
            !matches!(
                finding,
                vectispire_cp_contract::Finding::NotServed { .. }
                    | vectispire_cp_contract::Finding::MethodNotServed { .. }
            )
        })
        .map(|finding| format!("  {finding}\n"))
        .collect();
    (!problems.is_empty()).then(|| format!("reference/not-yet-ported/ cannot be read as it is:\n{}", problems.concat()))
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
