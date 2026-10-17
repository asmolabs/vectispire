//! `cp-contract` — the one command of the crate.
//!
//! `replay-plan <dir>` reads every recording the Java suite's recorder wrote under `<dir>` and says what a replay
//! of them owes (`plan.rs`): exit 0 when nothing is owed, 1 when a recording cannot be read, 3 when a route that has
//! been ported has recordings waiting to be replayed, 2 on a bad command line.
//!
//! `allowlist-write` writes `reference/not-yet-ported.txt` and its ceiling for a router that serves
//! nothing: every documented route. It is run **once**, when the document moves (`refresh.sh`), and
//! never to make a check pass — the list only shrinks.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use vectispire_cp_contract::{Allowlist, Document, load_dir, plan};

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
    let (goldens, _normaliser) = match load_dir(Path::new(dir)) {
        Ok(read) => read,
        Err(error) => {
            err(&format!("cannot read the recordings: {error}\n"));
            return ExitCode::FAILURE;
        }
    };
    if goldens.is_empty() {
        err(&format!("{dir} holds no recording: a plan of nothing would pass whatever the recorder did\n"));
        return ExitCode::FAILURE;
    }
    let document = Document::embedded();
    let not_ported = Allowlist::embedded();
    let found = plan(&goldens, &document, &not_ported);
    out(&format!(
        "{} recordings; {} of routes not yet ported, {} to replay, {} outside the contract; {} of {} operations recorded\n",
        found.total,
        found.not_ported,
        found.to_replay.len(),
        found.outside_contract.len(),
        found.operations_recorded,
        document.operations().len()
    ));
    for request in &found.outside_contract {
        out(&format!("  outside the contract: {request}\n"));
    }
    if found.owes_nothing() {
        return ExitCode::SUCCESS;
    }
    for owed in &found.to_replay {
        err(&format!("  owed a replay: {owed}\n"));
    }
    err("a ported route has recordings and nothing replays them: run the replay of cp-app's tests on them\n");
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
