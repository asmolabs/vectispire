//! `cp-contract` — the one command of the crate.
//!
//! `allowlist-write` writes `reference/not-yet-ported.txt` and its ceiling for a router that serves
//! nothing: every documented route. It is run **once**, when the document moves (`refresh.sh`), and
//! never to make a check pass — the list only shrinks.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use vectispire_cp_contract::{Allowlist, Document};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("allowlist-write") => write_allowlist(),
        Some("summary") => summary(),
        _ => {
            err("usage: cp-contract allowlist-write | summary\n");
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
