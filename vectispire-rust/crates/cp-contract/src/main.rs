//! `cp-contract` — the one command of the crate.
//!
//! `allowlist-write` writes `reference/not-yet-ported.txt` and its ceiling for a router that serves
//! nothing: every documented route. It is run **once**, when the document moves (`refresh.sh`), and
//! never to make a check pass — the list only shrinks.

use std::path::Path;
use std::process::ExitCode;

use vectispire_cp_contract::{Allowlist, Document};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("allowlist-write") => write_allowlist(),
        Some("summary") => summary(),
        _ => {
            eprintln!("usage: cp-contract allowlist-write | summary");
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
            println!("{count} routes written to {}", reference.join("not-yet-ported.txt").display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cannot write the allowlist: {error}");
            ExitCode::FAILURE
        }
    }
}

fn summary() -> ExitCode {
    let document = Document::embedded();
    let allowlist = Allowlist::embedded();
    println!(
        "openapi {} — {} operations; {} not ported yet (ceiling {})",
        document.version(),
        document.operations().len(),
        allowlist.entries().len(),
        allowlist.ceiling()
    );
    ExitCode::SUCCESS
}
