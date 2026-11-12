//! `sql.rs` on synthetic module crates: a statement naming another module's table is found, listed or refused.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;

use common::{Fixture, config};
use vectispire_cp_arch_tests::model::Config;
use vectispire_cp_arch_tests::sql::{Known, Ownership, Reference, check, parse_known, references};

/// A table map big enough to pass the "the map is complete" guard, with the tables the tests name.
fn ownership() -> Ownership {
    let mut text = String::from(
        "[tables.targets]\nt_repository = \"RepositoryEntity\"\nt_container = \"ContainerEntity\"\n\
         [tables.scanning]\nt_scan = \"ScanEntity\"\n[tables.issues]\nt_issue = \"IssueEntity\"\n[tables.access]\n",
    );
    for i in 0..40 {
        text.push_str(&format!("t_filler_{i} = \"Filler{i}\"\n"));
    }
    Ownership::parse(&text).unwrap()
}

fn found(fixture: &Fixture) -> (BTreeSet<Reference>, usize) {
    let result = references(&config(), &fixture.workspace(), &ownership());
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    (result.found, result.literals)
}

fn known(module: &str, query: &str, owner: &str, table: &str, against: bool) -> Known {
    parse_known(&format!(
        "[[known]]\nquery = \"{query}\"\nmodule = \"{module}\"\nowner = \"{owner}\"\ntable = \"{table}\"\n\
         against_the_direction = {against}\nreason = \"one statement over two tables, cheaper than two queries and a set difference\"\n"
    ))
    .unwrap()
    .remove(0)
}

const SCANNING: &str = "vectispire-cp-scanning";

fn orphan_sweep(fixture: &Fixture, sql: &str) {
    fixture.write(
        SCANNING,
        "src/persistence/mod.rs",
        &format!("pub(crate) struct ScanRepository;\nimpl ScanRepository {{\n    pub(crate) fn orphans(&self) {{ run(\"{sql}\"); }}\n}}\nfn run(_: &str) {{}}\npub(crate) fn rows() {{}}\n"),
    );
}

#[test]
fn the_clean_workspace_has_no_cross_module_reference_and_the_check_read_literals() {
    // targets reads its own table: nothing crosses.
    let (found, literals) = found(&Fixture::clean());
    assert!(found.is_empty(), "{found:#?}");
    assert!(literals >= 1, "the rule read no literal at all");
}

#[test]
fn a_statement_naming_another_modules_table_fails_unless_listed() {
    let fixture = Fixture::clean();
    orphan_sweep(&fixture, "select id from t_scan where repository_id not in (select id from t_repository)");
    let (references, _) = found(&fixture);
    assert_eq!(references.len(), 1, "{references:#?}");
    let reference = references.iter().next().unwrap();
    assert_eq!(
        (reference.module.as_str(), reference.query.as_str(), reference.owner.as_str(), reference.table.as_str()),
        ("scanning", "ScanRepository::orphans", "targets", "t_repository")
    );

    let violations = check(&config(), &ownership(), &[], &references);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("`ScanRepository::orphans` in the scanning module names targets's table t_repository")),
        "{violations:#?}"
    );

    // Listed, with its reason, it passes; scanning may use targets, so the direction holds.
    let entry = known("scanning", "ScanRepository::orphans", "targets", "t_repository", false);
    assert!(check(&config(), &ownership(), &[entry], &references).is_empty());
}

#[test]
fn the_entry_of_a_ported_module_goes_when_the_code_stops_needing_it() {
    let fixture = Fixture::clean();
    orphan_sweep(&fixture, "select 1");
    let (references, _) = found(&fixture);
    assert!(references.is_empty());
    let entry = known("scanning", "ScanRepository::orphans", "targets", "t_repository", false);

    // Pending: held to the ceiling only.
    assert!(check(&config(), &ownership(), std::slice::from_ref(&entry), &references).is_empty());
    // Ported: the list only shrinks.
    let ported = Config::parse(
        &common::CONFIG.replace("[module.scanning]\nstatus = \"pending\"", "[module.scanning]\nstatus = \"ported\""),
    )
    .unwrap();
    let violations = check(&ported, &ownership(), &[entry], &references);
    assert!(
        violations.iter().any(|v| v.contains("is no longer in the code: the list only shrinks, remove the entry")),
        "{violations:#?}"
    );
}

#[test]
fn a_statement_against_the_direction_has_to_say_so() {
    // targets may not use scanning: a read of t_scan from targets is a forbidden dependency hidden in a string.
    let fixture = Fixture::clean();
    fixture.write(
        "vectispire-cp-targets",
        "src/persistence/mod.rs",
        "pub(crate) struct TargetRepository;\nimpl TargetRepository { pub(crate) fn busy(&self) { run(\"select 1 from t_scan\"); } }\nfn run(_: &str) {}\npub(crate) fn rows() {}\n",
    );
    let (references, _) = found(&fixture);
    assert_eq!(references.len(), 1, "{references:#?}");

    let silent = known("targets", "TargetRepository::busy", "scanning", "t_scan", false);
    let violations = check(&config(), &ownership(), &[silent], &references);
    assert!(
        violations.iter().any(|v| v
            .contains("reads scanning, which targets may not use; its entry must say `against_the_direction = true`")),
        "{violations:#?}"
    );

    let honest = known("targets", "TargetRepository::busy", "scanning", "t_scan", true);
    assert!(check(&config(), &ownership(), &[honest], &references).is_empty());

    // And an entry that claims it against a direction that holds is wrong the other way.
    let fixture = Fixture::clean();
    orphan_sweep(&fixture, "select 1 from t_repository");
    let (references, _) = found(&fixture);
    let wrong = known("scanning", "ScanRepository::orphans", "targets", "t_repository", true);
    let violations = check(&config(), &ownership(), &[wrong], &references);
    assert!(
        violations.iter().any(|v| v.contains("is marked against the direction but scanning may use targets")),
        "{violations:#?}"
    );
}

#[test]
fn sql_inside_a_macro_is_read() {
    // `sqlx::query!("…")` keeps its statement in the macro's tokens.
    let fixture = Fixture::clean();
    fixture.write(
        SCANNING,
        "src/persistence/mod.rs",
        "pub(crate) fn find() { sqlx::query!(\"select id from t_repository where id = $1\", 1); }\npub(crate) fn rows() {}\n",
    );
    let (references, _) = found(&fixture);
    assert_eq!(references.len(), 1, "{references:#?}");
    assert_eq!(references.iter().next().unwrap().query, "find");
}

#[test]
fn a_table_is_a_word_and_not_a_prefix_or_a_suffix() {
    let fixture = Fixture::clean();
    orphan_sweep(&fixture, "select * from t_repository_summary join xt_repository on 1 = 1 where t_repositoryx = 1");
    assert!(found(&fixture).0.is_empty(), "names that merely contain a table's name are not that table");

    // An identifier literal that is exactly a table's name is a reference too (the query builder's way).
    let fixture = Fixture::clean();
    fixture.write(
        SCANNING,
        "src/persistence/mod.rs",
        "pub(crate) fn table() -> &'static str { \"t_repository\" }\npub(crate) fn rows() {}\n",
    );
    assert_eq!(found(&fixture).0.len(), 1);

    // A sentence that is not SQL and names no table as a word is not one.
    let fixture = Fixture::clean();
    orphan_sweep(&fixture, "the repositories table is t_repo");
    assert!(found(&fixture).0.is_empty());
}

#[test]
fn test_code_is_not_scanned() {
    let fixture = Fixture::clean();
    fixture.append(
        SCANNING,
        "src/persistence/mod.rs",
        "#[cfg(test)]\nmod tests { fn t() { let _ = \"select 1 from t_repository\"; } }\n",
    );
    assert!(found(&fixture).0.is_empty());
}

#[test]
fn a_table_owned_by_nobody_or_twice_is_refused_and_a_short_map_is_incomplete() {
    assert!(
        Ownership::parse("[tables.access]\nt_a = \"A\"\n[tables.targets]\nt_a = \"A\"\n")
            .unwrap_err()
            .contains("t_a is owned twice")
    );
    let short = Ownership::parse("[tables.access]\nt_a = \"A\"\n").unwrap();
    let violations = check(&config(), &short, &[], &BTreeSet::new());
    assert!(violations.iter().any(|v| v.contains("the map is incomplete")), "{violations:#?}");
    let stranger = Ownership::parse(&format!("[tables.nowhere]\nt_a = \"A\"\n{}", "")).unwrap();
    assert!(
        check(&config(), &stranger, &[], &BTreeSet::new())
            .iter()
            .any(|v| v.contains("owned by nowhere, which is no module"))
    );
}

#[test]
fn an_entry_needs_a_reason_and_a_true_owner() {
    let mut entry = known("scanning", "ScanRepository::orphans", "targets", "t_repository", false);
    entry.reason = "short".to_owned();
    let violations = check(&config(), &ownership(), &[entry], &BTreeSet::new());
    assert!(violations.iter().any(|v| v.contains("has no reason")), "{violations:#?}");

    let lying = known("scanning", "ScanRepository::orphans", "issues", "t_repository", false);
    let violations = check(&config(), &ownership(), &[lying], &BTreeSet::new());
    assert!(
        violations.iter().any(|v| v.contains("says issues owns t_repository, and tables.toml says otherwise")),
        "{violations:#?}"
    );
}
