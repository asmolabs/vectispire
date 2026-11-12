//! A query naming another module's table — `CrossModuleQueriesTest`, for strings.
//!
//! Neither the dependency edges nor the layers can see this coupling: a SQL string is a string, and
//! `… not in (select id from t_repository)` in `scanning` names `targets`' table with no `use` to say so. After
//! the Java modules were cut, every read of another module's rows went through the owner's API but these; this
//! reads every string literal of every module crate (and the tokens of `sqlx::query!`), resolves each table
//! name it contains to the module that owns it (`data/tables.toml`, read from the 77 JPA entities), and fails
//! on a reference to another module's table that `data/sql-known.toml` does not carry.
//!
//! **The list only shrinks.** Each entry says why the statement crosses; the entry of a ported module fails the
//! day its query stops naming the table, so the list cannot outlive the coupling. A new entry is a decision for
//! the review, like a line of a module's allowed dependencies: the owner's API, or a port, is the default
//! answer. An entry pointing against the modules' direction — at a module the origin's list does not allow —
//! says so, because it is a dependency the graph forbids, hidden in a string.
//!
//! What it cannot see: SQL assembled at run time from pieces (the dynamic reads are built with `sea-query`
//! from identifiers, which carry the table name in a literal like any other).

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::graph::Workspace;
use crate::model::{Config, Kind, Status};
use crate::source::read_package;

pub const TABLES: &str = include_str!("../data/tables.toml");
pub const KNOWN: &str = include_str!("../data/sql-known.toml");

/// A table, and the module that owns it.
#[derive(Debug, Deserialize)]
struct TablesFile {
    tables: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct KnownFile {
    #[serde(default)]
    known: Vec<Known>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Known {
    /// The function holding the statement: `Type::function` or `function`.
    pub query: String,
    /// The module whose crate holds it.
    pub module: String,
    pub owner: String,
    pub table: String,
    #[serde(default)]
    pub against_the_direction: bool,
    pub reason: String,
}

/// A reference from one function's statement to a table another module owns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reference {
    pub module: String,
    pub query: String,
    pub owner: String,
    pub table: String,
    pub at: String,
}

#[derive(Debug)]
pub struct Ownership {
    /// table → owning module.
    pub owner_of: BTreeMap<String, String>,
}

impl Ownership {
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: TablesFile = toml::from_str(text).map_err(|error| format!("tables.toml: {error}"))?;
        let mut owner_of = BTreeMap::new();
        for (module, tables) in file.tables {
            for table in tables.keys() {
                if owner_of.insert(table.clone(), module.clone()).is_some() {
                    return Err(format!("tables.toml: {table} is owned twice"));
                }
            }
        }
        Ok(Self { owner_of })
    }
}

pub fn parse_known(text: &str) -> Result<Vec<Known>, String> {
    toml::from_str::<KnownFile>(text).map(|file| file.known).map_err(|error| format!("sql-known.toml: {error}"))
}

/// A table named as a word: `t_scan` in `from t_scan s`, not in `t_scan_summary`, and not in a longer name.
fn names_table(text: &str, table: &str) -> bool {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(found) = text[from..].find(table) {
        let start = from + found;
        let end = start + table.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        if !before.is_some_and(word) && !after.is_some_and(word) {
            return true;
        }
        from = start + 1;
    }
    false
}

/// A literal that can be SQL: it holds whitespace (a statement) or is exactly a table's name (an identifier).
fn may_be_sql(literal: &str, owners: &BTreeMap<String, String>) -> bool {
    literal.chars().any(char::is_whitespace) || owners.contains_key(literal)
}

#[derive(Debug, Default)]
pub struct References {
    pub found: BTreeSet<Reference>,
    pub literals: usize,
    pub errors: Vec<String>,
}

/// Every cross-module reference in the workspace's module crates.
pub fn references(config: &Config, workspace: &Workspace, ownership: &Ownership) -> References {
    let mut result = References::default();
    for package in workspace.members() {
        let Kind::Module(module) = config.classify(&package.name) else { continue };
        let (files, errors) = read_package(&package.dir, &["src"]);
        result.errors.extend(errors.into_iter().map(|error| format!("{}: {error}", package.name)));
        for file in &files {
            for literal in &file.facts.literals {
                result.literals += 1;
                if !may_be_sql(&literal.value, &ownership.owner_of) {
                    continue;
                }
                for (table, owner) in &ownership.owner_of {
                    if *owner != module && names_table(&literal.value, table) {
                        result.found.insert(Reference {
                            module: module.clone(),
                            query: literal.context.clone().unwrap_or_else(|| "(outside a function)".to_owned()),
                            owner: owner.clone(),
                            table: table.clone(),
                            at: format!("{}:{}", file.rel, literal.line),
                        });
                    }
                }
            }
        }
    }
    result
}

/// The violations: a reference no entry carries, an entry whose direction is misdeclared, an entry of a ported
/// module that the code no longer needs, and a table map that does not make sense.
pub fn check(config: &Config, ownership: &Ownership, known: &[Known], found: &BTreeSet<Reference>) -> Vec<String> {
    let mut violations = Vec::new();

    // A wrong map would find nothing and pass: the failure mode of a rule that reads strings.
    if ownership.owner_of.len() <= 30 {
        violations.push(format!(
            "tables.toml names {} tables; the schema has 77: the map is incomplete",
            ownership.owner_of.len()
        ));
    }
    for (table, owner) in &ownership.owner_of {
        if !config.module.contains_key(owner) {
            violations.push(format!("tables.toml: {table} is owned by {owner}, which is no module"));
        }
    }

    for reference in found {
        let entry = known.iter().find(|entry| {
            entry.module == reference.module
                && entry.query == reference.query
                && entry.owner == reference.owner
                && entry.table == reference.table
        });
        match entry {
            None => violations.push(format!(
                "{}: `{}` in the {} module names {}'s table {}: the owner's API, or a port, is the default answer; \
                 a new entry in sql-known.toml is a decision for the review",
                reference.at, reference.query, reference.module, reference.owner, reference.table
            )),
            Some(entry) => {
                let allowed = config.allows_module(&reference.module, &reference.owner);
                if !allowed && !entry.against_the_direction {
                    violations.push(format!(
                        "{}: `{}` reads {}, which {} may not use; its entry must say `against_the_direction = true`",
                        reference.at, reference.query, reference.owner, reference.module
                    ));
                }
                if allowed && entry.against_the_direction {
                    violations.push(format!(
                        "sql-known.toml: `{}` is marked against the direction but {} may use {}",
                        entry.query, reference.module, reference.owner
                    ));
                }
            }
        }
    }

    for entry in known {
        let ported = config.module.get(&entry.module).is_some_and(|module| module.status == Status::Ported);
        let still_there = found.iter().any(|reference| {
            reference.module == entry.module
                && reference.query == entry.query
                && reference.owner == entry.owner
                && reference.table == entry.table
        });
        if ported && !still_there {
            violations.push(format!(
                "sql-known.toml: `{}` ({} -> {}.{}) is no longer in the code: the list only shrinks, remove the entry",
                entry.query, entry.module, entry.owner, entry.table
            ));
        }
        if ownership.owner_of.get(&entry.table) != Some(&entry.owner) {
            violations.push(format!(
                "sql-known.toml: `{}` says {} owns {}, and tables.toml says otherwise",
                entry.query, entry.owner, entry.table
            ));
        }
        if entry.reason.trim().len() < 20 {
            violations.push(format!(
                "sql-known.toml: `{}` has no reason: each entry says why the statement crosses",
                entry.query
            ));
        }
    }

    violations.sort();
    violations
}
