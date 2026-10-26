//! The rules, over the real workspace.
//!
//! Every test says how much it read and asserts a floor, so that a rule pointed at nothing cannot report green:
//! the secrets scan that examined zero commits did exactly that for six weeks. Today the workspace holds the
//! agent and not one control-plane module, so the rules that need module crates are silent here by necessity and
//! are proven on the synthetic workspaces of the other test files; the rules that apply to what exists — the
//! agent's isolation, `unsafe`, the pure crates, the edge list's own consistency — are live.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use vectispire_cp_arch_tests::graph::Workspace;
use vectispire_cp_arch_tests::model::{Config, EDGES};
use vectispire_cp_arch_tests::sql::{KNOWN, Ownership, TABLES, parse_known, references};
use vectispire_cp_arch_tests::{edges, isolation, layering, routes, unsafe_code, wire_time};

/// Java's `ArchitectureTest.MODULES`, which `ModularityTest` reads: the twenty-eight modules of `core`.
const JAVA_MODULES: [&str; 28] = [
    "settings",
    "outbound",
    "crypto",
    "audit",
    "outbox",
    "reporting",
    "siem",
    "rules",
    "ai",
    "threatintel",
    "tickets",
    "agents",
    "notifications",
    "exports",
    "gate",
    "inventory",
    "posture",
    "compliance",
    "access",
    "targets",
    "scanning",
    "issues",
    "maintenance",
    "platform",
    "plugins",
    "checklists",
    "reportplugins",
    "forges",
];

fn workspace() -> Workspace {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    Workspace::load(&manifest, true).unwrap()
}

fn config() -> Config {
    Config::parse(EDGES).unwrap()
}

fn assert_none(what: &str, violations: &[String]) {
    assert!(violations.is_empty(), "{what}:\n  {}", violations.join("\n  "));
}

#[test]
fn the_edge_list_is_the_java_modules_and_has_an_order() {
    let config = config();
    let mut listed: Vec<&str> = config.module.keys().map(String::as_str).collect();
    let mut expected = JAVA_MODULES.to_vec();
    listed.sort_unstable();
    expected.sort_unstable();
    assert_eq!(listed, expected, "edges.toml lists the modules ModularityTest lists");

    let order = config.porting_order().unwrap();
    assert_eq!(order.len(), 28);
    // Each module comes after everything it may use: the order the port goes in.
    for (index, module) in order.iter().enumerate() {
        for dependency in config.allowed_modules(module) {
            let at = order.iter().position(|m| *m == dependency).unwrap();
            assert!(at < index, "{module} comes before {dependency}, which it may use");
        }
    }
    // The plan's §1.2: no dependency at all for these, so they can all be ported first.
    for leaf in ["access", "audit", "outbound", "settings", "maintenance", "reporting"] {
        assert!(config.allowed_modules(leaf).is_empty(), "{leaf}");
    }
    assert!(config.module["platform"].open, "platform is the shell");
    println!("porting order: {}", order.join(" → "));
}

#[test]
fn the_named_interfaces_are_the_three_modulith_lists() {
    let config = config();
    let mut interfaces: Vec<String> = config
        .module
        .iter()
        .flat_map(|(module, entry)| entry.interfaces.iter().map(move |i| format!("{module}::{i}")))
        .collect();
    interfaces.sort();
    assert_eq!(interfaces, ["access::security", "issues::queries", "scanning::queries"]);
}

#[test]
fn the_workspace_obeys_the_edge_list() {
    let workspace = workspace();
    let members = workspace.members().count();
    assert!(members >= 10, "the walk reached {members} members");
    assert_none("edges", &edges::check(&config(), &workspace));
    println!("edges: {members} workspace crates read");
}

#[test]
fn every_module_crate_that_exists_obeys_the_layers() {
    let outcome = layering::check_workspace(&config(), &workspace());
    assert_none("layers", &outcome.violations);
    // No module crate exists yet; the day one does, this reports what it read.
    println!("layers: {} module crates, {} files, {} paths", outcome.crates, outcome.files, outcome.paths);
}

#[test]
fn no_module_crate_names_another_modules_table_unlisted() {
    let ownership = Ownership::parse(TABLES).unwrap();
    assert_eq!(ownership.owner_of.len(), 77, "the schema has 77 tables, one per JPA entity");
    let known = parse_known(KNOWN).unwrap();
    assert_eq!(known.len(), 4, "the orphan sweep: two statements over two tables");
    let config = config();
    let result = references(&config, &workspace(), &ownership);
    assert_none("unreadable", &result.errors);
    assert_none("sql", &vectispire_cp_arch_tests::sql::check(&config, &ownership, &known, &result.found));
    println!("sql: {} literals read in module crates", result.literals);
}

#[test]
fn unsafe_stays_the_one_documented_exception() {
    let (violations, read) = unsafe_code::check(&config(), &workspace());
    assert_none("unsafe", &violations);
    assert!(read >= 40, "the check read {read} files");
    println!("unsafe: {read} files read");
}

#[test]
fn every_serialised_instant_names_its_format() {
    let (violations, read) = wire_time::check(&config(), &workspace());
    assert_none("wire time", &violations);
    assert!(read >= 200, "the check read {read} files");
    println!("wire time: {read} files read");
}

#[test]
fn the_agent_is_isolated_from_the_control_plane() {
    let (violations, linked) = isolation::check(&config(), &workspace());
    assert_none("isolation", &violations);
    assert!(linked >= 20, "the agent's graph holds {linked} packages");
    println!("isolation: {linked} packages in the agent's graph");
}

#[test]
fn the_anonymous_routes_are_the_java_seven() {
    let anonymous = routes::parse_anonymous(routes::ANONYMOUS).unwrap();
    assert_eq!(anonymous.len(), 7);
}

/// `edges.toml` against the module model Spring Modulith reads, as Java writes it (`ModulesReferenceSetTest`,
/// `reference/modules/modules.json`): the same modules, the same shared foundation, the same lists, the same named
/// interfaces, the same open shell. The list was written by hand from the `package-info` files, and nothing compared
/// the two after that; a line added on one side only would leave the Rust rules enforcing a graph Java no longer has.
#[test]
fn the_edge_list_is_the_module_model_java_reads() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/modules/modules.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let java: serde_json::Value = serde_json::from_str(&text).unwrap();
    let config = config();

    let shared: Vec<String> =
        java["shared"].as_array().unwrap().iter().map(|name| name.as_str().unwrap().to_owned()).collect();
    assert_eq!(shared.len(), 7, "Java's foundation is seven modules");
    assert_eq!(config.shared_modules().into_iter().collect::<Vec<_>>(), shared, "the shared modules");

    let modules = java["modules"].as_array().unwrap();
    assert_eq!(modules.len(), 28);
    let mut problems = Vec::new();
    for module in modules {
        let name = module["name"].as_str().unwrap();
        let Some(entry) = config.module.get(name) else {
            problems.push(format!("{name}: in Java's model, not in edges.toml"));
            continue;
        };
        let strings = |key: &str| -> std::collections::BTreeSet<String> {
            module[key].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned()).collect()
        };
        let allowed: std::collections::BTreeSet<String> = entry.allowed.iter().cloned().collect();
        if allowed != strings("allowed") {
            problems.push(format!("{name}: edges.toml allows {allowed:?}, Java {:?}", strings("allowed")));
        }
        let interfaces: std::collections::BTreeSet<String> = entry.interfaces.iter().cloned().collect();
        if interfaces != strings("interfaces") {
            problems.push(format!("{name}: edges.toml exposes {interfaces:?}, Java {:?}", strings("interfaces")));
        }
        if entry.open != module["open"].as_bool().unwrap() {
            problems.push(format!("{name}: open is {} here and {} in Java", entry.open, module["open"]));
        }
    }
    assert_none("edges.toml against Java's module model", &problems);
}
