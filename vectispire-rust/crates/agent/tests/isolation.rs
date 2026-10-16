//! **The agent holds no database connection and never sees `ENCRYPTION_KEY`** — decision 0003's
//! property, which the Java build gets from its module graph (`vectispire-agent` does not depend on
//! `vectispire-core`) and `AgentIsolationTest`.
//!
//! Here the resolved dependency graph itself is read: every crate the agent binary links, through
//! normal and build dependencies, and none may be a database client, a server framework (the agent
//! opens no port), or test support. `deny.toml` bans the same crates workspace-wide; this test is the
//! one that fails on the agent's own graph, whatever `deny.toml` is later made to allow.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeSet, HashMap};

const FORBIDDEN: [&str; 23] = [
    // Database clients and drivers.
    "sqlx",
    "sqlx-core",
    "diesel",
    "postgres",
    "tokio-postgres",
    "postgres-types",
    "mysql",
    "mysql_async",
    "mysql_common",
    "mysqlclient-sys",
    "rusqlite",
    "libsqlite3-sys",
    "sea-orm",
    "redis",
    // Server frameworks: the agent opens no port. (`hyper` and `tower-http` are linked, as reqwest's
    // client side; a server built on them would need one of these, or the agent's own code to listen.)
    "axum",
    "actix-web",
    "warp",
    "rocket",
    "poem",
    "tiny_http",
    "hyper-server",
    // Test support.
    "vectispire-testkit",
    "mockall",
];

fn metadata() -> serde_json::Value {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let output = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked", "--manifest-path", manifest])
        .output()
        .expect("cargo metadata runs");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Every package the agent links, by name: the closure of its non-dev dependencies.
fn linked_by_the_agent(metadata: &serde_json::Value) -> BTreeSet<String> {
    let names: HashMap<&str, &str> = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| (package["id"].as_str().unwrap(), package["name"].as_str().unwrap()))
        .collect();
    let nodes: HashMap<&str, &serde_json::Value> = metadata["resolve"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| (node["id"].as_str().unwrap(), node))
        .collect();
    let agent =
        names.iter().find(|(_, name)| **name == "vectispire-agent").map(|(id, _)| *id).expect("the agent package");
    let mut seen = BTreeSet::new();
    let mut pending = vec![agent];
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        for dependency in nodes[id]["deps"].as_array().unwrap() {
            let linked =
                dependency["dep_kinds"].as_array().unwrap().iter().any(|kind| kind["kind"].as_str() != Some("dev"));
            if linked {
                pending.push(dependency["pkg"].as_str().unwrap());
            }
        }
    }
    seen.into_iter().map(|id| names[id].to_owned()).collect()
}

#[test]
fn the_agent_links_no_database_client_no_server_and_no_test_support() {
    let linked = linked_by_the_agent(&metadata());
    assert!(
        linked.contains("vectispire-git") && linked.contains("reqwest"),
        "the walk reaches the agent's graph: {linked:?}"
    );
    let found: Vec<&str> = FORBIDDEN.iter().copied().filter(|name| linked.contains(*name)).collect();
    assert!(found.is_empty(), "the agent must not link {found:?}");
}

#[test]
fn no_source_of_the_workspace_names_the_encryption_key() {
    let crates = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
    let mut pending = vec![crates.to_owned()];
    let mut offenders = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(std::fs::read_dir(&path).unwrap().map(|entry| entry.unwrap().path()));
        } else if path.extension().is_some_and(|extension| extension == "rs") && !path.ends_with("tests/isolation.rs") {
            let source = std::fs::read_to_string(&path).unwrap();
            if source.contains(&["ENCRYPTION", "_KEY"].concat()) {
                offenders.push(path.display().to_string());
            }
        }
    }
    assert!(offenders.is_empty(), "only the control plane holds the key that decrypts deployment keys: {offenders:?}");
}
