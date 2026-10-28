//! `isolation.rs` on synthetic workspaces: the agent links no control-plane code and never names the key.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, config};
use vectispire_cp_arch_tests::isolation::check;

fn violations(fixture: &Fixture) -> Vec<String> {
    let (violations, linked) = check(&config(), &fixture.workspace());
    assert!(linked >= 3, "the walk reached {linked} packages of the agent's graph");
    violations
}

fn mentions(violations: &[String], needle: &str) -> bool {
    violations.iter().any(|violation| violation.contains(needle))
}

/// The key's name, assembled: the real agent isolation test fails on any source of this workspace that spells it.
fn key() -> String {
    ["ENCRYPTION", "_KEY"].concat()
}

#[test]
fn the_clean_workspace_is_isolated() {
    let found = violations(&Fixture::clean());
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn the_agent_linking_a_control_plane_crate_fails_directly_or_through_another_crate() {
    let mut fixture = Fixture::clean();
    fixture.depends("vectispire-agent", &["vectispire-domain", "vectispire-git", "vectispire-cp-db"]);
    assert!(mentions(&violations(&fixture), "the agent links vectispire-cp-db"));

    // Through a shared crate: domain links the pool, the agent links domain.
    let mut fixture = Fixture::clean();
    fixture.depends("vectispire-domain", &["vectispire-cp-db"]);
    let found = violations(&fixture);
    assert!(mentions(&found, "the agent links vectispire-cp-db"), "{found:#?}");
}

#[test]
fn the_migration_runner_is_control_plane_code() {
    let mut fixture = Fixture::clean();
    fixture.krate("vectispire-migrate", &[], &[], false);
    fixture.depends("vectispire-git", &["vectispire-migrate"]);
    assert!(mentions(&violations(&fixture), "the agent links vectispire-migrate"));
}

#[test]
fn a_crate_the_agent_links_naming_the_key_fails_and_the_control_plane_may() {
    let fixture = Fixture::clean();
    fixture.append("vectispire-git", "src/lib.rs", &format!("pub fn x() -> &'static str {{ \"{}\" }}\n", key()));
    assert!(mentions(&violations(&fixture), "vectispire-git: src/lib.rs names the encryption key"));

    // The control plane holds the key: naming it there is the point, and is not seen by this rule.
    let fixture = Fixture::clean();
    fixture.append("vectispire-cp-targets", "src/lib.rs", &format!("pub fn x() -> &'static str {{ \"{}\" }}\n", key()));
    assert!(violations(&fixture).is_empty());
}

#[test]
fn a_workspace_without_the_agent_says_it_has_nothing_to_check() {
    let mut fixture = Fixture::empty();
    fixture.krate("vectispire-domain", &[], &[], false);
    let (violations, linked) = check(&config(), &fixture.workspace());
    assert_eq!(linked, 0);
    assert!(mentions(&violations, "the workspace has no vectispire-agent"), "{violations:#?}");
}
