//! `edges.rs` on synthetic workspaces: silent on the clean one, and loud, with the cause, on each break.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, config};
use vectispire_cp_arch_tests::edges::check;
use vectispire_cp_arch_tests::model::Config;

fn violations(fixture: &Fixture) -> Vec<String> {
    check(&config(), &fixture.workspace())
}

fn mentions(violations: &[String], needle: &str) -> bool {
    violations.iter().any(|violation| violation.contains(needle))
}

#[test]
fn the_clean_workspace_has_no_violation() {
    let fixture = Fixture::clean();
    let violations = violations(&fixture);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn a_dependency_the_list_does_not_allow_fails() {
    // inventory is a sibling of issues, not in its list; the edge makes no cycle, which Cargo would refuse first.
    let mut fixture = Fixture::clean();
    fixture.module("inventory", &["vectispire-cp-access", "vectispire-cp-targets"]);
    fixture.depends(
        "vectispire-cp-issues",
        &["vectispire-cp-access", "vectispire-cp-scanning", "vectispire-cp-targets", "vectispire-cp-inventory"],
    );
    let found = violations(&fixture);
    assert!(
        mentions(&found, "issues depends on inventory, which its allowedDependencies in edges.toml do not list"),
        "{found:#?}"
    );
}

#[test]
fn a_module_that_edges_toml_does_not_list_fails() {
    let mut fixture = Fixture::clean();
    fixture.module("newcomer", &[]);
    let found = violations(&fixture);
    assert!(
        mentions(&found, "vectispire-cp-newcomer: a control-plane crate that edges.toml does not list"),
        "{found:#?}"
    );
}

#[test]
fn a_cycle_between_crates_fails() {
    // Cargo refuses a cycle of normal dependencies before `cargo metadata` answers, so a cycle cannot be built out
    // of real manifests; the rule is the second line, for a graph that reaches it by another road (a metadata
    // document from another tool, a feature-gated edge). It is proven on a metadata document written by hand.
    let metadata = serde_json::json!({
        "workspace_members": ["a 0.0.0 (path+file:///a)", "b 0.0.0 (path+file:///b)", "c 0.0.0 (path+file:///c)"],
        "packages": [
            {"id": "a 0.0.0 (path+file:///a)", "name": "a", "manifest_path": "/a/Cargo.toml"},
            {"id": "b 0.0.0 (path+file:///b)", "name": "b", "manifest_path": "/b/Cargo.toml"},
            {"id": "c 0.0.0 (path+file:///c)", "name": "c", "manifest_path": "/c/Cargo.toml"},
        ],
        "resolve": {"nodes": [
            {"id": "a 0.0.0 (path+file:///a)", "deps": [{"name": "b", "pkg": "b 0.0.0 (path+file:///b)", "dep_kinds": [{"kind": null}]}]},
            {"id": "b 0.0.0 (path+file:///b)", "deps": [{"name": "a", "pkg": "a 0.0.0 (path+file:///a)", "dep_kinds": [{"kind": null}]},
                                                     {"name": "c", "pkg": "c 0.0.0 (path+file:///c)", "dep_kinds": [{"kind": null}]}]},
            {"id": "c 0.0.0 (path+file:///c)", "deps": []},
        ]},
    });
    let workspace = vectispire_cp_arch_tests::graph::Workspace::from_metadata(&metadata).unwrap();
    assert_eq!(workspace.cycles(), vec![vec!["a".to_owned(), "b".to_owned()]], "c is not in the cycle");
    let found = check(&config(), &workspace);
    assert!(mentions(&found, "a dependency cycle between crates: a, b"), "{found:#?}");

    // The same document with the back edge a dev-dependency has no cycle: Cargo allows it, and Modulith reads main code.
    let mut dev = metadata.clone();
    dev["resolve"]["nodes"][1]["deps"][0]["dep_kinds"] = serde_json::json!([{"kind": "dev"}]);
    let workspace = vectispire_cp_arch_tests::graph::Workspace::from_metadata(&dev).unwrap();
    assert!(workspace.cycles().is_empty());
}

#[test]
fn a_cycle_in_the_edge_list_itself_is_refused() {
    // The list is what the port's order is read from: a cycle in it means no order exists.
    let cycle = common::CONFIG.replace(
        "[module.access]\nstatus = \"pending\"\nallowed = []",
        "[module.access]\nstatus = \"pending\"\nallowed = [\"issues\"]",
    );
    let error = Config::parse(&cycle).unwrap_err();
    assert!(error.contains("a cycle in edges.toml"), "{error}");
}

#[test]
fn a_dev_dependency_is_not_an_edge() {
    // Modulith verifies main code only; a module's tests may use what its main code may not — and a crate and
    // its test support may refer to each other, which Cargo allows and which is no cycle of the program.
    let mut fixture = Fixture::clean();
    fixture.krate(
        "vectispire-cp-targets",
        &["vectispire-cp-access", "vectispire-cp-db", "sqlx", "vectispire-domain"],
        &["vectispire-cp-issues"],
        false,
    );
    fixture.krate("vectispire-cp-access", &["vectispire-domain"], &["vectispire-cp-targets"], false);
    let found = violations(&fixture);
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn a_ported_module_with_a_line_nothing_uses_fails() {
    let mut text =
        common::CONFIG.replace("[module.scanning]\nstatus = \"pending\"", "[module.scanning]\nstatus = \"ported\"");
    let config = Config::parse(&text).unwrap();
    let mut fixture = Fixture::clean();
    // Clean: scanning uses access and targets, both listed.
    assert!(check(&config, &fixture.workspace()).is_empty());
    // It stops using targets while still listing it.
    fixture.depends("vectispire-cp-scanning", &["vectispire-cp-access", "vectispire-cp-db"]);
    let found = check(&config, &fixture.workspace());
    assert!(
        mentions(
            &found,
            "scanning lists targets in edges.toml and its crate does not depend on it: a line nothing uses"
        ),
        "{found:#?}"
    );
    // A pending module is held to the ceiling only.
    text = text.replace("status = \"ported\"", "status = \"pending\"");
    assert!(check(&Config::parse(&text).unwrap(), &fixture.workspace()).is_empty());
}

#[test]
fn a_ported_module_without_its_crate_fails() {
    let text = common::CONFIG.replace("[module.issues]\nstatus = \"pending\"", "[module.issues]\nstatus = \"ported\"");
    let config = Config::parse(&text).unwrap();
    // The clean workspace has an issues crate; take a config that ports a module that has none.
    let text = text.replace("[module.platform]\nstatus = \"pending\"", "[module.platform]\nstatus = \"ported\"");
    let found = check(&Config::parse(&text).unwrap(), &Fixture::clean().workspace());
    assert!(
        mentions(&found, "platform is `ported` in edges.toml and the workspace has no crate vectispire-cp-platform"),
        "{found:#?}"
    );
    assert!(check(&config, &Fixture::clean().workspace()).is_empty());
}

#[test]
fn the_agent_linking_control_plane_code_fails() {
    let mut fixture = Fixture::clean();
    fixture.depends("vectispire-agent", &["vectispire-domain", "vectispire-git", "vectispire-cp-access"]);
    let found = violations(&fixture);
    assert!(
        mentions(
            &found,
            "vectispire-agent links vectispire-cp-access: control-plane code is never a dependency of the agent"
        ),
        "{found:#?}"
    );
}

#[test]
fn what_the_two_programs_share_linking_the_control_plane_fails() {
    let mut fixture = Fixture::clean();
    fixture.depends("vectispire-domain", &["vectispire-cp-db"]);
    let found = violations(&fixture);
    assert!(mentions(&found, "vectispire-domain links vectispire-cp-db"), "{found:#?}");
}

#[test]
fn a_module_using_infrastructure_no_module_may_use_fails() {
    let mut fixture = Fixture::clean();
    fixture.depends(
        "vectispire-cp-targets",
        &["vectispire-cp-access", "vectispire-cp-db", "sqlx", "vectispire-domain", "vectispire-cp-runtime"],
    );
    let found = violations(&fixture);
    assert!(
        mentions(&found, "targets depends on vectispire-cp-runtime: infrastructure no module may use"),
        "{found:#?}"
    );
}

#[test]
fn infrastructure_using_a_module_fails() {
    // core.config, in Java: it uses no module.
    let mut fixture = Fixture::clean();
    fixture.depends("vectispire-cp-db", &["sqlx", "vectispire-cp-access"]);
    let found = violations(&fixture);
    assert!(
        mentions(&found, "vectispire-cp-db depends on module access: infrastructure sits under every module"),
        "{found:#?}"
    );
}

#[test]
fn the_binary_may_use_every_module_and_nothing_may_use_the_binary() {
    let mut fixture = Fixture::clean();
    assert!(violations(&fixture).is_empty(), "the clean app depends on every module");
    // platform is open, and not among the binary's own dependencies in this fixture: no cycle.
    fixture.module("platform", &["vectispire-cp-app"]);
    let found = violations(&fixture);
    assert!(mentions(&found, "platform depends on vectispire-cp-app: infrastructure no module may use"), "{found:#?}");
    fixture.krate("vectispire-cp-runtime", &["vectispire-cp-app"], &[], false);
    let found = violations(&fixture);
    assert!(mentions(&found, "vectispire-cp-runtime depends on the binary"), "{found:#?}");
}

#[test]
fn a_module_depending_on_a_workspace_crate_outside_the_shared_list_fails() {
    let mut fixture = Fixture::clean();
    fixture.krate("vectispire-extra", &[], &[], false);
    fixture.depends(
        "vectispire-cp-targets",
        &["vectispire-cp-access", "vectispire-cp-db", "sqlx", "vectispire-domain", "vectispire-extra"],
    );
    let found = violations(&fixture);
    assert!(
        mentions(&found, "targets depends on vectispire-extra, a workspace crate that is not in `shared`"),
        "{found:#?}"
    );
}

#[test]
fn a_pure_crate_linking_a_driver_fails() {
    let mut fixture = Fixture::clean();
    fixture.depends("vectispire-domain", &["sqlx"]);
    let found = violations(&fixture);
    assert!(mentions(&found, "vectispire-domain is a pure crate and links [\"sqlx\"]"), "{found:#?}");
}

#[test]
fn an_open_module_may_use_any_module() {
    // platform is the shell: it lists nothing and may use anything.
    let mut fixture = Fixture::clean();
    fixture.module("platform", &["vectispire-cp-issues", "vectispire-cp-access"]);
    let found = violations(&fixture);
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn an_inconsistent_edge_list_is_refused() {
    let cycle = common::CONFIG.replace(
        "[module.access]\nstatus = \"pending\"\nallowed = []",
        "[module.access]\nstatus = \"pending\"\nallowed = [\"targets\"]",
    );
    let error = Config::parse(&cycle).unwrap_err();
    assert!(error.contains("a cycle in edges.toml"), "{error}");

    let missing =
        common::CONFIG.replace("allowed = [\"access\", \"access::security\"]", "allowed = [\"access\", \"nowhere\"]");
    assert!(Config::parse(&missing).unwrap_err().contains("no module nowhere"));

    let interface = common::CONFIG.replace("\"access::security\", \"targets\"]", "\"access::secrets\", \"targets\"]");
    assert!(Config::parse(&interface).unwrap_err().contains("which access does not expose"));

    let open = common::CONFIG.replace("open = true\nallowed = []", "open = true\nallowed = [\"access\"]");
    assert!(Config::parse(&open).unwrap_err().contains("an open module lists none"));
}

// ── the shared modules: Java's foundation, `@Modulithic(sharedModules)` ──────────────────────────────────────

/// The clean config with `module` no longer shared: what the same workspace looks like without the rule.
fn unshared(module: &str) -> Config {
    let header = format!("[module.{module}]\nstatus = \"pending\"\nallowed = []\nshared = true\n");
    assert!(common::CONFIG.contains(&header), "{module} is shared in the fixture's config");
    Config::parse(&common::CONFIG.replace(&header, &format!("[module.{module}]\nstatus = \"pending\"\nallowed = []\n")))
        .unwrap()
}

#[test]
fn a_domain_uses_a_shared_module_without_listing_it() {
    // targets uses audit in the clean workspace and does not list it; scanning takes settings too.
    let mut fixture = Fixture::clean();
    fixture.depends(
        "vectispire-cp-scanning",
        &["vectispire-cp-access", "vectispire-cp-targets", "vectispire-cp-db", "vectispire-cp-settings"],
    );
    let found = violations(&fixture);
    assert!(found.is_empty(), "{found:#?}");

    // The rule, and nothing else, admits them: the same workspace with audit no longer shared fails on targets.
    let found = check(&unshared("audit"), &fixture.workspace());
    assert!(
        mentions(&found, "targets depends on audit, which its allowedDependencies in edges.toml do not list"),
        "{found:#?}"
    );
    let found = check(&unshared("settings"), &fixture.workspace());
    assert!(
        mentions(&found, "scanning depends on settings, which its allowedDependencies in edges.toml do not list"),
        "{found:#?}"
    );
}

#[test]
fn a_shared_module_using_another_unlisted_fails() {
    // Modulith would allow it — it adds the shared modules to the foundation's own lists — and
    // `ModularityTest.eachModuleDeclaresExactlyWhatItUses` is what refuses it. So does this.
    let mut fixture = Fixture::clean();
    fixture.depends("vectispire-cp-audit", &["vectispire-cp-db", "vectispire-cp-settings"]);
    let found = violations(&fixture);
    assert!(
        mentions(
            &found,
            "audit depends on settings, which its allowedDependencies in edges.toml do not list: both are shared"
        ),
        "{found:#?}"
    );
    // Listed, with its reason, it is a decision taken.
    let text = common::CONFIG.replace(
        "[module.audit]\nstatus = \"pending\"\nallowed = []",
        "[module.audit]\nstatus = \"pending\"\nallowed = [\"settings\"]",
    );
    let found = check(&Config::parse(&text).unwrap(), &fixture.workspace());
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn a_shared_module_using_a_domain_unlisted_fails() {
    // Shared is a direction: the foundation may not use a domain it does not list.
    let mut fixture = Fixture::clean();
    fixture.depends("vectispire-cp-settings", &["vectispire-cp-db", "vectispire-cp-inventory"]);
    fixture.module("inventory", &["vectispire-cp-access", "vectispire-cp-targets"]);
    let found = violations(&fixture);
    assert!(
        mentions(&found, "settings depends on inventory, which its allowedDependencies in edges.toml do not list"),
        "{found:#?}"
    );
}

#[test]
fn a_shared_module_listing_a_domain_closes_a_cycle_and_is_refused() {
    // Every domain may use audit, so audit listing targets is targets → audit → targets.
    let text = common::CONFIG.replace(
        "[module.audit]\nstatus = \"pending\"\nallowed = []",
        "[module.audit]\nstatus = \"pending\"\nallowed = [\"targets\"]",
    );
    let error = Config::parse(&text).unwrap_err();
    assert!(error.contains("a cycle in edges.toml"), "{error}");
    // The cycle goes through the unlisted edge: without the sharing, the same list has none.
    let text = text.replace("allowed = [\"targets\"]\nshared = true\n", "allowed = [\"targets\"]\n");
    assert!(Config::parse(&text).is_ok());
}

#[test]
fn the_shared_modules_come_first_in_the_porting_order() {
    let config = config();
    let order = config.porting_order().unwrap();
    let position = |module: &str| order.iter().position(|m| m == module).unwrap();
    for domain in ["access", "targets", "scanning", "issues", "inventory"] {
        assert!(position("audit") < position(domain), "{order:?}");
        assert!(position("settings") < position(domain), "{order:?}");
    }
}

#[test]
fn a_domain_listing_a_shared_module_is_refused() {
    let text = common::CONFIG.replace(
        "allowed = [\"access\", \"access::security\"]",
        "allowed = [\"access\", \"access::security\", \"audit\"]",
    );
    let error = Config::parse(&text).unwrap_err();
    assert!(error.contains("targets lists audit, a shared module: a domain does not list the foundation"), "{error}");
}

#[test]
fn a_shared_module_is_not_open() {
    let text = common::CONFIG.replace(
        "[module.audit]\nstatus = \"pending\"\nallowed = []\nshared = true",
        "[module.audit]\nstatus = \"pending\"\nallowed = []\nopen = true\nshared = true",
    );
    let error = Config::parse(&text).unwrap_err();
    assert!(error.contains("audit is open and shared"), "{error}");
}

#[test]
fn a_list_or_a_sharing_without_its_reason_is_refused() {
    let text = common::CONFIG.replace("reason = \"a scan is of a target\"\n", "");
    let error = Config::parse(&text).unwrap_err();
    assert!(
        error.contains("scanning lists [\"access::security\", \"targets\"] without a reason beside them"),
        "{error}"
    );

    let blank = common::CONFIG.replace("reason = \"a scan is of a target\"", "reason = \"  \"");
    assert!(Config::parse(&blank).unwrap_err().contains("scanning lists"));

    let text = common::CONFIG.replace("reason = \"read by every domain\"\n", "");
    let error = Config::parse(&text).unwrap_err();
    assert!(error.contains("settings is shared without a reason beside it"), "{error}");

    // A module that lists nothing and is not shared has nothing to justify.
    assert!(!common::CONFIG.contains("[module.access]\nstatus = \"pending\"\nallowed = []\nreason"));
    assert!(Config::parse(common::CONFIG).is_ok());
}
