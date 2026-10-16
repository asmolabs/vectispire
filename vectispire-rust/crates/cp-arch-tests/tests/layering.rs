//! `layering.rs` on synthetic module crates: silent on the clean layout, loud on each way across a layer.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, config};
use vectispire_cp_arch_tests::layering::{Outcome, check_workspace};

fn check(fixture: &Fixture) -> Outcome {
    check_workspace(&config(), &fixture.workspace())
}

fn found(outcome: &Outcome, needle: &str) -> bool {
    outcome.violations.iter().any(|violation| violation.contains(needle))
}

const WEB: &str = "vectispire-cp-targets";

#[test]
fn the_clean_layout_has_no_violation_and_the_check_read_something() {
    let outcome = check(&Fixture::clean());
    assert!(outcome.violations.is_empty(), "{:#?}", outcome.violations);
    // A rule that read nothing is the failure mode: four module crates, their files and their paths.
    assert!(outcome.crates >= 4, "crates read: {}", outcome.crates);
    assert!(outcome.files >= 16, "files read: {}", outcome.files);
    assert!(outcome.paths >= 4, "paths read: {}", outcome.paths);
}

#[test]
fn web_naming_persistence_fails() {
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/web/mod.rs", "pub(crate) fn routes() { crate::persistence::rows(); }\n");
    let outcome = check(&fixture);
    assert!(found(&outcome, "web names persistence (`crate::persistence::rows`)"), "{:#?}", outcome.violations);
}

#[test]
fn web_naming_persistence_by_a_relative_path_fails() {
    // `super::super::persistence` from `src/web/routes.rs` is `crate::persistence`: the rule reads where the use sits.
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/web/routes.rs", "pub(crate) fn go() { super::super::persistence::rows(); }\n");
    fixture.append(WEB, "src/web/mod.rs", "mod routes;\n");
    let outcome = check(&fixture);
    assert!(found(&outcome, "src/web/routes.rs:1: web names persistence"), "{:#?}", outcome.violations);
}

#[test]
fn web_naming_persistence_by_a_use_and_a_bare_module_name_fails() {
    // From the root file a bare `persistence::rows()` is the crate's own module, not a registry crate.
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/web/mod.rs", "use crate::persistence::rows;\npub(crate) fn routes() { rows(); }\n");
    let outcome = check(&fixture);
    assert!(found(&outcome, "web names persistence (`crate::persistence::rows`)"), "{:#?}", outcome.violations);
}

#[test]
fn web_holding_a_query_api_or_the_pool_fails() {
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/web/mod.rs", "pub(crate) fn routes() { sqlx::query(\"x\"); }\n");
    assert!(found(&check(&fixture), "web names `sqlx::query`: a controller holds nothing of the query API"));

    let fixture = Fixture::clean();
    fixture.write(WEB, "src/web/mod.rs", "use vectispire_cp_db::Pool;\npub(crate) fn routes() {}\n");
    assert!(found(&check(&fixture), "web names `vectispire_cp_db::Pool`"));
}

#[test]
fn a_query_api_inside_a_macro_is_seen() {
    // `sqlx::query!` and `format!("{:?}", sqlx::query(..))` keep their paths in tokens.
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/web/mod.rs", "pub(crate) fn routes() { let _ = format!(\"{:?}\", sqlx::query(\"a\")); }\n");
    let outcome = check(&fixture);
    assert!(found(&outcome, "web names `sqlx::query`"), "{:#?}", outcome.violations);
}

#[test]
fn a_query_api_in_a_derive_is_seen() {
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/web/mod.rs", "#[derive(sqlx::FromRow)]\nstruct Row;\npub(crate) fn routes() {}\n");
    assert!(found(&check(&fixture), "web names `sqlx::FromRow`"));
}

#[test]
fn a_service_holding_a_query_api_fails() {
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/internal/mod.rs", "pub(crate) fn list() { sqlx::query(\"select 1\"); }\n");
    let outcome = check(&fixture);
    assert!(
        found(&outcome, "the root names `sqlx::query`")
            || found(&outcome, "internal names `sqlx::query`: a service holds no query API"),
        "{:#?}",
        outcome.violations
    );

    // The root's own files are the service layer too.
    let fixture = Fixture::clean();
    fixture.append(WEB, "src/lib.rs", "pub fn helper() { sqlx::query(\"x\"); }\n");
    assert!(found(&check(&fixture), "the root names `sqlx::query`: a service holds no query API"));
}

#[test]
fn persistence_naming_a_service_fails() {
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/persistence/mod.rs", "pub(crate) fn rows() { crate::internal::list(); }\n");
    let outcome = check(&fixture);
    assert!(found(&outcome, "persistence names internal (`crate::internal::list`)"), "{:#?}", outcome.violations);

    let fixture = Fixture::clean();
    fixture.write(WEB, "src/persistence/mod.rs", "pub(crate) fn rows() { let _ = crate::View; }\n");
    assert!(found(&check(&fixture), "persistence names the root (`crate::View`)"));
}

#[test]
fn persistence_naming_http_fails() {
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/persistence/mod.rs", "pub(crate) fn rows() { axum::query(\"x\"); }\n");
    assert!(found(
        &check(&fixture),
        "persistence names `axum::query`: nothing in the persistence layer knows about HTTP"
    ));
}

#[test]
fn a_layer_naming_web_fails_except_the_root_file() {
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/internal/mod.rs", "pub(crate) fn list() { crate::web::routes(); }\n");
    assert!(found(
        &check(&fixture),
        "internal names web (`crate::web::routes`): nothing reaches the api layer but the crate's root file"
    ));
    // The root file hands the routes to the application, and may.
    assert!(check(&Fixture::clean()).violations.is_empty());
}

#[test]
fn a_public_private_layer_fails() {
    let fixture = Fixture::clean();
    fixture.replace(WEB, "src/lib.rs", "mod persistence;", "pub mod persistence;");
    assert!(found(&check(&fixture), "`pub mod persistence` opens a module's private layer to every crate"));
    let fixture = Fixture::clean();
    fixture.replace(WEB, "src/lib.rs", "mod web;", "pub mod web;");
    assert!(found(&check(&fixture), "`pub mod web`"));
    // pub(crate) is the other way of saying private.
    let fixture = Fixture::clean();
    fixture.replace(WEB, "src/lib.rs", "mod web;", "pub(crate) mod web;");
    assert!(check(&fixture).violations.is_empty());
}

#[test]
fn a_directory_that_is_no_layer_fails() {
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/helpers/mod.rs", "pub fn x() {}\n");
    fixture.append(WEB, "src/lib.rs", "mod helpers;\n");
    assert!(found(&check(&fixture), "src/helpers/mod.rs:1: this directory is no layer of a module"));
}

#[test]
fn a_named_interface_directory_is_a_place() {
    // access::security is declared in the list, so `src/security/` is the module's, not a stray directory.
    assert!(check(&Fixture::clean()).violations.is_empty());
}

#[test]
fn a_path_attribute_fails() {
    let fixture = Fixture::clean();
    fixture.append(WEB, "src/lib.rs", "#[path = \"web/mod.rs\"]\nmod again;\n");
    assert!(found(&check(&fixture), "#[path] hides where `again` sits"));
}

#[test]
fn a_file_that_does_not_parse_is_a_violation_not_a_skip() {
    let fixture = Fixture::clean();
    fixture.write(WEB, "src/web/mod.rs", "pub(crate) fn routes( {\n");
    assert!(found(&check(&fixture), "unreadable"));
}

#[test]
fn test_code_is_not_held_to_the_layers() {
    // ArchUnit imports no tests: a `#[cfg(test)]` module may reach for what the layer may not.
    let fixture = Fixture::clean();
    fixture.append(WEB, "src/web/mod.rs", "#[cfg(test)]\nmod tests {\n    use sqlx::query;\n    fn t() { crate::persistence::rows(); query(\"x\"); }\n}\n");
    let outcome = check(&fixture);
    assert!(outcome.violations.is_empty(), "{:#?}", outcome.violations);
    // And the same code outside `cfg(test)` is flagged.
    let fixture = Fixture::clean();
    fixture.append(WEB, "src/web/mod.rs", "mod tests {\n    use sqlx::query;\n}\n");
    assert!(found(&check(&fixture), "web names `sqlx::query`"));
}

#[test]
fn a_module_using_another_modules_root_when_only_an_interface_is_listed_fails() {
    // scanning lists access::security, not access: its root is not scanning's to use.
    let fixture = Fixture::clean();
    fixture.write(
        "vectispire-cp-scanning",
        "src/internal/mod.rs",
        "pub(crate) fn list() { let _ = vectispire_cp_access::View; crate::persistence::rows(); }\n",
    );
    let outcome = check(&fixture);
    assert!(
        found(
            &outcome,
            "uses access's root, which scanning's allowedDependencies do not list (only a named interface of access is)"
        ),
        "{:#?}",
        outcome.violations
    );

    // The listed interface is fine.
    let fixture = Fixture::clean();
    fixture.write(
        "vectispire-cp-scanning",
        "src/internal/mod.rs",
        "pub(crate) fn list() { let _ = vectispire_cp_access::security::Guard; crate::persistence::rows(); }\n",
    );
    assert!(check(&fixture).violations.is_empty());
}

#[test]
fn a_module_using_an_interface_it_does_not_list_fails() {
    // targets lists access and access::security, not scanning::queries — but it cannot even depend on scanning; the
    // interface rule is for a crate that may depend on the module and lists only part of it.
    let fixture = Fixture::clean();
    fixture.write(
        "vectispire-cp-issues",
        "src/internal/mod.rs",
        "pub(crate) fn list() { let _ = vectispire_cp_scanning::queries::Guard; crate::persistence::rows(); }\n",
    );
    assert!(check(&fixture).violations.is_empty(), "issues lists scanning::queries");
    // Remove the interface from issues' list and the same line fails.
    let text =
        common::CONFIG.replace("\"scanning\", \"scanning::queries\", \"targets\"]", "\"scanning\", \"targets\"]");
    let config = vectispire_cp_arch_tests::model::Config::parse(&text).unwrap();
    let outcome = check_workspace(&config, &fixture.workspace());
    assert!(
        outcome.violations.iter().any(|v| v.contains(
            "uses scanning's queries interface, which issues's allowedDependencies do not list (scanning::queries)"
        )),
        "{:#?}",
        outcome.violations
    );
}
