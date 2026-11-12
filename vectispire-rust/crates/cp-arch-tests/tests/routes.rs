//! `routes.rs` on descriptors written by hand: the coverage rules, and a registry that lists too little.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vectispire_cp_arch_tests::routes::{ANONYMOUS, Requirement, RouteDescriptor, Scope, check, parse_anonymous};

fn route(path: &str, requirement: Option<Requirement>) -> RouteDescriptor {
    RouteDescriptor {
        method: "GET".to_owned(),
        path: path.to_owned(),
        requirement,
        accepts_api_key: false,
        names_target: false,
        scope: Scope::NotTargetScoped { reason: "the route serves the caller's own preferences".to_owned() },
    }
}

fn target_route(path: &str, requirement: Requirement, scope: Scope) -> RouteDescriptor {
    RouteDescriptor { names_target: true, scope, ..route(path, Some(requirement)) }
}

/// A registry that holds what the real one will: the seven open routes, and routes of every kind.
fn clean() -> Vec<RouteDescriptor> {
    let anonymous = parse_anonymous(ANONYMOUS).unwrap();
    let mut routes: Vec<RouteDescriptor> =
        anonymous.keys().map(|path| route(path, Some(Requirement::Anonymous))).collect();
    routes.push(route("/api/v1/settings", Some(Requirement::Administrator)));
    routes.push(target_route("/api/v1/issues", Requirement::Account, Scope::Resolved));
    routes.push(target_route("/api/v1/repositories/{id}", Requirement::Account, Scope::Refuses404));
    routes.push(target_route("/api/v1/estate", Requirement::GovernanceRead, Scope::Unsettled));
    routes
}

fn violations(routes: &[RouteDescriptor]) -> Vec<String> {
    check(routes, &parse_anonymous(ANONYMOUS).unwrap(), 5)
}

fn mentions(violations: &[String], needle: &str) -> bool {
    violations.iter().any(|violation| violation.contains(needle))
}

#[test]
fn the_clean_registry_has_no_violation() {
    let found = violations(&clean());
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn the_anonymous_list_is_the_seven_of_the_java_control_plane_each_with_a_reason() {
    let anonymous = parse_anonymous(ANONYMOUS).unwrap();
    assert_eq!(anonymous.len(), 7);
    assert!(anonymous.contains_key("/api/v1/auth/login"));
    assert!(anonymous.contains_key("/api/v1/tickets/webhook/{provider}"));
    assert!(parse_anonymous("/a | no\n").is_err(), "a reason that is not one");
    assert!(parse_anonymous("/a\n").is_err());
    assert!(parse_anonymous("/a | a real reason here\n/a | another reason here\n").is_err(), "twice");
}

#[test]
fn a_route_with_no_requirement_fails() {
    let mut routes = clean();
    routes.push(route("/api/v1/forgotten", None));
    assert!(mentions(&violations(&routes), "GET /api/v1/forgotten: no requirement"));
}

#[test]
fn an_anonymous_route_nobody_listed_fails() {
    let mut routes = clean();
    routes.push(route("/api/v1/new-open-thing", Some(Requirement::Anonymous)));
    assert!(mentions(
        &violations(&routes),
        "/api/v1/new-open-thing is open to anonymous callers and anonymous-routes.txt does not list it"
    ));
}

#[test]
fn a_listed_anonymous_route_that_is_not_registered_fails() {
    let mut routes = clean();
    routes.retain(|route| route.path != "/api/v1/crypto/public-key.pub");
    assert!(mentions(
        &violations(&routes),
        "lists /api/v1/crypto/public-key.pub, which no route registers as anonymous"
    ));
}

#[test]
fn target_data_on_a_bare_account_fails() {
    // The twenty-three holes: @RequiresAccount alone over data that belongs to a target.
    let mut routes = clean();
    routes.push(target_route("/api/v1/leaky", Requirement::Account, Scope::Unsettled));
    assert!(mentions(&violations(&routes), "GET /api/v1/leaky: serves a target's data and settles no scope"));

    // WriteAccount names who may call, and admits the roles with a restricted scope: it settles nothing either.
    let mut routes = clean();
    routes.push(target_route("/api/v1/leaky2", Requirement::WriteAccount, Scope::Unsettled));
    assert!(mentions(&violations(&routes), "GET /api/v1/leaky2"));
}

#[test]
fn a_role_that_sees_everything_settles_scope_except_where_an_api_key_is_accepted() {
    let mut routes = clean();
    let mut keyed = target_route("/api/v1/export", Requirement::GovernanceRead, Scope::Unsettled);
    keyed.accepts_api_key = true;
    routes.push(keyed);
    assert!(mentions(&violations(&routes), "GET /api/v1/export: serves a target's data and settles no scope"));

    // With an allowance resolved, the key is narrowed as it must be.
    let mut routes = clean();
    let mut keyed = target_route("/api/v1/export", Requirement::GovernanceRead, Scope::Resolved);
    keyed.accepts_api_key = true;
    routes.push(keyed);
    assert!(violations(&routes).is_empty());
}

#[test]
fn an_exemption_needs_a_reason_and_may_not_name_a_target() {
    let mut routes = clean();
    let mut bare = route("/api/v1/x", Some(Requirement::Account));
    bare.scope = Scope::NotTargetScoped { reason: "admin".to_owned() };
    routes.push(bare);
    assert!(mentions(&violations(&routes), "declared not target-scoped without a reason"));

    let mut routes = clean();
    routes.push(target_route(
        "/api/v1/y",
        Requirement::Administrator,
        Scope::NotTargetScoped { reason: "an administrator sees all of it".to_owned() },
    ));
    assert!(mentions(&violations(&routes), "names a target and claims to serve nothing target-scoped"));
}

#[test]
fn a_registry_that_lists_too_little_fails() {
    // The failure mode that let three holes through: a rule that inspected nothing.
    let found = check(&[], &parse_anonymous(ANONYMOUS).unwrap(), 5);
    assert!(
        mentions(&found, "the registry lists 0 routes, expected at least 5: the check read too little"),
        "{found:#?}"
    );
}
