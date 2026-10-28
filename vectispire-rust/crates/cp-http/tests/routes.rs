//! The route table a coverage test walks, the duplicate refusal, and the 404 that must not tell an absent row from a hidden one.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use axum::body::Body;
use common::*;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::RecordingAudit;
use vectispire_cp_http::principal::ApiKeyScope;
use vectispire_cp_http::problem::Problem;
use vectispire_cp_http::routes::{NoVisibility, Route, Routes, Visibility, require_visible};

#[test]
fn every_registered_route_is_in_the_table_with_the_two_answers_it_gave() {
    let table = routes().table();
    assert!(table.len() > 20);
    let repositories =
        table.iter().find(|decl| decl.method == "GET" && decl.path == "/api/v1/repositories").expect("declared");
    assert_eq!(repositories.access, Access::Account);
    assert_eq!(repositories.visibility, Visibility::Scoped);
    assert_eq!(repositories.accepts_api_key, Some(ApiKeyScope::Read));
    let users = table.iter().find(|decl| decl.path == "/api/v1/users").expect("declared");
    assert_eq!((users.access, users.visibility), (Access::Administrator, Visibility::NamesNoTarget));
    let me = table.iter().find(|decl| decl.path == "/api/v1/auth/me").expect("declared");
    assert!(me.allows_pending_password_change);
    assert!(!users.allows_pending_password_change, "the default is to refuse while a password change is owed");
    assert_eq!(users.accepts_api_key, None, "a key reaches a route only when the route says so");
}

#[test]
fn the_markers_have_the_java_names_so_a_coverage_test_can_compare_them() {
    assert_eq!(Access::Anonymous.marker(), "OpenToAnonymous");
    assert_eq!(Access::Account.marker(), "RequiresAccount");
    assert_eq!(Access::WriteAccount.marker(), "RequiresWriteAccount");
    assert_eq!(Access::AgentKey.marker(), "RequiresAgentKey");
}

#[test]
fn a_route_registered_twice_is_refused_when_the_router_is_built() {
    async fn handler() {}
    let routes = Routes::<()>::new(NoVisibility)
        .route(Route::get("/x").requires(Access::Account).names_no_target().handler(handler))
        .route(Route::get("/x").requires(Access::Administrator).names_no_target().handler(handler));
    let chain = std::sync::Arc::new(Chain::new(
        ChainConfig::default(),
        std::sync::Arc::new(credentials()),
        std::sync::Arc::new(RecordingAudit::default()),
    ));
    let error = routes.build(&chain, None).expect_err("two routes for one method and path");
    assert_eq!(error.to_string(), "GET /x is registered twice");
}

#[test]
fn two_methods_on_one_path_are_not_a_duplicate() {
    async fn handler() {}
    let routes = Routes::<()>::new(NoVisibility)
        .route(Route::get("/x").requires(Access::Account).names_no_target().handler(handler))
        .route(Route::post("/x").requires(Access::Account).names_no_target().handler(handler));
    let chain = std::sync::Arc::new(Chain::new(
        ChainConfig::default(),
        std::sync::Arc::new(credentials()),
        std::sync::Arc::new(RecordingAudit::default()),
    ));
    assert!(routes.build(&chain, None).is_ok());
}

#[test]
fn an_absent_row_and_one_the_caller_may_not_see_are_the_same_404_to_the_byte() {
    let absent = require_visible(None::<u32>, |_| true, "Project not found.").expect_err("absent");
    let hidden = require_visible(Some(7_u32), |_| false, "Project not found.").expect_err("hidden");
    assert_eq!(absent.status(), 404);
    assert_eq!(absent.body(), hidden.body(), "a refusal that differed would confirm the thing exists");
    assert_eq!(require_visible(Some(7_u32), |row| *row == 7, "Project not found.").expect("visible"), 7);
}

#[test]
fn a_refusal_is_a_404_never_a_403() {
    let refused: Problem = require_visible(Some(1_u32), |_| false, "Repository not found.").expect_err("hidden");
    assert_eq!(refused.status(), http::StatusCode::NOT_FOUND);
    assert_ne!(refused.status(), http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn through_the_chain_a_hidden_row_and_an_absent_one_answer_the_same_bytes() {
    let app = app();
    let ask = |id: u64| {
        request("GET", &format!("/api/v1/projects/{id}"), &[("authorization", &bearer(ADMIN))], Body::empty())
    };
    let (status_a, _, body_a) = text(send(&app, ask(1)).await).await;
    let (status_b, _, body_b) = text(send(&app, ask(987_654_321)).await).await;
    assert_eq!((status_a.as_u16(), status_b.as_u16()), (404, 404));
    assert_eq!(body_a.replace("/api/v1/projects/1", "X"), body_b.replace("/api/v1/projects/987654321", "X"));
}
