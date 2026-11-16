//! **A hidden target is refused as an absent one, before anything is read.** A reader granted repository 1 asks for
//! repository 2's card, its attack graph and its badge, and image 5's card: each is "Target not found.", 404 — never
//! 403. The database here is one nobody listens on, so a route that looked the row up first would answer 500: the
//! order of the guard is what these tests hold, which is what keeps a refusal from confirming that a thing exists.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use vectispire_cp_access::{Allowance, CallerScope};
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{BoxFuture, RecordingAudit, StaticCredentials};
use vectispire_cp_http::principal::{Account, Principal, Role};
use vectispire_cp_http::routes::{Routes, VisibilityOf};

const READER: &str = "tok-reader";

/// Granted repository 1 and nothing else.
struct OneRepository;

impl VisibilityOf<CallerScope> for OneRepository {
    fn of<'a>(&'a self, _principal: &'a Principal) -> BoxFuture<'a, CallerScope> {
        Box::pin(async {
            Ok(Allowance {
                visibility: Visibility::Only(BTreeSet::from([ScanTarget::Repository(1)])),
                granted_projects: BTreeSet::new(),
                narrowed_by_credential: false,
            })
        })
    }
}

fn router() -> axum::Router {
    let account = Account { username: "reader".to_owned(), role: Some(Role::User), must_change_password: false };
    let credentials = StaticCredentials::default().session(READER, Principal::session(account));
    let chain =
        Arc::new(Chain::new(ChainConfig::default(), Arc::new(credentials), Arc::new(RecordingAudit::default())));
    let mut routes = Routes::new(OneRepository);
    for entry in support::module().routes() {
        routes = routes.route(entry);
    }
    routes.build(&chain, None).unwrap()
}

async fn ask(router: &axum::Router, method: &str, uri: &str) -> (StatusCode, String) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {READER}"))
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo("203.0.113.9:40000".parse::<SocketAddr>().unwrap()));
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn a_hidden_target_is_not_found_before_it_is_looked_up() {
    let router = router();
    let mut answers = BTreeMap::new();
    for (method, uri) in [
        ("GET", "/api/v1/scorecards/repositories/2"),
        ("GET", "/api/v1/scorecards/containers/5"),
        ("GET", "/api/v1/attack-paths/repositories/2"),
        ("GET", "/api/v1/scorecards/repositories/2/badge"),
        ("POST", "/api/v1/scorecards/repositories/2/badge"),
        ("DELETE", "/api/v1/scorecards/repositories/2/badge"),
    ] {
        let (status, body) = ask(&router, method, uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}: {body}");
        assert!(body.contains("\"detail\":\"Target not found.\""), "{method} {uri}: {body}");
        answers.insert(format!("{method} {uri}"), body.replace(uri, "«path»"));
    }
    // One sentence for every hidden target: a second wording would tell one kind of absence from another.
    let distinct: BTreeSet<&String> = answers.values().collect();
    assert_eq!(distinct.len(), 1, "{answers:#?}");
}

#[tokio::test]
async fn the_simulation_is_refused_by_role_before_its_weights_are_read() {
    let (status, _) = ask(&router(), "GET", "/api/v1/scorecards/simulation?k=-1").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_path_variable_that_is_no_number_is_spring_s_400() {
    let (status, body) = ask(&router(), "GET", "/api/v1/scorecards/repositories/abc").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("Failed to convert 'repoId' with value: 'abc'"), "{body}");
}
