//! The eighteen posture routes against the contract they must not change (`openapi.json` of the 0.11.1 line):
//! documented under the same method and path, with Java's operation ids and query parameters, out of `cp-contract`'s
//! `not-yet-ported/` since the commit that ported them — then the router probed, so a route declared and not
//! registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
};
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{RecordingAudit, StaticCredentials};
use vectispire_cp_http::routes::{NoVisibility, Routes};

type QueryParam = (&'static str, bool);
type DeclaredRoute = (&'static str, &'static str, &'static str, &'static [QueryParam]);

mod support;

const BADGE: &str = "/api/v1/scorecards/repositories/{repoId}/badge";

const DECLARED: &[DeclaredRoute] = &[
    ("GET", "/api/v1/dashboard", "overview_2", &[]),
    ("GET", "/api/v1/dashboard/trends", "trends", &[("days", false)]),
    ("GET", "/api/v1/dashboard/posture-analytics", "postureAnalytics", &[("days", false)]),
    ("GET", "/api/v1/quality/overview", "overview_1", &[]),
    ("GET", "/api/v1/remediation/distribution", "distribution", &[("days", false)]),
    ("GET", "/api/v1/remediation/debt", "debt", &[("repoId", false), ("containerId", false)]),
    ("GET", "/api/v1/remediation/coverage", "coverage_1", &[("repoId", false), ("containerId", false)]),
    (
        "GET",
        "/api/v1/remediation/high-impact-fixes",
        "highImpactFixes",
        &[("repoId", false), ("containerId", false), ("limit", false)],
    ),
    ("GET", "/api/v1/attack-paths/repositories/{repoId}", "getRepositoryAttackPath", &[]),
    ("GET", "/api/v1/attack-paths/overview", "getOverview", &[("limit", false), ("offset", false)]),
    ("GET", "/api/v1/scorecards/repositories/{repoId}", "getRepositoryScorecard", &[]),
    ("GET", "/api/v1/scorecards/containers/{containerId}", "getContainerScorecard", &[]),
    ("GET", "/api/v1/scorecards/global", "getGlobalScorecard", &[]),
    (
        "GET",
        "/api/v1/scorecards/simulation",
        "simulateScores",
        &[
            ("exploited", false),
            ("critical", false),
            ("high", false),
            ("medium", false),
            ("low", false),
            ("licence", false),
            ("k", false),
        ],
    ),
    ("GET", BADGE, "badgeState", &[]),
    ("GET", "/api/v1/scorecards/badges/{token}.svg", "getPublishedBadge", &[]),
    ("POST", BADGE, "publishBadge", &[]),
    ("DELETE", BADGE, "revokeBadge", &[]),
];

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let entries = support::module().routes();
    assert_eq!(entries.len(), DECLARED.len());

    let declared: Vec<RouteDecl> = DECLARED
        .iter()
        .map(|(method, path, id, query)| {
            query.iter().fold(RouteDecl::new(method, path, id), |route, (name, required)| route.query(name, *required))
        })
        .collect();
    let document = Document::embedded();
    // Every documented route this module does not declare is another's: the test names none of them, and `cp-app`'s
    // registry test holds the whole partition to the document.
    let ours: BTreeSet<(String, String)> =
        declared.iter().map(|route| (route.method.clone(), route.path.clone())).collect();
    let not_ours = Allowlist::all_but(&document, &ours);
    assert_none(&check_module(&document, &declared, &Allowlist::committed()));
    assert_none(&check_published(&document, &Published::embedded(), Some(&declared)));

    let mut routes = Routes::new(NoVisibility);
    for entry in entries {
        routes = routes.route(entry);
    }
    let chain = Arc::new(Chain::new(
        ChainConfig::default(),
        Arc::new(StaticCredentials::default()),
        Arc::new(RecordingAudit::default()),
    ));
    let router = routes.build(&chain, None).unwrap();
    assert_none(&probe(&router, &document, &not_ours).await);
}
