//! `/actuator/**` mounted behind the chain, and who may read it — `ActuatorAccess` and `PrometheusScrapeTest`: an
//! administrator's session for every page beyond `health`, and the **scrape token** on `/actuator/prometheus` alone,
//! compared in constant time, refused everywhere else as any unknown bearer is.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use common::*;
use vectispire_cp_http::actuator::{ActuatorPage, ActuatorPages};
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{BoxFuture, RecordingAudit, ScrapeToken};
use vectispire_cp_http::routes::Routes;
use vectispire_cp_http::{Access, Route};
use vectispire_domain::secret::Secret;

const SCRAPE: &str = "apitest-scrape-token-0123456789abcdef";

/// The pages as the actuator answers them: a page per path, the census failing on demand.
#[derive(Debug)]
struct Pages {
    census_fails: bool,
}

impl ActuatorPages for Pages {
    fn page<'a>(
        &'a self,
        path: &'a str,
        _query: &'a str,
        base_url: &'a str,
    ) -> BoxFuture<'a, Result<Option<ActuatorPage>, String>> {
        Box::pin(async move {
            let page =
                |status, body: &str| ActuatorPage { status, content_type: Some("text/plain"), body: body.to_owned() };
            Ok(match path {
                "/actuator" => Some(page(200, base_url)),
                "/actuator/health" | "/actuator/metrics" | "/actuator/info" => Some(page(200, path)),
                "/actuator/prometheus" => Some(page(200, "vectispire_scans_running{application=\"vectispire\"} 0.0\n")),
                "/actuator/encryption" if self.census_fails => return Err("the database is down".to_owned()),
                "/actuator/encryption" => Some(page(200, "{}")),
                "/actuator/health/nope" => Some(ActuatorPage { status: 404, content_type: None, body: String::new() }),
                _ => None,
            })
        })
    }
}

/// The token as the settings give it, read at each call: a file rotated, or unreadable.
#[derive(Debug)]
struct Token(Mutex<Result<Option<String>, String>>);

impl ScrapeToken for Token {
    fn token(&self) -> Result<Option<Secret>, String> {
        self.0.lock().unwrap().clone().map(|token| token.map(Secret::new))
    }
}

struct Actuated {
    app: App,
    token: Arc<Token>,
}

fn actuated(census_fails: bool) -> Actuated {
    let audit = Arc::new(RecordingAudit::default());
    let token = Arc::new(Token(Mutex::new(Ok(Some(SCRAPE.to_owned())))));
    let clock = Arc::new(ManualClock::default());
    let trace = vectispire_cp_http::chain::Trace::new();
    let chain = Arc::new(
        Chain::with_clock(ChainConfig::default(), Arc::new(credentials()), audit.clone(), clock.clone())
            .with_scrape_token(token.clone()),
    );
    let router = Routes::new(NameOf)
        .route(
            Route::get("/api/v1/auth/me")
                .requires(Access::Account)
                .names_no_target()
                .allows_pending_password_change()
                .handler(|| async { "me" }),
        )
        .actuator(Arc::new(Pages { census_fails }))
        .build(&chain, None)
        .unwrap();
    Actuated { app: App { router, audit, trace, clock, chain }, token }
}

async fn status(app: &App, path: &str, headers: &[(&str, &str)]) -> u16 {
    send(app, request("GET", path, headers, Body::empty())).await.status().as_u16()
}

async fn as_bearer(app: &App, path: &str, token: &str) -> u16 {
    status(app, path, &[("authorization", &bearer(token))]).await
}

#[tokio::test]
async fn the_scrape_token_reads_the_prometheus_page_and_an_administrator_too() {
    let Actuated { app, .. } = actuated(false);
    let (code, headers, body) = text(
        send(&app, request("GET", "/actuator/prometheus", &[("authorization", &bearer(SCRAPE))], Body::empty())).await,
    )
    .await;
    assert_eq!((code.as_u16(), body.as_str()), (200, "vectispire_scans_running{application=\"vectispire\"} 0.0\n"));
    assert_eq!(headers["content-type"], "text/plain");
    // The scheme without case, as every bearer.
    assert_eq!(status(&app, "/actuator/prometheus", &[("authorization", &format!("BEARER {SCRAPE}"))]).await, 200);
    assert_eq!(as_bearer(&app, "/actuator/prometheus", ADMIN).await, 200);
}

#[tokio::test]
async fn the_scrape_token_opens_nothing_but_that_page() {
    let Actuated { app, .. } = actuated(false);
    // Elsewhere it is an unknown bearer: 401, not the SCIM token's mistake again.
    for elsewhere in ["/actuator/metrics", "/actuator/encryption", "/actuator/info", "/actuator", "/api/v1/auth/me"] {
        assert_eq!(as_bearer(&app, elsewhere, SCRAPE).await, 401, "{elsewhere}");
    }
    // The path matched exactly, not a prefix of it.
    assert_eq!(as_bearer(&app, "/actuator/prometheus/", SCRAPE).await, 401);
    // A bearer only: the key header does not carry it.
    assert_eq!(status(&app, "/actuator/prometheus", &[("x-api-key", SCRAPE)]).await, 401);
    assert!(app.audit.denied.lock().unwrap().is_empty(), "nobody was signed in to be refused");
}

#[tokio::test]
async fn a_wrong_token_or_none_is_refused_as_unauthenticated() {
    let Actuated { app, token } = actuated(false);
    assert_eq!(status(&app, "/actuator/prometheus", &[]).await, 401);
    assert_eq!(as_bearer(&app, "/actuator/prometheus", "apitest-scrape-token-0123456789abcdeX").await, 401);
    assert_eq!(as_bearer(&app, "/actuator/prometheus", &SCRAPE[..SCRAPE.len() - 1]).await, 401, "a prefix of it");
    // Unset, the page answers an administrator's session only.
    *token.0.lock().unwrap() = Ok(None);
    assert_eq!(as_bearer(&app, "/actuator/prometheus", SCRAPE).await, 401);
    assert_eq!(as_bearer(&app, "/actuator/prometheus", ADMIN).await, 200);
    // Rotated in its file: the new one is read at the next scrape, the old one is refused.
    *token.0.lock().unwrap() = Ok(Some("rotated-scrape-token-0123456789abcdefgh".to_owned()));
    assert_eq!(as_bearer(&app, "/actuator/prometheus", SCRAPE).await, 401);
    assert_eq!(as_bearer(&app, "/actuator/prometheus", "rotated-scrape-token-0123456789abcdefgh").await, 200);
}

#[tokio::test]
async fn a_token_file_that_cannot_be_read_fails_the_scrape_rather_than_letting_it_pass_or_ignoring_it() {
    let Actuated { app, token } = actuated(false);
    *token.0.lock().unwrap() = Err("VECTISPIRE_METRICS_SCRAPE_TOKEN_FILE names a file that does not exist".to_owned());
    let (code, _, body) = text(
        send(&app, request("GET", "/actuator/prometheus", &[("authorization", &bearer(SCRAPE))], Body::empty())).await,
    )
    .await;
    assert_eq!(code.as_u16(), 500);
    assert!(!body.contains("does not exist"), "the reason is the log's: {body}");
    // A session resolves before the token is looked at.
    assert_eq!(as_bearer(&app, "/actuator/prometheus", ADMIN).await, 200);
}

/// The scraper's principal is accepted by the Prometheus page's rule alone: however it reached the chain, it reads
/// no other page — `ActuatorAccess.administratorSession()` does not know its authority.
#[tokio::test]
async fn a_scraper_principal_reads_the_prometheus_page_and_nothing_else_wherever_it_came_from() {
    const MINTED: &str = "a-credential-that-resolves-to-the-scraper";
    let audit = Arc::new(RecordingAudit::default());
    let credentials = credentials().session(MINTED, vectispire_cp_http::Principal::metrics_scraper());
    let chain = Arc::new(Chain::with_clock(
        ChainConfig::default(),
        Arc::new(credentials),
        audit.clone(),
        Arc::new(ManualClock::default()),
    ));
    let router = Routes::new(NameOf).actuator(Arc::new(Pages { census_fails: false })).build(&chain, None).unwrap();
    let app = App {
        router,
        audit,
        trace: vectispire_cp_http::chain::Trace::new(),
        clock: Arc::new(ManualClock::default()),
        chain,
    };
    assert_eq!(as_bearer(&app, "/actuator/prometheus", MINTED).await, 200);
    for page in ["/actuator/metrics", "/actuator/encryption", "/actuator/info", "/actuator"] {
        assert_eq!(as_bearer(&app, page, MINTED).await, 403, "{page}");
    }
    let denied = app.audit.denied.lock().unwrap();
    assert_eq!(denied[0].who.as_deref(), Some("metrics-scraper"), "named, not anonymous");
}

#[tokio::test]
async fn every_page_beyond_health_is_an_administrators_session_s_and_no_other_credential_s() {
    let Actuated { app, .. } = actuated(false);
    for page in ["/actuator/metrics", "/actuator/info", "/actuator/encryption", "/actuator/prometheus"] {
        for refused in [READ_KEY, AGENT_KEY, USER, CISO, PENDING] {
            assert_eq!(as_bearer(&app, page, refused).await, 403, "{refused} on {page}");
        }
        assert_eq!(as_bearer(&app, page, ADMIN).await, 200, "{page}");
    }
    assert_eq!(app.audit.denied.lock().unwrap().len(), 20, "every refusal audited");
    // The probe stays open: a container's health check has no session.
    assert_eq!(status(&app, "/actuator/health", &[]).await, 200);
}

#[tokio::test]
async fn what_the_actuator_does_not_expose_is_not_there_and_a_census_that_fails_is_a_failure() {
    let Actuated { app, .. } = actuated(true);
    let (code, _, body) =
        text(send(&app, request("GET", "/actuator/env", &[("authorization", &bearer(ADMIN))], Body::empty())).await)
            .await;
    assert_eq!(code.as_u16(), 404);
    assert!(body.contains("\"code\":\"no-such-route\""), "{body}");
    // An exposed endpoint with nothing at that name: the actuator's bare 404.
    let (code, headers, body) = text(
        send(&app, request("GET", "/actuator/health/nope", &[("authorization", &bearer(ADMIN))], Body::empty())).await,
    )
    .await;
    assert_eq!((code.as_u16(), body.as_str()), (404, ""));
    assert!(!headers.contains_key("content-type"));
    let (code, _, body) = text(
        send(&app, request("GET", "/actuator/encryption", &[("authorization", &bearer(ADMIN))], Body::empty())).await,
    )
    .await;
    assert_eq!(code.as_u16(), 500);
    assert!(!body.contains("database"), "the reason is the log's: {body}");
    // The links name the address the caller used.
    let (_, _, body) = text(
        send(
            &app,
            request(
                "GET",
                "/actuator",
                &[("authorization", &bearer(ADMIN)), ("host", "vs.example:3180")],
                Body::empty(),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(body, "http://vs.example:3180");
}
