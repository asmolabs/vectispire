//! **A key that could not be verified is answered 503, not 401** — `BearerAuthenticationFilter`'s catch of
//! `DerivationsSaturated`: an API key is verified as a password is, under the bound on derivations, and with no permit
//! free nothing was compared. Read as no credential, a valid key under load was refused as if it were wrong.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use axum::body::Body;
use common::*;
use vectispire_cp_http::chain::{Chain, ChainConfig, Trace};
use vectispire_cp_http::credentials::{BoxFuture, Credentials, KeyLookup, RecordingAudit, StaticCredentials};
use vectispire_cp_http::principal::Principal;

const BUSY: &str = "vs_busy-key";

/// The test's credentials, but a key the gate had no permit for.
#[derive(Debug)]
struct Saturated(StaticCredentials);

impl Credentials for Saturated {
    fn session<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Principal>> {
        Credentials::session(&self.0, token)
    }

    fn api_key<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Principal>> {
        Credentials::api_key(&self.0, token)
    }

    fn api_key_lookup<'a>(&'a self, token: &'a str) -> BoxFuture<'a, KeyLookup> {
        Box::pin(async move {
            if token == BUSY {
                return KeyLookup::Busy {
                    detail: "Too many passwords are being verified at once. Try again in a few seconds.".to_owned(),
                    retry_after_seconds: 2,
                };
            }
            match Credentials::api_key(&self.0, token).await {
                Some(found) => KeyLookup::Found(found),
                None => KeyLookup::Absent,
            }
        })
    }

    fn scim<'a>(&'a self, token: &'a str) -> BoxFuture<'a, bool> {
        Credentials::scim(&self.0, token)
    }
}

fn saturated_app() -> App {
    let audit = Arc::new(RecordingAudit::default());
    let trace = Trace::new();
    let clock = Arc::new(ManualClock::default());
    let chain = Arc::new(
        Chain::with_clock(ChainConfig::default(), Arc::new(Saturated(credentials())), audit.clone(), clock.clone())
            .with_trace(trace.clone()),
    );
    let router = routes().build(&chain, None).expect("no route twice");
    App { router, audit, trace, clock, chain }
}

#[tokio::test]
async fn a_key_the_gate_could_not_verify_is_a_503_with_its_wait_in_both_places() {
    let app = saturated_app();
    for headers in [vec![("authorization", bearer(BUSY))], vec![("x-api-key", BUSY.to_owned())]] {
        let headers: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let (status, response_headers, body) =
            text(send(&app, request("GET", "/api/v1/_t/account", &headers, Body::empty())).await).await;
        assert_eq!(status, 503, "{body}");
        assert_eq!(response_headers.get("retry-after").map(|v| v.to_str().unwrap()), Some("2"));
        assert_eq!(
            body,
            r#"{"title":"Service Unavailable","status":503,"detail":"Too many passwords are being verified at once. Try again in a few seconds.","instance":"/api/v1/_t/account","code":"unavailable","retryAfterSeconds":2}"#
        );
    }
    // A key that is merely unknown is still no credential.
    let (status, _, _) = text(
        send(&app, request("GET", "/api/v1/_t/account", &[("authorization", &bearer("vs_unknown"))], Body::empty()))
            .await,
    )
    .await;
    assert_eq!(status, 401);
}
