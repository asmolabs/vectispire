//! The three limiters, the per-key budget and the way an address is resolved — each asserted in the chain that ships,
//! as the Java `BearerThrottleWiringTest` does: a limiter that counts correctly with a mock chain and wrongly inside the real
//! one stays green in a unit test.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use axum::body::Body;
use common::*;
use std::time::Duration;
use vectispire_cp_http::address::TrustedProxies;
use vectispire_cp_http::chain::ChainConfig;

fn login() -> http::Request<Body> {
    request("POST", "/api/v1/auth/login", &[("content-type", "application/json")], Body::from(r#"{"username":"a"}"#))
}

fn login_from(peer: &str, headers: &[(&str, &str)]) -> http::Request<Body> {
    let mut all = vec![("content-type", "application/json")];
    all.extend_from_slice(headers);
    request_from(peer, "POST", "/api/v1/auth/login", &all, Body::from(r#"{"username":"a"}"#))
}

#[tokio::test]
async fn an_address_has_ten_sign_in_attempts_a_minute_and_the_eleventh_is_refused_with_how_long_to_wait() {
    let app = app();
    for attempt in 1..=10 {
        assert_eq!(send(&app, login()).await.status(), 401, "attempt {attempt}");
    }
    let (status, headers, body) = text(send(&app, login()).await).await;
    assert_eq!(status, 429);
    assert_eq!(headers["retry-after"], "6");
    assert_eq!(headers["x-rate-limit-retry-after-seconds"], "6");
    assert!(body.contains(r#""retryAfterSeconds":6"#), "{body}");
    app.clock.advance(Duration::from_secs(6));
    assert_eq!(send(&app, login()).await.status(), 401, "a token is back after six seconds");
}

#[tokio::test]
async fn only_the_sign_in_routes_are_limited_and_only_a_post() {
    let app = app();
    for _ in 0..30 {
        assert_eq!(
            send(&app, request("GET", "/api/v1/whoami", &[("authorization", &bearer(ADMIN))], Body::empty()))
                .await
                .status(),
            200
        );
    }
    for _ in 0..12 {
        send(&app, request("DELETE", "/api/v1/auth/login", &[], Body::empty())).await;
    }
    assert_eq!(send(&app, login()).await.status(), 401, "a DELETE spends nothing of the sign-in budget");
}

#[tokio::test]
async fn a_path_parameter_or_an_encoded_letter_does_not_hide_the_route_from_its_limit() {
    let app = app();
    for _ in 0..10 {
        send(&app, request("POST", "/api/v1/auth/%6Cogin", &[("content-type", "application/json")], Body::from("{}")))
            .await;
    }
    assert_eq!(send(&app, login()).await.status(), 429, "the encoded spelling spent the same budget");
}

#[tokio::test]
async fn an_ipv6_client_spends_its_slash_64_and_not_one_address() {
    let app = app();
    for n in 0..10 {
        send(&app, login_from(&format!("[2001:db8:1:2::{n:x}]:5000"), &[])).await;
    }
    assert_eq!(send(&app, login_from("[2001:db8:1:2:ffff::1]:5000", &[])).await.status(), 429);
    assert_eq!(send(&app, login_from("[2001:db8:1:3::1]:5000", &[])).await.status(), 401, "another /64 has its own");
}

#[tokio::test]
async fn behind_a_trusted_proxy_the_client_is_counted_not_the_proxy() {
    let config =
        ChainConfig { trusted_proxies: TrustedProxies::parse("10.0.0.0/8").expect("a list"), ..ChainConfig::default() };
    let app = app_with(config, None);
    for _ in 0..10 {
        send(&app, login_from("10.1.1.1:5000", &[("x-forwarded-for", "198.51.100.7")])).await;
    }
    assert_eq!(send(&app, login_from("10.1.1.1:5000", &[("x-forwarded-for", "198.51.100.7")])).await.status(), 429);
    assert_eq!(
        send(&app, login_from("10.1.1.1:5000", &[("x-forwarded-for", "198.51.100.8")])).await.status(),
        401,
        "another client, same proxy"
    );
}

#[tokio::test]
async fn with_no_trusted_proxy_a_forwarded_header_is_not_believed() {
    let app = app();
    for n in 0..10 {
        send(&app, login_from("203.0.113.9:5000", &[("x-forwarded-for", &format!("198.51.100.{n}"))])).await;
    }
    assert_eq!(
        send(&app, login_from("203.0.113.9:5000", &[("x-forwarded-for", "198.51.100.99")])).await.status(),
        429,
        "one peer, one bucket"
    );
}

#[tokio::test]
async fn a_ceiling_of_zero_falls_back_to_the_shipped_one_instead_of_locking_the_deployment_out() {
    let config = ChainConfig { login_attempts: 0, login_window: Duration::ZERO, ..ChainConfig::default() };
    let app = app_with(config, None);
    for _ in 0..10 {
        assert_eq!(send(&app, login()).await.status(), 401);
    }
    assert_eq!(send(&app, login()).await.status(), 429);
}

fn refused_token() -> http::Request<Body> {
    request("GET", "/api/v1/repositories", &[("authorization", "Bearer zsk_not-a-real-key")], Body::empty())
}

#[tokio::test]
async fn an_address_spending_its_allowance_on_refused_tokens_is_answered_429_and_audited_once() {
    let app = app();
    for attempt in 1..=60 {
        assert_eq!(send(&app, refused_token()).await.status(), 401, "attempt {attempt}");
    }
    let (status, headers, body) = text(send(&app, refused_token()).await).await;
    assert_eq!(status, 429);
    assert!(headers.contains_key("retry-after"));
    assert!(body.contains("Too many refused credentials from this address. Try again in 5 seconds."), "{body}");
    let throttled = app.audit.throttled.lock().expect("lock");
    assert_eq!(throttled.len(), 1, "the entry is written when the ceiling is reached, not on each refusal after it");
    assert!(
        throttled[0].detail.contains("60 bearer tokens refused from this address within PT5M"),
        "{}",
        throttled[0].detail
    );
    assert_eq!(throttled[0].address, "203.0.113.9");
}

#[tokio::test]
async fn a_token_that_resolves_is_never_counted_however_many_times_it_is_used() {
    let app = app();
    for _ in 0..65 {
        assert_eq!(
            send(&app, request("GET", "/api/v1/whoami", &[("authorization", &bearer(ADMIN))], Body::empty()))
                .await
                .status(),
            200
        );
    }
}

#[tokio::test]
async fn a_request_with_no_credential_at_all_is_not_a_credential_attempt() {
    let app = app();
    for _ in 0..65 {
        assert_eq!(send(&app, request("GET", "/api/v1/repositories", &[], Body::empty())).await.status(), 401);
    }
    assert_eq!(
        send(&app, request("GET", "/api/v1/whoami", &[("authorization", &bearer(ADMIN))], Body::empty()))
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn a_basic_credential_is_not_a_bearer_attempt_but_a_blank_api_key_header_is_not_one_either() {
    let app = app();
    for _ in 0..65 {
        send(&app, request("GET", "/api/v1/repositories", &[("authorization", "Basic YTpi")], Body::empty())).await;
        send(&app, request("GET", "/api/v1/repositories", &[("x-api-key", "  ")], Body::empty())).await;
    }
    assert_eq!(
        send(&app, request("GET", "/api/v1/whoami", &[("authorization", &bearer(ADMIN))], Body::empty()))
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn a_refused_api_key_header_counts_like_a_refused_bearer() {
    let app = app();
    for _ in 0..60 {
        send(&app, request("GET", "/api/v1/repositories", &[("x-api-key", "zsk_wrong")], Body::empty())).await;
    }
    assert_eq!(
        send(&app, request("GET", "/api/v1/repositories", &[("x-api-key", "zsk_wrong")], Body::empty())).await.status(),
        429
    );
}

#[tokio::test]
async fn the_bearer_scheme_is_matched_without_case_and_a_good_token_after_the_ceiling_is_still_refused() {
    let app = app();
    for _ in 0..60 {
        send(&app, refused_token()).await;
    }
    // The ceiling is the address's: it refuses before the token is looked at, as the Java filter does.
    let refused =
        send(&app, request("GET", "/api/v1/whoami", &[("authorization", &format!("bEaReR {ADMIN}"))], Body::empty()))
            .await;
    assert_eq!(refused.status(), 429);
    app.clock.advance(Duration::from_secs(10));
    let admitted =
        send(&app, request("GET", "/api/v1/whoami", &[("authorization", &format!("bEaReR {ADMIN}"))], Body::empty()))
            .await;
    assert_eq!(admitted.status(), 200);
}

#[tokio::test]
async fn an_integration_key_has_a_budget_of_its_own_per_minute_and_a_429_that_says_how_long() {
    let app = app();
    let call = || request("GET", "/api/v1/repositories", &[("authorization", &bearer(READ_KEY))], Body::empty());
    for attempt in 1..=600 {
        assert_eq!(send(&app, call()).await.status(), 200, "call {attempt}");
    }
    let (status, headers, body) = text(send(&app, call()).await).await;
    assert_eq!(status, 429);
    assert_eq!(headers["retry-after"], "1");
    assert_eq!(
        body,
        r#"{"detail":"This API key has made too many requests. Try again in 1 seconds.","instance":"/api/v1/repositories","status":429,"title":"Too Many Requests","retryAfterSeconds":1}"#
    );
    // The session of the same account is not the key's budget.
    assert_eq!(
        send(&app, request("GET", "/api/v1/repositories", &[("authorization", &bearer(ADMIN))], Body::empty()))
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn the_tracker_webhook_has_a_budget_per_address_and_refuses_before_any_secret_is_read() {
    let app = app();
    let delivery = || request("POST", "/api/v1/tickets/webhook/abc", &[], Body::from("{}"));
    for attempt in 1..=300 {
        assert_eq!(send(&app, delivery()).await.status(), 200, "delivery {attempt}");
    }
    let (status, headers, body) = text(send(&app, delivery()).await).await;
    assert_eq!(status, 429);
    assert_eq!(headers["retry-after"], "1");
    assert!(body.starts_with(r#"{"title":"Too Many Requests","status":429,"detail":"Too many webhook deliveries from this address. Try again in 1 seconds.""#), "{body}");
    assert_eq!(
        send(&app, request_from("203.0.113.10:1", "POST", "/api/v1/tickets/webhook/abc", &[], Body::from("{}")))
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn a_webhook_delivery_over_its_ceiling_is_refused_by_the_body_limit_before_the_handler() {
    let app = app();
    let declared = (1024 * 1024 + 1).to_string();
    let refused =
        send(&app, request("POST", "/api/v1/tickets/webhook/abc", &[("content-length", &declared)], Body::empty()))
            .await;
    assert_eq!(refused.status(), 413);
}
