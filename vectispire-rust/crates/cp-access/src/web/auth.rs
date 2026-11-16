//! `AuthController` (task 1.7, second stage): signing in by password and by second factor, the methods screen, the
//! single sign-on hand-off, signing out, the password change, who am I, and the second factor's enrolment — over the
//! sign-in services of task 1.3.
//!
//! **Every refusal is the controller's `ResponseStatusException`**, in its words and its statuses: 401 for a missing
//! proof of identity (a wrong password, a wrong code, an expired challenge), 429 with `Retry-After` for a budget spent,
//! 503 for challenges or derivations saturated. A throttled answer carries the wait three ways — the `Retry-After`
//! header, `X-Rate-Limit-Retry-After-Seconds`, and the problem's `retryAfterSeconds` — as the sign-in screen reads it.

use std::sync::Arc;

use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Serialize;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem};

use super::read::Fields;
use super::{account_refusal, body_of, ok, unexpected, user_agent};
use crate::accounts::{AccountStore, Audit, PasswordChange, SessionHash, UserView};
use crate::credentials::{CredentialService, IssuedSession};
use crate::second_factor::{SecondFactorError, SecretSeal};
use crate::sign_in::SignInStore;
use crate::sign_in::{Handoff, LoginRequest, SessionDoor, SignIn, SignInError, SignInFlow, Verification};

const AUTH: &str = "/api/v1/auth";

/// `OidcConfiguration.HANDOFF_COOKIE`: the single sign-on's callback hands the browser over through it.
pub const HANDOFF_COOKIE: &str = "zs_handoff";

/// `BrandingProperties`: what the sign-in screen names the product and links to. Blank is the default, trimmed
/// otherwise, as the record's compact constructor reads it.
#[derive(Clone, Debug)]
pub struct Branding {
    pub name: String,
    pub gitlab_url: String,
}

impl Branding {
    pub fn of(name: Option<&str>, gitlab_url: Option<&str>) -> Branding {
        let read = |value: Option<&str>, default: &str| match value.map(vectispire_domain::java::trim) {
            Some(value) if !value.is_empty() => value.to_owned(),
            _ => default.to_owned(),
        };
        Branding {
            name: read(name, "Vectispire"),
            gitlab_url: read(gitlab_url, "https://github.com/asmolabs/vectispire"),
        }
    }
}

/// `UserSummary`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserSummary {
    username: String,
    display_name: Option<String>,
    role: String,
    must_change_password: bool,
    mfa_enabled: bool,
}

impl UserSummary {
    fn of(user: &UserView) -> UserSummary {
        UserSummary {
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            role: user.role.clone(),
            must_change_password: user.must_change_password,
            mfa_enabled: user.mfa_enabled,
        }
    }
}

/// `LoginResponse`: a session, or a second factor to give.
#[derive(Debug, Serialize)]
struct LoginResponse {
    token: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    user: Option<UserSummary>,
    mfa_required: bool,
    mfa_token: Option<String>,
}

impl LoginResponse {
    fn signed_in(issued: &IssuedSession, user: &UserView) -> LoginResponse {
        LoginResponse {
            token: Some(issued.token.expose().to_owned()),
            expires_at: Some(super::json::instant(issued.session.expires_at)),
            user: Some(UserSummary::of(user)),
            mfa_required: false,
            mfa_token: None,
        }
    }
}

/// `SignInMethods`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignInMethods {
    configured: bool,
    label: Option<String>,
    password: bool,
    brand_name: String,
    gitlab_url: String,
}

/// `TotpService.SetupResponse`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupResponse {
    secret: String,
    qr_code_uri: String,
    issuer: &'static str,
}

/// `TotpService.EnableResponse`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EnableResponse {
    success: bool,
    backup_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MfaDisabled {
    mfa_enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasswordChanged {
    must_change_password: bool,
    revoked_api_keys: usize,
}

/// A `ResponseStatusException`: the handler's problem, in the controller's words.
fn refused(status: StatusCode, detail: &str) -> Response {
    Problem::handler(status, detail).into_response()
}

/// `throttled(retryAfter)`: 429, the wait in whole seconds (`toSeconds` truncates), at least one.
fn throttled(retry_after: time::Duration) -> Problem {
    throttled_seconds(retry_after.whole_seconds())
}

fn throttled_seconds(whole_seconds: i64) -> Problem {
    let seconds = whole_seconds.max(1);
    Problem::handler(StatusCode::TOO_MANY_REQUESTS, format!("Too many attempts. Try again in {seconds}s."))
        .with("retryAfterSeconds", seconds)
        .header("Retry-After", seconds.to_string())
        .header("X-Rate-Limit-Retry-After-Seconds", seconds.to_string())
}

fn sign_in_failure(error: SignInError) -> Response {
    match error {
        SignInError::Saturated(saturated) => saturated.problem().into_response(),
        failure => unexpected(AUTH, &failure),
    }
}

/// The hand-off cookie's value, when the request carries a non-blank one.
fn handoff_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, value)| *name == HANDOFF_COOKIE && !vectispire_domain::java::is_blank(value))
        .map(|(_, value)| value.to_owned())
}

/// `clearHandoff`: the cookie emptied and expired, whatever the exchange answers.
fn clear_handoff(response: &mut Response, secure: bool) {
    let mut cookie = format!("{HANDOFF_COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie.push_str("; HttpOnly");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// The routes, over the sign-in flow the binary composes and the credential service sessions are revoked through.
pub fn routes<S, A, T, D, V>(
    flow: Arc<SignInFlow<S, A, T, D, V>>,
    credentials: Arc<CredentialService>,
    branding: Branding,
    entries: &mut Vec<RouteEntry>,
) where
    S: AccountStore + Clone + Send + Sync + 'static,
    A: Audit + Clone + Send + Sync + 'static,
    T: SignInStore + Clone + Send + Sync + 'static,
    D: SessionDoor + 'static,
    V: SecretSeal + 'static,
{
    let login = flow.clone();
    entries.push(Route::post("/api/v1/auth/login").requires(Access::Anonymous).names_no_target().handler(
        move |address: ClientAddress, headers: HeaderMap, request: Request| {
            let flow = login.clone();
            async move {
                let fields = read!(Fields::of(read!(body_of(request).await)));
                let username = read!(fields.text("username")).unwrap_or_default();
                let password = read!(fields.text("password")).unwrap_or_default();
                let code = read!(fields.text("mfa_code"));
                let agent = user_agent(&headers);
                let attempt = LoginRequest {
                    username: &username,
                    password: &password,
                    user_agent: agent.as_deref(),
                    ip_address: Some(&address.0),
                };
                match flow.sign_in_with(&attempt, code.as_deref()).await {
                    Ok(SignIn::PasswordDisabled) => {
                        refused(StatusCode::FORBIDDEN, "Password sign-in is disabled here. Use single sign-on.")
                    }
                    Ok(SignIn::Throttled(wait)) => throttled(wait).into_response(),
                    Ok(SignIn::AccountThrottled(wait)) => throttled(wait).code("account-throttled").into_response(),
                    Ok(SignIn::Refused) => refused(StatusCode::UNAUTHORIZED, "Invalid credentials."),
                    // 503 rather than 500: the condition is transient by construction, and five minutes clears it.
                    Ok(SignIn::ChallengesSaturated) => refused(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Too many sign-ins are awaiting verification. Try again in a few minutes.",
                    ),
                    Ok(SignIn::ChallengeIssued(token)) => ok(
                        StatusCode::OK,
                        &LoginResponse {
                            token: None,
                            expires_at: None,
                            user: None,
                            mfa_required: true,
                            mfa_token: Some(token.expose().to_owned()),
                        },
                    ),
                    Ok(SignIn::SignedIn { issued, user }) => {
                        ok(StatusCode::OK, &LoginResponse::signed_in(&issued, &user))
                    }
                    Err(failure) => sign_in_failure(failure),
                }
            }
        },
    ));

    let verify = flow.clone();
    entries.push(Route::post("/api/v1/auth/mfa/verify").requires(Access::Anonymous).names_no_target().handler(
        move |address: ClientAddress, headers: HeaderMap, request: Request| {
            let flow = verify.clone();
            async move {
                let fields = read!(Fields::of(read!(body_of(request).await)));
                let (Some(token), Some(code)) = (read!(fields.text("mfa_token")), read!(fields.text("code"))) else {
                    return refused(StatusCode::BAD_REQUEST, "MFA token and verification code are required.");
                };
                let agent = user_agent(&headers);
                match flow.verify(&token, &code, agent.as_deref(), Some(&address.0)).await {
                    Ok(Verification::ChallengeInvalid) => refused(
                        StatusCode::UNAUTHORIZED,
                        "MFA challenge has expired or is invalid. Please sign in again.",
                    ),
                    Ok(Verification::AccountMissing) => refused(StatusCode::UNAUTHORIZED, "Account not found."),
                    // The same message whether or not that code destroyed the challenge: which of the two it is tells
                    // an attacker how many tries are left.
                    Ok(Verification::WrongCode) => refused(StatusCode::UNAUTHORIZED, "Invalid verification code."),
                    Ok(Verification::Throttled(wait)) => throttled(wait).into_response(),
                    Ok(Verification::Verified { issued, user }) => {
                        ok(StatusCode::OK, &LoginResponse::signed_in(&issued, &user))
                    }
                    Err(failure) => sign_in_failure(failure),
                }
            }
        },
    ));

    let setup = flow.clone();
    entries.push(Route::post("/api/v1/auth/mfa/setup").requires(Access::Account).names_no_target().handler(
        move |caller: Caller| {
            let flow = setup.clone();
            async move {
                let Some(account) = caller.0.account.as_ref() else {
                    return unexpected(AUTH, &"an account route reached without an account");
                };
                let setup = flow.second_factor().setup(&account.username);
                ok(
                    StatusCode::OK,
                    &SetupResponse {
                        secret: setup.secret.expose().to_owned(),
                        qr_code_uri: setup.qr_code_uri.expose().to_owned(),
                        issuer: setup.issuer,
                    },
                )
            }
        },
    ));

    let enable = flow.clone();
    entries.push(Route::post("/api/v1/auth/mfa/enable").requires(Access::Account).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let flow = enable.clone();
            async move {
                let fields = read!(Fields::of(read!(body_of(request).await)));
                let (Some(secret), Some(code)) = (read!(fields.text("secret")), read!(fields.text("code"))) else {
                    return refused(StatusCode::BAD_REQUEST, "Secret and verification code are required.");
                };
                let password = read!(fields.text("password")).unwrap_or_default();
                if password.is_empty() {
                    return refused(StatusCode::BAD_REQUEST, "The current password is required to enable MFA.");
                }
                let Some(account) = caller.0.grounds.account_id else {
                    return unexpected(AUTH, &"an account route reached without an account");
                };
                let agent = user_agent(&headers);
                match flow
                    .second_factor()
                    .enable(account, &password, &secret, &code, Some(&address.0), agent.as_deref())
                    .await
                {
                    Ok(codes) => ok(
                        StatusCode::OK,
                        &EnableResponse {
                            success: true,
                            backup_codes: codes.iter().map(|code| code.expose().to_owned()).collect(),
                        },
                    ),
                    Err(refusal) => second_factor_refusal(refusal),
                }
            }
        },
    ));

    let disable = flow.clone();
    entries.push(Route::post("/api/v1/auth/mfa/disable").requires(Access::Account).names_no_target().handler(
        move |caller: Caller, request: Request| {
            let flow = disable.clone();
            async move {
                let fields = read!(Fields::of(read!(body_of(request).await)));
                let Some(code) = read!(fields.text("code")) else {
                    return refused(StatusCode::BAD_REQUEST, "Verification code is required to disable MFA.");
                };
                let Some(account) = caller.0.grounds.account_id else {
                    return unexpected(AUTH, &"an account route reached without an account");
                };
                match flow.second_factor().disable(account, &code).await {
                    Ok(()) => ok(StatusCode::OK, &MfaDisabled { mfa_enabled: false }),
                    Err(refusal) => second_factor_refusal(refusal),
                }
            }
        },
    ));

    let methods = flow.clone();
    entries.push(Route::get("/api/v1/auth/methods").requires(Access::Anonymous).names_no_target().handler(move || {
        let flow = methods.clone();
        let branding = branding.clone();
        async move {
            let options = flow.options();
            ok(
                StatusCode::OK,
                &SignInMethods {
                    configured: options.single_sign_on,
                    label: options.label,
                    password: options.password,
                    brand_name: branding.name,
                    gitlab_url: branding.gitlab_url,
                },
            )
        }
    }));

    let exchange = flow.clone();
    entries.push(Route::post("/api/v1/auth/session/exchange").requires(Access::Anonymous).names_no_target().handler(
        move |headers: HeaderMap, uri: http::Uri| {
            let flow = exchange.clone();
            async move {
                let Some(token) = handoff_token(&headers) else {
                    return refused(StatusCode::UNAUTHORIZED, "No sign-on to complete.");
                };
                let secure = uri.scheme_str() == Some("https");
                let mut response = match flow.exchange(&token).await {
                    Ok(Handoff::Expired) => refused(StatusCode::UNAUTHORIZED, "This sign-on has expired."),
                    Ok(Handoff::AccountMissing) => refused(StatusCode::UNAUTHORIZED, "Account not found."),
                    Ok(Handoff::Exchanged { issued, user }) => {
                        ok(StatusCode::OK, &LoginResponse::signed_in(&issued, &user))
                    }
                    Err(failure) => sign_in_failure(failure),
                };
                clear_handoff(&mut response, secure);
                response
            }
        },
    ));

    entries.push(
        Route::delete("/api/v1/auth/session")
            .requires(Access::Account)
            .allows_pending_password_change()
            .names_no_target()
            .handler(move |caller: Caller| {
                let credentials = credentials.clone();
                async move {
                    // The row disappears: signing out is real, including for a tab left open elsewhere.
                    if let Some(hash) = caller.0.grounds.session_hash.as_deref()
                        && let Err(failure) = credentials.revoke_hash(hash).await
                    {
                        return unexpected(AUTH, &failure);
                    }
                    StatusCode::NO_CONTENT.into_response()
                }
            }),
    );

    let change = flow.clone();
    entries.push(
        Route::post("/api/v1/auth/change-password")
            .requires(Access::Account)
            .allows_pending_password_change()
            .names_no_target()
            .handler(move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
                let flow = change.clone();
                async move {
                    let fields = read!(Fields::of(read!(body_of(request).await)));
                    let current = read!(fields.text("current_password")).unwrap_or_default();
                    let next = read!(fields.text("new_password")).unwrap_or_default();
                    let Some(account) = caller.0.grounds.account_id else {
                        return unexpected(AUTH, &"an account route reached without an account");
                    };
                    let session = caller.0.grounds.session_hash.clone().map(SessionHash);
                    let agent = user_agent(&headers);
                    match flow
                        .change_password(
                            account,
                            session,
                            Some(&current),
                            Some(&next),
                            Some(&address.0),
                            agent.as_deref(),
                        )
                        .await
                    {
                        // 401 and not 400: what is missing is proof of identity, not a well-formed field.
                        Ok(PasswordChange::CurrentPasswordWrong) => {
                            refused(StatusCode::UNAUTHORIZED, "Current password is incorrect.")
                        }
                        Ok(PasswordChange::Throttled { retry_after_seconds }) => {
                            throttled_seconds(i64::try_from(retry_after_seconds).unwrap_or(i64::MAX)).into_response()
                        }
                        Ok(PasswordChange::Changed { revoked_api_keys }) => {
                            ok(StatusCode::OK, &PasswordChanged { must_change_password: false, revoked_api_keys })
                        }
                        Err(refusal) => account_refusal(AUTH, refusal),
                    }
                }
            }),
    );

    entries.push(
        Route::get("/api/v1/auth/me")
            .requires(Access::Account)
            .allows_pending_password_change()
            .names_no_target()
            .handler(move |caller: Caller| {
                let flow = flow.clone();
                async move {
                    let Some(account) = caller.0.grounds.account_id else {
                        return unexpected(AUTH, &"an account route reached without an account");
                    };
                    match flow.account(account).await {
                        Ok(Some(user)) => ok(StatusCode::OK, &UserSummary::of(&user)),
                        Ok(None) => unexpected(AUTH, &"the signed-in account is gone"),
                        Err(failure) => sign_in_failure(failure),
                    }
                }
            }),
    );
}

/// What the second factor's gestures refuse, as `AuthController` and the handler answer them.
fn second_factor_refusal(refusal: SecondFactorError) -> Response {
    match refusal {
        SecondFactorError::InvalidInput(message) => refused(StatusCode::BAD_REQUEST, message),
        // 401 and not 400, as at the password change: what is missing is proof of identity.
        refusal @ SecondFactorError::CurrentPasswordWrong => refused(StatusCode::UNAUTHORIZED, &refusal.to_string()),
        SecondFactorError::PasswordLocked { retry_after } | SecondFactorError::Locked { retry_after } => {
            throttled(retry_after).into_response()
        }
        refusal @ SecondFactorError::AccountMissing => refused(StatusCode::NOT_FOUND, &refusal.to_string()),
        SecondFactorError::Saturated(saturated) => saturated.problem().into_response(),
        failure @ (SecondFactorError::Encryption(_) | SecondFactorError::Store(_)) => unexpected(AUTH, &failure),
    }
}
