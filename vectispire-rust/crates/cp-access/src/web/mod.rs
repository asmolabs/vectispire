//! The access module's administration routes (task 1.7, first stage): `UsersController`, `AccountRequestsController`,
//! `TeamsController` and `ApiKeysController` — every one `@RequiresAdministrator`, over the services ported in tasks
//! 1.1, 1.2 and stage 2b.
//!
//! **Read in Spring's order**: the path variable converted first, then the query's window, then the body — so a
//! malformed identifier is refused in Spring's sentence before anything is read — and a refusal answered as
//! `ApiExceptionHandler` answers the service's exception. A service's `AccessDeniedException` is the chain's 403,
//! audited `Access denied: <reason>`, never the handler's.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Request};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use serde::Serialize;
use serde_json::Value;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::extract::{JsonBody, Scoped};
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem};
use vectispire_domain::list_window::ListWindow;
use vectispire_domain::secret::Secret;

use crate::account_targets::AccountTargets;
use crate::accounts::{
    AccountChange, AccountError, AccountStore, Accounts, Audit, Clock, IndependenceError, MANAGED_BY_DIRECTORY,
    NewAccount, OWN_ACCOUNT_REQUEST, Outcome, RequestActor,
};
use crate::administration::AdminError;
use crate::api_key_administration::ApiKeyAdministration;
use crate::credentials::KeyRequest;
use crate::security::CallerScope;
use crate::teams::{TargetAssignment, TeamAdministration};

mod json;
mod read;

use json::{
    AccountRequestJson, AccountRequestListing, ApiKeySummary, IssuedKey, KeyTargets, TargetGrantJson, TeamSummary,
    UserAdminSummary, UserListing,
};
use read::Fields;

const USERS: &str = "/api/v1/users";
const ACCOUNT_REQUESTS: &str = "/api/v1/account-requests";
const TEAMS: &str = "/api/v1/teams";
const API_KEYS: &str = "/api/v1/api-keys";

/// What the administration routes are built over.
#[allow(missing_debug_implementations)] // a bag of services, moved into the routes at once
pub struct Administration<S, A, C> {
    pub accounts: Arc<Accounts<S, A, C>>,
    pub account_targets: Arc<AccountTargets<A>>,
    pub teams: Arc<TeamAdministration<A, C>>,
    pub keys: Arc<ApiKeyAdministration<A, C>>,
}

/// The twenty-four routes.
pub fn administration_routes<S, A, C>(services: Administration<S, A, C>) -> Vec<RouteEntry>
where
    S: AccountStore + Send + Sync + 'static,
    A: Audit + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    let mut entries = Vec::new();
    users(&services, &mut entries);
    account_requests(&services, &mut entries);
    teams(&services, &mut entries);
    keys(&services, &mut entries);
    entries
}

/// Answers the refusal a read produced, or goes on with the value.
macro_rules! read {
    ($attempt:expr) => {
        match $attempt {
            Ok(value) => value,
            Err(problem) => return Problem::into_response(problem),
        }
    };
}

mod auth;
mod scim;

/// `ScimUsersController`'s and `ScimGroupsController`'s twelve routes, over SCIM's provisioning service.
pub fn scim_routes<A, C>(provisioning: Arc<crate::scim::ScimProvisioning<A, C>>) -> Vec<RouteEntry>
where
    A: Audit + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    let mut entries = Vec::new();
    scim::routes(provisioning, &mut entries);
    entries
}

pub use auth::{Branding, HANDOFF_COOKIE};

/// `AuthController`'s ten routes, over the sign-in flow and the credential service the binary composes.
pub fn auth_routes<S, A, T, D, V>(
    flow: Arc<crate::sign_in::SignInFlow<S, A, T, D, V>>,
    credentials: Arc<crate::credentials::CredentialService>,
    branding: Branding,
) -> Vec<RouteEntry>
where
    S: AccountStore + Clone + Send + Sync + 'static,
    A: Audit + Clone + Send + Sync + 'static,
    T: crate::sign_in::SignInStore + Clone + Send + Sync + 'static,
    D: crate::sign_in::SessionDoor + 'static,
    V: crate::second_factor::SecretSeal + 'static,
{
    let mut entries = Vec::new();
    auth::routes(flow, credentials, branding, &mut entries);
    entries
}

fn ok<T: Serialize + ?Sized>(status: StatusCode, value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// `RequestActors.of(principal, request)`: the account — with the key beside it for an integration key — the client's
/// address as the trusted proxies resolve it, and the user agent.
fn actor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor { username: caller.0.actor(), ip_address: Some(address.0.clone()), user_agent: user_agent(headers) }
}

/// The `User-Agent` header as the servlet container hands it to Java: its bytes read as text, **not only visible
/// ASCII** — `HeaderValue::to_str` gives up on anything else, and a browser's agent string past ASCII was then no agent
/// at all, where Java stores it (clipped where its column ends).
pub(crate) fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers.get(header::USER_AGENT).map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

/// `principal.user().map(UserView::id)`.
fn acting(caller: &Caller) -> Option<i64> {
    caller.0.grounds.account_id
}

/// `UnexpectedFailure`: a reference the operator can find in the log, and nothing of the failure itself.
fn unexpected(path: &str, failure: &dyn std::fmt::Display) -> Response {
    let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
    tracing::error!(reference = %reference, path, error = %failure, "Unexpected failure");
    Problem::handler(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
    )
    .with("correlationId", reference)
    .into_response()
}

/// `ListWindow.requested` on the query's `limit` and `offset`.
fn window(uri: &Uri) -> Result<Option<ListWindow>, Problem> {
    let (limit, offset) = raw_window(uri)?;
    ListWindow::requested(limit, offset).map_err(|refused| Problem::handler(StatusCode::BAD_REQUEST, refused))
}

/// The query's `limit` and `offset`, converted as Spring binds an `Integer`, the window's rules left to the service.
fn raw_window(uri: &Uri) -> Result<(Option<i64>, Option<i64>), Problem> {
    let limit = read::query_int(uri.query(), "limit")?.map(i64::from);
    let offset = read::query_int(uri.query(), "offset")?.map(i64::from);
    Ok((limit, offset))
}

/// `ApiExceptionHandler` on what the account services throw.
fn account_refusal(path: &str, error: AccountError) -> Response {
    match error {
        AccountError::InvalidInput(message) => Problem::handler(StatusCode::BAD_REQUEST, message).into_response(),
        refused @ (AccountError::NotFound | AccountError::RequestNotFound) => {
            Problem::handler(StatusCode::NOT_FOUND, refused.to_string()).into_response()
        }
        AccountError::AccessDenied(reason) => vectispire_cp_http::chain::denied(reason),
        refused @ AccountError::ManagedByDirectory(_) => {
            Problem::handler(StatusCode::CONFLICT, refused.to_string()).caused_by(MANAGED_BY_DIRECTORY).into_response()
        }
        AccountError::Conflict(message) => Problem::handler(StatusCode::CONFLICT, message).into_response(),
        refused @ AccountError::OwnAccountRequest => {
            Problem::handler(StatusCode::CONFLICT, refused.to_string()).caused_by(OWN_ACCOUNT_REQUEST).into_response()
        }
        AccountError::Independence(refused) => independence_refusal(path, refused),
        AccountError::Saturated(saturated) => saturated.problem().into_response(),
        failure @ AccountError::Store(_) => unexpected(path, &failure),
    }
}

/// `ApproverNotIndependentException` and `PasswordKnownException`: 409, the cause, and the members `gesture` and
/// `windowDays`.
fn independence_refusal(path: &str, refused: IndependenceError) -> Response {
    let cause = refused.cause();
    match refused {
        IndependenceError::NotIndependent { sentence, gesture, window_days }
        | IndependenceError::PasswordKnown { sentence, gesture, window_days } => {
            Problem::handler(StatusCode::CONFLICT, sentence)
                .caused_by(cause.unwrap_or_default())
                .with("gesture", gesture.wire_name())
                .with("windowDays", window_days)
                .into_response()
        }
        failure @ IndependenceError::Failed(_) => unexpected(path, &failure),
    }
}

/// `ApiExceptionHandler` on what the administration services throw.
fn admin_refusal(path: &str, error: AdminError) -> Response {
    match error {
        AdminError::InvalidInput(message) | AdminError::InvalidApiKey(message) => {
            Problem::handler(StatusCode::BAD_REQUEST, message).into_response()
        }
        AdminError::NotFound(message) => Problem::handler(StatusCode::NOT_FOUND, message).into_response(),
        AdminError::UnsafeUrl(message) => {
            Problem::handler(StatusCode::UNPROCESSABLE_ENTITY, message).code("unsafe-url").into_response()
        }
        refused @ AdminError::IntegrationDisabled(integration) => {
            Problem::handler(StatusCode::CONFLICT, refused.to_string())
                .caused_by(vectispire_domain::integrations::DISABLED_CAUSE)
                .with("integration", integration.key())
                .into_response()
        }
        failure @ AdminError::Failed(_) => unexpected(path, &failure),
    }
}

/// An applied change answers the account, a filed one the request.
fn outcome(outcome: Outcome) -> Response {
    match outcome {
        Outcome::Applied(account) => ok(StatusCode::OK, &UserAdminSummary::of(&account)),
        Outcome::Queued(request) => ok(StatusCode::ACCEPTED, &AccountRequestJson::of(&request)),
    }
}

/// The body as JSON — the 415 and 400 Spring answers otherwise.
async fn body_of(request: Request) -> Result<Value, Problem> {
    use axum::extract::FromRequest as _;
    JsonBody::<Value>::from_request(request, &()).await.map(|JsonBody(body)| body)
}

/// A `List<TargetAssignment>` body, null entries carried through: skipping them is the service's rule.
fn assignments(body: Value) -> Result<Vec<Option<TargetAssignment>>, Problem> {
    read::records(body)?
        .into_iter()
        .map(|entry| match entry {
            None => Ok(None),
            Some(fields) => Ok(Some(TargetAssignment { kind: fields.text("kind")?, id: fields.long("id")? })),
        })
        .collect()
}

fn users<S, A, C>(services: &Administration<S, A, C>, entries: &mut Vec<RouteEntry>)
where
    S: AccountStore + Send + Sync + 'static,
    A: Audit + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    let accounts = services.accounts.clone();
    entries.push(Route::get(USERS).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, uri: Uri| {
            let accounts = accounts.clone();
            async move {
                let window = read!(window(&uri));
                let cut = window
                    .and_then(|page| Some((usize::try_from(page.limit).ok()?, usize::try_from(page.offset).ok()?)));
                match accounts.list(cut).await {
                    Ok(listed) => ok(
                        StatusCode::OK,
                        &UserListing {
                            users: listed.accounts.iter().map(UserAdminSummary::of).collect(),
                            // The screen needs to know which account is its own, so it does not offer what the server
                            // will refuse anyway.
                            current_user_id: acting(&caller),
                            total: listed.total,
                        },
                    ),
                    Err(refused) => account_refusal(USERS, refused),
                }
            }
        },
    ));

    let accounts = services.accounts.clone();
    entries.push(Route::post(USERS).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let accounts = accounts.clone();
            async move {
                let fields = read!(Fields::of(read!(body_of(request).await)));
                let account = NewAccount {
                    username: read!(fields.text("username")),
                    password: read!(fields.text("password")).map(Secret::new),
                    role: read!(fields.text("role")),
                    email: read!(fields.text("email")),
                    display_name: read!(fields.text("display_name")),
                };
                match accounts.create(account, acting(&caller), &actor(&caller, &address, &headers)).await {
                    Ok(done) => outcome(done),
                    Err(refused) => account_refusal(USERS, refused),
                }
            }
        },
    ));

    let accounts = services.accounts.clone();
    entries.push(Route::patch("/api/v1/users/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>, request: Request| {
            let accounts = accounts.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                let fields = read!(Fields::of(read!(body_of(request).await)));
                let change = AccountChange {
                    role: read!(fields.text("role")),
                    is_active: read!(fields.flag("is_active")),
                    password: read!(fields.text("password")).map(Secret::new),
                    email: read!(fields.text("email")),
                };
                match accounts.update(id, change, acting(&caller), &actor(&caller, &address, &headers)).await {
                    Ok(done) => outcome(done),
                    Err(refused) => account_refusal(USERS, refused),
                }
            }
        },
    ));

    let accounts = services.accounts.clone();
    entries.push(
        Route::delete("/api/v1/users/{id}/password-change-requirement")
            .requires(Access::Administrator)
            .names_no_target()
            .handler(move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>| {
                let accounts = accounts.clone();
                async move {
                    let id = read!(read::path_long("id", &id));
                    let actor = actor(&caller, &address, &headers);
                    match accounts.clear_password_change_requirement(id, acting(&caller), &actor).await {
                        Ok(account) => ok(StatusCode::OK, &UserAdminSummary::of(&account)),
                        Err(refused) => account_refusal(USERS, refused),
                    }
                }
            }),
    );

    let accounts = services.accounts.clone();
    entries.push(
        Route::delete("/api/v1/users/{id}/second-factor").requires(Access::Administrator).names_no_target().handler(
            move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>| {
                let accounts = accounts.clone();
                async move {
                    let id = read!(read::path_long("id", &id));
                    match accounts.reset_second_factor(id, acting(&caller), &actor(&caller, &address, &headers)).await {
                        Ok(account) => ok(StatusCode::OK, &UserAdminSummary::of(&account)),
                        Err(refused) => account_refusal(USERS, refused),
                    }
                }
            },
        ),
    );

    let targets = services.account_targets.clone();
    entries.push(Route::get("/api/v1/users/{id}/targets").requires(Access::Administrator).names_no_target().handler(
        move |Path(id): Path<String>, uri: Uri| {
            let targets = targets.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                let (limit, offset) = read!(raw_window(&uri));
                match targets.targets(id, limit, offset).await {
                    Ok(grants) => ok(StatusCode::OK, &TargetGrantJson::all(&grants)),
                    Err(refused) => admin_refusal(USERS, refused),
                }
            }
        },
    ));

    let targets = services.account_targets.clone();
    entries.push(Route::put("/api/v1/users/{id}/targets").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>,
              request: Request| {
            let targets = targets.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                let requested = read!(assignments(read!(body_of(request).await)));
                let Ok(granter) = scope else {
                    return unexpected(USERS, &"the granter's visibility could not be resolved");
                };
                let actor = actor(&caller, &address, &headers);
                match targets.replace_targets(id, Some(&requested), &granter.visibility, &actor).await {
                    Ok(grants) => ok(StatusCode::OK, &TargetGrantJson::all(&grants)),
                    Err(refused) => admin_refusal(USERS, refused),
                }
            }
        },
    ));

    let accounts = services.accounts.clone();
    entries.push(Route::delete("/api/v1/users/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>| {
            let accounts = accounts.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                match accounts.delete(id, acting(&caller), &actor(&caller, &address, &headers)).await {
                    Ok(()) => no_content(),
                    Err(refused) => account_refusal(USERS, refused),
                }
            }
        },
    ));
}

fn account_requests<S, A, C>(services: &Administration<S, A, C>, entries: &mut Vec<RouteEntry>)
where
    S: AccountStore + Send + Sync + 'static,
    A: Audit + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    let accounts = services.accounts.clone();
    entries.push(Route::get(ACCOUNT_REQUESTS).requires(Access::Administrator).names_no_target().handler(
        move |uri: Uri| {
            let accounts = accounts.clone();
            async move {
                let window = read!(window(&uri));
                let cut = window
                    .and_then(|page| Some((usize::try_from(page.limit).ok()?, usize::try_from(page.offset).ok()?)));
                match accounts.pending(cut).await {
                    Ok(pending) => ok(
                        StatusCode::OK,
                        &AccountRequestListing {
                            requests: pending.requests.iter().map(AccountRequestJson::of).collect(),
                            total: pending.total,
                        },
                    ),
                    Err(refused) => account_refusal(ACCOUNT_REQUESTS, refused),
                }
            }
        },
    ));

    let accounts = services.accounts.clone();
    entries.push(
        Route::post("/api/v1/account-requests/{id}/approve").requires(Access::Administrator).names_no_target().handler(
            move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>| {
                let accounts = accounts.clone();
                async move {
                    let id = read!(read::path_long("id", &id));
                    match accounts.approve(id, acting(&caller), &actor(&caller, &address, &headers)).await {
                        Ok(account) => ok(StatusCode::OK, &UserAdminSummary::of(&account)),
                        Err(refused) => account_refusal(ACCOUNT_REQUESTS, refused),
                    }
                }
            },
        ),
    );

    let accounts = services.accounts.clone();
    entries.push(
        Route::post("/api/v1/account-requests/{id}/reject").requires(Access::Administrator).names_no_target().handler(
            move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>| {
                let accounts = accounts.clone();
                async move {
                    let id = read!(read::path_long("id", &id));
                    match accounts.reject(id, acting(&caller), &actor(&caller, &address, &headers)).await {
                        Ok(()) => no_content(),
                        Err(refused) => account_refusal(ACCOUNT_REQUESTS, refused),
                    }
                }
            },
        ),
    );
}

fn teams<S, A, C>(services: &Administration<S, A, C>, entries: &mut Vec<RouteEntry>)
where
    S: AccountStore + Send + Sync + 'static,
    A: Audit + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    let teams = services.teams.clone();
    entries.push(Route::get(TEAMS).requires(Access::Administrator).names_no_target().handler(move |uri: Uri| {
        let teams = teams.clone();
        async move {
            let window = read!(window(&uri));
            match teams.list(window).await {
                Ok(listed) => ok(StatusCode::OK, &listed.iter().map(TeamSummary::of).collect::<Vec<_>>()),
                Err(refused) => admin_refusal(TEAMS, refused),
            }
        }
    }));

    let teams = services.teams.clone();
    entries.push(Route::post(TEAMS).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let teams = teams.clone();
            async move {
                let fields = read!(Fields::of(read!(body_of(request).await)));
                let (name, description) = (read!(fields.text("name")), read!(fields.text("description")));
                let actor = actor(&caller, &address, &headers);
                match teams.create(name.as_deref(), description.as_deref(), &actor).await {
                    Ok(team) => ok(StatusCode::CREATED, &TeamSummary::of(&team)),
                    Err(refused) => admin_refusal(TEAMS, refused),
                }
            }
        },
    ));

    let teams = services.teams.clone();
    entries.push(Route::patch("/api/v1/teams/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>, request: Request| {
            let teams = teams.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                let fields = read!(Fields::of(read!(body_of(request).await)));
                let (name, description) = (read!(fields.text("name")), read!(fields.text("description")));
                let actor = actor(&caller, &address, &headers);
                match teams.rename(id, name.as_deref(), description.as_deref(), &actor).await {
                    Ok(team) => ok(StatusCode::OK, &TeamSummary::of(&team)),
                    Err(refused) => admin_refusal(TEAMS, refused),
                }
            }
        },
    ));

    let teams = services.teams.clone();
    entries.push(Route::delete("/api/v1/teams/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>| {
            let teams = teams.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                match teams.delete(id, &actor(&caller, &address, &headers)).await {
                    Ok(()) => no_content(),
                    Err(refused) => admin_refusal(TEAMS, refused),
                }
            }
        },
    ));

    let teams = services.teams.clone();
    entries.push(Route::get("/api/v1/teams/{id}/members").requires(Access::Administrator).names_no_target().handler(
        move |Path(id): Path<String>, uri: Uri| {
            let teams = teams.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                let (limit, offset) = read!(raw_window(&uri));
                match teams.members(id, limit, offset).await {
                    Ok(members) => ok(StatusCode::OK, &members),
                    Err(refused) => admin_refusal(TEAMS, refused),
                }
            }
        },
    ));

    let teams = services.teams.clone();
    entries.push(Route::put("/api/v1/teams/{id}/members").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>, request: Request| {
            let teams = teams.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                let requested = read!(read::longs(read!(body_of(request).await)));
                match teams.replace_members(id, &requested, &actor(&caller, &address, &headers)).await {
                    Ok(members) => ok(StatusCode::OK, &members),
                    Err(refused) => admin_refusal(TEAMS, refused),
                }
            }
        },
    ));

    let teams = services.teams.clone();
    entries.push(Route::get("/api/v1/teams/{id}/targets").requires(Access::Administrator).names_no_target().handler(
        move |Path(id): Path<String>, uri: Uri| {
            let teams = teams.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                let (limit, offset) = read!(raw_window(&uri));
                match teams.targets(id, limit, offset).await {
                    Ok(grants) => ok(StatusCode::OK, &TargetGrantJson::all(&grants)),
                    Err(refused) => admin_refusal(TEAMS, refused),
                }
            }
        },
    ));

    let teams = services.teams.clone();
    entries.push(Route::put("/api/v1/teams/{id}/targets").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>,
              request: Request| {
            let teams = teams.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                let requested = read!(assignments(read!(body_of(request).await)));
                let Ok(granter) = scope else {
                    return unexpected(TEAMS, &"the granter's visibility could not be resolved");
                };
                let actor = actor(&caller, &address, &headers);
                match teams.replace_targets(id, &requested, &granter.visibility, &actor).await {
                    Ok(grants) => ok(StatusCode::OK, &TargetGrantJson::all(&grants)),
                    Err(refused) => admin_refusal(TEAMS, refused),
                }
            }
        },
    ));

    let teams = services.teams.clone();
    entries.push(Route::put("/api/v1/teams/{id}/webhook").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>, request: Request| {
            let teams = teams.clone();
            async move {
                let id = read!(read::path_long("id", &id));
                let fields = read!(Fields::of(read!(body_of(request).await)));
                let url = read!(fields.text("url"));
                match teams.set_webhook(id, url.as_deref(), &actor(&caller, &address, &headers)).await {
                    Ok(team) => ok(StatusCode::OK, &TeamSummary::of(&team)),
                    Err(refused) => admin_refusal(TEAMS, refused),
                }
            }
        },
    ));
}

fn keys<S, A, C>(services: &Administration<S, A, C>, entries: &mut Vec<RouteEntry>)
where
    S: AccountStore + Send + Sync + 'static,
    A: Audit + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    let keys = services.keys.clone();
    entries.push(Route::get(API_KEYS).requires(Access::Administrator).names_no_target().handler(move |uri: Uri| {
        let keys = keys.clone();
        async move {
            let window = read!(window(&uri));
            match keys.list(window).await {
                Ok(listed) => ok(StatusCode::OK, &listed.iter().map(ApiKeySummary::of).collect::<Vec<_>>()),
                Err(refused) => admin_refusal(API_KEYS, refused),
            }
        }
    }));

    let keys = services.keys.clone();
    entries.push(Route::post(API_KEYS).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let keys = keys.clone();
            async move {
                let fields = read!(Fields::of(read!(body_of(request).await)));
                let requested = KeyRequest {
                    name: read!(fields.text("name")),
                    scopes: read!(fields.texts("scopes")),
                    target_kind: read!(fields.text("target_kind")),
                    target_id: read!(fields.long("target_id")),
                    expires_in_days: read!(fields.int("expires_in_days")),
                };
                // `principal.requireUser()`: an administrator is an account; nothing else reaches this route.
                let Some(owner) = acting(&caller) else {
                    return unexpected(API_KEYS, &"an administrator without an account");
                };
                match keys.issue(owner, &requested, &actor(&caller, &address, &headers)).await {
                    Ok(issued) => ok(
                        StatusCode::OK,
                        &IssuedKey { key: ApiKeySummary::of(&issued.key), secret: issued.secret.expose().to_owned() },
                    ),
                    Err(refused) => admin_refusal(API_KEYS, refused),
                }
            }
        },
    ));

    let keys = services.keys.clone();
    entries.push(Route::delete("/api/v1/api-keys/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>| {
            let keys = keys.clone();
            async move {
                let id = read!(read::path_uuid("id", &id));
                match keys.revoke(id, acting(&caller), &actor(&caller, &address, &headers)).await {
                    Ok(()) => no_content(),
                    Err(refused) => admin_refusal(API_KEYS, refused),
                }
            }
        },
    ));

    let keys = services.keys.clone();
    entries.push(Route::get("/api/v1/api-keys/targets").requires(Access::Administrator).names_no_target().handler(
        move || {
            let keys = keys.clone();
            async move {
                match keys.targets().await {
                    Ok(options) => ok(StatusCode::OK, &KeyTargets::of(&options)),
                    Err(refused) => admin_refusal(API_KEYS, refused),
                }
            }
        },
    ));
}
