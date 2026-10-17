//! The twenty-nine routes: `RepositoriesController`, `ContainersController`, `SolutionsController`,
//! `ProjectsController`, `GitTokensController` and `SshKeysController`.
//!
//! **Every route that names a target or aggregates over them is `.scoped()`**: the chain resolves the caller's
//! allowance — the account's grants intersected with the credential's restriction — before the handler runs, and the
//! handler hands it to the service, which applies it in the query or refuses through `cp-access`' row guards. The
//! routes that name none — the clone credentials, a new solution — say so with `.names_no_target()`.
//!
//! **Administrators' routes stay administrators' when they could have been read as nobody's**: a solution's or a
//! project's administration is reached by an administrator's session only (no API key is accepted there), whose
//! allowance is everything; the handler still requires that, and refuses anyone else as the row's absence, so that a
//! later change to who reaches the route cannot turn into a reader editing what they cannot see.

mod json;
mod read;

use std::sync::Arc;

use axum::extract::{FromRequest, Path, RawQuery, Request};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, Method, StatusCode, Uri, header};
use serde_json::Value;
use vectispire_cp_access::rows;
use vectispire_cp_access::{Allowance, CallerScope};
use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{ApiKeyScope, Caller, ClientAddress, JsonBody, Problem, Scoped};

use self::json::{no_content, ok};
use self::read::Fields;
use crate::error::TargetError;
use crate::{Targets, containers, repositories};

/// The routes, each with its marker and its answer on visibility, in the controllers' order.
pub fn routes(targets: Arc<Targets>) -> Vec<RouteEntry> {
    let mut entries = Vec::new();
    repositories_routes(&targets, &mut entries);
    containers_routes(&targets, &mut entries);
    solutions_routes(&targets, &mut entries);
    projects_routes(&targets, &mut entries);
    credentials_routes(&targets, &mut entries);
    entries
}

/// What every handler is handed besides its own parameters: who calls, from where, and what they see.
struct Call {
    actor: RequestActor,
    method: Method,
    path: String,
}

fn call(Caller(principal): &Caller, address: &ClientAddress, headers: &HeaderMap, method: &Method, uri: &Uri) -> Call {
    Call {
        actor: RequestActor {
            username: principal.actor(),
            ip_address: Some(address.0.clone()),
            user_agent: headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned),
        },
        method: method.clone(),
        path: uri.path().to_owned(),
    }
}

impl Call {
    /// A refusal as `ApiExceptionHandler` answers it; an unexpected failure as a 500 quoting a reference, logged
    /// under it — never the failure's own text, which would put internals on the wire.
    fn refuse(&self, error: TargetError) -> Response {
        problem(&self.method, &self.path, error).into_response()
    }
}

fn problem(method: &Method, path: &str, error: TargetError) -> Problem {
    match error {
        TargetError::Invalid(message) => Problem::handler(StatusCode::BAD_REQUEST, message),
        TargetError::NotFound(message) => Problem::handler(StatusCode::NOT_FOUND, message),
        TargetError::Conflict { message, cause, members } => {
            let mut problem = Problem::handler(StatusCode::CONFLICT, message);
            if let Some(cause) = cause {
                problem = problem.caused_by(cause);
            }
            for (name, value) in members {
                problem = problem.with(name, value);
            }
            problem
        }
        TargetError::MissingKey(message) => Problem::handler(StatusCode::PRECONDITION_FAILED, message),
        TargetError::UnsafeUrl(message) => Problem::handler(StatusCode::UNPROCESSABLE_ENTITY, message),
        TargetError::Unexpected(failure) => unexpected(method, path, failure.as_ref()),
    }
}

/// `UnexpectedFailure`: a reference the operator can find in the log, and nothing of the failure itself.
fn unexpected(method: &Method, path: &str, failure: &(dyn std::error::Error + 'static)) -> Problem {
    let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
    tracing::error!(reference = %reference, method = %method, path, error = %failure, "Unexpected failure");
    Problem::handler(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
    )
    .with("correlationId", reference)
}

#[derive(Debug, thiserror::Error)]
#[error("the caller's visibility could not be resolved")]
struct NoAllowance;

/// The allowance the chain resolved, or the 500 a failure to resolve one is: **never an empty allowance**, which
/// would answer a 404 or an empty list for what is a failure of the server (decision 0007).
fn allowance(call: &Call, scope: CallerScope) -> Result<Allowance, Box<Response>> {
    scope.map_err(|_| Box::new(problem(&call.method, &call.path, TargetError::unexpected(NoAllowance)).into_response()))
}

/// An administrator's gesture on a solution or a project: refused, as the row's absence, to a caller whose allowance
/// is not everything.
fn require_everything(allowance: &Allowance, absent: &'static str) -> Result<(), TargetError> {
    if allowance.visibility == Allowance::everything().visibility {
        Ok(())
    } else {
        Err(TargetError::not_found(absent))
    }
}

/// The JSON body, read **after** the path variables, as Spring resolves a handler's arguments in their order: a
/// malformed identifier is refused before the body is looked at, its media type included.
async fn body_of(request: Request) -> Result<Value, Problem> {
    JsonBody::<Value>::from_request(request, &()).await.map(|JsonBody(body)| body)
}

fn repository_changes(body: Value) -> Result<repositories::Changes, Problem> {
    let fields = Fields::of(body)?;
    Ok(repositories::Changes {
        url: fields.text("url")?,
        branch: fields.text("branch")?,
        name: fields.text("name")?,
        sub_path: fields.text("subPath")?,
        scan_interval_minutes: fields.int("scanIntervalMinutes")?,
        scan_cron: fields.text("scanCron")?,
        required_agent_label: fields.text("required_agent_label")?,
        ssh_key_id: fields.text("sshKeyId")?,
        tier: fields.text("tier")?,
        https_token_id: fields.text("https_token_id")?,
        scan_manual_only: fields.flag("scanManualOnly")?,
    })
}

fn container_changes(body: Value) -> Result<containers::Changes, Problem> {
    let fields = Fields::of(body)?;
    Ok(containers::Changes {
        registry: fields.text("registry")?,
        image_name: fields.text("image_name")?,
        tag: fields.text("tag")?,
        scan_interval_minutes: fields.int("scanIntervalMinutes")?,
        scan_cron: fields.text("scanCron")?,
        required_agent_label: fields.text("required_agent_label")?,
        tier: fields.text("tier")?,
        scan_manual_only: fields.flag("scanManualOnly")?,
    })
}

macro_rules! attempt {
    ($call:expr, $result:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => return $call.refuse(error),
        }
    };
}

macro_rules! read {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(problem) => return problem.into_response(),
        }
    };
}

// ── /api/v1/repositories ─────────────────────────────────────────────────────────────────

fn repositories_routes(targets: &Arc<Targets>, entries: &mut Vec<RouteEntry>) {
    let t = targets.clone();
    entries.push(
        Route::get("/api/v1/repositories")
            .requires(Access::Account)
            .scoped()
            .accepts_api_key(ApiKeyScope::Read)
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      method: Method,
                      uri: Uri,
                      Scoped(scope): Scoped<CallerScope>,
                      RawQuery(query): RawQuery| {
                    let t = t.clone();
                    async move {
                        let call = call(&caller, &address, &headers, &method, &uri);
                        let allowance = match allowance(&call, scope) {
                            Ok(allowance) => allowance,
                            Err(refused) => return *refused,
                        };
                        let limit = read!(read::query_int(query.as_deref(), "limit"));
                        let offset = read!(read::query_int(query.as_deref(), "offset"));
                        let listed = attempt!(
                            call,
                            t.list_repositories(&allowance.visibility, limit.map(i64::from), offset.map(i64::from))
                                .await
                        );
                        ok(StatusCode::OK, &listed.iter().map(json::RepositorySummary::of).collect::<Vec<_>>())
                    }
                },
            ),
    );
    let t = targets.clone();
    entries.push(Route::post("/api/v1/repositories").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              request: Request| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let body = read!(body_of(request).await);
                let changes = read!(repository_changes(body));
                let saved = attempt!(call, t.create_repository(&changes, &allowance.visibility, &call.actor).await);
                let listed = attempt!(call, t.listed_repository(&allowance.visibility, saved.id).await);
                match listed {
                    Some(listed) => ok(StatusCode::OK, &json::RepositorySummary::of(&listed)),
                    None => call.refuse(TargetError::unexpected(NotListed)),
                }
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::get("/api/v1/repositories/duplicates").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let groups = attempt!(call, t.duplicates(&allowance.visibility).await);
                ok(StatusCode::OK, &groups.iter().map(json::DuplicateTarget::of).collect::<Vec<_>>())
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::patch("/api/v1/repositories/{id}").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>,
              request: Request| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let id = read!(read::path_long("id", &id));
                let body = read!(body_of(request).await);
                let changes = read!(repository_changes(body));
                let saved = attempt!(call, t.update_repository(id, &changes, &allowance.visibility, &call.actor).await);
                let listed = attempt!(call, t.listed_repository(&allowance.visibility, saved.id).await);
                match listed {
                    Some(listed) => ok(StatusCode::OK, &json::RepositorySummary::of(&listed)),
                    None => call.refuse(TargetError::unexpected(NotListed)),
                }
            }
        },
    ));
    let t = targets.clone();
    entries.push(
        Route::post("/api/v1/repositories/{id}/scan")
            .requires(Access::Administrator)
            .scoped()
            .accepts_api_key(ApiKeyScope::Scan)
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      method: Method,
                      uri: Uri,
                      Scoped(scope): Scoped<CallerScope>,
                      Path(id): Path<String>| {
                    let t = t.clone();
                    async move {
                        let call = call(&caller, &address, &headers, &method, &uri);
                        let allowance = match allowance(&call, scope) {
                            Ok(allowance) => allowance,
                            Err(refused) => return *refused,
                        };
                        let id = read!(read::path_long("id", &id));
                        let triggered =
                            attempt!(call, t.trigger_repository(id, &allowance.visibility, &call.actor).await);
                        ok(StatusCode::OK, &json::QueuedScan { id: triggered.scan.id, status: triggered.scan.status })
                    }
                },
            ),
    );
    let t = targets.clone();
    entries.push(Route::delete("/api/v1/repositories/{id}").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let id = read!(read::path_long("id", &id));
                attempt!(call, t.delete_repository(id, &allowance.visibility, &call.actor).await);
                no_content()
            }
        },
    ));
}

#[derive(Debug, thiserror::Error)]
#[error("a row written a moment ago is not in the list it was written to")]
struct NotListed;

// ── /api/v1/containers ───────────────────────────────────────────────────────────────────

fn containers_routes(targets: &Arc<Targets>, entries: &mut Vec<RouteEntry>) {
    let t = targets.clone();
    entries.push(
        Route::get("/api/v1/containers").requires(Access::Account).scoped().accepts_api_key(ApiKeyScope::Read).handler(
            move |caller: Caller,
                  address: ClientAddress,
                  headers: HeaderMap,
                  method: Method,
                  uri: Uri,
                  Scoped(scope): Scoped<CallerScope>,
                  RawQuery(query): RawQuery| {
                let t = t.clone();
                async move {
                    let call = call(&caller, &address, &headers, &method, &uri);
                    let allowance = match allowance(&call, scope) {
                        Ok(allowance) => allowance,
                        Err(refused) => return *refused,
                    };
                    let limit = read!(read::query_int(query.as_deref(), "limit"));
                    let offset = read!(read::query_int(query.as_deref(), "offset"));
                    let listed = attempt!(
                        call,
                        t.list_containers(&allowance.visibility, limit.map(i64::from), offset.map(i64::from)).await
                    );
                    ok(StatusCode::OK, &listed.iter().map(json::ContainerSummary::of).collect::<Vec<_>>())
                }
            },
        ),
    );
    let t = targets.clone();
    entries.push(Route::post("/api/v1/containers").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              request: Request| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let body = read!(body_of(request).await);
                let changes = read!(container_changes(body));
                let saved = attempt!(call, t.create_container(&changes, &call.actor).await);
                let listed = attempt!(call, t.listed_container(&allowance.visibility, saved.id).await);
                match listed {
                    Some(listed) => ok(StatusCode::OK, &json::ContainerSummary::of(&listed)),
                    None => call.refuse(TargetError::unexpected(NotListed)),
                }
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::patch("/api/v1/containers/{id}").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>,
              request: Request| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let id = read!(read::path_long("id", &id));
                let body = read!(body_of(request).await);
                let changes = read!(container_changes(body));
                let saved = attempt!(call, t.update_container(id, &changes, &allowance.visibility, &call.actor).await);
                let listed = attempt!(call, t.listed_container(&allowance.visibility, saved.id).await);
                match listed {
                    Some(listed) => ok(StatusCode::OK, &json::ContainerSummary::of(&listed)),
                    None => call.refuse(TargetError::unexpected(NotListed)),
                }
            }
        },
    ));
    let t = targets.clone();
    entries.push(
        Route::post("/api/v1/containers/{id}/scan")
            .requires(Access::Administrator)
            .scoped()
            .accepts_api_key(ApiKeyScope::Scan)
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      method: Method,
                      uri: Uri,
                      Scoped(scope): Scoped<CallerScope>,
                      Path(id): Path<String>| {
                    let t = t.clone();
                    async move {
                        let call = call(&caller, &address, &headers, &method, &uri);
                        let allowance = match allowance(&call, scope) {
                            Ok(allowance) => allowance,
                            Err(refused) => return *refused,
                        };
                        let id = read!(read::path_long("id", &id));
                        let triggered =
                            attempt!(call, t.trigger_container(id, &allowance.visibility, &call.actor).await);
                        ok(StatusCode::OK, &json::QueuedScan { id: triggered.scan.id, status: triggered.scan.status })
                    }
                },
            ),
    );
    let t = targets.clone();
    entries.push(Route::delete("/api/v1/containers/{id}").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let id = read!(read::path_long("id", &id));
                attempt!(call, t.delete_container(id, &allowance.visibility, &call.actor).await);
                no_content()
            }
        },
    ));
}

// ── /api/v1/solutions ────────────────────────────────────────────────────────────────────

fn name_and_description(body: Value) -> Result<(Option<String>, Option<String>), Problem> {
    let fields = Fields::of(body)?;
    Ok((fields.text("name")?, fields.text("description")?))
}

fn solutions_routes(targets: &Arc<Targets>, entries: &mut Vec<RouteEntry>) {
    let t = targets.clone();
    // A read key's, like the repository and image lists this tree regroups; the key's restriction narrows it, and
    // drops the account's project grants (`narrowed_by_credential`).
    entries.push(
        Route::get("/api/v1/solutions").requires(Access::Account).scoped().accepts_api_key(ApiKeyScope::Read).handler(
            move |caller: Caller,
                  address: ClientAddress,
                  headers: HeaderMap,
                  method: Method,
                  uri: Uri,
                  Scoped(scope): Scoped<CallerScope>| {
                let t = t.clone();
                async move {
                    let call = call(&caller, &address, &headers, &method, &uri);
                    let allowance = match allowance(&call, scope) {
                        Ok(allowance) => allowance,
                        Err(refused) => return *refused,
                    };
                    let tree = attempt!(call, t.tree(&allowance).await);
                    ok(StatusCode::OK, &json::Tree::of(&tree))
                }
            },
        ),
    );
    let t = targets.clone();
    entries.push(Route::post("/api/v1/solutions").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              request: Request| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let body = read!(body_of(request).await);
                let (name, description) = read!(name_and_description(body));
                let created =
                    attempt!(call, t.create_solution(name.as_deref(), description.as_deref(), &call.actor).await);
                ok(StatusCode::CREATED, &json::Solution::of(&created))
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::patch("/api/v1/solutions/{id}").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>,
              request: Request| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let id = read!(read::path_long("id", &id));
                let body = read!(body_of(request).await);
                let (name, description) = read!(name_and_description(body));
                attempt!(call, require_everything(&allowance, rows::SOLUTION_NOT_FOUND));
                let updated =
                    attempt!(call, t.update_solution(id, name.as_deref(), description.as_deref(), &call.actor).await);
                ok(StatusCode::OK, &json::Solution::of(&updated))
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::delete("/api/v1/solutions/{id}").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let id = read!(read::path_long("id", &id));
                attempt!(call, require_everything(&allowance, rows::SOLUTION_NOT_FOUND));
                attempt!(call, t.delete_solution(id, &call.actor).await);
                no_content()
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::post("/api/v1/solutions/{id}/projects").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>,
              request: Request| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let id = read!(read::path_long("id", &id));
                let body = read!(body_of(request).await);
                let (name, description) = read!(name_and_description(body));
                attempt!(call, require_everything(&allowance, rows::SOLUTION_NOT_FOUND));
                let created =
                    attempt!(call, t.create_project(id, name.as_deref(), description.as_deref(), &call.actor).await);
                ok(StatusCode::CREATED, &json::Project::of(&created))
            }
        },
    ));
}

// ── /api/v1/projects ─────────────────────────────────────────────────────────────────────

fn projects_routes(targets: &Arc<Targets>, entries: &mut Vec<RouteEntry>) {
    let t = targets.clone();
    entries.push(
        Route::get("/api/v1/projects/{id}")
            .requires(Access::Account)
            .scoped()
            .accepts_api_key(ApiKeyScope::Read)
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      method: Method,
                      uri: Uri,
                      Scoped(scope): Scoped<CallerScope>,
                      Path(id): Path<String>| {
                    let t = t.clone();
                    async move {
                        let call = call(&caller, &address, &headers, &method, &uri);
                        let allowance = match allowance(&call, scope) {
                            Ok(allowance) => allowance,
                            Err(refused) => return *refused,
                        };
                        let id = read!(read::path_long("id", &id));
                        let detail = attempt!(call, t.project_detail(id, &allowance).await);
                        ok(StatusCode::OK, &json::Detail::of(&detail))
                    }
                },
            ),
    );
    let t = targets.clone();
    entries.push(Route::patch("/api/v1/projects/{id}").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>,
              request: Request| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let id = read!(read::path_long("id", &id));
                let body = read!(body_of(request).await);
                let fields = read!(Fields::of(body));
                let name = read!(fields.text("name"));
                let description = read!(fields.text("description"));
                let solution_id = read!(fields.long("solutionId"));
                attempt!(call, require_everything(&allowance, rows::PROJECT_NOT_FOUND));
                let updated = attempt!(
                    call,
                    t.update_project(
                        id,
                        name.as_deref(),
                        description.as_deref(),
                        solution_id,
                        &allowance.visibility,
                        &call.actor
                    )
                    .await
                );
                ok(StatusCode::OK, &json::Project::of(&updated))
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::delete("/api/v1/projects/{id}").requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path(id): Path<String>| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let id = read!(read::path_long("id", &id));
                attempt!(call, require_everything(&allowance, rows::PROJECT_NOT_FOUND));
                attempt!(call, t.delete_project(id, &call.actor).await);
                no_content()
            }
        },
    ));
    for (method_route, kind) in [
        (Filing::File, Kind::Repository),
        (Filing::Remove, Kind::Repository),
        (Filing::File, Kind::Container),
        (Filing::Remove, Kind::Container),
    ] {
        entries.push(filing_route(targets, method_route, kind));
    }
}

#[derive(Clone, Copy)]
enum Filing {
    File,
    Remove,
}

#[derive(Clone, Copy)]
enum Kind {
    Repository,
    Container,
}

/// `PUT` files a target into the project, `DELETE` returns it to none — within the caller's allowance on the target.
fn filing_route(targets: &Arc<Targets>, filing: Filing, kind: Kind) -> RouteEntry {
    let (path, variable) = match kind {
        Kind::Repository => ("/api/v1/projects/{id}/repositories/{repositoryId}", "repositoryId"),
        Kind::Container => ("/api/v1/projects/{id}/containers/{containerId}", "containerId"),
    };
    let spec = match filing {
        Filing::File => Route::put(path),
        Filing::Remove => Route::delete(path),
    };
    let t = targets.clone();
    spec.requires(Access::Administrator).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Scoped(scope): Scoped<CallerScope>,
              Path((project, target)): Path<(String, String)>| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let allowance = match allowance(&call, scope) {
                    Ok(allowance) => allowance,
                    Err(refused) => return *refused,
                };
                let project = read!(read::path_long("id", &project));
                let target = read!(read::path_long(variable, &target));
                let visibility = &allowance.visibility;
                let done = match (filing, kind) {
                    (Filing::File, Kind::Repository) => {
                        t.file_repository(project, target, visibility, &call.actor).await
                    }
                    (Filing::Remove, Kind::Repository) => {
                        t.remove_repository(project, target, visibility, &call.actor).await
                    }
                    (Filing::File, Kind::Container) => t.file_container(project, target, visibility, &call.actor).await,
                    (Filing::Remove, Kind::Container) => {
                        t.remove_container(project, target, visibility, &call.actor).await
                    }
                };
                attempt!(call, done);
                no_content()
            }
        },
    )
}

// ── /api/v1/git-tokens, /api/v1/ssh-keys ─────────────────────────────────────────────────

/// The clone credentials name no target: an administrator's configuration, the same whoever the targets are.
fn credentials_routes(targets: &Arc<Targets>, entries: &mut Vec<RouteEntry>) {
    let t = targets.clone();
    entries.push(Route::get("/api/v1/git-tokens").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, method: Method, uri: Uri| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let tokens = attempt!(call, t.git_tokens().await);
                ok(StatusCode::OK, &tokens.iter().map(json::GitTokenSummary::of).collect::<Vec<_>>())
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::post("/api/v1/git-tokens").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              request: Request| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let body = read!(body_of(request).await);
                let fields = read!(Fields::of(body));
                let (name, host, username, token) = (
                    read!(fields.text("name")),
                    read!(fields.text("host")),
                    read!(fields.text("username")),
                    read!(fields.text("token")),
                );
                let added = attempt!(
                    call,
                    t.add_git_token(
                        name.as_deref(),
                        host.as_deref(),
                        username.as_deref(),
                        token.as_deref(),
                        &call.actor
                    )
                    .await
                );
                ok(StatusCode::OK, &json::GitTokenSummary::of(&added))
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::delete("/api/v1/git-tokens/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Path(id): Path<String>| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let id = read!(read::path_uuid("id", &id));
                attempt!(call, t.remove_git_token(id, &call.actor).await);
                no_content()
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::get("/api/v1/ssh-keys").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, method: Method, uri: Uri| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let keys = attempt!(call, t.ssh_keys().await);
                ok(StatusCode::OK, &keys.iter().map(json::SshKeySummary::of).collect::<Vec<_>>())
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::post("/api/v1/ssh-keys").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              request: Request| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let body = read!(body_of(request).await);
                let fields = read!(Fields::of(body));
                let (name, private_key, public_key) =
                    (read!(fields.text("name")), read!(fields.text("private_key")), read!(fields.text("public_key")));
                let added = attempt!(
                    call,
                    t.add_ssh_key(name.as_deref(), private_key.as_deref(), public_key.as_deref(), &call.actor).await
                );
                ok(StatusCode::OK, &json::SshKeySummary::of(&added))
            }
        },
    ));
    let t = targets.clone();
    entries.push(Route::delete("/api/v1/ssh-keys/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              method: Method,
              uri: Uri,
              Path(id): Path<String>| {
            let t = t.clone();
            async move {
                let call = call(&caller, &address, &headers, &method, &uri);
                let id = read!(read::path_uuid("id", &id));
                attempt!(call, t.remove_ssh_key(id, &call.actor).await);
                no_content()
            }
        },
    ));
}
