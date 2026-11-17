//! `ScimUsersController` and `ScimGroupsController` (task 1.7, third stage): the identity provider's provisioning, over
//! SCIM's service of stage 2c. `@RequiresAdministrator` on both — the SCIM token's principal is one, on `/scim` alone.
//!
//! **SCIM's own documents, not problem documents**: every answer is `application/scim+json`, a refusal the controllers'
//! `ScimErrorResponse` (`schemas`, the status as a string, `scimType` when RFC 7644 names one, `detail`), every member
//! that is `null` left out (`@JsonInclude(NON_NULL)`). What Spring refuses before a controller runs — a path variable
//! that is no number, a body that is not JSON — stays the handler's problem document, as it does in Java.

use std::sync::Arc;

use axum::extract::{Path, Request};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use serde::Serialize;
use serde_json::Value;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::principal::Credential;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem};
use vectispire_domain::java;

use super::read::{self, UNREADABLE};
use super::{body_of, unexpected, user_agent};
use crate::accounts::{Audit, Clock, RequestActor, UserView};
use crate::scim::{
    GroupChange, GroupCreation, GroupView, PatchOperation, ScimError, ScimProvisioning, UserAttributes, UserChange,
    UserCreation,
};

const SCIM_JSON: &str = "application/scim+json";
const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCHEMA_LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCHEMA_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const USERS: &str = "/scim/v2/Users";
const GROUPS: &str = "/scim/v2/Groups";

/// A SCIM document, written as Jackson writes it under `produces = "application/scim+json"`.
fn scim<T: Serialize + ?Sized>(status: StatusCode, value: &T) -> Response {
    let mut response = Response::new(axum::body::Body::from(vectispire_domain::wire::to_wire_string(value)));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(SCIM_JSON));
    response
}

/// `ResponseEntity.created(URI.create(location))`.
fn created<T: Serialize + ?Sized>(location: String, value: &T) -> Response {
    let mut response = scim(StatusCode::CREATED, value);
    if let Ok(location) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

/// `ScimErrorResponse.of(status, scimType, detail)`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    schemas: [&'static str; 1],
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scim_type: Option<&'static str>,
    detail: String,
}

/// A refusal, written by the controllers' `@ExceptionHandler`s with no content type of their own: `application/json`,
/// not the routes' `application/scim+json`.
fn refused(status: StatusCode, scim_type: Option<&'static str>, detail: impl Into<String>) -> Response {
    let mut response = scim(
        status,
        &ErrorResponse {
            schemas: [SCHEMA_ERROR],
            status: status.as_u16().to_string(),
            scim_type,
            detail: detail.into(),
        },
    );
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// **`/scim` takes the SCIM token and nothing else**: an administrator's session or key reaching it is the chain's
/// 403, audited `Access denied: Access Denied`, as Java answers it — the directory's provisioning is the directory's,
/// and an account that could drive it would bypass every rule of the account screens.
fn only_the_token(caller: &Caller) -> Option<Response> {
    (!matches!(caller.0.credential, Credential::Scim)).then(|| vectispire_cp_http::chain::denied("Access Denied"))
}

fn not_found(detail: String) -> Response {
    refused(StatusCode::NOT_FOUND, None, detail)
}

fn uniqueness(detail: &str) -> Response {
    refused(StatusCode::CONFLICT, Some("uniqueness"), detail)
}

/// The controllers' `@ExceptionHandler`s: an input refused 400, a filter refused 400 `invalidFilter`, an
/// administrative account 403; a failure is the handler's 500.
fn scim_refusal(path: &str, error: ScimError) -> Response {
    match error {
        ScimError::InvalidInput(message) => refused(StatusCode::BAD_REQUEST, None, message),
        refusal @ ScimError::InvalidFilter(_) => {
            let scim_type = refusal.scim_type();
            refused(StatusCode::BAD_REQUEST, scim_type, refusal.to_string())
        }
        ScimError::ProtectedAccount(message) => refused(StatusCode::FORBIDDEN, None, message),
        failure @ ScimError::Failed(_) => unexpected(path, &failure),
    }
}

/// `RequestActors.unnamed(request)`: SCIM writes in nobody's name — the directory is not an account.
fn unnamed(address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor { username: None, ip_address: Some(address.0.clone()), user_agent: user_agent(headers) }
}

fn unreadable() -> Problem {
    Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE)
}

/// A `String` member as Jackson binds it: absent or `null` is `None`; a scalar is its text; a container refuses the body.
fn text(value: Option<&Value>) -> Result<Option<String>, Problem> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(Value::Number(number)) => Ok(Some(number.to_string())),
        Some(Value::Bool(flag)) => Ok(Some(flag.to_string())),
        Some(_) => Err(unreadable()),
    }
}

/// A record member, or `None` for absent and `null`; anything but an object refuses the body.
fn object(value: Option<&Value>) -> Result<Option<&serde_json::Map<String, Value>>, Problem> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(fields)) => Ok(Some(fields)),
        Some(_) => Err(unreadable()),
    }
}

/// A list member, or `None` for absent and `null`; anything but an array refuses the body.
fn list(value: Option<&Value>) -> Result<Option<&Vec<Value>>, Problem> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => Ok(Some(items)),
        Some(_) => Err(unreadable()),
    }
}

/// The first element's `value`, as the controller reads `emails.get(0).value()` and `roles.get(0).value()`.
fn first_value(items: Option<&Vec<Value>>) -> Result<Option<String>, Problem> {
    let Some(first) = items.and_then(|items| items.first()) else { return Ok(None) };
    match object(Some(first))? {
        Some(fields) => text(fields.get("value")),
        // A `null` element is a `NullPointerException` in Java's controller: refused here as unreadable instead.
        None => Err(unreadable()),
    }
}

/// `attributesOf(ScimUserDto)`.
fn user_attributes(body: &Value) -> Result<UserAttributes, Problem> {
    let Value::Object(fields) = body else { return Err(unreadable()) };
    let display_name = text(fields.get("displayName"))?;
    let formatted = match object(fields.get("name"))? {
        Some(name) => text(name.get("formatted"))?,
        None => None,
    };
    // `displayNameOf`: the display name when not blank, else the name's formatted one, trimmed either way.
    let display_name = display_name
        .filter(|name| !java::is_blank(name))
        .or(formatted.filter(|name| !java::is_blank(name)))
        .map(|name| java::trim(&name).to_owned());
    let active = match fields.get("active") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(flag)) => Some(*flag),
        Some(Value::String(flag)) if flag == "true" || flag == "false" => Some(flag == "true"),
        Some(_) => return Err(unreadable()),
    };
    Ok(UserAttributes {
        user_name: text(fields.get("userName"))?,
        display_name,
        email: first_value(list(fields.get("emails"))?)?,
        external_id: text(fields.get("externalId"))?,
        active,
        role: first_value(list(fields.get("roles"))?)?,
    })
}

/// `operationsOf(ScimPatchOp)`: `Operations`, each `op`, `path` and `value` as sent; absent is `None`.
fn operations(body: &Value) -> Result<Option<Vec<PatchOperation>>, Problem> {
    let Value::Object(fields) = body else { return Err(unreadable()) };
    let Some(items) = list(fields.get("Operations"))? else { return Ok(None) };
    items
        .iter()
        .map(|item| {
            let fields = object(Some(item))?.ok_or_else(unreadable)?;
            Ok(PatchOperation {
                op: text(fields.get("op"))?,
                path: text(fields.get("path"))?,
                value: fields.get("value").filter(|value| !value.is_null()).cloned(),
            })
        })
        .collect::<Result<Vec<_>, Problem>>()
        .map(Some)
}

/// A group body: its `displayName`, and `memberValuesOf` — each member's `value`, the list absent when not sent.
type GroupBody = (Option<String>, Option<Vec<Option<String>>>);

/// A group body's `displayName` and `memberValuesOf`.
fn group_body(body: &Value) -> Result<GroupBody, Problem> {
    let Value::Object(fields) = body else { return Err(unreadable()) };
    let members = match list(fields.get("members"))? {
        None => None,
        Some(items) => Some(
            items
                .iter()
                .map(|item| match object(Some(item))? {
                    Some(member) => text(member.get("value")),
                    None => Err(unreadable()),
                })
                .collect::<Result<Vec<_>, Problem>>()?,
        ),
    };
    Ok((text(fields.get("displayName"))?, members))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    resource_type: &'static str,
    created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_modified: Option<String>,
    location: String,
}

#[derive(Debug, Serialize)]
struct Name {
    #[serde(skip_serializing_if = "Option::is_none")]
    formatted: Option<String>,
}

#[derive(Debug, Serialize)]
struct Email {
    value: String,
    #[serde(rename = "type")]
    kind: &'static str,
    primary: bool,
}

#[derive(Debug, Serialize)]
struct RoleEntry {
    value: String,
    primary: bool,
}

/// `ScimUserDto`, as `toDto(UserView)` fills it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserDto {
    schemas: [&'static str; 1],
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    user_name: String,
    name: Name,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    emails: Vec<Email>,
    roles: Vec<RoleEntry>,
    active: bool,
    meta: Meta,
}

impl UserDto {
    fn of(user: &UserView) -> UserDto {
        let emails = match user.email.as_deref() {
            Some(email) if !java::is_blank(email) => {
                vec![Email { value: email.to_owned(), kind: "work", primary: true }]
            }
            _ => Vec::new(),
        };
        UserDto {
            schemas: [SCHEMA_USER],
            id: user.id.to_string(),
            external_id: user.keycloak_id.clone(),
            user_name: user.username.clone(),
            name: Name { formatted: user.display_name.clone() },
            display_name: user.display_name.clone(),
            emails,
            roles: vec![RoleEntry { value: user.role.clone(), primary: true }],
            active: user.is_active,
            meta: Meta {
                resource_type: "User",
                created: super::json::instant(user.created_at),
                last_modified: Some(super::json::instant(user.updated_at)),
                location: format!("{USERS}/{}", user.id),
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct Member {
    value: String,
    display: String,
    #[serde(rename = "ref")]
    reference: String,
}

/// `ScimGroupDto`, as `toDto(GroupView)` fills it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupDto {
    schemas: [&'static str; 1],
    id: String,
    display_name: String,
    members: Vec<Member>,
    meta: Meta,
}

impl GroupDto {
    fn of(group: &GroupView) -> GroupDto {
        GroupDto {
            schemas: [SCHEMA_GROUP],
            id: group.id.to_string(),
            display_name: group.name.clone(),
            members: group
                .members
                .iter()
                .map(|member| Member {
                    value: member.user_id.to_string(),
                    display: member.display.clone(),
                    reference: format!("{USERS}/{}", member.user_id),
                })
                .collect(),
            meta: Meta {
                resource_type: "Group",
                created: super::json::instant(group.created_at),
                last_modified: None,
                location: format!("{GROUPS}/{}", group.id),
            },
        }
    }
}

/// `ScimListResponse.page`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListResponse<T> {
    schemas: [&'static str; 1],
    total_results: usize,
    start_index: i32,
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<T>,
}

impl<T> ListResponse<T> {
    fn page(resources: Vec<T>, total_results: usize, start_index: i32) -> ListResponse<T> {
        ListResponse { schemas: [SCHEMA_LIST], total_results, start_index, items_per_page: resources.len(), resources }
    }
}

pub(super) fn routes<A, C>(provisioning: Arc<ScimProvisioning<A, C>>, entries: &mut Vec<RouteEntry>)
where
    A: Audit + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    let service = provisioning.clone();
    entries.push(Route::get(USERS).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, uri: Uri| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let filter = read::query_text(uri.query(), "filter");
                let start = read!(read::query_int(uri.query(), "startIndex"));
                let count = read!(read::query_int(uri.query(), "count"));
                match service.users(filter.as_deref(), start, count).await {
                    Ok(page) => scim(
                        StatusCode::OK,
                        &ListResponse::page(
                            page.resources.iter().map(UserDto::of).collect(),
                            page.total_results,
                            page.start_index,
                        ),
                    ),
                    Err(refusal) => scim_refusal(USERS, refusal),
                }
            }
        },
    ));

    let service = provisioning.clone();
    entries.push(Route::get("/scim/v2/Users/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, Path(id): Path<String>| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let id = read!(read::path_long("id", &id));
                match service.user(id).await {
                    Ok(Some(user)) => scim(StatusCode::OK, &UserDto::of(&user)),
                    Ok(None) => not_found(format!("User {id} not found.")),
                    Err(refusal) => scim_refusal(USERS, refusal),
                }
            }
        },
    ));

    let service = provisioning.clone();
    entries.push(Route::post(USERS).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let attributes = read!(user_attributes(&read!(body_of(request).await)));
                match service.create_user(&attributes, &unnamed(&address, &headers)).await {
                    Ok(UserCreation::Created(user)) => created(format!("{USERS}/{}", user.id), &UserDto::of(&user)),
                    Ok(UserCreation::UsernameTaken) => uniqueness("An account with this userName already exists."),
                    Ok(UserCreation::ExternalIdTaken) => uniqueness("An account with this externalId already exists."),
                    Err(refusal) => scim_refusal(USERS, refusal),
                }
            }
        },
    ));

    let service = provisioning.clone();
    entries.push(Route::put("/scim/v2/Users/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>, request: Request| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let id = read!(read::path_long("id", &id));
                let attributes = read!(user_attributes(&read!(body_of(request).await)));
                match service.replace_user(id, &attributes, &unnamed(&address, &headers)).await {
                    Ok(UserChange::Changed(user)) => scim(StatusCode::OK, &UserDto::of(&user)),
                    Ok(UserChange::Absent) => not_found(format!("User {id} not found.")),
                    Ok(UserChange::ExternalIdTaken) => uniqueness("An account with this externalId already exists."),
                    Err(refusal) => scim_refusal(USERS, refusal),
                }
            }
        },
    ));

    let service = provisioning.clone();
    entries.push(Route::patch("/scim/v2/Users/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>, request: Request| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let id = read!(read::path_long("id", &id));
                let operations = read!(operations(&read!(body_of(request).await)));
                match service.patch_user(id, operations.as_deref(), &unnamed(&address, &headers)).await {
                    Ok(Some(user)) => scim(StatusCode::OK, &UserDto::of(&user)),
                    Ok(None) => not_found(format!("User {id} not found.")),
                    Err(refusal) => scim_refusal(USERS, refusal),
                }
            }
        },
    ));

    let service = provisioning.clone();
    entries.push(Route::delete("/scim/v2/Users/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let id = read!(read::path_long("id", &id));
                match service.delete_user(id, &unnamed(&address, &headers)).await {
                    Ok(()) => StatusCode::NO_CONTENT.into_response(),
                    Err(refusal) => scim_refusal(USERS, refusal),
                }
            }
        },
    ));

    let service = provisioning.clone();
    entries.push(Route::get(GROUPS).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, uri: Uri| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let start = read!(read::query_int(uri.query(), "startIndex"));
                let count = read!(read::query_int(uri.query(), "count"));
                match service.groups(start, count).await {
                    Ok(page) => scim(
                        StatusCode::OK,
                        &ListResponse::page(
                            page.resources.iter().map(GroupDto::of).collect(),
                            page.total_results,
                            page.start_index,
                        ),
                    ),
                    Err(refusal) => scim_refusal(GROUPS, refusal),
                }
            }
        },
    ));

    let service = provisioning.clone();
    entries.push(Route::get("/scim/v2/Groups/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, Path(id): Path<String>| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let id = read!(read::path_long("id", &id));
                match service.group(id).await {
                    Ok(Some(group)) => scim(StatusCode::OK, &GroupDto::of(&group)),
                    Ok(None) => not_found(format!("Group {id} not found.")),
                    Err(refusal) => scim_refusal(GROUPS, refusal),
                }
            }
        },
    ));

    let service = provisioning.clone();
    entries.push(Route::post(GROUPS).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, request: Request| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let (name, members) = read!(group_body(&read!(body_of(request).await)));
                match service.create_group(name.as_deref(), members.as_deref(), &unnamed(&address, &headers)).await {
                    Ok(GroupCreation::Created(group)) => {
                        created(format!("{GROUPS}/{}", group.id), &GroupDto::of(&group))
                    }
                    Ok(GroupCreation::NameTaken) => uniqueness("A group with this displayName already exists."),
                    Err(refusal) => scim_refusal(GROUPS, refusal),
                }
            }
        },
    ));

    let service = provisioning.clone();
    entries.push(Route::put("/scim/v2/Groups/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>, request: Request| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let id = read!(read::path_long("id", &id));
                let (name, members) = read!(group_body(&read!(body_of(request).await)));
                let actor = unnamed(&address, &headers);
                group_answer(id, service.replace_group(id, name.as_deref(), members.as_deref(), &actor).await)
            }
        },
    ));

    let service = provisioning.clone();
    entries.push(Route::patch("/scim/v2/Groups/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>, request: Request| {
            let service = service.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let id = read!(read::path_long("id", &id));
                let operations = read!(operations(&read!(body_of(request).await)));
                let actor = unnamed(&address, &headers);
                group_answer(id, service.patch_group(id, operations.as_deref(), &actor).await)
            }
        },
    ));

    entries.push(Route::delete("/scim/v2/Groups/{id}").requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(id): Path<String>| {
            let service = provisioning.clone();
            async move {
                if let Some(refused) = only_the_token(&caller) {
                    return refused;
                }
                let id = read!(read::path_long("id", &id));
                match service.delete_group(id, &unnamed(&address, &headers)).await {
                    Ok(()) => StatusCode::NO_CONTENT.into_response(),
                    Err(refusal) => scim_refusal(GROUPS, refusal),
                }
            }
        },
    ));
}

/// `answer(id, change)`.
fn group_answer(id: i64, change: Result<GroupChange, ScimError>) -> Response {
    match change {
        Ok(GroupChange::Changed(group)) => scim(StatusCode::OK, &GroupDto::of(&group)),
        Ok(GroupChange::Absent) => not_found(format!("Group {id} not found.")),
        Ok(GroupChange::NameTaken) => uniqueness("A group with this displayName already exists."),
        Err(refusal) => scim_refusal(GROUPS, refusal),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use vectispire_cp_http::principal::{Account, Principal, Role};

    #[test]
    fn only_the_scim_token_reaches_scim() {
        assert!(only_the_token(&Caller(Principal::scim())).is_none());
        let administrator = Principal::session(Account {
            username: "admin".into(),
            role: Some(Role::Admin),
            must_change_password: false,
        });
        let refused = only_the_token(&Caller(administrator)).unwrap();
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert!(refused.extensions().get::<vectispire_cp_http::chain::Denied>().is_some(), "audited by the chain");
    }

    #[test]
    fn a_refusal_is_plain_json_and_names_its_scim_type() {
        let answer = uniqueness("taken");
        assert_eq!(answer.status(), StatusCode::CONFLICT);
        assert_eq!(answer.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
        let ok = scim(StatusCode::OK, &serde_json::json!({}));
        assert_eq!(ok.headers().get(header::CONTENT_TYPE).unwrap(), SCIM_JSON);
    }

    #[test]
    fn the_display_name_falls_back_on_the_formatted_name_and_is_trimmed() {
        let read = |body: Value| user_attributes(&body).unwrap();
        let both = read(serde_json::json!({"displayName": " Ada ", "name": {"formatted": "Other"}}));
        assert_eq!(both.display_name.as_deref(), Some("Ada"));
        let blank = read(serde_json::json!({"displayName": "  ", "name": {"formatted": " Ada L "}}));
        assert_eq!(blank.display_name.as_deref(), Some("Ada L"));
        let roles =
            read(serde_json::json!({"roles": [{"value": "USER"}, {"value": "ADMIN"}], "emails": [{"value": "a@x"}]}));
        assert_eq!((roles.role.as_deref(), roles.email.as_deref()), (Some("USER"), Some("a@x")), "the first of each");
    }
}
