//! The module's routes: `ChecklistTemplatesController` (eleven), `ProjectChecklistsController` (twenty) and
//! `ChecklistContactsController` (four).
//!
//! **Read in Spring's order**: the role first (the route builder), then the path variables converted, the query's
//! parameters, then the body — refused in Spring's sentences — and the service's refusal answered as
//! `ApiExceptionHandler` answers it. A template names no target, so its routes resolve no visibility and the roles
//! decide; a project's checklist names a project, and each of its routes resolves the caller's allowance for the
//! service to refuse it (404, never 403).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Request};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use serde::Serialize;
use serde_json::Value;
use vectispire_cp_access::independence::IndependenceError;
use vectispire_cp_access::roles::{Role, role_of};
use vectispire_cp_access::security::CallerScope;
use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::extract::{JsonBody, Scoped};
use vectispire_cp_http::principal::ApiKeyScope;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem};

use crate::contact_service::ChecklistContacts;
use crate::documents::Documents;
use crate::error::{ChecklistError, Members};
use crate::node::Node;
use crate::project_checklists::{Participant, ProjectChecklists, ShownMeasurement};
use crate::templates::{
    AnswerWordsForm, ChecklistTemplates, Editor, EvidenceForm, HeaderCellForm, LayoutForm, PairForm, RuleLineForm,
};

mod read;

const TEMPLATES: &str = "/api/v1/checklist-templates";
const PROJECTS: &str = "/api/v1/projects/{projectId}/checklists";
const WORKBOOK_TYPES: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet, application/octet-stream";

/// What the routes are built over.
#[allow(missing_debug_implementations)] // a bag of services, moved into the routes at once
pub struct ChecklistServices {
    pub templates: Arc<ChecklistTemplates>,
    pub checklists: Arc<ProjectChecklists>,
    pub documents: Arc<Documents>,
    pub contacts: Arc<ChecklistContacts>,
}

/// The thirty-five routes.
pub fn routes(services: ChecklistServices) -> Vec<RouteEntry> {
    let mut entries = Vec::new();
    templates(&services, &mut entries);
    project_reads(&services, &mut entries);
    project_writes(&services, &mut entries);
    contacts(&services, &mut entries);
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

/// The caller's allowance, or the 500 a visibility that could not be resolved is.
macro_rules! allowance {
    ($scope:expr) => {
        match $scope {
            Ok(allowance) => allowance,
            Err(_) => return unexpected(&"the caller's visibility could not be resolved"),
        }
    };
}

fn ok<T: Serialize + ?Sized>(status: StatusCode, value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn answer<T: Serialize>(status: StatusCode, result: Result<T, ChecklistError>) -> Response {
    match result {
        Ok(value) => ok(status, &value),
        Err(refused) => refusal(refused),
    }
}

/// `UnexpectedFailure`: a reference the operator can find in the log, and nothing of the failure itself.
fn unexpected(failure: &dyn std::fmt::Display) -> Response {
    let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
    tracing::error!(reference = %reference, error = %failure, "Unexpected failure");
    Problem::handler(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
    )
    .with("correlationId", reference)
    .into_response()
}

/// `ApiExceptionHandler` on what the checklist services throw.
fn refusal(error: ChecklistError) -> Response {
    match error {
        ChecklistError::Invalid(message) => Problem::handler(StatusCode::BAD_REQUEST, message).into_response(),
        ChecklistError::NotFound(message) => Problem::handler(StatusCode::NOT_FOUND, message).into_response(),
        ChecklistError::Conflict(conflict) => {
            let problem = Problem::handler(StatusCode::CONFLICT, conflict.message).caused_by(conflict.cause.token());
            let problem = match conflict.members {
                Members::None => problem,
                Members::Incomplete(lines) => problem.with("lines", to_value(&lines)),
                Members::Measured(lines) => problem.with("lines", to_value(&lines)),
                Members::Cells(cells) => problem.with("cells", to_value(&cells)),
            };
            problem.into_response()
        }
        ChecklistError::AccessDenied(reason) => vectispire_cp_http::chain::denied(reason),
        ChecklistError::Independence(refused) => {
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
                failure @ IndependenceError::Failed(_) => unexpected(&failure),
            }
        }
        refused @ ChecklistError::TooLarge(_) => {
            Problem::handler(StatusCode::PAYLOAD_TOO_LARGE, refused.to_string()).into_response()
        }
        failure @ ChecklistError::Failed(_) => unexpected(&failure),
    }
}

fn to_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// `RequestActors.of(principal, request)`.
fn actor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor {
        username: caller.0.actor(),
        ip_address: Some(address.0.clone()),
        user_agent: headers.get(header::USER_AGENT).map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned()),
    }
}

/// `ChecklistTemplateService.Editor`: the signed-in account and the actor.
fn editor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> Editor {
    Editor { account_id: caller.0.grounds.account_id.unwrap_or(0), actor: actor(caller, address, headers) }
}

/// `ProjectChecklistService.Participant`: `principal.requireUser()` and the actor.
fn participant(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> Participant {
    Participant {
        account_id: caller.0.grounds.account_id.unwrap_or(0),
        username: caller.0.account.as_ref().map(|account| account.username.clone()).unwrap_or_default(),
        role: caller.0.grounds.stored_role.clone(),
        actor: actor(caller, address, headers),
    }
}

/// Whether the caller may relink a profile — and so is told why an account would not be reminded.
fn writes(caller: &Caller) -> bool {
    role_of(caller.0.grounds.stored_role.as_deref()).is_some_and(Role::can_cause_effects)
}

/// The body as JSON — the 415 and 400 Spring answers otherwise; `required` false reads a missing body as `null`.
async fn body_of(request: Request, required: bool) -> Result<Value, Problem> {
    use axum::extract::FromRequest as _;
    if !required {
        let (parts, body) = request.into_parts();
        let bytes = read::raw_body(body).await?;
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        let rebuilt = Request::from_parts(parts, Body::from(bytes));
        return JsonBody::<Value>::from_request(rebuilt, &()).await.map(|JsonBody(body)| body);
    }
    JsonBody::<Value>::from_request(request, &()).await.map(|JsonBody(body)| body)
}

/// A record body's fields; `None` stands for Java's `body == null`, which a required body never is.
fn fields(body: &Value) -> Result<Option<&serde_json::Map<String, Value>>, Problem> {
    match body {
        Value::Null => Ok(None),
        other => read::object(other).map(Some),
    }
}

fn query(uri: &Uri, name: &str) -> Option<String> {
    read::query_text(uri.query(), name)
}

fn query_int(uri: &Uri, name: &str) -> Result<Option<i32>, Problem> {
    read::query_int(uri.query(), name)
}

/// `ListWindow`'s two parameters, converted as Spring binds `Integer`s.
fn window(uri: &Uri) -> Result<(Option<i64>, Option<i64>), Problem> {
    Ok((query_int(uri, "limit")?.map(i64::from), query_int(uri, "offset")?.map(i64::from)))
}

/// `ContentDisposition.attachment().filename(name, UTF_8)`: the name quoted — as quoted-printable when it is not
/// printable ASCII — and again as RFC 5987's `filename*`.
fn attachment(name: &str) -> String {
    let printable = name.bytes().all(|byte| (b' '..=b'~').contains(&byte));
    let quoted = if printable {
        name.replace('\\', "\\\\").replace('"', "\\\"")
    } else {
        let mut encoded = String::from("=?UTF-8?Q?");
        for byte in name.bytes() {
            if byte.is_ascii_graphic() && !matches!(byte, b'=' | b'?' | b'_' | b'"') {
                encoded.push(char::from(byte));
            } else if byte == b' ' {
                encoded.push('_');
            } else {
                encoded.push_str(&format!("={byte:02X}"));
            }
        }
        encoded.push_str("?=");
        encoded
    };
    let mut extended = String::from("UTF-8''");
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&byte) {
            extended.push(char::from(byte));
        } else {
            extended.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("attachment; filename=\"{quoted}\"; filename*={extended}")
}

/// A download: always an attachment, an opaque or stated type, and no sniffing whatever the uploader declared.
fn download(name: &str, content_type: &'static str, content: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(content));
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&attachment(name)) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

// ------------------------------------------------------------------ the bodies, as Jackson binds the records

fn layout_form(body: &Value) -> Result<Option<LayoutForm>, Problem> {
    let Some(fields) = fields(body)? else { return Ok(None) };
    let columns = match fields.get("columns") {
        None | Some(Value::Null) => None,
        Some(Value::Object(map)) => Some(
            map.iter()
                .map(|(name, letters)| Ok((name.clone(), read::text(Some(letters))?)))
                .collect::<Result<Vec<_>, Problem>>()?,
        ),
        Some(_) => return Err(Problem::handler(StatusCode::BAD_REQUEST, read::UNREADABLE)),
    };
    let header = match fields.get("header") {
        None | Some(Value::Null) => None,
        Some(Value::Object(map)) => Some(
            map.iter()
                .map(|(name, cell)| {
                    let cell = read::record(Some(cell))?.map(|cell| -> Result<HeaderCellForm, Problem> {
                        Ok(HeaderCellForm {
                            label: read::text(cell.get("label"))?,
                            value: read::text(cell.get("value"))?,
                        })
                    });
                    Ok((name.clone(), cell.transpose()?))
                })
                .collect::<Result<Vec<_>, Problem>>()?,
        ),
        Some(_) => return Err(Problem::handler(StatusCode::BAD_REQUEST, read::UNREADABLE)),
    };
    let answers = match read::record(fields.get("answers"))? {
        None => None,
        Some(words) => Some(AnswerWordsForm {
            yes: read::text(words.get("yes"))?,
            no: read::text(words.get("no"))?,
            not_applicable: read::text(words.get("notApplicable"))?,
        }),
    };
    Ok(Some(LayoutForm {
        sheet: read::text(fields.get("sheet"))?,
        columns,
        first_item_row: read::int(fields.get("firstItemRow"))?,
        last_item_row: read::int(fields.get("lastItemRow"))?,
        header,
        answers,
    }))
}

/// `ChecklistRuleForm` bound as Jackson binds it, then `valueToTree`: every component present, `null` where unset,
/// each coerced to its declared type — what `ChecklistRule.parse` then reads.
fn rule_node(rule: &serde_json::Map<String, Value>) -> Result<Node, Problem> {
    let unreadable = || Problem::handler(StatusCode::BAD_REQUEST, read::UNREADABLE);
    let text = |name: &str| Ok::<Node, Problem>(read::text(rule.get(name))?.map_or(Node::Null, Node::Text));
    let int = |value: Option<&Value>| {
        Ok::<Node, Problem>(read::int(value)?.map_or(Node::Null, |read| Node::Integer(read.to_string())))
    };
    let texts = |value: Option<&Value>| {
        Ok::<Node, Problem>(read::texts(value)?.map_or(Node::Null, |items| {
            Node::Array(items.into_iter().map(|item| item.map_or(Node::Null, Node::Text)).collect())
        }))
    };
    // `BigDecimal`: a number as written (its digits, as the double serde read it), or a string read as one.
    let decimal = |value: Option<&Value>| -> Result<Node, Problem> {
        match value {
            None | Some(Value::Null) => Ok(Node::Null),
            Some(number @ Value::Number(_)) => match Node::of(number) {
                Node::Integer(digits) => Ok(crate::decimal::Decimal::parse(&digits).map_or(Node::Null, Node::Decimal)),
                other => Ok(other),
            },
            Some(Value::String(text)) if !vectispire_domain::java::trim(text).is_empty() => {
                crate::decimal::Decimal::parse(vectispire_domain::java::trim(text))
                    .map(Node::Decimal)
                    .ok_or_else(unreadable)
            }
            Some(Value::String(_)) => Ok(Node::Null),
            Some(_) => Err(unreadable()),
        }
    };
    let thresholds = match rule.get("thresholds") {
        None | Some(Value::Null) => Node::Null,
        Some(Value::Object(map)) => Node::Object(
            map.iter()
                .map(|(severity, threshold)| {
                    let node = match read::record(Some(threshold))? {
                        None => Node::Null,
                        Some(threshold) => Node::Object(vec![
                            ("maxOpen".to_owned(), int(threshold.get("maxOpen"))?),
                            ("minResolvedRatio".to_owned(), decimal(threshold.get("minResolvedRatio"))?),
                        ]),
                    };
                    Ok((severity.clone(), node))
                })
                .collect::<Result<Vec<_>, Problem>>()?,
        ),
        Some(_) => return Err(unreadable()),
    };
    let components = match read::records(rule.get("components"))? {
        None => Node::Null,
        Some(items) => Node::Array(
            items
                .into_iter()
                .map(|item| match item {
                    None => Ok(Node::Null),
                    Some(component) => Ok(Node::Object(vec![
                        (
                            "purlPrefix".to_owned(),
                            read::text(component.get("purlPrefix"))?.map_or(Node::Null, Node::Text),
                        ),
                        ("versions".to_owned(), texts(component.get("versions"))?),
                    ])),
                })
                .collect::<Result<Vec<_>, Problem>>()?,
        ),
    };
    let scope = match read::record(rule.get("scope"))? {
        None => Node::Null,
        Some(scope) => Node::Object(vec![
            ("include".to_owned(), texts(scope.get("include"))?),
            ("exclude".to_owned(), texts(scope.get("exclude"))?),
        ]),
    };
    let flag = read::flag(rule.get("requireSchedule"))?.map_or(Node::Null, Node::Bool);
    Ok(Node::Object(vec![
        ("kind".to_owned(), text("kind")?),
        ("maxAgeDays".to_owned(), int(rule.get("maxAgeDays"))?),
        ("requireSchedule".to_owned(), flag),
        ("scopes".to_owned(), texts(rule.get("scopes"))?),
        ("thresholds".to_owned(), thresholds),
        ("metric".to_owned(), text("metric")?),
        ("minimumRatio".to_owned(), decimal(rule.get("minimumRatio"))?),
        ("aggregation".to_owned(), text("aggregation")?),
        ("suitePattern".to_owned(), text("suitePattern")?),
        ("suitePatterns".to_owned(), texts(rule.get("suitePatterns"))?),
        ("minimumTests".to_owned(), int(rule.get("minimumTests"))?),
        ("components".to_owned(), components),
        ("scope".to_owned(), scope),
        ("minimumApprovals".to_owned(), int(rule.get("minimumApprovals"))?),
        ("windowDays".to_owned(), int(rule.get("windowDays"))?),
        ("branch".to_owned(), text("branch")?),
    ]))
}

// ------------------------------------------------------------------ the templates

fn templates(services: &ChecklistServices, entries: &mut Vec<RouteEntry>) {
    let service = services.templates.clone();
    entries.push(Route::get(TEMPLATES).requires(Access::GovernanceRead).names_no_target().handler(move |uri: Uri| {
        let service = service.clone();
        async move {
            let (limit, offset) = read!(window(&uri));
            answer(StatusCode::OK, service.list(limit, offset).await)
        }
    }));

    let service = services.templates.clone();
    entries.push(
        Route::get("/api/v1/checklist-templates/{slug}").requires(Access::GovernanceRead).names_no_target().handler(
            move |Path(slug): Path<String>| {
                let service = service.clone();
                async move { answer(StatusCode::OK, service.template(Some(&slug)).await) }
            },
        ),
    );

    let service = services.templates.clone();
    entries.push(
        Route::post("/api/v1/checklist-templates/{slug}/versions")
            .requires(Access::SecurityLead)
            .names_no_target()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Path(slug): Path<String>,
                      uri: Uri,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let content_type = headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
                        let essence =
                            content_type.map(|value| value.split(';').next().unwrap_or("").trim().to_ascii_lowercase());
                        if let Some(essence) = essence.as_deref()
                            && essence != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                            && essence != "application/octet-stream"
                        {
                            return read::unsupported(content_type, WORKBOOK_TYPES).into_response();
                        }
                        let name = query(&uri, "name");
                        let label = query(&uri, "label");
                        let workbook = read!(read::raw_body(request.into_body()).await);
                        if workbook.is_empty() {
                            // `@RequestBody byte[]`, required: an empty body is a missing one.
                            return Problem::handler(StatusCode::BAD_REQUEST, read::UNREADABLE).into_response();
                        }
                        let editor = editor(&caller, &address, &headers);
                        answer(
                            StatusCode::CREATED,
                            service
                                .import_workbook(Some(&slug), name.as_deref(), label.as_deref(), &workbook, &editor)
                                .await,
                        )
                    }
                },
            ),
    );

    let service = services.templates.clone();
    entries.push(
        Route::get("/api/v1/checklist-templates/{slug}/versions/{ordinal}")
            .requires(Access::GovernanceRead)
            .names_no_target()
            .handler(move |Path((slug, ordinal)): Path<(String, String)>| {
                let service = service.clone();
                async move {
                    let ordinal = read!(read::path_int("ordinal", &ordinal));
                    answer(StatusCode::OK, service.version(Some(&slug), ordinal).await)
                }
            }),
    );

    let service = services.templates.clone();
    entries.push(
        Route::get("/api/v1/checklist-templates/{slug}/versions/{ordinal}/preview")
            .requires(Access::GovernanceRead)
            .names_no_target()
            .handler(move |Path((slug, ordinal)): Path<(String, String)>, uri: Uri| {
                let service = service.clone();
                async move {
                    let ordinal = read!(read::path_int("ordinal", &ordinal));
                    let sheet = query(&uri, "sheet");
                    answer(StatusCode::OK, service.preview(Some(&slug), ordinal, sheet.as_deref()).await)
                }
            }),
    );

    let service = services.templates.clone();
    entries.push(
        Route::put("/api/v1/checklist-templates/{slug}/versions/{ordinal}/layout")
            .requires(Access::SecurityLead)
            .names_no_target()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Path((slug, ordinal)): Path<(String, String)>,
                      uri: Uri,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let ordinal = read!(read::path_int("ordinal", &ordinal));
                        let revision = read!(query_int(&uri, "revision"));
                        let body = read!(body_of(request, true).await);
                        let form = read!(layout_form(&body));
                        let editor = editor(&caller, &address, &headers);
                        answer(
                            StatusCode::OK,
                            service.confirm_layout(Some(&slug), ordinal, revision, form.as_ref(), &editor).await,
                        )
                    }
                },
            ),
    );

    let service = services.templates.clone();
    entries.push(
        Route::put("/api/v1/checklist-templates/{slug}/versions/{ordinal}/pairs")
            .requires(Access::SecurityLead)
            .names_no_target()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Path((slug, ordinal)): Path<(String, String)>,
                      uri: Uri,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let ordinal = read!(read::path_int("ordinal", &ordinal));
                        let revision = read!(query_int(&uri, "revision"));
                        let body = read!(body_of(request, true).await);
                        let pairs = match read!(fields(&body)) {
                            None => None,
                            Some(fields) => read!(read::records(fields.get("pairs"))).map(|items| {
                                items
                                    .into_iter()
                                    .map(|item| {
                                        item.map(|pair| -> Result<PairForm, Problem> {
                                            Ok(PairForm {
                                                added: read::text(pair.get("added"))?,
                                                removed: read::text(pair.get("removed"))?,
                                            })
                                        })
                                        .transpose()
                                    })
                                    .collect::<Result<Vec<_>, Problem>>()
                            }),
                        };
                        let pairs = read!(pairs.transpose());
                        let editor = editor(&caller, &address, &headers);
                        answer(
                            StatusCode::OK,
                            service.pair_items(Some(&slug), ordinal, revision, pairs.as_deref(), &editor).await,
                        )
                    }
                },
            ),
    );

    let service = services.templates.clone();
    entries.push(
        Route::put("/api/v1/checklist-templates/{slug}/versions/{ordinal}/evidence")
            .requires(Access::SecurityLead)
            .names_no_target()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Path((slug, ordinal)): Path<(String, String)>,
                      uri: Uri,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let ordinal = read!(read::path_int("ordinal", &ordinal));
                        let revision = read!(query_int(&uri, "revision"));
                        let body = read!(body_of(request, true).await);
                        let lines = match read!(fields(&body)) {
                            None => None,
                            Some(fields) => read!(read::records(fields.get("items"))).map(|items| {
                                items
                                    .into_iter()
                                    .map(|item| {
                                        item.map(|line| -> Result<EvidenceForm, Problem> {
                                            Ok(EvidenceForm {
                                                item_key: read::text(line.get("itemKey"))?,
                                                evidence_kind: read::text(line.get("evidenceKind"))?,
                                                evidence_validity_months: read::int(
                                                    line.get("evidenceValidityMonths"),
                                                )?,
                                            })
                                        })
                                        .transpose()
                                    })
                                    .collect::<Result<Vec<_>, Problem>>()
                            }),
                        };
                        let lines = read!(lines.transpose());
                        let editor = editor(&caller, &address, &headers);
                        answer(
                            StatusCode::OK,
                            service.set_evidence(Some(&slug), ordinal, revision, lines.as_deref(), &editor).await,
                        )
                    }
                },
            ),
    );

    let service = services.templates.clone();
    entries.push(
        Route::put("/api/v1/checklist-templates/{slug}/versions/{ordinal}/rules")
            .requires(Access::SecurityLead)
            .names_no_target()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Path((slug, ordinal)): Path<(String, String)>,
                      uri: Uri,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let ordinal = read!(read::path_int("ordinal", &ordinal));
                        let revision = read!(query_int(&uri, "revision"));
                        let body = read!(body_of(request, true).await);
                        let lines = match read!(fields(&body)) {
                            None => None,
                            Some(fields) => read!(read::records(fields.get("items"))).map(|items| {
                                items
                                    .into_iter()
                                    .map(|item| {
                                        item.map(|line| -> Result<RuleLineForm, Problem> {
                                            Ok(RuleLineForm {
                                                item_key: read::text(line.get("itemKey"))?,
                                                rule: read::record(line.get("rule"))?.map(rule_node).transpose()?,
                                            })
                                        })
                                        .transpose()
                                    })
                                    .collect::<Result<Vec<_>, Problem>>()
                            }),
                        };
                        let lines = read!(lines.transpose());
                        let editor = editor(&caller, &address, &headers);
                        answer(
                            StatusCode::OK,
                            service.bind_rules(Some(&slug), ordinal, revision, lines.as_deref(), &editor).await,
                        )
                    }
                },
            ),
    );

    let service = services.templates.clone();
    entries.push(
        Route::post("/api/v1/checklist-templates/{slug}/versions/{ordinal}/derive")
            .requires(Access::SecurityLead)
            .names_no_target()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Path((slug, ordinal)): Path<(String, String)>,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let ordinal = read!(read::path_int("ordinal", &ordinal));
                        let body = read!(body_of(request, false).await);
                        let label = match read!(fields(&body)) {
                            None => None,
                            Some(fields) => read!(read::text(fields.get("label"))),
                        };
                        let editor = editor(&caller, &address, &headers);
                        answer(
                            StatusCode::CREATED,
                            service.derive(Some(&slug), ordinal, label.as_deref(), &editor).await,
                        )
                    }
                },
            ),
    );

    let service = services.templates.clone();
    entries.push(
        Route::post("/api/v1/checklist-templates/{slug}/versions/{ordinal}/publish")
            .requires(Access::SecurityLead)
            .names_no_target()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Path((slug, ordinal)): Path<(String, String)>,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let ordinal = read!(read::path_int("ordinal", &ordinal));
                        let body = read!(body_of(request, true).await);
                        let revision = match read!(fields(&body)) {
                            None => None,
                            Some(fields) => read!(read::int(fields.get("revision"))),
                        };
                        let editor = editor(&caller, &address, &headers);
                        answer(StatusCode::OK, service.publish(Some(&slug), ordinal, revision, &editor).await)
                    }
                },
            ),
    );

    let service = services.templates.clone();
    entries.push(
        Route::post("/api/v1/checklist-templates/{slug}/versions/{ordinal}/retire")
            .requires(Access::SecurityLead)
            .names_no_target()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Path((slug, ordinal)): Path<(String, String)>| {
                    let service = service.clone();
                    async move {
                        let ordinal = read!(read::path_int("ordinal", &ordinal));
                        let editor = editor(&caller, &address, &headers);
                        answer(StatusCode::OK, service.retire(Some(&slug), ordinal, &editor).await)
                    }
                },
            ),
    );
}

// ------------------------------------------------------------------ a project's checklists: reads

fn project_reads(services: &ChecklistServices, entries: &mut Vec<RouteEntry>) {
    let service = services.checklists.clone();
    entries.push(Route::get(PROJECTS).requires(Access::Account).scoped().handler(
        move |Scoped(scope): Scoped<CallerScope>, Path(project): Path<String>, uri: Uri| {
            let service = service.clone();
            async move {
                let project = read!(read::path_long("projectId", &project));
                let (limit, offset) = read!(window(&uri));
                let allowance = allowance!(scope);
                answer(StatusCode::OK, service.list(project, &allowance, limit, offset).await)
            }
        },
    ));

    let service = services.checklists.clone();
    entries.push(
        Route::get("/api/v1/projects/{projectId}/checklists/context").requires(Access::Account).scoped().handler(
            move |Scoped(scope): Scoped<CallerScope>, Path(project): Path<String>| {
                let service = service.clone();
                async move {
                    let project = read!(read::path_long("projectId", &project));
                    let allowance = allowance!(scope);
                    answer(StatusCode::OK, service.context(project, &allowance).await)
                }
            },
        ),
    );

    let service = services.checklists.clone();
    entries.push(
        Route::get("/api/v1/projects/{projectId}/checklists/offered").requires(Access::Account).scoped().handler(
            move |Scoped(scope): Scoped<CallerScope>, Path(project): Path<String>| {
                let service = service.clone();
                async move {
                    let project = read!(read::path_long("projectId", &project));
                    let allowance = allowance!(scope);
                    answer(StatusCode::OK, service.offered(project, &allowance).await)
                }
            },
        ),
    );

    let service = services.checklists.clone();
    entries.push(
        Route::get("/api/v1/projects/{projectId}/checklists/{revision}").requires(Access::Account).scoped().handler(
            move |Scoped(scope): Scoped<CallerScope>, Path((project, revision)): Path<(String, String)>| {
                let service = service.clone();
                async move {
                    let project = read!(read::path_long("projectId", &project));
                    let revision = read!(read::path_int("revision", &revision));
                    let allowance = allowance!(scope);
                    answer(StatusCode::OK, service.read(project, revision, &allowance).await)
                }
            },
        ),
    );

    let service = services.checklists.clone();
    entries.push(
        Route::get("/api/v1/projects/{projectId}/checklists/{revision}/items/{itemId}/history")
            .requires(Access::Account)
            .scoped()
            .handler(
                move |Scoped(scope): Scoped<CallerScope>,
                      Path((project, revision, item)): Path<(String, String, String)>| {
                    let service = service.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let revision = read!(read::path_int("revision", &revision));
                        let item = read!(read::path_long("itemId", &item));
                        let allowance = allowance!(scope);
                        answer(StatusCode::OK, service.history(project, revision, item, &allowance).await)
                    }
                },
            ),
    );

    let service = services.checklists.clone();
    entries.push(
        Route::get("/api/v1/projects/{projectId}/checklists/{revision}/measurements")
            .requires(Access::Account)
            .scoped()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Scoped(scope): Scoped<CallerScope>,
                      Path((project, revision)): Path<(String, String)>| {
                    let service = service.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let revision = read!(read::path_int("revision", &revision));
                        let allowance = allowance!(scope);
                        let reader = participant(&caller, &address, &headers);
                        answer(StatusCode::OK, service.measurements(project, revision, &allowance, &reader).await)
                    }
                },
            ),
    );

    let service = services.checklists.clone();
    entries.push(
        Route::get("/api/v1/projects/{projectId}/checklists/{revision}/evidence/{evidenceId}/file")
            .requires(Access::Account)
            .scoped()
            .handler(
                move |Scoped(scope): Scoped<CallerScope>,
                      Path((project, revision, evidence)): Path<(String, String, String)>| {
                    let service = service.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let revision = read!(read::path_int("revision", &revision));
                        let evidence = read!(read::path_long("evidenceId", &evidence));
                        let allowance = allowance!(scope);
                        match service.download(project, revision, evidence, &allowance).await {
                            Ok(file) => download(&file.file_name, "application/octet-stream", file.content),
                            Err(refused) => refusal(refused),
                        }
                    }
                },
            ),
    );

    let documents = services.documents.clone();
    entries.push(
        Route::get("/api/v1/projects/{projectId}/checklists/{revision}/document")
            .requires(Access::Account)
            .accepts_api_key(ApiKeyScope::Export)
            .scoped()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Scoped(scope): Scoped<CallerScope>,
                      Path((project, revision)): Path<(String, String)>| {
                    let documents = documents.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let revision = read!(read::path_int("revision", &revision));
                        let allowance = allowance!(scope);
                        let actor = actor(&caller, &address, &headers);
                        match documents.export(project, revision, &allowance, &actor).await {
                            Ok(document) => download(&document.file_name, "application/zip", document.content),
                            Err(refused) => refusal(refused),
                        }
                    }
                },
            ),
    );
}

// ------------------------------------------------------------------ a project's checklists: writes

/// `ChecklistEditionRequest.edition`, `null` for a `null` body.
fn edition(body: &Value) -> Result<Option<i32>, Problem> {
    match fields(body)? {
        None => Ok(None),
        Some(fields) => read::int(fields.get("edition")),
    }
}

/// A route on one revision whose body is `ChecklistEditionRequest` — confirm, withdraw, submit, sign off, reopen.
macro_rules! edition_route {
    ($entries:expr, $service:expr, $path:literal, $id:literal, $status:expr, |$s:ident, $project:ident, $revision:ident, $third:ident, $allowance:ident, $edition:ident, $who:ident| $call:expr) => {{
        let service = $service.clone();
        $entries.push(Route::post($path).requires(Access::WriteAccount).scoped().handler(
            move |caller: Caller,
                  address: ClientAddress,
                  headers: HeaderMap,
                  Scoped(scope): Scoped<CallerScope>,
                  Path(segments): Path<std::collections::HashMap<String, String>>,
                  request: Request| {
                let $s = service.clone();
                async move {
                    let $project =
                        read!(read::path_long("projectId", segments.get("projectId").map_or("", String::as_str)));
                    let $revision =
                        read!(read::path_int("revision", segments.get("revision").map_or("", String::as_str)));
                    let $third = match segments.get($id) {
                        Some(raw) => read!(read::path_long($id, raw)),
                        None => 0,
                    };
                    let _ = $third;
                    let body = read!(body_of(request, true).await);
                    let $edition = read!(edition(&body));
                    let $allowance = allowance!(scope);
                    let $who = participant(&caller, &address, &headers);
                    answer($status, $call.await)
                }
            },
        ));
    }};
}

fn project_writes(services: &ChecklistServices, entries: &mut Vec<RouteEntry>) {
    let service = services.checklists.clone();
    entries.push(Route::post(PROJECTS).requires(Access::WriteAccount).scoped().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              Scoped(scope): Scoped<CallerScope>,
              Path(project): Path<String>,
              request: Request| {
            let service = service.clone();
            async move {
                let project = read!(read::path_long("projectId", &project));
                let body = read!(body_of(request, true).await);
                let (template, version, edition) = match read!(fields(&body)) {
                    None => (None, None, None),
                    Some(fields) => (
                        read!(read::text(fields.get("template"))),
                        read!(read::int(fields.get("version"))),
                        read!(read::int(fields.get("edition"))),
                    ),
                };
                let allowance = allowance!(scope);
                let who = participant(&caller, &address, &headers);
                answer(
                    StatusCode::CREATED,
                    service.open(project, &allowance, template.as_deref(), version, edition, &who).await,
                )
            }
        },
    ));

    let service = services.checklists.clone();
    entries.push(
        Route::post("/api/v1/projects/{projectId}/checklists/{revision}/items/{itemId}/answers")
            .requires(Access::WriteAccount)
            .scoped()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Scoped(scope): Scoped<CallerScope>,
                      Path((project, revision, item)): Path<(String, String, String)>,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let revision = read!(read::path_int("revision", &revision));
                        let item = read!(read::path_long("itemId", &item));
                        let body = read!(body_of(request, true).await);
                        let (value, comment, digest, edition) = match read!(fields(&body)) {
                            None => (None, None, None, None),
                            Some(fields) => (
                                read!(read::text(fields.get("value"))),
                                read!(read::text(fields.get("comment"))),
                                read!(read::text(fields.get("measurementDigest"))),
                                read!(read::int(fields.get("edition"))),
                            ),
                        };
                        let allowance = allowance!(scope);
                        let who = participant(&caller, &address, &headers);
                        answer(
                            StatusCode::CREATED,
                            service
                                .answer(
                                    project,
                                    revision,
                                    item,
                                    &allowance,
                                    value.as_deref(),
                                    comment.as_deref(),
                                    digest.as_deref(),
                                    edition,
                                    &who,
                                )
                                .await,
                        )
                    }
                },
            ),
    );

    let service = services.checklists.clone();
    entries.push(
        Route::post("/api/v1/projects/{projectId}/checklists/{revision}/answers/as-measured")
            .requires(Access::WriteAccount)
            .scoped()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Scoped(scope): Scoped<CallerScope>,
                      Path((project, revision)): Path<(String, String)>,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let revision = read!(read::path_int("revision", &revision));
                        let body = read!(body_of(request, true).await);
                        let (edition, lines) = match read!(fields(&body)) {
                            None => (None, None),
                            Some(fields) => {
                                let lines = read!(read::records(fields.get("lines"))).map(|items| {
                                    items
                                        .into_iter()
                                        .map(|item| {
                                            item.map(|line| -> Result<ShownMeasurement, Problem> {
                                                Ok(ShownMeasurement {
                                                    item_id: read::long(line.get("itemId"))?,
                                                    measurement_digest: read::text(line.get("measurementDigest"))?,
                                                })
                                            })
                                            .transpose()
                                        })
                                        .collect::<Result<Vec<_>, Problem>>()
                                });
                                (read!(read::int(fields.get("edition"))), read!(lines.transpose()))
                            }
                        };
                        let allowance = allowance!(scope);
                        let who = participant(&caller, &address, &headers);
                        answer(
                            StatusCode::OK,
                            service
                                .answer_as_measured(project, revision, &allowance, edition, lines.as_deref(), &who)
                                .await,
                        )
                    }
                },
            ),
    );

    edition_route!(
        entries,
        services.checklists,
        "/api/v1/projects/{projectId}/checklists/{revision}/items/{itemId}/confirmation",
        "itemId",
        StatusCode::CREATED,
        |s, project, revision, item, allowance, edition, who| s
            .confirm(project, revision, item, &allowance, edition, &who)
    );

    let service = services.checklists.clone();
    entries.push(
        Route::post("/api/v1/projects/{projectId}/checklists/{revision}/items/{itemId}/evidence/links")
            .requires(Access::WriteAccount)
            .scoped()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Scoped(scope): Scoped<CallerScope>,
                      Path((project, revision, item)): Path<(String, String, String)>,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let revision = read!(read::path_int("revision", &revision));
                        let item = read!(read::path_long("itemId", &item));
                        let body = read!(body_of(request, true).await);
                        let (link, performed_on, edition) = match read!(fields(&body)) {
                            None => (None, None, None),
                            Some(fields) => (
                                read!(read::text(fields.get("link"))),
                                read!(read::text(fields.get("performedOn"))),
                                read!(read::int(fields.get("edition"))),
                            ),
                        };
                        let allowance = allowance!(scope);
                        let who = participant(&caller, &address, &headers);
                        answer(
                            StatusCode::CREATED,
                            service
                                .attach_link(
                                    project,
                                    revision,
                                    item,
                                    &allowance,
                                    link.as_deref(),
                                    performed_on.as_deref(),
                                    edition,
                                    &who,
                                )
                                .await,
                        )
                    }
                },
            ),
    );

    let service = services.checklists.clone();
    entries.push(
        Route::post("/api/v1/projects/{projectId}/checklists/{revision}/items/{itemId}/evidence/files")
            .requires(Access::WriteAccount)
            .scoped()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Scoped(scope): Scoped<CallerScope>,
                      Path((project, revision, item)): Path<(String, String, String)>,
                      uri: Uri,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let revision = read!(read::path_int("revision", &revision));
                        let item = read!(read::path_long("itemId", &item));
                        let name = query(&uri, "name");
                        let performed_on = query(&uri, "performedOn");
                        let edition = read!(query_int(&uri, "edition"));
                        let content_type = headers
                            .get(header::CONTENT_TYPE)
                            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
                        let content = read!(read::raw_body(request.into_body()).await);
                        if content.is_empty() {
                            // `@RequestBody byte[]`, required: an empty body is a missing one.
                            return Problem::handler(StatusCode::BAD_REQUEST, read::UNREADABLE).into_response();
                        }
                        let allowance = allowance!(scope);
                        let who = participant(&caller, &address, &headers);
                        answer(
                            StatusCode::CREATED,
                            service
                                .attach_file(
                                    project,
                                    revision,
                                    item,
                                    &allowance,
                                    name.as_deref(),
                                    content_type.as_deref(),
                                    performed_on.as_deref(),
                                    &content,
                                    edition,
                                    &who,
                                )
                                .await,
                        )
                    }
                },
            ),
    );

    edition_route!(
        entries,
        services.checklists,
        "/api/v1/projects/{projectId}/checklists/{revision}/evidence/{evidenceId}/withdrawal",
        "evidenceId",
        StatusCode::OK,
        |s, project, revision, evidence, allowance, edition, who| s
            .withdraw(project, revision, evidence, &allowance, edition, &who)
    );
    edition_route!(
        entries,
        services.checklists,
        "/api/v1/projects/{projectId}/checklists/{revision}/submission",
        "",
        StatusCode::OK,
        |s, project, revision, unused, allowance, edition, who| s.submit(project, revision, &allowance, edition, &who)
    );
    edition_route!(
        entries,
        services.checklists,
        "/api/v1/projects/{projectId}/checklists/{revision}/sign-off",
        "",
        StatusCode::OK,
        |s, project, revision, unused, allowance, edition, who| s
            .sign_off(project, revision, &allowance, edition, &who)
    );
    edition_route!(
        entries,
        services.checklists,
        "/api/v1/projects/{projectId}/checklists/{revision}/reopen",
        "",
        StatusCode::CREATED,
        |s, project, revision, unused, allowance, edition, who| s.reopen(project, revision, &allowance, edition, &who)
    );

    let service = services.checklists.clone();
    entries.push(
        Route::post("/api/v1/projects/{projectId}/checklists/{revision}/return")
            .requires(Access::WriteAccount)
            .scoped()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Scoped(scope): Scoped<CallerScope>,
                      Path((project, revision)): Path<(String, String)>,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let revision = read!(read::path_int("revision", &revision));
                        let body = read!(body_of(request, true).await);
                        let (reason, edition) = match read!(fields(&body)) {
                            None => (None, None),
                            Some(fields) => {
                                (read!(read::text(fields.get("reason"))), read!(read::int(fields.get("edition"))))
                            }
                        };
                        let allowance = allowance!(scope);
                        let who = participant(&caller, &address, &headers);
                        answer(
                            StatusCode::OK,
                            service
                                .return_to_authors(project, revision, &allowance, reason.as_deref(), edition, &who)
                                .await,
                        )
                    }
                },
            ),
    );
}

// ------------------------------------------------------------------ contacts

fn contacts(services: &ChecklistServices, entries: &mut Vec<RouteEntry>) {
    let service = services.contacts.clone();
    entries.push(
        Route::get("/api/v1/projects/{projectId}/checklists/contacts").requires(Access::Account).scoped().handler(
            move |caller: Caller, Scoped(scope): Scoped<CallerScope>, Path(project): Path<String>| {
                let service = service.clone();
                async move {
                    let project = read!(read::path_long("projectId", &project));
                    let allowance = allowance!(scope);
                    answer(StatusCode::OK, service.contacts(project, &allowance, writes(&caller)).await)
                }
            },
        ),
    );

    let service = services.contacts.clone();
    entries.push(
        Route::get("/api/v1/projects/{projectId}/checklists/contacts/candidates")
            .requires(Access::WriteAccount)
            .scoped()
            .handler(move |Scoped(scope): Scoped<CallerScope>, Path(project): Path<String>, uri: Uri| {
                let service = service.clone();
                async move {
                    let project = read!(read::path_long("projectId", &project));
                    let (limit, offset) = read!(window(&uri));
                    let allowance = allowance!(scope);
                    answer(StatusCode::OK, service.candidates(project, &allowance, limit, offset).await)
                }
            }),
    );

    let service = services.contacts.clone();
    entries.push(
        Route::put("/api/v1/projects/{projectId}/checklists/contacts/{profile}")
            .requires(Access::WriteAccount)
            .scoped()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Scoped(scope): Scoped<CallerScope>,
                      Path((project, profile)): Path<(String, String)>,
                      request: Request| {
                    let service = service.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let body = read!(body_of(request, true).await);
                        let account = match read!(fields(&body)) {
                            None => None,
                            Some(fields) => read!(read::long(fields.get("accountId"))),
                        };
                        let allowance = allowance!(scope);
                        let who = participant(&caller, &address, &headers);
                        answer(StatusCode::OK, service.link(project, Some(&profile), account, &allowance, &who).await)
                    }
                },
            ),
    );

    let service = services.contacts.clone();
    entries.push(
        Route::delete("/api/v1/projects/{projectId}/checklists/contacts/{profile}")
            .requires(Access::WriteAccount)
            .scoped()
            .handler(
                move |caller: Caller,
                      address: ClientAddress,
                      headers: HeaderMap,
                      Scoped(scope): Scoped<CallerScope>,
                      Path((project, profile)): Path<(String, String)>| {
                    let service = service.clone();
                    async move {
                        let project = read!(read::path_long("projectId", &project));
                        let allowance = allowance!(scope);
                        let who = participant(&caller, &address, &headers);
                        answer(StatusCode::OK, service.unlink(project, Some(&profile), &allowance, &who).await)
                    }
                },
            ),
    );
}
