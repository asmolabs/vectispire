//! `ForgeDiscoveriesController` and `ForgeImportsController`: a connection's discoveries, the selection over its
//! snapshot, the preview and the import. Administrators only; the services decide, these map the requests.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery};
use axum::response::IntoResponse;
use http::{HeaderMap, StatusCode};
use serde_json::{Map, Value};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem};
use vectispire_domain::forges::mapping::Rule;

use super::read::{self, Record};
use super::{
    DISCOVERIES, DISCOVERY, IMPORTS, PREVIEW, REPOSITORIES, SELECTION, actor, json_response, ok, optional_record,
    refuse,
};
use crate::Services;
use crate::imports::{Filters, SelectionChange};
use crate::internal::planner::{CredentialChoice, ImportRequest};

macro_rules! or_answer {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(problem) => return problem.into_response(),
        }
    };
}

fn filters(fields: &Map<String, Value>) -> Result<Filters, Problem> {
    Ok(Filters {
        archived: read::text(fields.get("archived"))?,
        forks: read::text(fields.get("forks"))?,
        inactive_days: read::int(fields.get("inactiveDays"))?.map(i64::from),
        language: read::text(fields.get("language"))?,
        visibility: read::text(fields.get("visibility"))?,
        namespace: read::text(fields.get("namespace"))?,
        path: read::text(fields.get("path"))?,
        personal: read::text(fields.get("personal"))?,
        present: read::text(fields.get("present"))?,
    })
}

fn selection_change(fields: &Map<String, Value>) -> Result<SelectionChange, Problem> {
    Ok(SelectionChange {
        filters: read::record(fields.get("filters"))?.map(filters).transpose()?,
        selected: read::texts(fields.get("selected"))?,
        operation: read::text(fields.get("operation"))?,
        forge_ids: read::texts(fields.get("forgeIds"))?,
    })
}

fn rule(fields: Record<'_>) -> Result<Rule, Problem> {
    Ok(Rule {
        namespace_path: read::text(fields.get("namespacePath"))?,
        forge_id: read::text(fields.get("forgeId"))?,
        solution: read::text(fields.get("solution"))?,
        project: read::text(fields.get("project"))?,
        no_project: read::flag(fields.get("noProject"))?,
    })
}

fn choice(fields: Record<'_>) -> Result<CredentialChoice, Problem> {
    Ok(CredentialChoice {
        host: read::text(fields.get("host"))?,
        ssh_key_id: read::text(fields.get("sshKeyId"))?,
        https_token_id: read::text(fields.get("httpsTokenId"))?,
    })
}

/// A list of records, each read by `each`; a `null` element kept as `None`.
fn records<T>(
    fields: &Map<String, Value>,
    name: &str,
    each: fn(Record<'_>) -> Result<T, Problem>,
) -> Result<Option<Vec<Option<T>>>, Problem> {
    read::records(fields.get(name))?
        .map(|items| items.into_iter().map(|item| item.map(each).transpose()).collect::<Result<Vec<_>, _>>())
        .transpose()
}

fn import_request(fields: &Map<String, Value>) -> Result<ImportRequest, Problem> {
    Ok(ImportRequest {
        discovery_id: read::long(fields.get("discoveryId"))?,
        forge_ids: read::texts(fields.get("forgeIds"))?,
        mapping: records(fields, "mapping", rule)?,
        credentials: records(fields, "credentials", choice)?,
        first_scan: read::flag(fields.get("firstScan"))?,
        spacing_seconds: read::int(fields.get("spacingSeconds"))?.map(i64::from),
        required_agent_label: read::text(fields.get("requiredAgentLabel"))?,
    })
}

fn optional_request(headers: &HeaderMap, body: &[u8]) -> Result<Option<ImportRequest>, Problem> {
    optional_record(headers, body)?.as_ref().map(import_request).transpose()
}

/// The two path variables, in their declared order: the connection's `UUID`, then the discovery's `long`.
fn ids(connection: &str, discovery: &str) -> Result<(String, i64), Problem> {
    Ok((read::path_uuid("connectionId", connection)?, read::path_long("discoveryId", discovery)?))
}

pub(crate) fn routes(services: &Arc<Services>, entries: &mut Vec<RouteEntry>) {
    let s = services.clone();
    entries.push(Route::post(DISCOVERIES).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, Path(connection): Path<String>| {
            let s = s.clone();
            async move {
                let connection = or_answer!(read::path_uuid("connectionId", &connection));
                match s.discoveries.request(&connection, &actor(&caller, &address, &headers)).await {
                    Ok(view) => json_response(StatusCode::ACCEPTED, &view),
                    Err(refused) => refuse("POST", DISCOVERIES, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::get(DISCOVERIES).requires(Access::Administrator).names_no_target().handler(
        move |Path(connection): Path<String>, RawQuery(query): RawQuery| {
            let s = s.clone();
            async move {
                let connection = or_answer!(read::path_uuid("connectionId", &connection));
                let limit = or_answer!(read::query_int(query.as_deref(), "limit"));
                let offset = or_answer!(read::query_int(query.as_deref(), "offset"));
                match s.discoveries.list(&connection, limit.map(i64::from), offset.map(i64::from)).await {
                    Ok(views) => ok(&views),
                    Err(refused) => refuse("GET", DISCOVERIES, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::get(DISCOVERY).requires(Access::Administrator).names_no_target().handler(
        move |Path((connection, discovery)): Path<(String, String)>| {
            let s = s.clone();
            async move {
                let (connection, discovery) = or_answer!(ids(&connection, &discovery));
                match s.discoveries.get(&connection, discovery).await {
                    Ok(view) => ok(&view),
                    Err(refused) => refuse("GET", DISCOVERY, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::get(REPOSITORIES).requires(Access::Administrator).names_no_target().handler(
        move |Path((connection, discovery)): Path<(String, String)>, RawQuery(query): RawQuery| {
            let s = s.clone();
            async move {
                let (connection, discovery) = or_answer!(ids(&connection, &discovery));
                let change = read::query_text(query.as_deref(), "change");
                let limit = or_answer!(read::query_int(query.as_deref(), "limit"));
                let offset = or_answer!(read::query_int(query.as_deref(), "offset"));
                let page = s
                    .discoveries
                    .repositories(
                        &connection,
                        discovery,
                        change.as_deref(),
                        limit.map(i64::from),
                        offset.map(i64::from),
                    )
                    .await;
                match page {
                    Ok(page) => ok(&page),
                    Err(refused) => refuse("GET", REPOSITORIES, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::get(SELECTION).requires(Access::Administrator).names_no_target().handler(
        move |Path((connection, discovery)): Path<(String, String)>, RawQuery(query): RawQuery| {
            let s = s.clone();
            async move {
                let (connection, discovery) = or_answer!(ids(&connection, &discovery));
                let q = query.as_deref();
                let wanted = Filters {
                    archived: read::query_text(q, "archived"),
                    forks: read::query_text(q, "forks"),
                    inactive_days: or_answer!(read::query_int(q, "inactiveDays")).map(i64::from),
                    language: read::query_text(q, "language"),
                    visibility: read::query_text(q, "visibility"),
                    namespace: read::query_text(q, "namespace"),
                    path: read::query_text(q, "path"),
                    personal: read::query_text(q, "personal"),
                    present: read::query_text(q, "present"),
                };
                let limit = or_answer!(read::query_int(q, "limit"));
                let offset = or_answer!(read::query_int(q, "offset"));
                let page = s
                    .imports
                    .candidates(&connection, discovery, &wanted, limit.map(i64::from), offset.map(i64::from))
                    .await;
                match page {
                    Ok(page) => ok(&page),
                    Err(refused) => refuse("GET", SELECTION, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::post(SELECTION).requires(Access::Administrator).names_no_target().handler(
        move |headers: HeaderMap, Path((connection, discovery)): Path<(String, String)>, body: Bytes| {
            let s = s.clone();
            async move {
                let (connection, discovery) = or_answer!(ids(&connection, &discovery));
                let fields = or_answer!(optional_record(&headers, &body));
                let change = or_answer!(fields.as_ref().map(selection_change).transpose());
                match s.imports.select(&connection, discovery, change).await {
                    Ok(selection) => ok(&selection),
                    Err(refused) => refuse("POST", SELECTION, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::post(PREVIEW).requires(Access::Administrator).names_no_target().handler(
        move |headers: HeaderMap, Path(connection): Path<String>, body: Bytes| {
            let s = s.clone();
            async move {
                let connection = or_answer!(read::path_uuid("connectionId", &connection));
                let request = or_answer!(optional_request(&headers, &body));
                match s.imports.preview(&connection, request.as_ref()).await {
                    Ok(preview) => ok(&preview),
                    Err(refused) => refuse("POST", PREVIEW, refused),
                }
            }
        },
    ));

    let s = services.clone();
    entries.push(Route::post(IMPORTS).requires(Access::Administrator).names_no_target().handler(
        move |caller: Caller,
              address: ClientAddress,
              headers: HeaderMap,
              Path(connection): Path<String>,
              body: Bytes| {
            let s = s.clone();
            async move {
                let connection = or_answer!(read::path_uuid("connectionId", &connection));
                let request = or_answer!(optional_request(&headers, &body));
                match s.imports.apply(&connection, request.as_ref(), &actor(&caller, &address, &headers)).await {
                    Ok(result) => ok(&result),
                    Err(refused) => refuse("POST", IMPORTS, refused),
                }
            }
        },
    ));
}
