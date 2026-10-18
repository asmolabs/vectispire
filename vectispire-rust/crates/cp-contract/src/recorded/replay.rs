//! A recorded test, replayed: the seed rows put in, each request of a route the Rust router serves sent to it and
//! its answer and rows held to Java's, each request of a route it does not serve played in Java's place — its
//! recorded effect written as a seed — so that the requests after it start from the state Java's left.
//!
//! **Playing Java's part** is what lets one golden of a ported route be replayed in a test that also calls routes
//! not ported yet: a scan test files a repository into a project (ported) after creating an agent (not), and the
//! filing is held to Java's whatever the agent route does. Its limit is the recording's: a value the recorder hid and
//! the replay cannot choose (a sealed credential, a blob, a PEM block) stops the test there, and every recording after
//! that point is reported unreplayable with the reason, never compared against a state that is not Java's.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::Router;
use axum::body::Body as AxumBody;
use axum::http::{HeaderName, HeaderValue};
use time::OffsetDateTime;
use tower::ServiceExt;
use vectispire_cp_db::Db;

use crate::document::Document;
use crate::json::Json;
use crate::recorded::format::{Body, Exchange, RecordedRequest, Recording, Test};
use crate::recorded::placeholders::{Bindings, Context, Minting, NumberText, Unseedable, secret_kinds};
use crate::recorded::rows::{self, Schema, Snapshot, Writes};
use crate::schema::{Check, Schemas};

/// What became of one recording.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Replayed, and the answer and the rows are Java's.
    Green,
    /// Replayed, and something differs: each line names where.
    Differs(Vec<String>),
    /// Of a served route, and not replayable: the reason.
    Unreplayable(String),
    /// Of a route the router does not serve: Java's effect was written in its place.
    Played,
    /// Of a route the router does not serve, after the test stopped being reproducible.
    NotPlayed(String),
    /// Of a test that did not pass when recorded: not an oracle (README § The manifest).
    NotAnOracle,
}

/// One recording and what became of it.
#[derive(Clone, Debug)]
pub struct Replayed {
    /// `class/test--NNN-METHOD-slug`, as `deferred.txt` names it.
    pub name: String,
    /// `(METHOD, /template)` of the contract's operation, `None` for a request no operation answers.
    pub route: Option<(String, String)>,
    pub served: bool,
    pub outcome: Outcome,
}

/// Headers a server sets on the wire that MockMvc never records: they say how the bytes travelled, not what the
/// application answered.
const TRANSPORT_HEADERS: [&str; 5] = ["content-length", "date", "transfer-encoding", "connection", "keep-alive"];

/// The replay of one recording directory against one database and one application.
pub struct Replayer<'a> {
    pub recording: &'a Recording,
    pub db: &'a Db,
    pub schema: &'a Schema,
    /// The tables as the migrations left them, before any test: what a baseline restores.
    pub pristine: &'a Snapshot,
    pub document: &'a Document,
    pub schemas: &'a Schemas,
    pub minting: &'a dyn Minting,
    /// The routes the router answers, `(METHOD, /template)` as the contract writes them.
    pub served: &'a BTreeSet<(String, String)>,
}

impl std::fmt::Debug for Replayer<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("Replayer").field("served", &self.served).finish_non_exhaustive()
    }
}

impl Replayer<'_> {
    /// The route `request` reaches, and whether the router serves it.
    #[must_use]
    pub fn route(&self, method: &str, path: &str) -> (Option<(String, String)>, bool) {
        match self.document.find(method, path) {
            Some(operation) => {
                let route = (operation.method.to_ascii_uppercase(), operation.path.clone());
                let served = self.served.contains(&route);
                (Some(route), served)
            }
            None => (None, false),
        }
    }

    /// Replays every recording of `test` against a router of its own: an application's caches belong to one test,
    /// as the Java suite's contexts did not — which is why the recorder made its ids grow, and why a fresh router
    /// per test is the stricter choice here.
    pub async fn test(&self, test: &Test, router: Router) -> Vec<Replayed> {
        let mut out = Vec::new();
        let mut exchanges = Vec::new();
        let mut texts = Vec::new();
        for file in &test.files {
            let name = test.golden_name(file);
            let read = self.recording.exchange(test, file).map_err(|error| error.to_string());
            if let Ok(exchange) = &read {
                texts.push(std::fs::read_to_string(&exchange.file).unwrap_or_default());
            }
            exchanges.push((name, read));
        }
        if test.outcome != "passed" {
            for (name, exchange) in exchanges {
                let (route, served) = exchange
                    .as_ref()
                    .map_or((None, false), |exchange| self.route(&exchange.request.method, &exchange.request.path));
                out.push(Replayed { name, route, served, outcome: Outcome::NotAnOracle });
            }
            return out;
        }
        let mut stopped = self.start(test).await.err();
        let starts = match rows::next_identities(self.db, self.schema).await {
            Ok(starts) => starts,
            Err(error) => {
                stopped = Some(format!("the identity counters could not be read: {error}"));
                BTreeMap::new()
            }
        };
        let now = OffsetDateTime::now_utc();
        let mut bindings = Bindings::new(starts, secret_kinds(texts.iter().map(String::as_str)), self.minting, now);
        for (name, exchange) in exchanges {
            let exchange = match exchange {
                Ok(exchange) => exchange,
                Err(error) => {
                    out.push(Replayed { name, route: None, served: false, outcome: Outcome::Unreplayable(error) });
                    continue;
                }
            };
            let (route, served) = self.route(&exchange.request.method, &exchange.request.path);
            let outcome = match &stopped {
                Some(reason) if served => Outcome::Unreplayable(reason.clone()),
                Some(reason) => Outcome::NotPlayed(reason.clone()),
                None => match self.one(&exchange, served, route.as_ref(), &router, &mut bindings, now).await {
                    Ok(outcome) => outcome,
                    Err(reason) => {
                        let reason = format!("{}: {reason}", file_name(&exchange));
                        stopped = Some(format!("an earlier request of the test cannot be reproduced — {reason}"));
                        if served { Outcome::Unreplayable(reason) } else { Outcome::NotPlayed(reason) }
                    }
                },
            };
            out.push(Replayed { name, route, served, outcome });
        }
        out
    }

    /// Empties the tables but the baseline's, checks they hold what the recording says the test started from.
    async fn start(&self, test: &Test) -> Result<(), String> {
        let restore: BTreeSet<String> = test
            .baseline
            .as_ref()
            .and_then(Json::as_object)
            .map(|tables| tables.iter().map(|(name, _)| name.clone()).collect())
            .unwrap_or_default();
        rows::reset(self.db, self.schema, self.pristine, &restore).await.map_err(|error| error.to_string())?;
        // What the test starts from must be what the recorder saw it start from; a migration that seeds a row Java's
        // does not would otherwise show as a difference of the first request that reads it.
        let state = rows::snapshot(self.db, self.schema).await.map_err(|error| error.to_string())?;
        let baseline = test.baseline.clone().unwrap_or(Json::Obj(Vec::new()));
        let mut bindings = Bindings::new(BTreeMap::new(), BTreeMap::new(), self.minting, OffsetDateTime::now_utc());
        let mut differences = Vec::new();
        for table in &self.schema.tables {
            let rows: Vec<Json> = state
                .tables
                .get(&table.name)
                .map(|rows| rows.iter().map(|row| table.object(row)).collect())
                .unwrap_or_default();
            let recorded = baseline.get(&table.name).cloned().unwrap_or(Json::Arr(Vec::new()));
            bindings.match_json(
                &recorded,
                &Json::Arr(rows),
                "",
                NumberText::Value,
                &format!("/{}", table.name),
                &mut differences,
            );
        }
        if !differences.is_empty() {
            return Err(format!("the tables do not start as the recording's baseline: {}", differences.join("; ")));
        }
        let counters = rows::next_identities(self.db, self.schema).await.map_err(|error| error.to_string())?;
        for table in &self.schema.tables {
            let Some(base) = table.base else {
                continue;
            };
            let next = counters.get(&table.name).copied().unwrap_or(0);
            let end = base.saturating_add(1_000_000);
            // The recorder's `placeIdentities`: once a table's counter is in its range it only grows; one outside it
            // (a fresh database, a range used up) is put back at the start of its range.
            if next <= base || next >= end {
                rows::place_identity(self.db, table, base.saturating_add(1))
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    async fn one(
        &self,
        exchange: &Exchange,
        served: bool,
        route: Option<&(String, String)>,
        router: &Router,
        bindings: &mut Bindings<'_>,
        now: OffsetDateTime,
    ) -> Result<Outcome, String> {
        if exchange.concurrent {
            return Err(
                "its requests overlapped (`concurrent`): the recorder could not say which rows each touched".into()
            );
        }
        if exchange.asynchronous.is_some() {
            return Err("a long poll's half (`async`): its two records are not merged by this replay yet".into());
        }
        if let Some(seed) = &exchange.seed {
            let writes = Writes::plan(self.schema, seed, bindings).map_err(|why| format!("its seed: {why}"))?;
            rows::apply(self.db, self.schema, &writes).await.map_err(|error| format!("its seed: {error}"))?;
        }
        if !served {
            if let Some(effect) = &exchange.effect {
                let writes = Writes::plan(self.schema, effect, bindings).map_err(|why| format!("its effect: {why}"))?;
                rows::apply(self.db, self.schema, &writes).await.map_err(|error| format!("its effect: {error}"))?;
            }
            return Ok(Outcome::Played);
        }
        let request = build(&exchange.request, bindings).map_err(|why| format!("its request: {why}"))?;
        let before = rows::snapshot(self.db, self.schema).await.map_err(|error| error.to_string())?;
        let answer = send(router, request).await?;
        let after = rows::snapshot(self.db, self.schema).await.map_err(|error| error.to_string())?;
        let effect = rows::diff(self.schema, &before, &after, now.date());

        let mut differences = Vec::new();
        self.compare_answer(exchange, &answer, route, bindings, &mut differences);
        if let Some(recorded) = &exchange.effect {
            compare_rows(self.schema, recorded, &effect, bindings, &mut differences);
        }
        differences.extend(bindings.take_violations());
        Ok(if differences.is_empty() { Outcome::Green } else { Outcome::Differs(differences) })
    }

    fn compare_answer(
        &self,
        exchange: &Exchange,
        answer: &Answer,
        route: Option<&(String, String)>,
        bindings: &mut Bindings<'_>,
        out: &mut Vec<String>,
    ) {
        let recorded = &exchange.response;
        if answer.status != recorded.status {
            out.push(format!("status {}, recorded {}", answer.status, recorded.status));
        }
        compare_headers(&recorded.headers, &answer.headers, bindings, out);
        let content_type = answer.header("content-type");
        let parsed = parse_body(content_type, &answer.body);
        match (&recorded.body, &parsed) {
            (None, Parsed::Empty) => {}
            (Some(Body::Json { json, .. }), Parsed::Json(actual)) => {
                bindings.match_json(json, actual, "", NumberText::Exact, "", out);
            }
            (Some(Body::Text { text, .. }), Parsed::Text(actual)) => {
                if let Err(why) = bindings.match_text(text, actual, "") {
                    out.push(format!("body: {why}"));
                }
            }
            (Some(Body::Binary { .. }), _) => {
                out.push("body: a binary answer, which this replay does not compare yet".into())
            }
            (recorded, actual) => out.push(format!("body: {actual:?}, recorded {recorded:?}")),
        }
        // The answer as the Rust server sent it, against the contract: a placeholder hides a value's text, never its
        // type, and this is where the type is held.
        //
        // A violation Java's own answer has as well is the document's defect, not the port's (the 0.11.1 contract
        // leaves `null` out of some nullable fields): only what the Rust answer alone violates is reported.
        if let (Some((method, path)), Parsed::Json(actual)) = (route, &parsed)
            && let Some(operation) = self.document.find(method, path)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&actual.to_text())
            && let Check::Invalid(errors) = self.schemas.check_response(operation, answer.status, content_type, &value)
        {
            let javas: Vec<String> = match &recorded.body {
                Some(Body::Json { json, .. }) => serde_json::from_str::<serde_json::Value>(&json.to_text())
                    .ok()
                    .map(|java| match self.schemas.check_response(operation, recorded.status, content_type, &java) {
                        Check::Invalid(errors) => errors.iter().map(ToString::to_string).collect(),
                        _ => Vec::new(),
                    })
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            out.extend(
                errors
                    .iter()
                    .map(ToString::to_string)
                    .filter(|error| !javas.contains(error))
                    .map(|error| format!("the answer against openapi.json: {error}")),
            );
        }
    }
}

fn file_name(exchange: &Exchange) -> String {
    exchange.file.file_name().map_or_else(String::new, |name| name.to_string_lossy().into_owned())
}

/// What the router answered.
#[derive(Debug)]
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}

#[derive(Debug)]
enum Parsed {
    Empty,
    Json(Json),
    Text(String),
}

/// The recorder's rule for what a JSON body is: a content type naming JSON, or none and a `{` or `[` first.
fn parse_body(content_type: Option<&str>, body: &[u8]) -> Parsed {
    if body.is_empty() {
        return Parsed::Empty;
    }
    let text = String::from_utf8_lossy(body).into_owned();
    let json_like = content_type.map_or_else(
        || text.trim_start().starts_with('{') || text.trim_start().starts_with('['),
        |kind| kind.to_ascii_lowercase().contains("json"),
    );
    if json_like && let Ok(json) = Json::parse(&text) {
        return Parsed::Json(json);
    }
    Parsed::Text(text)
}

/// The request to send, every placeholder made concrete.
#[derive(Debug)]
struct Outgoing {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    peer: IpAddr,
    body: Vec<u8>,
}

fn encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(char::from(byte)),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// A recorded request body made concrete. A string that is one identity or long number and nothing else was a JSON
/// integer the recorder wrote as a placeholder string, and is sent as the number.
fn concrete_json(json: &Json, field: &str, bindings: &mut Bindings<'_>) -> Result<Json, Unseedable> {
    Ok(match json {
        Json::Str(template) => {
            let text = bindings.concrete(template, field, Context::Wire)?;
            let integer = template.starts_with('«')
                && template.ends_with('»')
                && template.matches('«').count() == 1
                && (template.starts_with("«t_") || template.starts_with("«n:"))
                && !text.is_empty()
                && text.chars().all(|c| c.is_ascii_digit());
            if integer { Json::Num(text) } else { Json::Str(text) }
        }
        Json::Arr(items) => {
            Json::Arr(items.iter().map(|item| concrete_json(item, field, bindings)).collect::<Result<_, _>>()?)
        }
        Json::Obj(members) => Json::Obj(
            members
                .iter()
                .map(|(name, value)| Ok((name.clone(), concrete_json(value, name, bindings)?)))
                .collect::<Result<_, Unseedable>>()?,
        ),
        other => other.clone(),
    })
}

fn build(request: &RecordedRequest, bindings: &mut Bindings<'_>) -> Result<Outgoing, Unseedable> {
    if request.scheme.as_deref().is_some_and(|scheme| scheme != "http") {
        return Err(Unseedable(format!("the test set the scheme {:?}", request.scheme)));
    }
    let peer = match &request.remote_addr {
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(address) => {
            address.parse().map_err(|_| Unseedable(format!("the peer address {address:?} is not an address")))?
        }
    };
    let path = bindings.concrete(&request.path, "path", Context::Wire)?;
    let query = match &request.query {
        Some(query) => Some(bindings.concrete(query, "query", Context::Wire)?),
        None => None,
    };
    let in_query: BTreeSet<String> = query
        .iter()
        .flat_map(|query| query.split('&'))
        .map(|pair| pair.split_once('=').map_or(pair, |(name, _)| name).to_owned())
        .collect();
    let mut headers = Vec::new();
    for (name, value) in &request.headers {
        headers.push((name.clone(), bindings.concrete(value, &name.to_ascii_lowercase(), Context::Wire)?));
    }
    if !request.cookies.is_empty() {
        let mut pairs = Vec::new();
        for (name, value) in &request.cookies {
            pairs.push(format!("{name}={}", bindings.concrete(value, "cookie", Context::Wire)?));
        }
        headers.push(("Cookie".to_owned(), pairs.join("; ")));
    }
    // A parameter set with `.param(…)` and not written in the URL: a form body when the request is a form, the
    // query string otherwise (README § request).
    let mut extra = Vec::new();
    for (name, values) in &request.params {
        if in_query.contains(&encode(name)) || in_query.contains(name) {
            continue;
        }
        for value in values {
            extra.push(format!("{}={}", encode(name), encode(&bindings.concrete(value, name, Context::Wire)?)));
        }
    }
    let form = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && value.to_ascii_lowercase().starts_with("application/x-www-form-urlencoded")
    });
    let mut body = match &request.body {
        None => Vec::new(),
        Some(Body::Json { json, .. }) => concrete_json(json, "", bindings)?.to_text().into_bytes(),
        Some(Body::Text { text, .. }) => bindings.concrete(text, "", Context::Wire)?.into_bytes(),
        Some(Body::Binary { .. }) => {
            return Err(Unseedable("a binary request body, which this replay does not send yet".into()));
        }
    };
    let mut target = path;
    let mut query_parts: Vec<String> = query.into_iter().collect();
    if !extra.is_empty() {
        if form && body.is_empty() {
            body = extra.join("&").into_bytes();
        } else {
            query_parts.push(extra.join("&"));
        }
    }
    if !query_parts.is_empty() {
        target = format!("{target}?{}", query_parts.join("&"));
    }
    Ok(Outgoing { method: request.method.clone(), target, headers, peer, body })
}

async fn send(router: &Router, request: Outgoing) -> Result<Answer, String> {
    let mut builder = axum::http::Request::builder().method(request.method.as_str()).uri(request.target.as_str());
    for (name, value) in &request.headers {
        let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) else {
            return Err(format!("the recorded header {name:?} cannot be sent"));
        };
        builder = builder.header(name, value);
    }
    let mut built = builder.body(AxumBody::from(request.body)).map_err(|error| format!("not a request: {error}"))?;
    // The peer the chain reads the client's address from, as MockMvc's `remoteAddr`.
    built.extensions_mut().insert(axum::extract::ConnectInfo(SocketAddr::new(request.peer, 40_000)));
    let response = match router.clone().oneshot(built).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned()))
        .collect();
    let body = axum::body::to_bytes(response.into_body(), 67_108_864)
        .await
        .map_err(|error| format!("the answer's body could not be read: {error}"))?;
    Ok(Answer { status, headers, body: body.to_vec() })
}

/// Every recorded header must be sent, with the recorded value (a template); a header the recording does not have is
/// a difference unless it is one of the transport's.
pub fn compare_headers(
    recorded: &[(String, String)],
    actual: &[(String, String)],
    bindings: &mut Bindings<'_>,
    out: &mut Vec<String>,
) {
    let mut names: Vec<String> = recorded.iter().map(|(name, _)| name.to_ascii_lowercase()).collect();
    names.dedup();
    for name in &names {
        let wanted: Vec<&String> =
            recorded.iter().filter(|(other, _)| other.eq_ignore_ascii_case(name)).map(|(_, value)| value).collect();
        let got: Vec<&String> =
            actual.iter().filter(|(other, _)| other.eq_ignore_ascii_case(name)).map(|(_, value)| value).collect();
        if wanted.len() != got.len() {
            out.push(format!("header {name}: {got:?}, recorded {wanted:?}"));
            continue;
        }
        for (template, value) in wanted.iter().zip(&got) {
            if let Err(why) = bindings.match_text(template, value, name) {
                out.push(format!("header {name}: {why}"));
            }
        }
    }
    for (name, value) in actual {
        let lower = name.to_ascii_lowercase();
        if !names.contains(&lower) && !TRANSPORT_HEADERS.contains(&lower.as_str()) {
            out.push(format!("header {lower}: {value:?} sent, not recorded"));
        }
    }
}

/// The rows a request changed, held to the recorded `effect`. A table keyed by its identity lists its rows in id
/// order on both sides, which is creation order, and is compared in order; any other table's rows are matched as a
/// set, each recorded row to one row of the server's — the recorder sorted those by their masked content, an order
/// in which an identity's digits (different here) decide ties.
pub fn compare_rows(
    schema: &Schema,
    recorded: &Json,
    actual: &Json,
    bindings: &mut Bindings<'_>,
    out: &mut Vec<String>,
) {
    let empty: &[(String, Json)] = &[];
    let recorded_tables = recorded.as_object().unwrap_or(empty);
    let actual_tables = actual.as_object().unwrap_or(empty);
    for (name, changes) in recorded_tables {
        if matches!(changes.get("overCeiling"), Some(Json::Bool(true))) {
            continue;
        }
        let ordered = schema.table(name).is_some_and(rows::Table::numeric_key);
        let theirs = actual_tables.iter().find(|(other, _)| other == name).map(|(_, changes)| changes);
        for kind in ["inserted", "updated", "deleted"] {
            let wanted = changes.get(kind).and_then(Json::as_array).unwrap_or(&[]);
            let got = theirs.and_then(|changes| changes.get(kind)).and_then(Json::as_array).unwrap_or(&[]);
            let at = format!("rows {name} {kind}");
            if wanted.len() != got.len() {
                out.push(format!(
                    "{at}: {} row(s), recorded {} — made {}, recorded {}",
                    got.len(),
                    wanted.len(),
                    Json::Arr(got.to_vec()).to_text(),
                    Json::Arr(wanted.to_vec()).to_text()
                ));
                continue;
            }
            if ordered {
                for (index, (left, right)) in wanted.iter().zip(got).enumerate() {
                    bindings.match_json(left, right, "", NumberText::Value, &format!("{at}/{index}"), out);
                }
                continue;
            }
            let mut used = vec![false; got.len()];
            for (index, left) in wanted.iter().enumerate() {
                let mut matched = false;
                let mut closest: Option<Vec<String>> = None;
                for (candidate, right) in got.iter().enumerate() {
                    if used.get(candidate).copied().unwrap_or(true) {
                        continue;
                    }
                    let mut trial = bindings.clone();
                    let mut differences = Vec::new();
                    trial.match_json(left, right, "", NumberText::Value, "", &mut differences);
                    if differences.is_empty() {
                        *bindings = trial;
                        if let Some(slot) = used.get_mut(candidate) {
                            *slot = true;
                        }
                        matched = true;
                        break;
                    }
                    if closest.as_ref().is_none_or(|best| differences.len() < best.len()) {
                        closest = Some(differences);
                    }
                }
                if !matched {
                    out.push(format!(
                        "{at}/{index}: no row made matches the recorded {}; the closest differs at {}",
                        left.to_text(),
                        closest.unwrap_or_default().join(", ")
                    ));
                }
            }
        }
    }
    for (name, changes) in actual_tables {
        if !recorded_tables.iter().any(|(other, _)| other == name) {
            out.push(format!("rows {name}: changed, the recording changed nothing — {}", changes.to_text()));
        }
    }
}
