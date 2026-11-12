//! Recorded Java traffic, replayed against the Rust control plane.
//!
//! The Java HTTP suite is the oracle for the port: 172 test files that say what the application
//! answers. A shared recorder on the Java side writes, for each request a test makes, one *golden*
//! file — the request, the status, headers and body served, and the rows the request touched — with
//! ids, timestamps and tokens replaced by placeholders. This module loads those files, seeds the
//! rows into a Rust server, sends the same requests, and reports every difference.
//!
//! # The golden file
//!
//! ```json
//! {
//!   "name": "checklistContacts/an-auditor-sees-not-reminded",
//!   "request":  { "method": "GET", "path": "/api/v1/projects/7/checklists/contacts",
//!                 "query": { "a": "1" }, "headers": { "Authorization": "Bearer <session>" },
//!                 "body": { "any": "json" } },
//!   "response": { "status": 200, "headers": { "Content-Type": "application/json" },
//!                 "body": { "any": "json" }, "keyOrder": true },
//!   "db": { "before": { "t_user": [ { "id": 1 } ] }, "after": { "t_user": [ { "id": 1 } ] } }
//! }
//! ```
//!
//! `body` is a JSON value, read here with its key order and number text intact; a body that is not
//! JSON is written as `"bodyText"` instead. `query` is an object or a ready `a=1&b=2` string.
//! Everything but `request.method`, `request.path` and `response.status` is optional. The recorder
//! is built in parallel with this reader: where its README says otherwise, **its README wins** and
//! this loader is adapted — the format is read in one place ([`Golden::from_json`]).
//!
//! # Normalisation
//!
//! `normalisation.json` beside the goldens says what the recorder replaced, so that the same rules
//! are applied to what the Rust server answers; without it, [`Normaliser::standard`] — timestamps,
//! UUIDs, API keys — applies. A rule applied to a golden is idempotent (a placeholder matches no
//! rule), so a recorder that normalised already costs nothing.

use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::document::{Document, Operation};
use crate::json::{self, Compare, Difference, Json, Numbers};
use crate::schema::{Check, Schemas};

/// A request to replay.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Option<Body>,
}

impl Request {
    /// `path?query`, as sent.
    #[must_use]
    pub fn target(&self) -> String {
        if self.query.is_empty() {
            return self.path.clone();
        }
        let query: Vec<String> =
            self.query.iter().map(|(name, value)| format!("{}={}", encode(name), encode(value))).collect();
        format!("{}?{}", self.path, query.join("&"))
    }
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

/// A request or response body.
#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    Json(Json),
    Text(String),
}

impl Body {
    /// The bytes to send.
    #[must_use]
    pub fn to_text(&self) -> String {
        match self {
            Body::Json(json) => json.to_text(),
            Body::Text(text) => text.clone(),
        }
    }
}

/// An answer.
#[derive(Clone, Debug, PartialEq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<Body>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}

/// One recorded exchange.
#[derive(Clone, Debug)]
pub struct Golden {
    pub name: String,
    pub file: PathBuf,
    pub request: Request,
    pub response: Response,
    /// Whether the order of the answer's keys is part of what was recorded.
    pub key_order: bool,
    /// The rows to seed, `{table: [row, …]}`.
    pub db_before: Option<Json>,
    /// The rows after the request, `{table: [row, …]}`.
    pub db_after: Option<Json>,
}

/// Why a golden could not be read.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("{path}: {message}")]
    Unreadable { path: String, message: String },
    #[error("{path}: not a golden — {message}")]
    Malformed { path: String, message: String },
}

impl Golden {
    /// Reads the one file. This is the only place the golden format is known.
    pub fn from_json(file: &Path, text: &str) -> Result<Golden, LoadError> {
        let path = file.display().to_string();
        let bad = |message: &str| LoadError::Malformed { path: path.clone(), message: message.to_owned() };
        let root = Json::parse(text)
            .map_err(|error| LoadError::Malformed { path: path.clone(), message: error.to_string() })?;
        let request = root.get("request").ok_or_else(|| bad("no `request`"))?;
        let response = root.get("response").ok_or_else(|| bad("no `response`"))?;

        let method = request
            .get("method")
            .and_then(Json::as_str)
            .ok_or_else(|| bad("no `request.method`"))?
            .to_ascii_uppercase();
        let target = request.get("path").and_then(Json::as_str).ok_or_else(|| bad("no `request.path`"))?;
        let (path_only, inline_query) =
            target.split_once('?').map_or((target, None), |(path, query)| (path, Some(query)));
        let mut query = match request.get("query") {
            Some(Json::Obj(entries)) => {
                entries.iter().map(|(name, value)| (name.clone(), scalar_text(value))).collect()
            }
            Some(Json::Str(text)) => parse_query(text),
            Some(_) => return Err(bad("`request.query` is neither an object nor a string")),
            None => Vec::new(),
        };
        if let Some(inline) = inline_query {
            query.extend(parse_query(inline));
        }
        let status = response
            .get("status")
            .and_then(|status| match status {
                Json::Num(text) => text.parse::<u16>().ok(),
                _ => None,
            })
            .ok_or_else(|| bad("no numeric `response.status`"))?;
        let name = root.get("name").and_then(Json::as_str).map_or_else(
            || file.file_stem().map_or_else(String::new, |stem| stem.to_string_lossy().into_owned()),
            str::to_owned,
        );
        let db = root.get("db");
        Ok(Golden {
            name,
            file: file.to_path_buf(),
            request: Request {
                method,
                path: path_only.to_owned(),
                query,
                headers: headers_of(request.get("headers")),
                body: body_of(request),
            },
            response: Response { status, headers: headers_of(response.get("headers")), body: body_of(response) },
            key_order: !matches!(response.get("keyOrder"), Some(Json::Bool(false))),
            db_before: db.and_then(|db| db.get("before")).cloned(),
            db_after: db.and_then(|db| db.get("after")).cloned(),
        })
    }
}

fn scalar_text(value: &Json) -> String {
    match value {
        Json::Str(text) | Json::Num(text) => text.clone(),
        other => other.to_text(),
    }
}

fn parse_query(text: &str) -> Vec<(String, String)> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            pair.split_once('=')
                .map_or((pair.to_owned(), String::new()), |(name, value)| (name.to_owned(), value.to_owned()))
        })
        .collect()
}

fn headers_of(headers: Option<&Json>) -> Vec<(String, String)> {
    match headers {
        Some(Json::Obj(entries)) => entries.iter().map(|(name, value)| (name.clone(), scalar_text(value))).collect(),
        _ => Vec::new(),
    }
}

fn body_of(holder: &Json) -> Option<Body> {
    if let Some(text) = holder.get("bodyText").and_then(Json::as_str) {
        return Some(Body::Text(text.to_owned()));
    }
    holder.get("body").map(|body| Body::Json(body.clone()))
}

/// Every golden under `dir`, in path order, and the normalisation that goes with them.
pub fn load_dir(dir: &Path) -> Result<(Vec<Golden>, Normaliser), LoadError> {
    let mut files = Vec::new();
    collect(dir, &mut files)?;
    files.sort();
    let mut goldens = Vec::new();
    let mut normaliser = Normaliser::standard();
    for file in files {
        let name = file.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        let text = std::fs::read_to_string(&file)
            .map_err(|error| LoadError::Unreadable { path: file.display().to_string(), message: error.to_string() })?;
        if name == "normalisation.json" {
            normaliser = Normaliser::from_json(&text)
                .map_err(|message| LoadError::Malformed { path: file.display().to_string(), message })?;
        } else if name != "manifest.json" {
            goldens.push(Golden::from_json(&file, &text)?);
        }
    }
    Ok((goldens, normaliser))
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), LoadError> {
    let unreadable =
        |error: std::io::Error| LoadError::Unreadable { path: dir.display().to_string(), message: error.to_string() };
    for entry in std::fs::read_dir(dir).map_err(unreadable)? {
        let path = entry.map_err(unreadable)?.path();
        if path.is_dir() {
            collect(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "json") {
            files.push(path);
        }
    }
    Ok(())
}

/// What is replaced before two answers are compared: whatever differs between runs and is not
/// behaviour.
#[derive(Clone, Debug)]
pub struct Normaliser {
    /// A string value matching the pattern becomes the placeholder (in bodies and header values).
    patterns: Vec<(Regex, String)>,
    /// Whatever sits under a key matching the pattern becomes the placeholder string.
    keys: Vec<(Regex, String)>,
    /// Headers that are not compared, lower case.
    volatile_headers: Vec<String>,
}

impl Normaliser {
    /// Timestamps, UUIDs and API keys; the headers a server sets per answer.
    #[must_use]
    pub fn standard() -> Normaliser {
        let rule = |pattern: &str, placeholder: &str| {
            // The patterns are literals of this file; one that does not compile is a defect that the
            // first test of this crate shows.
            (
                Regex::new(pattern).unwrap_or_else(|error| panic!("a standard normalisation pattern is bad: {error}")),
                placeholder.to_owned(),
            )
        };
        Normaliser {
            patterns: vec![
                rule(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})\b", "<timestamp>"),
                rule(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<uuid>"),
                rule(r"\bzsk_[A-Za-z0-9_-]+", "<api-key>"),
            ],
            keys: Vec::new(),
            volatile_headers: ["date", "content-length", "transfer-encoding", "connection", "keep-alive"]
                .map(str::to_owned)
                .to_vec(),
        }
    }

    /// Reads `normalisation.json`:
    /// `{"stringPatterns": [{"regex": "…", "placeholder": "…"}], "keyPlaceholders": [{"key": "…",
    /// "placeholder": "…"}], "volatileHeaders": ["…"]}`. The standard rules always apply.
    pub fn from_json(text: &str) -> Result<Normaliser, String> {
        let root = Json::parse(text).map_err(|error| error.to_string())?;
        let mut normaliser = Normaliser::standard();
        let rules = |name: &str, field: &str| -> Result<Vec<(Regex, String)>, String> {
            let mut found = Vec::new();
            for rule in root.get(name).and_then(Json::as_array).unwrap_or(&[]) {
                let pattern = rule
                    .get(field)
                    .and_then(Json::as_str)
                    .ok_or_else(|| format!("a `{name}` rule has no `{field}`"))?;
                let placeholder = rule
                    .get("placeholder")
                    .and_then(Json::as_str)
                    .ok_or_else(|| format!("a `{name}` rule has no `placeholder`"))?;
                let regex = Regex::new(pattern).map_err(|error| format!("`{pattern}`: {error}"))?;
                found.push((regex, placeholder.to_owned()));
            }
            Ok(found)
        };
        normaliser.patterns.extend(rules("stringPatterns", "regex")?);
        normaliser.keys.extend(rules("keyPlaceholders", "key")?);
        for header in root.get("volatileHeaders").and_then(Json::as_array).unwrap_or(&[]) {
            if let Some(name) = header.as_str() {
                normaliser.volatile_headers.push(name.to_ascii_lowercase());
            }
        }
        Ok(normaliser)
    }

    /// Applies the rules to a tree.
    pub fn json(&self, value: &mut Json) {
        match value {
            Json::Str(text) => *text = self.text(text),
            Json::Arr(items) => items.iter_mut().for_each(|item| self.json(item)),
            Json::Obj(entries) => {
                for (name, entry) in entries.iter_mut() {
                    if let Some((_, placeholder)) = self.keys.iter().find(|(pattern, _)| pattern.is_match(name)) {
                        *entry = Json::Str(placeholder.clone());
                    } else {
                        self.json(entry);
                    }
                }
            }
            Json::Null | Json::Bool(_) | Json::Num(_) => {}
        }
    }

    /// Applies the string rules to a text.
    #[must_use]
    pub fn text(&self, text: &str) -> String {
        let mut current = text.to_owned();
        for (pattern, placeholder) in &self.patterns {
            current = pattern.replace_all(&current, placeholder.as_str()).into_owned();
        }
        current
    }

    fn headers(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        let mut kept: Vec<(String, String)> = headers
            .iter()
            .filter(|(name, _)| !self.volatile_headers.contains(&name.to_ascii_lowercase()))
            .map(|(name, value)| (name.to_ascii_lowercase(), self.text(value)))
            .collect();
        kept.sort();
        kept
    }

    fn body(&self, body: &Body) -> Body {
        match body {
            Body::Json(json) => {
                let mut copy = json.clone();
                self.json(&mut copy);
                Body::Json(copy)
            }
            Body::Text(text) => Body::Text(self.text(text)),
        }
    }
}

/// Why a server could not do what a replay asked.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ServerError(pub String);

/// A control plane to replay against: in process, or over HTTP, Rust under test.
pub trait Server {
    /// Puts the server in the state the golden was recorded in (`db.before`).
    fn prepare(&mut self, golden: &Golden) -> impl Future<Output = Result<(), ServerError>> + Send;
    /// Sends the request and returns the answer.
    fn send(&mut self, request: &Request) -> impl Future<Output = Result<Response, ServerError>> + Send;
    /// The rows of `tables` as the server now holds them, `{table: [row, …]}`; `None` for a server
    /// that cannot say — which a replay counts, and fails on when it was told to compare rows.
    fn db_effects(&mut self, _tables: &[String]) -> impl Future<Output = Result<Option<Json>, ServerError>> + Send {
        async { Ok(None) }
    }
}

/// How a replay is run.
#[derive(Debug)]
pub struct Replay<'a> {
    pub document: &'a Document,
    pub schemas: &'a Schemas,
    pub normaliser: Normaliser,
    /// A golden that records rows must have them compared: a server that cannot dump them fails.
    pub require_db_effects: bool,
    /// Extra headers the server sends are not a difference.
    pub ignore_extra_headers: bool,
    /// The *recorded* answer is checked against the document's schema too. Off by default: a recorder
    /// that replaced an id by `"<id>"` has made a string of a field the schema says is an integer.
    /// The replayed answer is always checked, before normalisation, as the server sent it.
    pub check_recorded: bool,
}

/// What a replay found out.
#[derive(Debug, Default)]
pub struct Report {
    pub total: usize,
    pub failures: Vec<Failure>,
    /// Answers (the recorded one and the replayed one) checked against the document's schema.
    pub schema_checked: usize,
    /// Answers whose status the document does not declare — counted, not failed.
    pub undeclared: usize,
    /// Goldens that record rows and were replayed without comparing them.
    pub rows_not_compared: usize,
}

impl Report {
    /// Whether every golden replayed identically.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }

    /// Fails — naming every difference — unless the replay was clean.
    ///
    /// # Panics
    /// When there is a failure.
    #[track_caller]
    pub fn assert_clean(&self) {
        assert!(self.is_clean(), "{self}");
    }
}

impl fmt::Display for Report {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            out,
            "{} golden(s) replayed, {} failed; {} answers checked against the schema, {} undeclared, {} without their rows compared",
            self.total,
            self.failures.len(),
            self.schema_checked,
            self.undeclared,
            self.rows_not_compared
        )?;
        for failure in &self.failures {
            writeln!(out, "- {} ({})", failure.golden, failure.file.display())?;
            for line in failure.kind.lines() {
                writeln!(out, "    {line}")?;
            }
        }
        Ok(())
    }
}

/// One golden that did not replay identically.
#[derive(Debug)]
pub struct Failure {
    pub golden: String,
    pub file: PathBuf,
    pub kind: FailureKind,
}

#[derive(Debug)]
pub enum FailureKind {
    /// The recorded request reaches no operation of the document.
    UnknownRoute {
        method: String,
        path: String,
    },
    /// The server could not prepare, answer, or dump rows.
    Server(String),
    Status {
        expected: u16,
        actual: u16,
    },
    Headers(Vec<String>),
    Body(Vec<Difference>),
    /// The recorded answer or the replayed one violates the document's schema.
    Schema {
        which: &'static str,
        errors: Vec<String>,
    },
    Rows(Vec<Difference>),
    /// The golden records rows and the server cannot dump them.
    RowsNotAvailable,
}

impl FailureKind {
    fn lines(&self) -> Vec<String> {
        match self {
            FailureKind::UnknownRoute { method, path } => {
                vec![format!("{method} {path} reaches no operation of openapi.json")]
            }
            FailureKind::Server(message) => vec![format!("the server: {message}")],
            FailureKind::Status { expected, actual } => vec![format!("status {actual}, recorded {expected}")],
            FailureKind::Headers(lines) => lines.clone(),
            FailureKind::Body(differences) => {
                differences.iter().map(|difference| format!("body {difference}")).collect()
            }
            FailureKind::Schema { which, errors } => {
                errors.iter().map(|error| format!("the {which} answer against the schema: {error}")).collect()
            }
            FailureKind::Rows(differences) => {
                differences.iter().map(|difference| format!("rows {difference}")).collect()
            }
            FailureKind::RowsNotAvailable => vec!["rows were recorded and this server cannot dump them".to_owned()],
        }
    }
}

/// Replays every golden under `dir` against `server`.
pub async fn replay<S: Server>(
    dir: &Path,
    server: &mut S,
    document: &Document,
    schemas: &Schemas,
) -> Result<Report, LoadError> {
    let (goldens, normaliser) = load_dir(dir)?;
    let run = Replay {
        document,
        schemas,
        normaliser,
        require_db_effects: false,
        ignore_extra_headers: false,
        check_recorded: false,
    };
    Ok(run.run(&goldens, server).await)
}

impl Replay<'_> {
    /// Replays `goldens`, one after the other.
    pub async fn run<S: Server>(&self, goldens: &[Golden], server: &mut S) -> Report {
        let mut report = Report { total: goldens.len(), ..Report::default() };
        for golden in goldens {
            if let Some(kind) = self.one(golden, server, &mut report).await {
                report.failures.push(Failure { golden: golden.name.clone(), file: golden.file.clone(), kind });
            }
        }
        report
    }

    async fn one<S: Server>(&self, golden: &Golden, server: &mut S, report: &mut Report) -> Option<FailureKind> {
        let request = &golden.request;
        let Some(operation) = self.document.find(&request.method, &request.path) else {
            return Some(FailureKind::UnknownRoute { method: request.method.clone(), path: request.path.clone() });
        };
        // What Java recorded must itself satisfy the contract: if it does not, the document and the
        // recorder disagree, and nothing the replay says afterwards means anything.
        if self.check_recorded
            && let Some(kind) = self.schema_failure("recorded", operation, &golden.response, report)
        {
            return Some(kind);
        }
        if let Err(error) = server.prepare(golden).await {
            return Some(FailureKind::Server(error.to_string()));
        }
        let actual = match server.send(request).await {
            Ok(actual) => actual,
            Err(error) => return Some(FailureKind::Server(error.to_string())),
        };

        if actual.status != golden.response.status {
            return Some(FailureKind::Status { expected: golden.response.status, actual: actual.status });
        }
        if let Some(kind) = self.schema_failure("replayed", operation, &actual, report) {
            return Some(kind);
        }
        let headers = self.header_differences(&golden.response, &actual);
        if !headers.is_empty() {
            return Some(FailureKind::Headers(headers));
        }
        if let Some(differences) = self.body_differences(golden, &actual) {
            return Some(FailureKind::Body(differences));
        }
        self.rows(golden, server, report).await
    }

    fn schema_failure(
        &self,
        which: &'static str,
        operation: &Operation,
        response: &Response,
        report: &mut Report,
    ) -> Option<FailureKind> {
        let value = match &response.body {
            Some(Body::Json(json)) => serde_json::from_str(&json.to_text()).unwrap_or(serde_json::Value::Null),
            Some(Body::Text(_)) | None => return None,
        };
        let content_type = response.header("content-type");
        match self.schemas.check_response(operation, response.status, content_type, &value) {
            Check::Valid => {
                report.schema_checked += 1;
                None
            }
            Check::Invalid(errors) => {
                report.schema_checked += 1;
                Some(FailureKind::Schema { which, errors: errors.iter().map(ToString::to_string).collect() })
            }
            Check::Undeclared(_) => {
                report.undeclared += 1;
                None
            }
            Check::NotChecked(_) => None,
        }
    }

    fn header_differences(&self, recorded: &Response, actual: &Response) -> Vec<String> {
        let expected = self.normaliser.headers(&recorded.headers);
        let got = self.normaliser.headers(&actual.headers);
        let mut lines = Vec::new();
        for (name, value) in &expected {
            match got.iter().find(|(other, _)| other == name) {
                None => lines.push(format!("header {name}: absent, recorded {value:?}")),
                Some((_, other)) if other != value => {
                    lines.push(format!("header {name}: {other:?}, recorded {value:?}"))
                }
                Some(_) => {}
            }
        }
        if !self.ignore_extra_headers {
            for (name, value) in &got {
                if !expected.iter().any(|(other, _)| other == name) {
                    lines.push(format!("header {name}: {value:?} sent, not recorded"));
                }
            }
        }
        lines
    }

    fn body_differences(&self, golden: &Golden, actual: &Response) -> Option<Vec<Difference>> {
        let how = Compare { key_order: golden.key_order, numbers: Numbers::Text };
        match (&golden.response.body, &actual.body) {
            (None, None) => None,
            (Some(expected), Some(got)) => match (self.normaliser.body(expected), self.normaliser.body(got)) {
                (Body::Json(left), Body::Json(right)) => {
                    let found = json::compare(&left, &right, how);
                    (!found.is_empty()).then_some(found)
                }
                (Body::Text(left), Body::Text(right)) if left == right => None,
                (left, right) => Some(vec![Difference {
                    pointer: String::new(),
                    kind: json::DifferenceKind::Value {
                        expected: format!("{:?}", left.to_text()),
                        actual: format!("{:?}", right.to_text()),
                    },
                }]),
            },
            (Some(_), None) => Some(vec![Difference { pointer: String::new(), kind: json::DifferenceKind::Missing }]),
            (None, Some(_)) => Some(vec![Difference { pointer: String::new(), kind: json::DifferenceKind::Extra }]),
        }
    }

    async fn rows<S: Server>(&self, golden: &Golden, server: &mut S, report: &mut Report) -> Option<FailureKind> {
        let expected = golden.db_after.as_ref()?;
        let Json::Obj(tables) = expected else {
            return None;
        };
        let names: Vec<String> = tables.iter().map(|(name, _)| name.clone()).collect();
        let dumped = match server.db_effects(&names).await {
            Ok(dumped) => dumped,
            Err(error) => return Some(FailureKind::Server(error.to_string())),
        };
        let Some(mut actual) = dumped else {
            report.rows_not_compared += 1;
            return self.require_db_effects.then_some(FailureKind::RowsNotAvailable);
        };
        let mut recorded = expected.clone();
        self.normaliser.json(&mut recorded);
        self.normaliser.json(&mut actual);
        let found = json::compare(&recorded, &actual, Compare { key_order: false, numbers: Numbers::Value });
        (!found.is_empty()).then_some(FailureKind::Rows(found))
    }
}
