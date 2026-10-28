//! The recorder's files as they are written (`core/golden/README.md` beside `TrafficRecorder.java`, format 1): a
//! `manifest.json` naming every test and its files, and one file per request with its `seed`, `response` and
//! `effect`. Read here and nowhere else; where the README and this reader disagree, the recorder's code is right.

use std::path::{Path, PathBuf};

use crate::json::Json;

/// The only format this reader knows. A recording of another one is refused rather than half-read.
pub const FORMAT: &str = "1";

/// Why a recording could not be read.
#[derive(Debug, thiserror::Error)]
#[error("{path}: {message}")]
pub struct Unreadable {
    pub path: String,
    pub message: String,
}

fn unreadable(path: &Path, message: impl Into<String>) -> Unreadable {
    Unreadable { path: path.display().to_string(), message: message.into() }
}

/// One test of the manifest.
#[derive(Clone, Debug)]
pub struct Test {
    /// `api.AuthRoutesTest`, `$` written `.` for a nested class.
    pub class: String,
    pub directory: String,
    pub name: String,
    /// `passed`, `failed` or `aborted`: only a passed test's recordings are an oracle.
    pub outcome: String,
    /// The tables that hold rows once the harness emptied the rest, rendered.
    pub baseline: Option<Json>,
    pub files: Vec<String>,
    pub notes: Vec<String>,
}

impl Test {
    /// `class/test--NNN-…` without `.json`: how `deferred.txt` names one recording.
    #[must_use]
    pub fn golden_name(&self, file: &str) -> String {
        format!("{}/{}", self.directory, file.strip_suffix(".json").unwrap_or(file))
    }
}

/// A recording directory and its manifest.
#[derive(Clone, Debug)]
pub struct Recording {
    pub dir: PathBuf,
    /// Each table's identity base: the recorder's `(100 + CRC32(name) mod 900) × 1 000 000`, probed.
    pub id_bases: Vec<(String, i64)>,
    pub tests: Vec<Test>,
    pub recorder_failures: Vec<String>,
}

fn strings(value: Option<&Json>) -> Vec<String> {
    value.and_then(Json::as_array).unwrap_or(&[]).iter().filter_map(|item| item.as_str().map(str::to_owned)).collect()
}

fn integer(value: &Json) -> Option<i64> {
    match value {
        Json::Num(text) => text.parse().ok(),
        _ => None,
    }
}

impl Recording {
    /// Reads `dir/manifest.json`.
    pub fn open(dir: &Path) -> Result<Recording, Unreadable> {
        let path = dir.join("manifest.json");
        let text = std::fs::read_to_string(&path).map_err(|error| unreadable(&path, error.to_string()))?;
        let root = Json::parse(&text).map_err(|error| unreadable(&path, error.to_string()))?;
        match root.get("format") {
            Some(Json::Num(format)) if format == FORMAT => {}
            other => return Err(unreadable(&path, format!("format {other:?}, this reader knows {FORMAT}"))),
        }
        let id_bases = root
            .get("idBases")
            .and_then(Json::as_object)
            .ok_or_else(|| unreadable(&path, "no `idBases`"))?
            .iter()
            .map(|(table, base)| {
                integer(base)
                    .map(|base| (table.clone(), base))
                    .ok_or_else(|| unreadable(&path, format!("idBases.{table}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut tests = Vec::new();
        for class in root.get("classes").and_then(Json::as_array).unwrap_or(&[]) {
            let name =
                class.get("class").and_then(Json::as_str).ok_or_else(|| unreadable(&path, "a class without a name"))?;
            let directory = class.get("directory").and_then(Json::as_str).unwrap_or(name);
            for test in class.get("tests").and_then(Json::as_array).unwrap_or(&[]) {
                tests.push(Test {
                    class: name.to_owned(),
                    directory: directory.to_owned(),
                    name: test
                        .get("name")
                        .and_then(Json::as_str)
                        .ok_or_else(|| unreadable(&path, format!("a test of {name} without a name")))?
                        .to_owned(),
                    outcome: test.get("outcome").and_then(Json::as_str).unwrap_or("").to_owned(),
                    baseline: test.get("baseline").cloned().filter(|baseline| !matches!(baseline, Json::Null)),
                    files: strings(test.get("files")),
                    notes: strings(test.get("notes")),
                });
            }
        }
        Ok(Recording {
            dir: dir.to_path_buf(),
            id_bases,
            tests,
            recorder_failures: strings(root.get("recorderFailures")),
        })
    }

    /// One recorded request of `test`.
    pub fn exchange(&self, test: &Test, file: &str) -> Result<Exchange, Unreadable> {
        let path = self.dir.join(&test.directory).join(file);
        let text = std::fs::read_to_string(&path).map_err(|error| unreadable(&path, error.to_string()))?;
        Exchange::from_json(&path, &text)
    }
}

/// A body as the recorder writes it.
#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    /// Parsed: anything whose content type says JSON. A request's members are sorted by name.
    Json {
        content_type: Option<String>,
        json: Json,
    },
    Text {
        content_type: Option<String>,
        text: String,
    },
    /// Its length and SHA-256 only, the bytes in base64 (a request) or in a gzip sidecar (`file`).
    Binary {
        content_type: Option<String>,
        length: Option<i64>,
        sha256: Option<String>,
        base64: Option<String>,
        file: Option<String>,
    },
}

impl Body {
    fn read(node: &Json) -> Body {
        let content_type = node.get("contentType").and_then(Json::as_str).map(str::to_owned);
        if let Some(json) = node.get("json") {
            return Body::Json { content_type, json: json.clone() };
        }
        if let Some(text) = node.get("text").and_then(Json::as_str) {
            return Body::Text { content_type, text: text.to_owned() };
        }
        Body::Binary {
            content_type,
            length: node.get("length").and_then(integer),
            sha256: node.get("sha256").and_then(Json::as_str).map(str::to_owned),
            base64: node.get("base64").and_then(Json::as_str).map(str::to_owned),
            file: node.get("file").and_then(Json::as_str).map(str::to_owned),
        }
    }
}

/// `Name: value` → `(Name, value)`.
fn header_pairs(value: Option<&Json>) -> Vec<(String, String)> {
    strings(value)
        .into_iter()
        .map(|line| match line.split_once(": ") {
            Some((name, value)) => (name.to_owned(), value.to_owned()),
            None => (line, String::new()),
        })
        .collect()
}

/// The request a test made.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    /// Every request parameter, in the order set; a parameter not in `query` was set with `.param(…)`.
    pub params: Vec<(String, Vec<String>)>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    /// Only when the test set another peer than `127.0.0.1`.
    pub remote_addr: Option<String>,
    pub scheme: Option<String>,
    pub body: Option<Body>,
}

/// The answer MockMvc saw.
#[derive(Clone, Debug)]
pub struct RecordedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<Body>,
    /// The exception that escaped the filter chain instead of an answer: a container would have answered 500.
    pub thrown: Option<String>,
    pub forwarded_url: Option<String>,
    pub redirected_url: Option<String>,
}

/// One recorded file.
#[derive(Clone, Debug)]
pub struct Exchange {
    pub file: PathBuf,
    pub sequence: i64,
    /// `started` or `dispatch` for the two halves of a long poll.
    pub asynchronous: Option<String>,
    /// Overlapping requests: no `seed`, no `effect`, and a rank the threads decided.
    pub concurrent: bool,
    pub request: RecordedRequest,
    pub seed: Option<Json>,
    pub response: RecordedResponse,
    pub effect: Option<Json>,
}

impl Exchange {
    /// Reads one file.
    pub fn from_json(path: &Path, text: &str) -> Result<Exchange, Unreadable> {
        let root = Json::parse(text).map_err(|error| unreadable(path, error.to_string()))?;
        match root.get("format") {
            Some(Json::Num(format)) if format == FORMAT => {}
            other => return Err(unreadable(path, format!("format {other:?}, this reader knows {FORMAT}"))),
        }
        let request = root.get("request").ok_or_else(|| unreadable(path, "no `request`"))?;
        let response = root.get("response").ok_or_else(|| unreadable(path, "no `response`"))?;
        let text_of = |node: &Json, key: &str| node.get(key).and_then(Json::as_str).map(str::to_owned);
        let thrown = text_of(response, "thrown");
        let status = match response.get("status").and_then(integer) {
            Some(status) => u16::try_from(status).map_err(|_| unreadable(path, "`response.status` out of range"))?,
            // A container answers an exception that escaped the chain with a 500.
            None if thrown.is_some() => 500,
            None => return Err(unreadable(path, "no `response.status`")),
        };
        Ok(Exchange {
            file: path.to_path_buf(),
            sequence: root.get("sequence").and_then(integer).unwrap_or(0),
            asynchronous: text_of(&root, "async"),
            concurrent: matches!(root.get("concurrent"), Some(Json::Bool(true))),
            request: RecordedRequest {
                method: text_of(request, "method").ok_or_else(|| unreadable(path, "no `request.method`"))?,
                path: text_of(request, "path").ok_or_else(|| unreadable(path, "no `request.path`"))?,
                query: text_of(request, "query"),
                params: request
                    .get("params")
                    .and_then(Json::as_object)
                    .unwrap_or(&[])
                    .iter()
                    .map(|(name, values)| (name.clone(), strings(Some(values))))
                    .collect(),
                headers: header_pairs(request.get("headers")),
                cookies: request
                    .get("cookies")
                    .and_then(Json::as_array)
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|pair| {
                        let pair = strings(Some(pair));
                        let mut parts = pair.into_iter();
                        Some((parts.next()?, parts.next()?))
                    })
                    .collect(),
                remote_addr: text_of(request, "remoteAddr"),
                scheme: text_of(request, "scheme"),
                body: request.get("body").map(Body::read),
            },
            seed: root.get("seed").cloned().filter(|seed| !matches!(seed, Json::Null)),
            response: RecordedResponse {
                status,
                headers: header_pairs(response.get("headers")),
                body: response.get("body").map(Body::read),
                thrown,
                forwarded_url: text_of(response, "forwardedUrl"),
                redirected_url: text_of(response, "redirectedUrl"),
            },
            effect: root.get("effect").cloned().filter(|effect| !matches!(effect, Json::Null)),
        })
    }
}
