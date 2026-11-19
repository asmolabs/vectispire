//! Static discovery of API endpoints and declared contracts in a cloned repository — `ApiDiscoveryScanner`.
//!
//! **A step like the others, whose result replaces the inventory.** The inventory takes what a discovery reports
//! as the repository's whole surface, so a discovery that did not happen is a failure, never empty lists: a tree
//! that is not there, a walk that broke off, a deadline passed, more endpoints than one repository may report —
//! each is an error and the inventory keeps what it had (decision 0007). One malformed file is not: it is a
//! property of the scanned code, and it is skipped.
//!
//! **The patterns read the repository's text in this process**, so each is the Java pattern with its meaning kept
//! and its backtracking gone — the `regex` crate has none to lose: `\s` spelled as Java's ASCII class, `\b` as
//! ASCII, the NestJS back-reference to the opening quote written as three alternatives. The Spring reader
//! counts in UTF-16 units, as Java's `String` does: the 500 characters read back for a route's guards, the 200
//! read on, and its line are Java's, astral characters and all. Pinned by `reference/workspace/`.

use std::collections::HashSet;
use std::fs::Metadata;
use std::path::Path;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Serialize;
use vectispire_domain::java;

use crate::source_files;
use crate::walk::{self, Visit, Visitor};

/// The most endpoints one repository's discovery may report, its contracts' declared paths included —
/// `ApiEndpoint.MAX_PER_REPOSITORY`. Past it the discovery is failed, not cut: a cut list would retire every
/// endpoint it left out.
pub const MAX_PER_REPOSITORY: usize = 50_000;

/// How long the whole discovery may run before it is abandoned as failed — far beyond what the linear passes take
/// on a large repository, far short of pinning a worker for the day.
pub const DEADLINE: Duration = Duration::from_secs(5 * 60);

/// The step's name, as the scan's page shows it.
pub const STEP: &str = "api discovery";

const IGNORED_DIRECTORIES: [&str; 16] = [
    ".git",
    "node_modules",
    "target",
    "build",
    ".gradle",
    "dist",
    "vendor",
    ".idea",
    ".vscode",
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "fixtures",
    "testdata",
];

const METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];

/// `ApiVisibility`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Visibility {
    Public,
    Internal,
    Unknown,
}

/// An endpoint, in the wire form the agent sends — `ApiEndpoint`'s components in order, then the `sensitivePath`
/// its accessor adds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiEndpoint {
    pub method: String,
    pub path: String,
    pub auth_required: bool,
    pub auth_type: String,
    pub visibility: Visibility,
    pub file_path: String,
    pub line_number: i32,
    pub framework: String,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub tags: String,
    pub sensitive_path: bool,
}

/// What an endpoint is found with; [`ApiEndpoint::new`] normalises it as the record's constructor does.
struct Found<'a> {
    method: &'a str,
    path: Option<&'a str>,
    auth: bool,
    auth_type: &'a str,
    file_path: &'a str,
    line: usize,
    framework: &'a str,
    operation_id: Option<String>,
    summary: Option<String>,
    tags: &'a str,
}

impl ApiEndpoint {
    /// The method upper-cased; a blank path is `/`, and every path starts with one.
    fn new(found: Found<'_>) -> ApiEndpoint {
        let path = match found.path {
            Some(path) if !java::is_blank(path) => {
                if path.starts_with('/') {
                    path.to_owned()
                } else {
                    format!("/{path}")
                }
            }
            _ => "/".to_owned(),
        };
        let lower = java::to_lower_root(&path);
        let sensitive_path = ["/admin", "/actuator", "/debug", "/internal", "/metrics", "/env", "/health"]
            .iter()
            .any(|word| lower.contains(word));
        ApiEndpoint {
            method: java::to_upper_root(found.method),
            path,
            auth_required: found.auth,
            auth_type: if found.auth { found.auth_type } else { "NONE" }.to_owned(),
            visibility: Visibility::Unknown,
            file_path: found.file_path.to_owned(),
            line_number: i32::try_from(found.line).unwrap_or(i32::MAX),
            framework: found.framework.to_owned(),
            operation_id: found.operation_id,
            summary: found.summary,
            tags: found.tags.to_owned(),
            sensitive_path,
        }
    }
}

/// A declared contract — `ApiContract`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiContract {
    pub contract_path: String,
    pub format: String,
    pub title: String,
    pub version: String,
    pub endpoints_count: i32,
    pub declared_paths: Vec<String>,
}

/// What a discovery found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovery {
    pub endpoints: Vec<ApiEndpoint>,
    pub contracts: Vec<ApiContract>,
}

/// Why the discovery did not happen, in the words the scan's page shows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Failed(pub String);

const WALK_FAILED: &str = "The source tree could not be walked for API discovery.";

fn too_many(found: &str, ceiling: usize) -> Failed {
    Failed(format!(
        "The API discovery found {found}, more than the {ceiling} one repository may report; the previous inventory \
         is kept. Narrow the scan to a sub-path, or leave generated or vendored specifications out of the tree."
    ))
}

fn timed_out(deadline: Duration) -> Failed {
    Failed(format!("Scanner \"{STEP}\" exceeded {}s and was stopped.", deadline.as_secs()))
}

/// The discovery over the tree at `root`.
pub fn scan(root: &Path) -> Result<Discovery, Failed> {
    scan_bounded(root, DEADLINE, &mut Instant::now, MAX_PER_REPOSITORY)
}

/// [`scan`] with its deadline, clock and ceiling named. `ceiling`: the most endpoints, and the most paths one
/// contract declares, before the discovery fails.
pub fn scan_bounded(
    root: &Path,
    deadline: Duration,
    clock: &mut dyn FnMut() -> Instant,
    ceiling: usize,
) -> Result<Discovery, Failed> {
    let give_up_at = clock().checked_add(deadline);
    // A root that is not there — a sub-path absent from this checkout — means nothing was looked at: empty lists
    // would say "looked, found no API". In Java's words, which reach the scan's page.
    if !std::fs::metadata(root).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(Failed(format!(
            "java.nio.file.NoSuchFileException: {}: no source tree to discover APIs in",
            root.display()
        )));
    }
    let mut discovery = Discover {
        root,
        deadline,
        give_up_at,
        clock,
        ceiling,
        endpoints: Vec::new(),
        contracts: Vec::new(),
        public_ingress_paths: HashSet::new(),
    };
    walk::walk(root, &mut discovery)?;
    let Discover { endpoints, contracts, public_ingress_paths, clock, .. } = discovery;

    if let Some(contract) =
        contracts.iter().find(|contract| usize::try_from(contract.endpoints_count).unwrap_or(0) > ceiling)
    {
        return Err(too_many(
            &format!("a contract declaring {} paths ({})", contract.endpoints_count, contract.contract_path),
            ceiling,
        ));
    }
    // The same endpoint may come from a contract and from the code: the first one met is kept, made public when an
    // ingress exposes it.
    let mut seen = HashSet::new();
    let mut adjusted = Vec::new();
    for mut endpoint in endpoints {
        require_time(clock, give_up_at, deadline)?;
        if seen.insert(format!("{}:{}", endpoint.method, endpoint.path)) {
            if matches_any_ingress(&endpoint.path, &public_ingress_paths) {
                endpoint.visibility = Visibility::Public;
            }
            adjusted.push(endpoint);
        }
    }
    if adjusted.len() > ceiling {
        return Err(too_many(&format!("{} endpoints", adjusted.len()), ceiling));
    }
    Ok(Discovery { endpoints: adjusted, contracts })
}

fn require_time(
    clock: &mut dyn FnMut() -> Instant,
    give_up_at: Option<Instant>,
    deadline: Duration,
) -> Result<(), Failed> {
    if give_up_at.is_some_and(|give_up_at| clock() > give_up_at) { Err(timed_out(deadline)) } else { Ok(()) }
}

struct Discover<'a> {
    root: &'a Path,
    deadline: Duration,
    give_up_at: Option<Instant>,
    clock: &'a mut dyn FnMut() -> Instant,
    ceiling: usize,
    endpoints: Vec<ApiEndpoint>,
    contracts: Vec<ApiContract>,
    public_ingress_paths: HashSet<String>,
}

impl Discover<'_> {
    fn relative(&self, path: &Path) -> String {
        path.strip_prefix(self.root).map(|relative| relative.to_string_lossy().into_owned()).unwrap_or_default()
    }
}

impl Visitor for Discover<'_> {
    type Error = Failed;

    fn pre_visit_directory(&mut self, dir: &Path, _: &Metadata) -> Result<Visit, Failed> {
        // The root's own name is asked too: a sub-path named `test` or `build` is skipped whole, and its discovery
        // is empty — as on the Java side, where the census spares the root and this walk does not.
        let name = dir.file_name().map(|name| java::to_lower_root(&name.to_string_lossy())).unwrap_or_default();
        if IGNORED_DIRECTORIES.contains(&name.as_str()) {
            return Ok(Visit::SkipSubtree);
        }
        let relative = java::to_lower_root(&self.relative(dir).replace('\\', "/"));
        if relative.starts_with("src/test")
            || relative.contains("/src/test/")
            || relative.starts_with("test")
            || relative.contains("/test/")
        {
            return Ok(Visit::SkipSubtree);
        }
        Ok(Visit::Continue)
    }

    fn visit_file(&mut self, file: &Path, metadata: &Metadata) -> Result<Visit, Failed> {
        require_time(self.clock, self.give_up_at, self.deadline)?;
        // Before reading on: the list before merging is allowed twice the ceiling and no more — otherwise what a
        // repository can make it hold is bounded by time alone.
        if self.endpoints.len() > self.ceiling.saturating_mul(2) {
            return Err(too_many(
                &format!("{} endpoints, before duplicates are merged", self.endpoints.len()),
                self.ceiling,
            ));
        }
        // Links and oversized files are not read: see `source_files`.
        if !source_files::is_readable(metadata) {
            return Ok(Visit::Continue);
        }
        let original_name = file.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        let name = java::to_lower_root(&original_name);
        let relative = self.relative(file);
        if is_test_path(&relative) {
            return Ok(Visit::Continue);
        }
        let contract = is_open_api_or_swagger(&name);
        let yaml = name.ends_with(".yaml") || name.ends_with(".yml");
        let code = [".java", ".ts", ".js", ".py", ".go"].iter().any(|extension| name.ends_with(extension));
        if !contract && !yaml && !code {
            return Ok(Visit::Continue);
        }
        // A file the walk admitted but that changed since, or cannot be read, is skipped like one that is malformed.
        let Ok(Some(content)) = source_files::read_text(file) else {
            return Ok(Visit::Continue);
        };
        let mut found = Vec::new();
        if contract && let Some(contract) = parse_contract(&original_name, &content, &relative, &mut found) {
            self.contracts.push(contract);
        }
        if yaml {
            ingress_paths(&content, &mut self.public_ingress_paths);
        }
        if name.ends_with(".java") {
            spring_endpoints(&content, &relative, &mut found);
        } else if name.ends_with(".ts") || name.ends_with(".js") {
            node_endpoints(&content, &relative, &mut found);
        } else if name.ends_with(".py") {
            python_endpoints(&content, &relative, &mut found);
        } else if name.ends_with(".go") {
            go_endpoints(&content, &relative, &mut found);
        }
        self.endpoints.append(&mut found);
        Ok(Visit::Continue)
    }

    fn visit_file_failed(&mut self, _: &Path, _: std::io::Error) -> Result<Visit, Failed> {
        Err(Failed(WALK_FAILED.to_owned()))
    }

    fn post_visit_directory(&mut self, _: &Path, error: Option<std::io::Error>) -> Result<Visit, Failed> {
        match error {
            Some(_) => Err(Failed(WALK_FAILED.to_owned())),
            None => Ok(Visit::Continue),
        }
    }
}

fn is_open_api_or_swagger(name: &str) -> bool {
    name.contains("openapi") || name.contains("swagger") || name == "api-docs.json" || name == "api.json"
}

fn is_test_path(relative: &str) -> bool {
    let lower = java::to_lower_root(relative).replace('\\', "/");
    lower.contains("/src/test/")
        || lower.starts_with("src/test/")
        || lower.contains("/test/")
        || lower.starts_with("test/")
        || lower.contains("/tests/")
        || lower.starts_with("tests/")
        || lower.contains("/__tests__/")
        || lower.contains("/spec/")
        || lower.contains("/specs/")
        || lower.contains("/fixtures/")
        || lower.ends_with("test.java")
        || lower.ends_with("tests.java")
        || lower.ends_with("spec.java")
        || lower.ends_with(".test.ts")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.js")
}

/// Whether an ingress path exposes this endpoint: the path itself, or one of its prefixes ending at a `/` —
/// written with the slash (`/api/`) or without (`/api`). Asked of the endpoint's own prefixes, a few lookups
/// whatever the manifests declare.
fn matches_any_ingress(path: &str, public_paths: &HashSet<String>) -> bool {
    if public_paths.contains(path) {
        return true;
    }
    path.match_indices('/').any(|(slash, _)| {
        let with = path.get(..slash.saturating_add(1)).is_some_and(|prefix| public_paths.contains(prefix));
        let without = slash > 0 && path.get(..slash).is_some_and(|prefix| public_paths.contains(prefix));
        with || without
    })
}

// ------------------------------------------------------------------------------------------------ patterns

/// `\s` as `java.util.regex` reads it without flags.
macro_rules! s {
    () => {
        r"[ \t\n\x0B\x0C\r]"
    };
}

fn compiled(pattern: &str) -> Regex {
    #[allow(clippy::expect_used)]
    Regex::new(pattern).expect("a fixed pattern")
}

/// The first type declaration, whose position splits class-level annotations from methods.
static CLASS_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| compiled(concat!(r"(?-u:\b)(?:class|interface|record)", s!(), r"+[A-Za-z0-9_]+")));
static CLASS_MAPPING: LazyLock<Regex> =
    LazyLock::new(|| compiled(concat!(r"@(?:RequestMapping|Path)", s!(), r"*(?:\(([^)]*)\))?")));
/// The route annotation alone; its parameters are delimited by hand ([`Neighbourhood::params`]).
static ROUTE_ANNOTATION: LazyLock<Regex> = LazyLock::new(|| {
    compiled(
        r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|GET|POST|PUT|DELETE|PATCH)(?-u:\b)",
    )
});
static QUOTED: LazyLock<Regex> = LazyLock::new(|| compiled(r#"["']([^"']+)["']"#));
static OPENAPI_VERSION: LazyLock<Regex> = LazyLock::new(|| compiled(concat!("openapi:", s!(), r#"*["']?([0-9]+)"#)));
static YAML_TITLE: LazyLock<Regex> = LazyLock::new(|| compiled(concat!("title:", s!(), r#"*["']?([^"'\r\n]+)["']?"#)));
static YAML_VERSION: LazyLock<Regex> =
    LazyLock::new(|| compiled(concat!("version:", s!(), r#"*["']?([^"'\r\n]+)["']?"#)));
static YAML_TOP_LEVEL_KEY: LazyLock<Regex> = LazyLock::new(|| compiled(r"^[a-zA-Z0-9_-]+:"));
static YAML_PATH: LazyLock<Regex> = LazyLock::new(|| compiled(concat!("^", s!(), r"{2}(/[^:]+):")));
static YAML_METHOD: LazyLock<Regex> =
    LazyLock::new(|| compiled(concat!("^", s!(), r"{4}(get|post|put|delete|patch|options|head):")));
static INGRESS_PATH: LazyLock<Regex> = LazyLock::new(|| compiled(concat!("path:", s!(), r"*([/a-zA-Z0-9_{}-]+)")));
static EXPRESS_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    compiled(concat!(r"(?:app|router)\.(get|post|put|delete|patch)", s!(), r"*\(", s!(), r#"*['"`]([^'"`]+)['"`]"#))
});
/// The annotation, then nothing or one quoted literal between parentheses, closed by the quote that opened it.
static NEST_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    compiled(concat!(
        r"@(Get|Post|Put|Delete|Patch)",
        s!(),
        r"*\(",
        s!(),
        r#"*(?:'([^'"`\r\n]*)'|"([^'"`\r\n]*)"|`([^'"`\r\n]*)`)?"#,
        s!(),
        r"*\)"
    ))
});
static NEST_CONTROLLER: LazyLock<Regex> = LazyLock::new(|| {
    compiled(concat!(
        r"@Controller",
        s!(),
        r"*\(",
        s!(),
        r#"*(?:'([^'"`\r\n]*)'|"([^'"`\r\n]*)"|`([^'"`\r\n]*)`)?"#,
        s!(),
        r"*\)"
    ))
});
static FASTAPI_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    compiled(concat!(r"@(?:app|router)\.(get|post|put|delete|patch)", s!(), r"*\(", s!(), r#"*['"`]([^'"`]+)['"`]"#))
});
static FLASK_ROUTE: LazyLock<Regex> =
    LazyLock::new(|| compiled(concat!(r"@app\.route", s!(), r"*\(", s!(), r#"*['"`]([^'"`]+)['"`]"#)));
static GIN_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    compiled(concat!(
        r"(?:r|router|engine|group|api)\.(GET|POST|PUT|DELETE|PATCH)",
        s!(),
        r"*\(",
        s!(),
        r#"*["']([^"']+)["']"#
    ))
});

/// The literal of a NestJS annotation, whichever quote it is written in — three groups from `first` — and none
/// for `()`.
fn quoted_literal<'h>(captures: &regex::Captures<'h>, first: usize) -> Option<&'h str> {
    (first..first.saturating_add(3)).find_map(|index| captures.get(index)).map(|literal| literal.as_str())
}

fn group<'h>(captures: &regex::Captures<'h>, index: usize) -> &'h str {
    captures.get(index).map_or("", |matched| matched.as_str())
}

// ------------------------------------------------------------------------------------------------ contracts

/// A file that looked like a specification: its contract, and its operations added to `endpoints`; nothing when it
/// is not one or does not parse.
fn parse_contract(
    original_name: &str,
    content: &str,
    relative: &str,
    endpoints: &mut Vec<ApiEndpoint>,
) -> Option<ApiContract> {
    // The name as written: `OPENAPI.JSON` is read as YAML, on both sides.
    if original_name.ends_with(".json") {
        json_contract(content, relative, endpoints)
    } else {
        yaml_contract(content, relative, endpoints)
    }
}

fn json_contract(content: &str, relative: &str, endpoints: &mut Vec<ApiEndpoint>) -> Option<ApiContract> {
    use crate::jackson_tree::Node;
    let root = match crate::jackson_tree::read_text(content) {
        Ok(Some(root @ Node::Object(_))) => root,
        Ok(_) => return None,
        Err(refused) => {
            // The one case an operator would want to fix: a contract they believe is inventoried.
            tracing::warn!(
                file = relative,
                reason = refused.0,
                "an API contract could not be parsed and is not inventoried"
            );
            return None;
        }
    };
    let format = if let Some(openapi) = root.get("openapi") {
        // `asText().charAt(0)`: the first UTF-16 unit — an empty text throws, and the file is not a contract.
        let first = openapi.as_text().encode_utf16().next()?;
        format!("OPENAPI_V{}", java::from_utf16(&[first]))
    } else if root.get("swagger").is_some() {
        "SWAGGER_V2".to_owned()
    } else {
        return None;
    };
    let info = root.get("info");
    let title = info.and_then(|info| info.get("title")).map_or_else(|| "API Spec".to_owned(), Node::as_text);
    let version = info.and_then(|info| info.get("version")).map_or_else(|| "1.0.0".to_owned(), Node::as_text);
    let global_security = root.get("security").is_some()
        || root.get("components").is_some_and(|components| components.get("securitySchemes").is_some())
        || root.get("securityDefinitions").is_some();

    let mut paths = Vec::new();
    if let Some(declared) = root.get("paths").and_then(Node::as_object) {
        for (path, operations) in declared.members() {
            paths.push(path.to_owned());
            let Some(operations) = operations.as_object() else { continue };
            for (key, _) in operations.members() {
                let method = java::to_upper_root(key);
                if !METHODS.contains(&method.as_str()) {
                    continue;
                }
                // The operation under the lower-case key, else the upper-case one — not necessarily `key`'s.
                let operation = operations.get(&java::to_lower_root(&method)).or_else(|| operations.get(&method));
                let text_of = |field: &str| operation.and_then(|operation| operation.get(field)).map(Node::as_text);
                let security = operation.and_then(|operation| operation.get("security"));
                let explicitly_public =
                    matches!(security, Some(security @ Node::Array(_)) if security.is_empty_container());
                let auth = !explicitly_public && (security.is_some() || global_security);
                endpoints.push(ApiEndpoint::new(Found {
                    method: &method,
                    path: Some(path),
                    auth,
                    auth_type: "OPENAPI_SECURITY",
                    file_path: relative,
                    line: 1,
                    framework: "OPENAPI_SPEC",
                    operation_id: text_of("operationId"),
                    summary: text_of("summary"),
                    tags: "OpenAPI",
                }));
            }
        }
    }
    Some(contract(relative, format, title, version, paths))
}

fn contract(relative: &str, format: String, title: String, version: String, paths: Vec<String>) -> ApiContract {
    ApiContract {
        contract_path: relative.to_owned(),
        format,
        title,
        version,
        endpoints_count: i32::try_from(paths.len()).unwrap_or(i32::MAX),
        declared_paths: paths,
    }
}

/// YAML without a YAML parser, line by line, as the Java side reads it.
fn yaml_contract(content: &str, relative: &str, endpoints: &mut Vec<ApiEndpoint>) -> Option<ApiContract> {
    let format = if content.contains("openapi:") {
        OPENAPI_VERSION
            .captures(content)
            .map_or_else(|| "OPENAPI_V3".to_owned(), |version| format!("OPENAPI_V{}", group(&version, 1)))
    } else if content.contains("swagger:") {
        "SWAGGER_V2".to_owned()
    } else {
        return None;
    };
    let title = YAML_TITLE
        .captures(content)
        .map_or_else(|| "API Spec".to_owned(), |title| java::trim(group(&title, 1)).to_owned());
    let version = YAML_VERSION
        .captures(content)
        .map_or_else(|| "1.0.0".to_owned(), |version| java::trim(group(&version, 1)).to_owned());
    let global_security =
        ["security:", "securitySchemes:", "securityDefinitions:", "bearerAuth", "oauth2", "ApiKey", "jwt"]
            .iter()
            .any(|word| content.contains(word));

    let mut paths = Vec::new();
    let mut in_paths = false;
    let mut current: Option<String> = None;
    for (index, line) in content.split('\n').enumerate() {
        if line.starts_with("paths:") {
            in_paths = true;
            continue;
        }
        if !in_paths {
            continue;
        }
        if YAML_TOP_LEVEL_KEY.is_match(line) {
            in_paths = false;
            continue;
        }
        if let Some(path) = YAML_PATH.captures(line) {
            let path = java::trim(group(&path, 1)).to_owned();
            paths.push(path.clone());
            current = Some(path);
            continue;
        }
        let Some(path) = current.as_deref() else { continue };
        if let Some(method) = YAML_METHOD.captures(line) {
            let auth = global_security && !line.contains("security: []");
            endpoints.push(ApiEndpoint::new(Found {
                method: group(&method, 1),
                path: Some(path),
                auth,
                auth_type: "OPENAPI_SECURITY",
                file_path: relative,
                line: index.saturating_add(1),
                framework: "OPENAPI_SPEC",
                operation_id: None,
                summary: None,
                tags: "OpenAPI",
            }));
        }
    }
    Some(contract(relative, format, title, version, paths))
}

/// The paths a Kubernetes `Ingress` exposes.
fn ingress_paths(content: &str, public_paths: &mut HashSet<String>) {
    if !content.contains("kind: Ingress") && !content.contains("kind: \"Ingress\"") {
        return;
    }
    for path in INGRESS_PATH.captures_iter(content) {
        public_paths.insert(java::trim(group(&path, 1)).to_owned());
    }
}

// ------------------------------------------------------------------------------------------------ Spring

/// The guards that make a Spring route authenticated, at class level.
const CLASS_GUARDS: [&str; 7] = [
    "@PreAuthorize",
    "@Secured",
    "@RolesAllowed",
    "@RequiresAccount",
    "@RequiresAdministrator",
    "@RequiresAgentKey",
    "@RequiresSecurityLead",
];

/// Spring Boot and JAX-RS controllers, read with their comments blanked out.
fn spring_endpoints(raw: &str, relative: &str, endpoints: &mut Vec<ApiEndpoint>) {
    let units = strip_comments(raw);
    let content = String::from_utf16_lossy(&units);
    if !["@RestController", "@Controller", "@RequestMapping", "@Path"].iter().any(|marker| content.contains(marker)) {
        return;
    }
    let offsets = Offsets::of(&content);
    let class_unit = CLASS_DECLARATION.find(&content).map(|declaration| offsets.unit(declaration.start()));
    // `classIdx > 0`: a declaration at the very first character has no header, as on the Java side.
    let class_unit = class_unit.filter(|&at| at > 0);
    let header = class_unit.and_then(|at| content.get(..offsets.byte(at)));
    let class_prefix = header
        .and_then(|header| CLASS_MAPPING.captures(header))
        .map(|mapping| path_of(mapping.get(1).map(|params| params.as_str())))
        .unwrap_or_default();
    let class_auth = header.is_some_and(|header| CLASS_GUARDS.iter().any(|guard| header.contains(guard)));

    let mut around = Neighbourhood::new(&units);
    let mut from = 0usize;
    while from <= units.len() {
        let Some(route) = ROUTE_ANNOTATION.captures_at(&content, offsets.byte(from)) else { break };
        let (Some(whole), Some(annotation)) = (route.get(0), route.get(1)) else { break };
        let start = offsets.unit(whole.start());
        let (params, end) = around.params(offsets.unit(whole.end()));
        from = end;
        if class_unit.is_some_and(|class_at| start < class_at) {
            continue;
        }
        let params = params.map(String::from_utf16_lossy);
        let sub_path = path_of(params.as_deref());
        let method = match annotation.as_str() {
            "GetMapping" | "GET" => "GET",
            "PostMapping" | "POST" => "POST",
            "PutMapping" | "PUT" => "PUT",
            "DeleteMapping" | "DELETE" => "DELETE",
            "PatchMapping" | "PATCH" => "PATCH",
            _ => method_of_request_mapping(params.as_deref()),
        };
        let full_path = combine_paths(Some(&class_prefix), Some(&sub_path));
        let line = around.line_of(start);
        let (Some(context_start), context_end) =
            (around.context_start(start, class_unit.unwrap_or(0)), around.context_end(end))
        else {
            // Where Java's `substring` would throw: the rest of the file is skipped, what was found kept.
            return;
        };
        let context = units.get(context_start..context_end).map(String::from_utf16_lossy).unwrap_or_default();
        let explicitly_public =
            context.contains("@OpenToAnonymous") || context.contains("@PermitAll") || is_known_public(&full_path);
        let method_auth = CLASS_GUARDS.iter().any(|guard| context.contains(guard))
            || context.contains("@AuthenticationPrincipal")
            || context.contains("Principal principal")
            || context.contains("VectispirePrincipal");
        let auth = !explicitly_public && (class_auth || method_auth);
        let auth_type = if context.contains("@RequiresAgentKey") || full_path.starts_with("/api/v1/agent") {
            "API_KEY"
        } else {
            "SPRING_SECURITY"
        };
        endpoints.push(ApiEndpoint::new(Found {
            method,
            path: Some(&full_path),
            auth,
            auth_type,
            file_path: relative,
            line,
            framework: "SPRING_BOOT",
            operation_id: None,
            summary: None,
            tags: "Java/Spring",
        }));
    }
}

/// The routes the control plane serves to anybody, whatever their annotations say.
fn is_known_public(path: &str) -> bool {
    path == "/api/v1/auth/login"
        || path == "/api/v1/auth/methods"
        || path == "/api/v1/auth/session/exchange"
        || path.starts_with("/actuator/health")
        || path == "/api/v1/crypto/public-key.pub"
        || (path.starts_with("/api/v1/scorecards/repositories/") && path.ends_with("/badge.svg"))
}

/// The first quoted literal of an annotation's parameters, trimmed; nothing for none.
fn path_of(params: Option<&str>) -> String {
    match params {
        Some(params) if !java::is_blank(params) => {
            QUOTED.captures(params).map(|quoted| java::trim(group(&quoted, 1)).to_owned()).unwrap_or_default()
        }
        _ => String::new(),
    }
}

fn method_of_request_mapping(params: Option<&str>) -> &'static str {
    let Some(params) = params else { return "ALL" };
    ["GET", "POST", "PUT", "DELETE", "PATCH"]
        .into_iter()
        .find(|method| params.contains(&format!("RequestMethod.{method}")))
        .unwrap_or("ALL")
}

/// Comments blanked out — each UTF-16 unit of one a space, its line ends kept — strings and characters kept as
/// written, so that every offset and line of the rest stays where it was.
fn strip_comments(code: &str) -> Vec<u16> {
    let units: Vec<u16> = code.encode_utf16().collect();
    let (slash, star, newline, quote, apostrophe, backslash, space) = (
        u16::from(b'/'),
        u16::from(b'*'),
        u16::from(b'\n'),
        u16::from(b'"'),
        u16::from(b'\''),
        u16::from(b'\\'),
        u16::from(b' '),
    );
    let mut out = Vec::with_capacity(units.len());
    let (mut in_block, mut in_line, mut in_string, mut in_char) = (false, false, false, false);
    let mut index = 0usize;
    while let Some(&c) = units.get(index) {
        let next = units.get(index.saturating_add(1)).copied();
        index = index.saturating_add(1);
        if in_block {
            if c == star && next == Some(slash) {
                in_block = false;
                out.extend([space, space]);
                index = index.saturating_add(1);
            } else {
                out.push(if c == newline { newline } else { space });
            }
        } else if in_line {
            if c == newline {
                in_line = false;
                out.push(newline);
            } else {
                out.push(space);
            }
        } else if in_string || in_char {
            out.push(c);
            let closing = if in_string { quote } else { apostrophe };
            if c == backslash {
                if let Some(escaped) = next {
                    out.push(escaped);
                    index = index.saturating_add(1);
                }
            } else if c == closing {
                in_string = false;
                in_char = false;
            }
        } else if c == slash && next == Some(star) {
            in_block = true;
            out.extend([space, space]);
            index = index.saturating_add(1);
        } else if c == slash && next == Some(slash) {
            in_line = true;
            out.extend([space, space]);
            index = index.saturating_add(1);
        } else {
            in_string = c == quote;
            in_char = c == apostrophe;
            out.push(c);
        }
    }
    out
}

/// Byte offsets of the text and UTF-16 offsets of its units, both ways, at every character boundary.
struct Offsets {
    unit_of_byte: Vec<usize>,
    byte_of_unit: Vec<usize>,
}

impl Offsets {
    fn of(text: &str) -> Offsets {
        let mut unit_of_byte = vec![0; text.len().saturating_add(1)];
        let mut byte_of_unit = Vec::with_capacity(text.len().saturating_add(1));
        let mut unit = 0usize;
        for (byte, c) in text.char_indices() {
            if let Some(slot) = unit_of_byte.get_mut(byte) {
                *slot = unit;
            }
            for _ in 0..c.len_utf16() {
                byte_of_unit.push(byte);
            }
            unit = unit.saturating_add(c.len_utf16());
        }
        if let Some(slot) = unit_of_byte.get_mut(text.len()) {
            *slot = unit;
        }
        byte_of_unit.push(text.len());
        Offsets { unit_of_byte, byte_of_unit }
    }

    fn unit(&self, byte: usize) -> usize {
        self.unit_of_byte.get(byte).copied().unwrap_or(0)
    }

    fn byte(&self, unit: usize) -> usize {
        self.byte_of_unit.get(unit).copied().unwrap_or(usize::MAX)
    }
}

/// What the Spring reader looks up around each route annotation, each lookup in amortised constant time: the
/// annotations come in order, so each search resumes where the previous one stopped.
struct Neighbourhood<'a> {
    content: &'a [u16],
    first_closing_brace: Option<usize>,
    last_opening_brace: Option<usize>,
    /// The next `)` at or after the last searched position: unknown before the first search, `None` once none is
    /// left — no `)` after an earlier position means none after a later one.
    next_parenthesis: Option<Option<usize>>,
    counted_up_to: usize,
    line: usize,
}

/// How far back and forward a route's annotations and signature are read for its guards.
const BEFORE: usize = 500;
const AFTER: usize = 200;

impl<'a> Neighbourhood<'a> {
    fn new(content: &'a [u16]) -> Neighbourhood<'a> {
        Neighbourhood {
            content,
            first_closing_brace: content.iter().position(|&c| c == u16::from(b'}')),
            last_opening_brace: content.iter().rposition(|&c| c == u16::from(b'{')),
            next_parenthesis: None,
            counted_up_to: 0,
            line: 1,
        }
    }

    /// The parameters of the annotation ending at `annotation_end` — `\s*(…)` up to the next `)` — or none, and
    /// where the annotation ends.
    fn params(&mut self, annotation_end: usize) -> (Option<&'a [u16]>, usize) {
        let mut cursor = annotation_end;
        while self.content.get(cursor).is_some_and(|&c| matches!(c, 0x20 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D)) {
            cursor = cursor.saturating_add(1);
        }
        if self.content.get(cursor) != Some(&u16::from(b'(')) {
            return (None, annotation_end);
        }
        let stale = match self.next_parenthesis {
            None => true,
            Some(Some(at)) => at <= cursor,
            Some(None) => false,
        };
        if stale {
            let after = cursor.saturating_add(1);
            self.next_parenthesis = Some(
                self.content
                    .get(after..)
                    .and_then(|rest| rest.iter().position(|&c| c == u16::from(b')')))
                    .map(|at| at.saturating_add(after)),
            );
        }
        match self.next_parenthesis.flatten() {
            Some(closing) => (self.content.get(cursor.saturating_add(1)..closing), closing.saturating_add(1)),
            None => (None, annotation_end),
        }
    }

    /// The 1-based line of an offset; offsets are asked in increasing order.
    fn line_of(&mut self, offset: usize) -> usize {
        let end = offset.min(self.content.len());
        if end > self.counted_up_to {
            let newlines = self
                .content
                .get(self.counted_up_to..end)
                .map_or(0, |run| run.iter().filter(|&&c| c == u16::from(b'\n')).count());
            self.line = self.line.saturating_add(newlines);
            self.counted_up_to = end;
        }
        self.line
    }

    /// Where the context read before an annotation starts: the last `}` within [`BEFORE`] units, else [`BEFORE`]
    /// units back — or, when the file has no `}` before the annotation at all, the class declaration if that is
    /// nearer. `None` where Java's offset would be negative.
    fn context_start(&self, annotation_start: usize, fallback: usize) -> Option<usize> {
        let floor = annotation_start.checked_sub(BEFORE);
        let lowest = floor.unwrap_or(0);
        if let Some(brace) = self
            .content
            .get(lowest..=annotation_start.min(self.content.len().saturating_sub(1)))
            .and_then(|window| window.iter().rposition(|&c| c == u16::from(b'}')))
        {
            return Some(brace.saturating_add(lowest));
        }
        let brace_earlier = self.first_closing_brace.is_some_and(|brace| brace < annotation_start);
        match floor {
            Some(floor) if brace_earlier => Some(floor),
            None if brace_earlier => None,
            floor => Some(fallback.max(floor.unwrap_or(0))),
        }
    }

    /// Where the context read after an annotation ends: the next `{` within [`AFTER`] units, else [`AFTER`] units
    /// on — or the annotation's end when the file has no `{` after it.
    fn context_end(&self, annotation_end: usize) -> usize {
        let ceiling = annotation_end.saturating_add(AFTER);
        let window_end = ceiling.saturating_add(1).min(self.content.len());
        if let Some(brace) = self
            .content
            .get(annotation_end..window_end)
            .and_then(|window| window.iter().position(|&c| c == u16::from(b'{')))
        {
            return brace.saturating_add(annotation_end);
        }
        if self.last_opening_brace.is_some_and(|brace| brace > ceiling) { ceiling } else { annotation_end }
    }
}

// ------------------------------------------------------------------------------------------------ the rest

/// `combinePaths`: one slash between them, a leading one, no trailing one but for the root.
fn combine_paths(prefix: Option<&str>, sub: Option<&str>) -> String {
    let prefix = java::trim(prefix.unwrap_or_default());
    let sub = java::trim(sub.unwrap_or_default());
    let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
    let sub = sub.strip_prefix('/').unwrap_or(sub);
    let mut combined = format!("{prefix}/{sub}");
    if !combined.starts_with('/') {
        combined.insert(0, '/');
    }
    if combined.len() > 1 && combined.ends_with('/') {
        combined.pop();
    }
    combined
}

/// Express and NestJS, a line at a time.
fn node_endpoints(content: &str, relative: &str, endpoints: &mut Vec<ApiEndpoint>) {
    let nest_prefix =
        NEST_CONTROLLER.captures(content).and_then(|controller| quoted_literal(&controller, 1).map(str::to_owned));
    let file_uses_guards = content.contains("@UseGuards");
    for (index, line) in content.split('\n').enumerate() {
        let number = index.saturating_add(1);
        if let Some(route) = EXPRESS_ROUTE.captures(line) {
            let auth = ["auth", "jwt", "passport", "guard"].iter().any(|word| line.contains(word));
            endpoints.push(ApiEndpoint::new(Found {
                method: group(&route, 1),
                path: Some(group(&route, 2)),
                auth,
                auth_type: "JWT/MIDDLEWARE",
                file_path: relative,
                line: number,
                framework: "EXPRESS",
                operation_id: None,
                summary: None,
                tags: "Node/Express",
            }));
        }
        if let Some(route) = NEST_ROUTE.captures(line) {
            let full_path = combine_paths(nest_prefix.as_deref(), quoted_literal(&route, 2));
            let auth = file_uses_guards || line.contains("Guard");
            endpoints.push(ApiEndpoint::new(Found {
                method: group(&route, 1),
                path: Some(&full_path),
                auth,
                auth_type: "NEST_GUARD",
                file_path: relative,
                line: number,
                framework: "NESTJS",
                operation_id: None,
                summary: None,
                tags: "Node/NestJS",
            }));
        }
    }
}

/// FastAPI and Flask.
fn python_endpoints(content: &str, relative: &str, endpoints: &mut Vec<ApiEndpoint>) {
    let lines: Vec<&str> = content.split('\n').collect();
    for (index, line) in lines.iter().enumerate() {
        let number = index.saturating_add(1);
        if let Some(route) = FASTAPI_ROUTE.captures(line) {
            let auth = ["Depends", "Security", "auth"].iter().any(|word| line.contains(word));
            endpoints.push(ApiEndpoint::new(Found {
                method: group(&route, 1),
                path: Some(group(&route, 2)),
                auth,
                auth_type: "FASTAPI_DEPENDS",
                file_path: relative,
                line: number,
                framework: "FASTAPI",
                operation_id: None,
                summary: None,
                tags: "Python/FastAPI",
            }));
        }
        if let Some(route) = FLASK_ROUTE.captures(line) {
            let around =
                |at: Option<usize>| at.and_then(|at| lines.get(at)).is_some_and(|line| line.contains("login_required"));
            let auth = around(index.checked_sub(1)) || around(index.checked_add(1));
            endpoints.push(ApiEndpoint::new(Found {
                method: "GET",
                path: Some(group(&route, 1)),
                auth,
                auth_type: "FLASK_LOGIN",
                file_path: relative,
                line: number,
                framework: "FLASK",
                operation_id: None,
                summary: None,
                tags: "Python/Flask",
            }));
        }
    }
}

/// Gin.
fn go_endpoints(content: &str, relative: &str, endpoints: &mut Vec<ApiEndpoint>) {
    for (index, line) in content.split('\n').enumerate() {
        if let Some(route) = GIN_ROUTE.captures(line) {
            let auth = ["Auth", "JWT", "Middleware"].iter().any(|word| line.contains(word));
            endpoints.push(ApiEndpoint::new(Found {
                method: group(&route, 1),
                path: Some(group(&route, 2)),
                auth,
                auth_type: "GIN_MIDDLEWARE",
                file_path: relative,
                line: index.saturating_add(1),
                framework: "GIN",
                operation_id: None,
                summary: None,
                tags: "Go/Gin",
            }));
        }
    }
}

/// Every file of a tree goes through these: the per-file readers on one text, for the fuzzer — no file system, no
/// panic whatever the bytes.
pub fn read_one(original_name: &str, content: &str) -> (Vec<ApiEndpoint>, Option<ApiContract>, HashSet<String>) {
    let mut endpoints = Vec::new();
    let mut ingress = HashSet::new();
    let contract = parse_contract(original_name, content, original_name, &mut endpoints);
    ingress_paths(content, &mut ingress);
    node_endpoints(content, original_name, &mut endpoints);
    python_endpoints(content, original_name, &mut endpoints);
    go_endpoints(content, original_name, &mut endpoints);
    spring_endpoints(content, original_name, &mut endpoints);
    for endpoint in &endpoints {
        let _ = matches_any_ingress(&endpoint.path, &ingress);
    }
    (endpoints, contract, ingress)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for (file, content) in files {
            let path = root.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        root
    }

    /// A clock that reads `start` for its first `readings`, and an hour later after them.
    fn clock_advancing_after(readings: u32) -> impl FnMut() -> Instant {
        let start = Instant::now();
        let mut read = 0u32;
        move || {
            read += 1;
            if read > readings { start + Duration::from_secs(3600) } else { start }
        }
    }

    #[test]
    fn a_discovery_past_its_deadline_fails() {
        let root = tree(&[("a.js", "app.get('/a', h)\n"), ("b.js", "app.get('/b', h)\n")]);
        // The first reading sets the deadline, the second is the first file's.
        let failed =
            scan_bounded(root.path(), DEADLINE, &mut clock_advancing_after(1), MAX_PER_REPOSITORY).unwrap_err();
        assert_eq!(failed.0, "Scanner \"api discovery\" exceeded 300s and was stopped.");
        assert!(scan_bounded(root.path(), DEADLINE, &mut clock_advancing_after(10), MAX_PER_REPOSITORY).is_ok());
    }

    #[test]
    fn the_merge_holds_the_deadline_too() {
        let root = tree(&[("a.js", "app.get('/a', h)\n")]);
        // One reading for the deadline, one for the only file, then the merge's.
        let failed =
            scan_bounded(root.path(), DEADLINE, &mut clock_advancing_after(2), MAX_PER_REPOSITORY).unwrap_err();
        assert!(failed.0.contains("exceeded"), "{failed}");
    }

    #[test]
    fn an_unwalkable_tree_fails_rather_than_finding_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let root = tree(&[("closed/a.js", "app.get('/a', h)\n")]);
        let closed = root.path().join("closed");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let outcome = scan(root.path());
        let readable = std::fs::read_dir(&closed).is_ok();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
        if readable {
            // Running as root, the directory is read: then the discovery saw everything.
            assert_eq!(outcome.unwrap().endpoints.len(), 1);
        } else {
            assert_eq!(outcome.unwrap_err().0, WALK_FAILED);
        }
    }

    #[test]
    fn paths_are_combined_as_java_combines_them() {
        assert_eq!(combine_paths(Some(" /api/ "), Some(" /users ")), "/api/users");
        assert_eq!(combine_paths(None, None), "/");
        assert_eq!(combine_paths(Some("api"), Some("")), "/api");
        assert_eq!(combine_paths(Some("//"), Some("//x/")), "///x", "one slash taken from each side, no more");
    }

    #[test]
    fn every_pattern_compiles() {
        for pattern in [
            &CLASS_DECLARATION,
            &CLASS_MAPPING,
            &ROUTE_ANNOTATION,
            &QUOTED,
            &OPENAPI_VERSION,
            &YAML_TITLE,
            &YAML_VERSION,
            &YAML_TOP_LEVEL_KEY,
            &YAML_PATH,
            &YAML_METHOD,
            &INGRESS_PATH,
            &EXPRESS_ROUTE,
            &NEST_ROUTE,
            &NEST_CONTROLLER,
            &FASTAPI_ROUTE,
            &FLASK_ROUTE,
            &GIN_ROUTE,
        ] {
            assert!(!pattern.as_str().is_empty());
        }
        assert!(ROUTE_ANNOTATION.is_match("@GET\u{e9}("), "an ASCII boundary, as Java's since JDK 19");
        assert!(!ROUTE_ANNOTATION.is_match("@GETTER"));
    }
}
