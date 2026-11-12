//! The layers inside a module's crate — what `ArchitectureTest` adds to Modulith.
//!
//! A module crate is laid out as the Java module's four packages were:
//!
//! ```text
//! src/lib.rs, src/*.rs     root         the module's API, and its services with `internal`
//! src/internal/            internal     the implementation
//! src/persistence/         persistence  entities, repositories, every query
//! src/web/                 web          the routes: HTTP mapping and nothing else
//! src/<interface>/         interface    a named interface another module may use (`security`, `queries`)
//! ```
//!
//! Rust's privacy carries part of the rule — `web`, `internal` and `persistence` are declared without `pub`, so
//! no other crate can name them — and this checks that, and the part privacy cannot express, which is what a
//! layer may *use* of the libraries. It is the Rust of: `layersOnlyReachDownwards`, `everyClassHasAPlace`,
//! `servicesHoldNoQueryApi`, `controllersHoldNoPersistenceApi`, `onlyRepositoriesReachTheDatabase` and
//! `apiNeverTouchesPersistence`.
//!
//! The libraries named below are the ones the plan chose (§3.1): `sqlx` and `sea-query` for the queries, the
//! pool crate `vectispire-cp-db` that wraps them. When the pool crate's layout lands, its query vocabulary is a
//! line in [`QUERY_API`] and the paging vocabulary stays allowed to a service, as Spring Data's `domain` package
//! was.

use std::collections::BTreeSet;
use std::path::Path;

use crate::facts::PathUse;
use crate::graph::Workspace;
use crate::model::{Config, Kind};
use crate::source::{SourceFile, read_package};

/// What only a module's `persistence` may name: a query API, a driver. A service hands its repository criteria,
/// and the repository writes the query.
pub const QUERY_API: &[&str] = &["sqlx", "sea_query", "sea_query_binder", "diesel", "tokio_postgres", "mysql_async"];

/// What a service may not name of the pool crate, `vectispire_cp_db` — the part that is the query API of a
/// pool crate rather than a driver's: the query builders and fixed queries, the table list a visible select is
/// made for, the column types and the schema declarations. What a service *may* name stays: `Tx`, `Mode` and
/// `retry_on_lock_conflict` (its transaction, as `@Transactional` was), the pool it begins one on, and the
/// `Visibility` it hands its repository as criteria.
pub const CP_DB_QUERY_VOCABULARY: &[&str] = &[
    "query",
    "VisibleSelect",
    "TargetTable",
    "store",
    "types",
    "parity",
    "settings",
    "DatabaseUrl",
    "DbSettings",
    "PoolSettings",
];

/// What a `web` module may not name besides the query API: the pool crate. A controller maps HTTP; it holds no
/// persistence API at all, not even the pool.
pub const NOT_IN_WEB: &[&str] = &["vectispire_cp_db"];

/// What `persistence` may not name: the HTTP stack. An entity or a repository that knew about a request would
/// be a controller in the wrong place.
pub const NOT_IN_PERSISTENCE: &[&str] = &["axum", "tower_http", "hyper", "vectispire_cp_http"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer {
    /// The crate root and its other files: the module's API.
    Root,
    Internal,
    Persistence,
    Web,
    /// A named interface's directory, another module's way in.
    Interface(String),
}

impl Layer {
    fn name(&self) -> String {
        match self {
            Layer::Root => "the root".to_owned(),
            Layer::Internal => "internal".to_owned(),
            Layer::Persistence => "persistence".to_owned(),
            Layer::Web => "web".to_owned(),
            Layer::Interface(name) => format!("the {name} interface"),
        }
    }

    /// A service, in the Java layering: the root's API classes and `internal` are one layer.
    fn is_service(&self) -> bool {
        !matches!(self, Layer::Persistence | Layer::Web)
    }
}

/// The layer a crate-relative module path belongs to.
pub fn layer_of(module_path: &[String], config: &Config, module: &str) -> Layer {
    match module_path.first().map(String::as_str) {
        Some("web") => Layer::Web,
        Some("internal") => Layer::Internal,
        Some("persistence") => Layer::Persistence,
        Some(first) if config.is_interface(module, first) => Layer::Interface(first.to_owned()),
        _ => Layer::Root,
    }
}

/// `src/web/routes.rs` → `["web", "routes"]`; `src/lib.rs` → `[]`; `src/a/mod.rs` → `["a"]`.
fn module_path_of(rel: &str) -> Vec<String> {
    let inside = rel.strip_prefix("src/").unwrap_or(rel);
    let mut parts: Vec<String> = inside.split('/').map(str::to_owned).collect();
    if let Some(last) = parts.pop() {
        let stem = last.strip_suffix(".rs").unwrap_or(&last);
        if stem != "lib" && stem != "mod" && stem != "main" {
            parts.push(stem.to_owned());
        }
    }
    parts
}

enum Resolved {
    Crate(Vec<String>),
    External(Vec<String>),
}

/// A path as written, made absolute: `crate::`, `self::` and `super::` against where the use sits, and a bare
/// first segment that names a child module of it.
fn resolve(modules: &BTreeSet<Vec<String>>, here: &[String], segments: &[String]) -> Resolved {
    let mut current = here.to_vec();
    match segments[0].as_str() {
        "crate" => Resolved::Crate(segments[1..].to_vec()),
        "self" => {
            current.extend(segments[1..].iter().cloned());
            Resolved::Crate(current)
        }
        "super" => {
            let mut skipped = 0;
            while segments.get(skipped).is_some_and(|segment| segment == "super") {
                current.pop();
                skipped += 1;
            }
            current.extend(segments[skipped..].iter().cloned());
            Resolved::Crate(current)
        }
        first => {
            let mut child = current.clone();
            child.push(first.to_owned());
            if modules.contains(&child) {
                child.extend(segments[1..].iter().cloned());
                Resolved::Crate(child)
            } else {
                Resolved::External(segments.to_vec())
            }
        }
    }
}

/// What a read of the workspace's module crates found, so that a green result can say how much it read.
#[derive(Debug, Default)]
pub struct Outcome {
    pub violations: Vec<String>,
    pub crates: usize,
    pub files: usize,
    pub paths: usize,
}

/// Every module crate of `workspace`, checked.
pub fn check_workspace(config: &Config, workspace: &Workspace) -> Outcome {
    let mut outcome = Outcome::default();
    for package in workspace.members() {
        if let Kind::Module(module) = config.classify(&package.name) {
            outcome.crates += 1;
            let one = check_crate(config, &module, &package.dir);
            outcome.files += one.files;
            outcome.paths += one.paths;
            outcome.violations.extend(one.violations);
        }
    }
    outcome.violations.sort();
    outcome
}

/// One module crate, checked.
pub fn check_crate(config: &Config, module: &str, dir: &Path) -> Outcome {
    let krate = config.crate_of(module);
    let (files, errors) = read_package(dir, &["src"]);
    let mut outcome = Outcome { crates: 1, files: files.len(), ..Outcome::default() };
    outcome.violations.extend(errors.into_iter().map(|error| format!("{krate}: unreadable: {error}")));

    let mut modules: BTreeSet<Vec<String>> = BTreeSet::new();
    for file in &files {
        let path = module_path_of(&file.rel);
        modules.insert(path.clone());
        for declared in &file.facts.mods {
            let mut full = path.clone();
            full.extend(declared.parent.iter().cloned());
            full.push(declared.name.clone());
            modules.insert(full);
        }
    }

    for file in &files {
        outcome.violations.extend(check_file(config, module, &krate, file, &modules, &mut outcome.paths));
    }
    outcome
}

fn check_file(
    config: &Config,
    module: &str,
    krate: &str,
    file: &SourceFile,
    modules: &BTreeSet<Vec<String>>,
    paths_read: &mut usize,
) -> Vec<String> {
    let mut violations = Vec::new();
    let here = module_path_of(&file.rel);
    let at = |line: usize| format!("{krate}: {}:{line}", file.rel);

    // everyClassHasAPlace: the places are closed.
    if let Some(first) = here.first() {
        let is_directory = file.rel.trim_start_matches("src/").contains('/');
        let allowed =
            ["web", "internal", "persistence"].contains(&first.as_str()) || config.is_interface(module, first);
        if is_directory && !allowed {
            violations.push(format!(
                "{}: this directory is no layer of a module: a module's places are its root, web, internal, persistence \
                 and its named interfaces",
                at(1)
            ));
        }
    }

    let here_layer = layer_of(&here, config, module);
    let composition_root = file.rel == "src/lib.rs";

    for declared in &file.facts.mods {
        if declared.path_attribute {
            violations.push(format!(
                "{}: #[path] hides where `{}` sits; a module's place is its directory",
                at(declared.line),
                declared.name
            ));
        }
        // The privacy half of the boundary: only the crate root declares these, and not `pub`.
        if declared.parent.is_empty()
            && here.is_empty()
            && declared.public
            && ["web", "internal", "persistence"].contains(&declared.name.as_str())
        {
            violations.push(format!(
                "{}: `pub mod {}` opens a module's private layer to every crate; declare it without `pub` and expose what \
                 other modules need at the root or in a named interface",
                at(declared.line),
                declared.name
            ));
        }
    }

    for used in &file.facts.paths {
        *paths_read += 1;
        violations.extend(check_path(
            config,
            module,
            &at(used.line),
            used,
            &here,
            &here_layer,
            composition_root,
            modules,
        ));
    }
    violations
}

#[allow(clippy::too_many_arguments)]
fn check_path(
    config: &Config,
    module: &str,
    at: &str,
    used: &PathUse,
    file_module: &[String],
    here: &Layer,
    composition_root: bool,
    modules: &BTreeSet<Vec<String>>,
) -> Vec<String> {
    let mut violations = Vec::new();
    let mut here_path = file_module.to_vec();
    here_path.extend(used.inline.iter().cloned());
    let shown = used.segments.join("::");

    match resolve(modules, &here_path, &used.segments) {
        Resolved::Crate(path) => {
            let there = layer_of(&path, config, module);
            // api mayNotBeAccessedByAnyLayer — but a crate has to hand its routes to the application, and the root file
            // is where it does: `pub fn routes() { web::router() }`. That one file may name `web`.
            if there == Layer::Web && *here != Layer::Web && !composition_root {
                violations.push(format!(
                    "{at}: {} names web (`{shown}`): nothing reaches the api layer but the crate's root file",
                    here.name()
                ));
            }
            if *here == Layer::Web && there == Layer::Persistence {
                violations.push(format!("{at}: web names persistence (`{shown}`): a route asks its module's service, which asks the repository"));
            }
            if *here == Layer::Persistence && (there.is_service() || there == Layer::Web) && !path.is_empty() {
                violations.push(format!(
                    "{at}: persistence names {} (`{shown}`): the layer below a service reaches nothing above it",
                    there.name()
                ));
            }
            if *here == Layer::Persistence && path.is_empty() {
                violations.push(format!(
                    "{at}: persistence names the crate root (`{shown}`), which is the service layer's API"
                ));
            }
        }
        Resolved::External(path) => {
            let first = path[0].replace('-', "_");
            if *here == Layer::Web && (QUERY_API.contains(&first.as_str()) || NOT_IN_WEB.contains(&first.as_str())) {
                violations.push(format!(
                    "{at}: web names `{shown}`: a controller holds nothing of the query API or the pool"
                ));
            }
            if here.is_service()
                && first == "vectispire_cp_db"
                && path.get(1).is_some_and(|next| CP_DB_QUERY_VOCABULARY.contains(&next.as_str()))
            {
                violations.push(format!(
                    "{at}: {} names `{shown}`: a service holds no query API — the pool crate's query vocabulary is the repository's",
                    here.name()
                ));
            }
            if here.is_service() && QUERY_API.contains(&first.as_str()) {
                violations.push(format!(
                    "{at}: {} names `{shown}`: a service holds no query API — it hands its repository criteria and the repository writes the query",
                    here.name()
                ));
            }
            if *here == Layer::Persistence && NOT_IN_PERSISTENCE.contains(&first.as_str()) {
                violations.push(format!(
                    "{at}: persistence names `{shown}`: nothing in the persistence layer knows about HTTP"
                ));
            }
            if let Some(other) = first.strip_prefix("vectispire_cp_") {
                let other = other.to_owned();
                // Granularity Cargo cannot see: `access::security` is a named interface, `access` its root.
                if config.module.contains_key(&other) && other != module && config.allows_module(module, &other) {
                    match path.get(1) {
                        Some(next) if config.is_interface(&other, next) => {
                            if !config.allows_interface(module, &other, next) {
                                violations.push(format!(
                                    "{at}: `{shown}` uses {other}'s {next} interface, which {module}'s allowedDependencies do not list ({other}::{next})"
                                ));
                            }
                        }
                        _ => {
                            if !config.allows_root(module, &other) {
                                violations.push(format!(
                                    "{at}: `{shown}` uses {other}'s root, which {module}'s allowedDependencies do not list (only a named interface of {other} is)"
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    violations
}
