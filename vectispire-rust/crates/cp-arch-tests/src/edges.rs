//! Which crate may depend on which — Spring Modulith's `verify()`, on `cargo metadata`.
//!
//! Modulith fails the Java build on a cycle, on a reach into another module's internals, and on a dependency
//! the module's `package-info` does not list (`ModularityTest`). The reach into internals is Rust's own
//! privacy; the other two are here, with what `ArchitectureTest` adds around them: `core.config` sits under
//! every module, `common.domain` is pure, and nothing the agent links may be control-plane code.

use std::collections::BTreeSet;

use crate::graph::Workspace;
use crate::model::{Config, Kind, Status, UsesModules};

/// Crates that a pure calculation must not link, as Java's `domainIsPure`: a framework, a driver, the Docker
/// client, the async runtime. A calculation that needs one stops being testable without it.
pub const NOT_PURE: &[&str] = &[
    "sqlx",
    "sqlx-core",
    "sea-query",
    "sea-query-binder",
    "diesel",
    "tokio-postgres",
    "postgres",
    "mysql",
    "mysql_async",
    "axum",
    "actix-web",
    "tower",
    "hyper",
    "bollard",
    "reqwest",
    "tokio",
    "async-std",
];

/// Every violation of the edge list in `workspace`.
pub fn check(config: &Config, workspace: &Workspace) -> Vec<String> {
    let mut violations = Vec::new();

    for package in workspace.members() {
        let kind = config.classify(&package.name);
        let linked: Vec<_> = workspace.linked_members(package).collect();

        match &kind {
            Kind::UnknownControlPlane => violations.push(format!(
                "{}: a control-plane crate that edges.toml does not list. A new module is a decision for the review: \
                 add it there, with its allowed edges, before its crate",
                package.name
            )),
            Kind::Module(module) => {
                let entry = &config.module[module];
                let mut used = BTreeSet::new();
                for dependency in &linked {
                    match config.classify(&dependency.name) {
                        Kind::Module(other) => {
                            if &other == module {
                                continue;
                            }
                            if !config.allows_module(module, &other) {
                                violations.push(format!(
                                    "{module} depends on {other}, which its allowedDependencies in edges.toml do not list"
                                ));
                            }
                            used.insert(other);
                        }
                        Kind::Infrastructure(name) => {
                            if !config.infrastructure[&name].used_by_modules {
                                violations.push(format!(
                                    "{module} depends on {}: infrastructure no module may use (it composes modules, or \
                                     reads them); only the binary does",
                                    dependency.name
                                ));
                            }
                        }
                        Kind::UnknownControlPlane => {
                            violations.push(format!("{module} depends on {}, which edges.toml does not list", dependency.name));
                        }
                        Kind::Agent => violations.push(format!("{module} depends on the agent's binary")),
                        Kind::Testkit => violations
                            .push(format!("{module} depends on test support through a normal dependency: it belongs in [dev-dependencies]")),
                        Kind::Other => violations.push(format!(
                            "{module} depends on {}, a workspace crate that is not in `shared` in edges.toml",
                            dependency.name
                        )),
                        Kind::Shared => {}
                    }
                }
                // Modulith: "a line nothing uses". Held only for a module whose port is finished — a pending one is
                // held to the ceiling, as a module being moved was in step 4 of the Java migration.
                if entry.status == Status::Ported && !entry.open {
                    for allowed in config.allowed_modules(module) {
                        if !used.contains(&allowed) {
                            violations.push(format!(
                                "{module} lists {allowed} in edges.toml and its crate does not depend on it: a line nothing uses"
                            ));
                        }
                    }
                }
            }
            Kind::Infrastructure(name) => {
                let infra = &config.infrastructure[name];
                for dependency in &linked {
                    match config.classify(&dependency.name) {
                        Kind::Module(other) => {
                            let allowed = match &infra.uses_modules {
                                UsesModules::All(_) => true,
                                UsesModules::Some(list) => list.contains(&other),
                            };
                            if !allowed {
                                violations.push(format!(
                                    "{} depends on module {other}: infrastructure sits under every module and uses none \
                                     (core.config, in Java)",
                                    package.name
                                ));
                            }
                        }
                        Kind::Infrastructure(other) if other == "app" => {
                            violations.push(format!("{} depends on the binary", package.name));
                        }
                        Kind::Agent => violations.push(format!("{} depends on the agent's binary", package.name)),
                        _ => {}
                    }
                }
            }
            Kind::Agent | Kind::Testkit | Kind::Shared | Kind::Other => {
                for dependency in &linked {
                    if matches!(
                        config.classify(&dependency.name),
                        Kind::Module(_) | Kind::Infrastructure(_) | Kind::UnknownControlPlane
                    ) {
                        violations.push(format!(
                            "{} links {}: control-plane code is never a dependency of the agent or of what the two share",
                            package.name, dependency.name
                        ));
                    }
                }
            }
        }
    }

    for cycle in workspace.cycles() {
        violations.push(format!("a dependency cycle between crates: {}", cycle.join(", ")));
    }

    for pure in &config.settings.pure {
        if let Some(closure) = workspace.linked_names(pure) {
            let found: Vec<&str> = NOT_PURE.iter().copied().filter(|name| closure.contains(*name)).collect();
            if !found.is_empty() {
                violations.push(format!("{pure} is a pure crate and links {found:?}: no framework, driver or runtime"));
            }
        } else {
            violations.push(format!("{pure} is listed as pure in edges.toml and is not in the workspace"));
        }
    }

    for (module, entry) in &config.module {
        let name = config.crate_of(module);
        if entry.status == Status::Ported && workspace.member(&name).is_none() {
            violations.push(format!("{module} is `ported` in edges.toml and the workspace has no crate {name}"));
        }
    }

    violations.sort();
    violations.dedup();
    violations
}
