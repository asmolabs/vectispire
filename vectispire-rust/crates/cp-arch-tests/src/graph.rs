//! The workspace's resolved dependency graph, read from `cargo metadata`.
//!
//! The same source of truth as `crates/agent/tests/isolation.rs`: the resolved graph, not the manifests, so a
//! dependency pulled in through a feature or a transitive crate is seen.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepKind {
    Normal,
    Build,
    Dev,
}

#[derive(Debug, Clone)]
pub struct Package {
    pub id: String,
    pub name: String,
    /// The directory holding the package's `Cargo.toml`.
    pub dir: PathBuf,
    pub member: bool,
    /// `(package id, kinds)`, one entry per resolved dependency.
    pub deps: Vec<(String, BTreeSet<DepKind>)>,
}

#[derive(Debug)]
pub struct Workspace {
    packages: BTreeMap<String, Package>,
}

impl Workspace {
    /// Reads the graph of the workspace whose manifest is given. `locked` for the real workspace, `offline`
    /// for the synthetic ones the tests build out of path-only crates.
    pub fn load(manifest: &Path, locked: bool) -> Result<Self, String> {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let mut command = Command::new(cargo);
        command.args(["metadata", "--format-version", "1"]);
        command.arg(if locked { "--locked" } else { "--offline" });
        command.arg("--manifest-path").arg(manifest);
        let output = command.output().map_err(|error| format!("cargo metadata did not start: {error}"))?;
        if !output.status.success() {
            return Err(format!("cargo metadata failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
        Self::from_metadata(&json)
    }

    pub fn from_metadata(json: &serde_json::Value) -> Result<Self, String> {
        let members: BTreeSet<&str> = json["workspace_members"]
            .as_array()
            .ok_or("no workspace_members")?
            .iter()
            .filter_map(|id| id.as_str())
            .collect();
        let mut packages = BTreeMap::new();
        for package in json["packages"].as_array().ok_or("no packages")? {
            let id = package["id"].as_str().ok_or("a package without an id")?.to_owned();
            let manifest = package["manifest_path"].as_str().ok_or("a package without a manifest")?;
            packages.insert(
                id.clone(),
                Package {
                    name: package["name"].as_str().ok_or("a package without a name")?.to_owned(),
                    dir: Path::new(manifest).parent().map(Path::to_path_buf).unwrap_or_default(),
                    member: members.contains(id.as_str()),
                    deps: Vec::new(),
                    id,
                },
            );
        }
        for node in json["resolve"]["nodes"].as_array().ok_or("no resolve graph")? {
            let id = node["id"].as_str().ok_or("a node without an id")?;
            let mut deps = Vec::new();
            for dep in node["deps"].as_array().into_iter().flatten() {
                let kinds = dep["dep_kinds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|kind| match kind["kind"].as_str() {
                        Some("dev") => DepKind::Dev,
                        Some("build") => DepKind::Build,
                        _ => DepKind::Normal,
                    })
                    .collect();
                deps.push((dep["pkg"].as_str().ok_or("a dependency without a package")?.to_owned(), kinds));
            }
            if let Some(package) = packages.get_mut(id) {
                package.deps = deps;
            }
        }
        Ok(Self { packages })
    }

    pub fn members(&self) -> impl Iterator<Item = &Package> {
        self.packages.values().filter(|package| package.member)
    }

    pub fn package(&self, id: &str) -> Option<&Package> {
        self.packages.get(id)
    }

    /// A member by name. Member names are unique in a workspace.
    pub fn member(&self, name: &str) -> Option<&Package> {
        self.members().find(|package| package.name == name)
    }

    /// The members `package` depends on through a normal or build dependency: what it links, as opposed to
    /// what its tests use.
    pub fn linked_members<'a>(&'a self, package: &'a Package) -> impl Iterator<Item = &'a Package> {
        package
            .deps
            .iter()
            .filter(|(_, kinds)| kinds.iter().any(|kind| *kind != DepKind::Dev))
            .filter_map(|(id, _)| self.package(id))
            .filter(|dependency| dependency.member)
    }

    /// Every package `root` links, itself included, by name: the closure of its normal and build dependencies.
    pub fn linked_names(&self, root: &str) -> Option<BTreeSet<String>> {
        let start = self.member(root)?;
        let mut seen = BTreeSet::new();
        let mut pending = vec![start.id.as_str()];
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(package) = self.package(id) {
                for (dependency, kinds) in &package.deps {
                    if kinds.iter().any(|kind| *kind != DepKind::Dev) {
                        pending.push(dependency);
                    }
                }
            }
        }
        Some(seen.into_iter().filter_map(|id| self.package(id)).map(|package| package.name.clone()).collect())
    }

    /// The cycles among the members' linked dependencies, one list of names per strongly connected component.
    /// Dev-dependencies are left out: Cargo allows a crate and its test support to refer to each other, and
    /// Modulith verifies main code only.
    pub fn cycles(&self) -> Vec<Vec<String>> {
        let ids: Vec<&str> = self.members().map(|package| package.id.as_str()).collect();
        let edges: BTreeMap<&str, Vec<&str>> = self
            .members()
            .map(|package| {
                (package.id.as_str(), self.linked_members(package).map(|dependency| dependency.id.as_str()).collect())
            })
            .collect();
        // Tarjan, written iteratively would be longer than the recursion on a few dozen crates.
        struct State<'a> {
            index: BTreeMap<&'a str, usize>,
            low: BTreeMap<&'a str, usize>,
            on_stack: BTreeSet<&'a str>,
            stack: Vec<&'a str>,
            counter: usize,
            components: Vec<Vec<&'a str>>,
        }
        fn connect<'a>(node: &'a str, edges: &BTreeMap<&'a str, Vec<&'a str>>, state: &mut State<'a>) {
            state.index.insert(node, state.counter);
            state.low.insert(node, state.counter);
            state.counter += 1;
            state.stack.push(node);
            state.on_stack.insert(node);
            for next in edges.get(node).into_iter().flatten() {
                if !state.index.contains_key(next) {
                    connect(next, edges, state);
                    let low = state.low[node].min(state.low[next]);
                    state.low.insert(node, low);
                } else if state.on_stack.contains(next) {
                    let low = state.low[node].min(state.index[next]);
                    state.low.insert(node, low);
                }
            }
            if state.low[node] == state.index[node] {
                let mut component = Vec::new();
                while let Some(top) = state.stack.pop() {
                    state.on_stack.remove(top);
                    component.push(top);
                    if top == node {
                        break;
                    }
                }
                state.components.push(component);
            }
        }
        let mut state = State {
            index: BTreeMap::new(),
            low: BTreeMap::new(),
            on_stack: BTreeSet::new(),
            stack: Vec::new(),
            counter: 0,
            components: Vec::new(),
        };
        for id in &ids {
            if !state.index.contains_key(id) {
                connect(id, &edges, &mut state);
            }
        }
        let mut cycles: Vec<Vec<String>> = state
            .components
            .into_iter()
            .filter(|component| {
                component.len() > 1
                    || component.first().is_some_and(|id| edges.get(id).is_some_and(|next| next.contains(id)))
            })
            .map(|component| {
                let mut names: Vec<String> =
                    component.iter().filter_map(|id| self.package(id)).map(|package| package.name.clone()).collect();
                names.sort();
                names
            })
            .collect();
        cycles.sort();
        cycles
    }
}
