//! The edge list, read: which crate is which, and what each module may use.
//!
//! `data/edges.toml` is Spring Modulith's `@ApplicationModule(allowedDependencies)` of the Java control plane
//! (decision 0030), written once for all twenty-eight modules and checked in, so that a new dependency
//! between two modules is a line in a reviewed file and not a `[dependencies]` entry nobody noticed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

/// The checked-in file, as the tests read it.
pub const EDGES: &str = include_str!("../data/edges.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub settings: Settings,
    #[serde(default)]
    pub infrastructure: BTreeMap<String, Infrastructure>,
    #[serde(default)]
    pub module: BTreeMap<String, Module>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub module_prefix: String,
    /// The crates a module may depend on besides other modules and the infrastructure.
    pub shared: Vec<String>,
    /// The crates that stay free of frameworks and drivers.
    pub pure: Vec<String>,
    #[serde(default)]
    pub unsafe_allowed: Vec<UnsafeAllowed>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsafeAllowed {
    #[serde(rename = "crate")]
    pub krate: String,
    pub file: String,
    pub max: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Infrastructure {
    #[serde(rename = "crate")]
    pub krate: String,
    pub uses_modules: UsesModules,
    pub used_by_modules: bool,
}

/// `[]` for the infrastructure that sits under every module, `"all"` for the binary that composes them.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum UsesModules {
    All(String),
    Some(Vec<String>),
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    Ported,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Module {
    pub status: Status,
    pub allowed: Vec<String>,
    #[serde(default)]
    pub open: bool,
    #[serde(default)]
    pub interfaces: Vec<String>,
}

/// What a workspace member is, to the rules.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Kind {
    /// A module's crate: `vectispire-cp-<module>`.
    Module(String),
    /// A control-plane crate that is not a module: the pool, the HTTP stack, the binary.
    Infrastructure(String),
    /// Carries the control plane's prefix and is in neither list: a module added without the review.
    UnknownControlPlane,
    /// The remote agent's binary.
    Agent,
    /// Test support, which no production crate may depend on.
    Testkit,
    /// A crate the agent port and the control plane share.
    Shared,
    /// Any other member of the workspace.
    Other,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(text).map_err(|error| format!("edges.toml: {error}"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        Self::parse(&text)
    }

    /// The crate of a module.
    pub fn crate_of(&self, module: &str) -> String {
        format!("{}{module}", self.settings.module_prefix)
    }

    /// What a package name is to the rules.
    pub fn classify(&self, package: &str) -> Kind {
        if let Some(module) = package.strip_prefix(&self.settings.module_prefix) {
            if self.module.contains_key(module) {
                return Kind::Module(module.to_owned());
            }
            if let Some((name, _)) = self.infrastructure.iter().find(|(_, infra)| infra.krate == package) {
                return Kind::Infrastructure(name.clone());
            }
            return Kind::UnknownControlPlane;
        }
        match package {
            "vectispire-agent" => Kind::Agent,
            "vectispire-testkit" => Kind::Testkit,
            _ if self.settings.shared.iter().any(|shared| shared == package) => Kind::Shared,
            _ => Kind::Other,
        }
    }

    /// The modules a module's list names, interfaces folded into their module.
    pub fn allowed_modules(&self, module: &str) -> BTreeSet<String> {
        self.module
            .get(module)
            .map(|m| m.allowed.iter().map(|entry| entry.split("::").next().unwrap_or(entry).to_owned()).collect())
            .unwrap_or_default()
    }

    /// May `from` use `to`'s root (the crate's own `pub` items)?
    pub fn allows_root(&self, from: &str, to: &str) -> bool {
        self.module.get(from).is_some_and(|m| m.open || m.allowed.iter().any(|entry| entry == to))
    }

    /// May `from` use `to`'s named interface?
    pub fn allows_interface(&self, from: &str, to: &str, interface: &str) -> bool {
        let entry = format!("{to}::{interface}");
        self.module.get(from).is_some_and(|m| m.open || m.allowed.contains(&entry))
    }

    /// May `from` depend on `to` at all, through any of its entries?
    pub fn allows_module(&self, from: &str, to: &str) -> bool {
        self.module.get(from).is_some_and(|m| m.open) || self.allowed_modules(from).contains(to)
    }

    /// Is `name` one of `module`'s named interfaces?
    pub fn is_interface(&self, module: &str, name: &str) -> bool {
        self.module.get(module).is_some_and(|m| m.interfaces.iter().any(|interface| interface == name))
    }

    /// The module edges as a graph, `open` modules aside (they list nothing, and may use anything).
    fn declared_edges(&self) -> BTreeMap<&str, BTreeSet<String>> {
        self.module.keys().map(|module| (module.as_str(), self.allowed_modules(module))).collect()
    }

    /// The modules in an order where each comes after everything it may use: the order the port goes in.
    /// A cycle in the list itself is an error: the dependency order the plan builds on would not exist.
    pub fn porting_order(&self) -> Result<Vec<String>, String> {
        let edges = self.declared_edges();
        let mut order = Vec::new();
        let mut state: BTreeMap<&str, u8> = BTreeMap::new();
        fn visit<'a>(
            module: &'a str,
            edges: &'a BTreeMap<&str, BTreeSet<String>>,
            state: &mut BTreeMap<&'a str, u8>,
            order: &mut Vec<String>,
            stack: &mut Vec<String>,
        ) -> Result<(), String> {
            match state.get(module) {
                Some(2) => return Ok(()),
                Some(1) => {
                    stack.push(module.to_owned());
                    return Err(format!("a cycle in edges.toml: {}", stack.join(" -> ")));
                }
                _ => {}
            }
            state.insert(module, 1);
            stack.push(module.to_owned());
            for next in edges.get(module).into_iter().flatten() {
                visit(next, edges, state, order, stack)?;
            }
            stack.pop();
            state.insert(module, 2);
            order.push(module.to_owned());
            Ok(())
        }
        for module in edges.keys() {
            visit(module, &edges, &mut state, &mut order, &mut Vec::new())?;
        }
        Ok(order)
    }

    /// The list's own consistency: every name is a module, every `x::y` names an interface x exposes, nothing
    /// lists itself, the list has no cycle, and a ported module has its crate's name free of a clash.
    fn validate(&self) -> Result<(), String> {
        let mut problems = Vec::new();
        for (module, entry) in &self.module {
            for allowed in &entry.allowed {
                let (target, interface) = match allowed.split_once("::") {
                    Some((target, interface)) => (target, Some(interface)),
                    None => (allowed.as_str(), None),
                };
                if target == module {
                    problems.push(format!("{module} lists itself"));
                }
                match self.module.get(target) {
                    None => problems.push(format!("{module} lists {allowed}: no module {target}")),
                    Some(owner) => {
                        if let Some(interface) = interface
                            && !owner.interfaces.iter().any(|name| name == interface)
                        {
                            problems.push(format!("{module} lists {allowed}, which {target} does not expose"));
                        }
                    }
                }
            }
            if entry.open && !entry.allowed.is_empty() {
                problems.push(format!("{module} is open and lists modules: an open module lists none"));
            }
        }
        for (name, infra) in &self.infrastructure {
            if infra.krate != format!("{}{name}", self.settings.module_prefix) {
                problems
                    .push(format!("infrastructure {name}: its crate is {}, not the prefix and its name", infra.krate));
            }
            if self.module.contains_key(name) {
                problems.push(format!("{name} is both a module and infrastructure"));
            }
            if let UsesModules::All(word) = &infra.uses_modules
                && word != "all"
            {
                problems.push(format!("infrastructure {name}: uses_modules is a list or \"all\", not {word:?}"));
            }
        }
        if let Err(cycle) = self.porting_order() {
            problems.push(cycle);
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(format!("edges.toml is inconsistent:\n  {}", problems.join("\n  ")))
        }
    }
}
