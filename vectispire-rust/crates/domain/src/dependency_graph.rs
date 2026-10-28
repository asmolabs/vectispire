//! `DependencyGraph` and `Directness`: which dependencies the project actually asked for.
//!
//! Syft's SBOM carries `dependency-of` relationships whose *parent* is the dependency: a package that is
//! never a parent is a root of the graph — "the project declared this". **With no edge at all, every
//! answer is unknown**: some catalogers emit none, and then every package would look like a root, labelling
//! a whole image "direct" — a confident wrong answer on the field meant to decide what to fix first.
//!
//! Read as Jackson's `asText(null)` reads the document (a number or a boolean is its text, an object `""`),
//! held to `reference/vocabulary/`.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::java;

/// Whether the project asked for a dependency, or something else dragged it in.
///
/// Three states, and [`Directness::Unknown`] is the one that matters: an `Option<bool>` spells the same
/// three, but nothing stops a caller reading absence as `false` — "we do not know" turned into
/// "transitive", on the very field meant to decide what to fix first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Directness {
    /// Declared in the project's own manifest: fixable this afternoon by changing one line.
    Direct,
    /// Pulled in by something else: waits on an upstream release, a pin, a fork or an accepted risk.
    Transitive,
    /// The SBOM did not say. Not a synonym for [`Directness::Transitive`].
    Unknown,
}

impl Directness {
    /// `Directness.of(boolean)`.
    pub fn of(direct: bool) -> Directness {
        if direct { Directness::Direct } else { Directness::Transitive }
    }

    /// The label in exports and tickets — empty, not "unknown", when nothing is known: a column filled
    /// with the word reads as a finding about the dependency.
    pub fn label(self) -> &'static str {
        match self {
            Directness::Direct => "direct",
            Directness::Transitive => "transitive",
            Directness::Unknown => "",
        }
    }
}

/// The directness of every package an SBOM lists, by purl and by name and version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyGraph {
    by_purl: HashMap<String, bool>,
    by_name_and_version: HashMap<String, bool>,
    available: bool,
}

const DEPENDENCY_OF: &str = "dependency-of";

impl DependencyGraph {
    /// `new DependencyGraph(sbom)`.
    pub fn new(sbom: Option<&Value>) -> DependencyGraph {
        let artifacts = match java::path(sbom, "artifacts") {
            Some(Value::Array(artifacts)) if !artifacts.is_empty() => artifacts,
            _ => return DependencyGraph::default(),
        };
        let mut depended_upon = HashSet::new();
        if let Some(Value::Array(relationships)) = java::path(sbom, "artifactRelationships") {
            for relation in relationships {
                if java::as_text(java::path(Some(relation), "type"), None).as_deref() == Some(DEPENDENCY_OF)
                    && let Some(parent) =
                        java::as_text(java::path(Some(relation), "parent"), None).filter(|p| !p.is_empty())
                {
                    depended_upon.insert(parent);
                }
            }
        }
        if depended_upon.is_empty() {
            return DependencyGraph::default();
        }
        let mut graph = DependencyGraph { available: true, ..DependencyGraph::default() };
        for artifact in artifacts {
            let field = |name: &str, default: Option<&str>| java::as_text(java::path(Some(artifact), name), default);
            let direct = field("id", None).is_some_and(|id| !depended_upon.contains(&id));
            // A purl carries the version, so two versions of one package keep distinct answers — one may be
            // declared and the other dragged in. The same package listed twice is direct if either says so.
            if let Some(purl) = field("purl", None).filter(|purl| !purl.is_empty()) {
                *graph.by_purl.entry(purl).or_insert(false) |= direct;
            }
            if let Some(name) = field("name", None).filter(|name| !name.is_empty()) {
                let version = field("version", Some("")).unwrap_or_default();
                *graph.by_name_and_version.entry(key(&name, &version)).or_insert(false) |= direct;
            }
        }
        graph
    }

    /// Did the graph carry any edge at all? If not, every answer is [`Directness::Unknown`].
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// `DependencyGraph.of`: the purl first — the ecosystem-qualified identity the vulnerability matches —
    /// then name and version. **Never the name alone**: two versions of one package can fall on either side,
    /// and a name-only match would be a coin toss on a field an operator prioritises by.
    pub fn of(&self, purl: Option<&str>, name: Option<&str>, version: Option<&str>) -> Directness {
        if !self.available {
            return Directness::Unknown;
        }
        if let Some(direct) = purl.filter(|purl| !purl.is_empty()).and_then(|purl| self.by_purl.get(purl)) {
            return Directness::of(*direct);
        }
        if let Some(direct) = name
            .filter(|name| !name.is_empty())
            .and_then(|name| self.by_name_and_version.get(&key(name, version.unwrap_or(""))))
        {
            return Directness::of(*direct);
        }
        Directness::Unknown
    }

    /// How many purls are direct — for the log, and for reassurance about the graph.
    pub fn direct_count(&self) -> usize {
        self.by_purl.values().filter(|direct| **direct).count()
    }
}

fn key(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}
