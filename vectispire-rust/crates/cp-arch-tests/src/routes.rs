//! Every route says who may call it, and every route over a target's data settles who may see which —
//! `RouteAuthorizationTest` and `AuthorizationCoverageTest`, over the routes the Rust control plane registers.
//!
//! **The shape this reads is the one the HTTP stack's route builder will expose.** `cp-http`'s builder will not
//! register a route without its requirement (a compile-time guarantee, proven there with `trybuild`); this is
//! the second line, run over what was actually registered, because a rule on the way a route is added does not
//! say what the router holds, and the day a registry grows a second way in, this is what notices.
//!
//! **The contract with `cp-http`, kept minimal.** The registry must be able to list, for each route: its method
//! and path, the requirement it declared (`None` if the registry allows an undeclared one), whether it accepts an
//! API key, whether it serves data that belongs to a target, and how it settles who may see it. `cp-http` exposes
//! those as one `descriptors()` iterator; the adapter that maps its type to [`RouteDescriptor`] lives with the
//! application's tests (`cp-app`), which depends on both. This crate depends on neither, so that the boundary
//! tests can be built before the stack they check.
//!
//! The Java test also checked that the role expressions and the `Role` enum agree, because Spring wrote the
//! roles twice (an annotation's expression, an enum's flags). In Rust the requirement is a value derived from
//! the role's flags, so there is one list and nothing to compare.

use std::collections::{BTreeMap, BTreeSet};

pub const ANONYMOUS: &str = include_str!("../data/anonymous-routes.txt");

/// The eight markers of the Java control plane (`AuthorizationMarkers.ALL`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    Administrator,
    PlatformGovernor,
    SecurityLead,
    GovernanceRead,
    WriteAccount,
    Account,
    AgentKey,
    Anonymous,
}

impl Requirement {
    /// Whether every role this requirement admits sees the whole estate by construction, so that it settles
    /// scope on its own (`SCOPE_GUARDS`): administrators, the platform governor, the security lead and governance
    /// readers — not `WriteAccount`, which admits the roles with a restricted scope, and not `Account`.
    ///
    /// **Listed here, derived on the Java side**: `AuthorizationMarkers` reads each marker's `hasAnyRole` and keeps
    /// the markers whose every role has a global scope, and this crate sees no role. `cp-access`'s
    /// `the_scope_guards_are_the_markers_whose_every_role_is_global` holds this list to that derivation, over the
    /// Java markers and flags; it is what found `PlatformGovernor` missing (`SUPERUSER` is global, so Java's set
    /// holds it).
    pub fn settles_scope(&self) -> bool {
        matches!(
            self,
            Requirement::Administrator
                | Requirement::PlatformGovernor
                | Requirement::SecurityLead
                | Requirement::GovernanceRead
        )
    }
}

/// How a route settles who may see what it serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Nothing the route serves belongs to a target, and the entry says why — each is a claim somebody can check,
    /// which is why none of them says "admin".
    NotTargetScoped { reason: String },
    /// A `Visibility` is resolved for the caller and applied in the query.
    Resolved,
    /// The route refuses through the visibility guard, which answers 404 and never 403.
    Refuses404,
    /// Nothing settles it.
    Unsettled,
}

#[derive(Debug, Clone)]
pub struct RouteDescriptor {
    pub method: String,
    pub path: String,
    pub requirement: Option<Requirement>,
    pub accepts_api_key: bool,
    pub names_target: bool,
    pub scope: Scope,
}

impl RouteDescriptor {
    fn label(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

/// The anonymous routes the review has accepted: path → reason.
pub fn parse_anonymous(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut routes = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let (path, reason) =
            line.split_once('|').ok_or_else(|| format!("anonymous-routes.txt: `{line}` has no reason"))?;
        if reason.trim().len() < 10 {
            return Err(format!("anonymous-routes.txt: `{}` has no real reason", path.trim()));
        }
        if routes.insert(path.trim().to_owned(), reason.trim().to_owned()).is_some() {
            return Err(format!("anonymous-routes.txt: {} is listed twice", path.trim()));
        }
    }
    Ok(routes)
}

/// The violations of `routes`. `minimum` is how many routes a registry must hold for the check to have read
/// anything: the guard against the failure mode that let three holes through, a rule that inspected nothing.
pub fn check(routes: &[RouteDescriptor], anonymous: &BTreeMap<String, String>, minimum: usize) -> Vec<String> {
    let mut violations = Vec::new();

    if routes.len() < minimum {
        violations.push(format!(
            "the registry lists {} routes, expected at least {minimum}: the check read too little",
            routes.len()
        ));
    }

    // everyHandlerIsMarked
    for route in routes.iter().filter(|route| route.requirement.is_none()) {
        violations.push(format!(
            "{}: no requirement. A route with none is reachable on whatever the filter chain happens to say",
            route.label()
        ));
    }

    // onlyTheWaysInAreOpen: exactly the listed ones.
    let open: BTreeSet<&str> = routes
        .iter()
        .filter(|route| route.requirement == Some(Requirement::Anonymous))
        .map(|route| route.path.as_str())
        .collect();
    for path in &open {
        if !anonymous.contains_key(*path) {
            violations.push(format!(
                "{path} is open to anonymous callers and anonymous-routes.txt does not list it: a further one is a review conversation"
            ));
        }
    }
    for path in anonymous.keys() {
        if !open.contains(path.as_str()) {
            violations.push(format!(
                "anonymous-routes.txt lists {path}, which no route registers as anonymous: the list is exact"
            ));
        }
    }

    // everyTargetScopedControllerResolvesAnAllowance: never `Account` alone over data that belongs to a target.
    for route in routes {
        if matches!(route.scope, Scope::NotTargetScoped { ref reason } if reason.trim().len() < 10) {
            violations.push(format!("{}: declared not target-scoped without a reason", route.label()));
        }
        if !route.names_target {
            continue;
        }
        let settled = match &route.scope {
            Scope::Resolved | Scope::Refuses404 => true,
            // A role that sees everything is an allowance stated differently — but not where an API key is accepted:
            // a key acts for its account narrowed to its target, which the role does not express.
            Scope::NotTargetScoped { .. } | Scope::Unsettled => {
                route.requirement.as_ref().is_some_and(Requirement::settles_scope) && !route.accepts_api_key
            }
        };
        if !settled {
            violations.push(format!(
                "{}: serves a target's data and settles no scope — {:?} alone does not say whose estate the response describes",
                route.label(),
                route.requirement
            ));
        }
        if matches!(route.scope, Scope::NotTargetScoped { .. }) && route.names_target {
            violations.push(format!("{}: names a target and claims to serve nothing target-scoped", route.label()));
        }
    }

    violations.sort();
    violations
}
