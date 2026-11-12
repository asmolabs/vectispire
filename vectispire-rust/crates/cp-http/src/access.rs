//! What a route requires of its caller, and which routes the chain lets through without a credential.
//!
//! **A role marker is not authorization**, and AGENTS.md says why it is the mistake made most often here: a
//! marker proves the caller is signed in, not whose estate the response describes. This module is the marker half
//! (`@RequiresAccount`, `@RequiresAdministrator`, …). The other half — resolving a `Visibility` and passing it to the
//! query — is why [`crate::routes`] makes a route say how it handles visibility before it can be registered.

use crate::principal::Role;

/// The role requirement of one route: the `@Requires*` marker the Java controller carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// `@OpenToAnonymous` — reachable with no credential at all (sign-in, the methods list, a badge).
    Anonymous,
    /// `@RequiresAccount` — any authenticated principal.
    Account,
    /// `@RequiresAdministrator` — `SUPERUSER`, `ADMIN`.
    Administrator,
    /// `@RequiresGovernanceRead` — `SUPERUSER`, `ADMIN`, `CISO`, `AUDITOR`.
    GovernanceRead,
    /// `@RequiresPlatformGovernor` — `SUPERUSER`.
    PlatformGovernor,
    /// `@RequiresSecurityLead` — `SUPERUSER`, `ADMIN`, `CISO`.
    SecurityLead,
    /// `@RequiresWriteAccount` — `ADMIN`, `CISO`, `SECURITY_CHAMPION`, `USER`.
    WriteAccount,
    /// `@RequiresAgentKey` — an agent's key, and nothing else. Not a role: an agent has none.
    AgentKey,
}

impl Access {
    /// Whether a principal with this role (or none) is admitted. An unreadable role admits nothing — not even
    /// `Account`'s "any authenticated principal" is decided here, it is decided by there being a principal.
    pub fn admits(self, role: Option<Role>) -> bool {
        let Some(role) = role else { return false };
        match self {
            Access::Anonymous | Access::Account => true,
            Access::Administrator => matches!(role, Role::Superuser | Role::Admin),
            Access::GovernanceRead => matches!(role, Role::Superuser | Role::Admin | Role::Ciso | Role::Auditor),
            Access::PlatformGovernor => matches!(role, Role::Superuser),
            Access::SecurityLead => matches!(role, Role::Superuser | Role::Admin | Role::Ciso),
            Access::WriteAccount => matches!(role, Role::Admin | Role::Ciso | Role::SecurityChampion | Role::User),
            Access::AgentKey => false,
        }
    }

    /// The Java marker's name, for the route table a coverage test walks.
    pub fn marker(self) -> &'static str {
        match self {
            Access::Anonymous => "OpenToAnonymous",
            Access::Account => "RequiresAccount",
            Access::Administrator => "RequiresAdministrator",
            Access::GovernanceRead => "RequiresGovernanceRead",
            Access::PlatformGovernor => "RequiresPlatformGovernor",
            Access::SecurityLead => "RequiresSecurityLead",
            Access::WriteAccount => "RequiresWriteAccount",
            Access::AgentKey => "RequiresAgentKey",
        }
    }
}

/// What the chain's `authorizeHttpRequests` decides about a request before any route is looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// `permitAll`.
    Open,
    /// `authenticated()`: a credential that resolved, or 401.
    Authenticated,
    /// An administrator's **session** — not an agent key, not an integration key, not a session that still owes a
    /// password change — for the actuator endpoints beyond `health`.
    AdministratorSession,
}

/// `springdoc`'s three paths, matched on the prefix: it appends group names and a trailing config path a literal
/// list would miss, and `/v3/api-docs/swagger-config` is the one that leaves the UI blank when only it is refused.
fn is_api_documentation(path: &str) -> bool {
    path.starts_with("/v3/api-docs") || path.starts_with("/swagger-ui") || path == "/swagger-ui.html"
}

/// Ant's `/prefix/**`: the prefix itself and everything below it.
fn under(path: &str, prefix: &str) -> bool {
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

/// A path of exactly one segment whose name ends with `suffix` (`/*.js`).
fn one_segment_ending(path: &str, suffix: &str) -> bool {
    path.strip_prefix('/').is_some_and(|name| !name.is_empty() && !name.contains('/') && name.ends_with(suffix))
}

/// `^/(?!api/|actuator/|scim/)[^.]*$` — the SPA's deep links: not under `/api`, `/actuator` or `/scim` and with no
/// dot, so an unmapped API path stays a 404 the caller can act on and a lost `.js` stays a 404 and not an HTML page
/// the browser reports as a syntax error.
pub fn is_spa_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("/api/")
        && !path.starts_with("/actuator/")
        && !path.starts_with("/scim/")
        && !path.contains('.')
}

/// The chain's access rules, in the order `SecurityConfiguration.apiSecurity` lists them; the first match decides.
pub fn gate(method: &str, path: &str, anonymous_api_docs: bool) -> Gate {
    let get = method.eq_ignore_ascii_case("GET");
    if matches!(
        path,
        "/api/v1/auth/login" | "/api/v1/auth/methods" | "/api/v1/auth/session/exchange" | "/api/v1/auth/mfa/verify"
    ) {
        // The first two are pre-authentication by construction, `exchange` trades a one-time cookie for the
        // session it stands for, and `mfa/verify` is called with the `mfa_token` step 1 returned and no bearer.
        return Gate::Open;
    }
    if under(path, "/api/v1/agent") || under(path, "/api/v1/tickets/webhook") || under(path, "/actuator/health") {
        return Gate::Open;
    }
    if under(path, "/actuator") {
        return Gate::AdministratorSession;
    }
    if is_api_documentation(path) {
        return if anonymous_api_docs { Gate::Open } else { Gate::Authenticated };
    }
    if get {
        let badge = path
            .strip_prefix("/api/v1/scorecards/badges/")
            .is_some_and(|name| name.ends_with(".svg") && !name.contains('/'));
        if path == "/api/v1/crypto/public-key.pub" || badge {
            return Gate::Open;
        }
        // The interface itself is not behind the token: it is the files that ask for one.
        let interface = matches!(path, "/" | "/index.html" | "/favicon.ico")
            || one_segment_ending(path, ".js")
            || one_segment_ending(path, ".css")
            || one_segment_ending(path, ".webmanifest")
            || under(path, "/assets")
            || under(path, "/fonts")
            || under(path, "/media")
            || under(path, "/i18n");
        if interface || is_spa_path(path) {
            return Gate::Open;
        }
    }
    Gate::Authenticated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_marker_admits_the_roles_the_java_marker_names() {
        use Role::*;
        let all = [Superuser, Admin, Ciso, SecurityChampion, Auditor, User];
        let admitted =
            |access: Access| all.iter().copied().filter(|role| access.admits(Some(*role))).collect::<Vec<_>>();
        assert_eq!(admitted(Access::Administrator), [Superuser, Admin]);
        assert_eq!(admitted(Access::GovernanceRead), [Superuser, Admin, Ciso, Auditor]);
        assert_eq!(admitted(Access::PlatformGovernor), [Superuser]);
        assert_eq!(admitted(Access::SecurityLead), [Superuser, Admin, Ciso]);
        assert_eq!(admitted(Access::WriteAccount), [Admin, Ciso, SecurityChampion, User]);
        assert_eq!(admitted(Access::Account), all);
        assert!(admitted(Access::AgentKey).is_empty(), "an agent key is not a role");
    }

    #[test]
    fn an_unreadable_role_authorizes_nothing() {
        for access in [Access::Account, Access::Administrator, Access::WriteAccount, Access::SecurityLead] {
            assert!(!access.admits(None), "{access:?}");
        }
    }

    #[test]
    fn the_routes_open_to_anyone_are_the_ones_the_java_chain_names() {
        for (method, path) in [
            ("POST", "/api/v1/auth/login"),
            ("DELETE", "/api/v1/auth/login"),
            ("GET", "/api/v1/auth/methods"),
            ("POST", "/api/v1/auth/session/exchange"),
            ("POST", "/api/v1/auth/mfa/verify"),
            ("GET", "/api/v1/agent/jobs"),
            ("POST", "/api/v1/agent/jobs/3/result"),
            ("POST", "/api/v1/tickets/webhook/abc"),
            ("GET", "/actuator/health"),
            ("GET", "/actuator/health/liveness"),
            ("GET", "/api/v1/crypto/public-key.pub"),
            ("GET", "/api/v1/scorecards/badges/abc.svg"),
            ("GET", "/"),
            ("GET", "/index.html"),
            ("GET", "/main-ABC.js"),
            ("GET", "/styles.css"),
            ("GET", "/ngsw.webmanifest"),
            ("GET", "/assets/logo.svg"),
            ("GET", "/fonts/a.woff2"),
            ("GET", "/media/a.png"),
            ("GET", "/i18n/en.json"),
            ("GET", "/projects"),
            ("GET", "/projects/1/checklist"),
            ("GET", "/api"),
        ] {
            assert_eq!(gate(method, path, false), Gate::Open, "{method} {path}");
        }
    }

    #[test]
    fn everything_else_needs_a_credential() {
        for (method, path) in [
            ("GET", "/api/v1/repositories"),
            ("POST", "/api/v1/repositories"),
            ("GET", "/api/v1/nothing-here"),
            // A path with a dot is not a deep link: a lost script is a 401 for the anonymous, then a 404.
            ("GET", "/missing.png"),
            ("HEAD", "/main-ABC.js"),
            ("POST", "/projects"),
            // `/actuator2` is a dotless segment outside `/actuator/`: a deep link, as the Java regex has it.
            ("GET", "/scim/v2/Users"),
            ("GET", "/api/v1/scorecards/badges/a/b.svg"),
            ("GET", "/js/app.js"),
        ] {
            assert_eq!(gate(method, path, false), Gate::Authenticated, "{method} {path}");
        }
    }

    #[test]
    fn the_actuator_beyond_health_is_an_administrators_session() {
        assert_eq!(gate("GET", "/actuator/metrics", false), Gate::AdministratorSession);
        assert_eq!(gate("GET", "/actuator/info", false), Gate::AdministratorSession);
        assert_eq!(gate("GET", "/actuator", false), Gate::AdministratorSession);
        assert_eq!(gate("GET", "/actuator/healthy", false), Gate::AdministratorSession);
    }

    #[test]
    fn the_api_documentation_is_closed_unless_somebody_opened_it() {
        for path in ["/v3/api-docs", "/v3/api-docs/swagger-config", "/swagger-ui/index.html", "/swagger-ui.html"] {
            assert_eq!(gate("GET", path, false), Gate::Authenticated, "{path}");
            assert_eq!(gate("GET", path, true), Gate::Open, "{path}");
        }
    }

    #[test]
    fn spa_paths_are_the_dotless_ones_outside_api_actuator_and_scim() {
        assert!(is_spa_path("/projects"));
        assert!(is_spa_path("/api"));
        assert!(is_spa_path("/"));
        assert!(!is_spa_path("/api/v1/x"));
        assert!(!is_spa_path("/actuator/metrics"));
        assert!(!is_spa_path("/scim/v2"));
        assert!(!is_spa_path("/a.b"));
    }
}
