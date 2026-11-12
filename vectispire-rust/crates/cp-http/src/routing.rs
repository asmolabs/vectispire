//! How a request's path is read before anything routes it: the path a limiter matches on, and the two refusals
//! of a URL that is not one this server accepts.
//!
//! **The path a limiter reads is not the path the router reads.** `routedPath` is what the Java filters match
//! their limits on: split at `/`, each segment cut at a `;` (a path parameter), percent-decoded, empty segments
//! dropped. A limiter that matched on the raw text would let `/api/v1/auth;x=1/login` or `/api/v1/auth/%6Cogin` walk
//! past the budget of `/api/v1/auth/login` while the router, which reads it the other way, still serves the login.

use http::StatusCode;
use percent_encoding::percent_decode_str;

use crate::problem::Problem;

/// `/a//b;p=1/%6Cogin` → `/a/b/login`.
pub fn routed_path(raw_path: &str) -> String {
    let mut routed = String::new();
    for segment in raw_path.split('/') {
        let name = segment.split(';').next().unwrap_or("");
        let decoded = percent_decode_str(name).decode_utf8_lossy();
        if !decoded.is_empty() {
            routed.push('/');
            routed.push_str(&decoded);
        }
    }
    routed
}

/// The URL is one the server refuses to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The firewall's: `//`, an encoded or doubled traversal, a `;`, a control character.
    Firewall,
    /// The container's, before the application: a `%` not followed by two hex digits, an encoded `/` or `\`.
    Container,
    /// The container's too, but for a target it could not even parse (a raw `\`): it has no path to name, so the
    /// problem carries no `instance` (`firewall-raw-backslash`).
    Unparsed,
}

const FIREWALL: &str = "The request was refused: its URL contains a sequence this server does not accept — a doubled or encoded separator, an encoded traversal, a ';' or a control character.";
const CONTAINER: &str = "The request was refused before it reached the application: its URL could not be decoded (a % must be followed by two hexadecimal digits, and an encoded / is not accepted), or the request was otherwise malformed.";

impl Refusal {
    /// The refusal as the chain answers it: **no security headers** — it is written before they are set, as the
    /// Java container and firewall write theirs (`firewall-*` goldens).
    pub fn problem(self, raw_path: &str) -> Problem {
        let detail = match self {
            Refusal::Firewall => FIREWALL,
            Refusal::Container | Refusal::Unparsed => CONTAINER,
        };
        let problem = Problem::chain(StatusCode::BAD_REQUEST, detail);
        if self == Refusal::Unparsed { problem } else { problem.at(raw_path) }
    }
}

/// Judges a raw request path. `None` is accepted.
pub fn judge(raw_path: &str) -> Option<Refusal> {
    let bytes = raw_path.as_bytes();
    // The container first: it sees the bytes before the firewall does. A raw backslash is refused there too
    // (`firewall-raw-backslash`), with the container's sentence and not the firewall's.
    if bytes.contains(&b'\\') {
        return Some(Refusal::Unparsed);
    }
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let (Some(high), Some(low)) = (bytes.get(index.saturating_add(1)), bytes.get(index.saturating_add(2)))
            else {
                return Some(Refusal::Container);
            };
            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return Some(Refusal::Container);
            }
            // An encoded `/` or `\` is refused by the container, not tolerated and decoded.
            let encoded = [high.to_ascii_lowercase(), low.to_ascii_lowercase()];
            if encoded == *b"2f" || encoded == *b"5c" {
                return Some(Refusal::Container);
            }
            index = index.saturating_add(3);
        } else {
            index = index.saturating_add(1);
        }
    }
    firewall(raw_path)
}

/// Spring Security's `StrictHttpFirewall`, with its defaults — as far as they were measured: a `%01` or a UTF-8 escape is *not*
/// refused (`firewall-control-character`, `firewall-non-ascii`: both reach the chain and are answered 401).
fn firewall(raw_path: &str) -> Option<Refusal> {
    let lower = raw_path.to_ascii_lowercase();
    // Doubled separator, a path parameter, an encoded period / semicolon / percent, a backslash.
    if raw_path.contains("//")
        || raw_path.contains(';')
        || lower.contains("%2e")
        || lower.contains("%3b")
        || lower.contains("%25")
    {
        return Some(Refusal::Firewall);
    }
    let decoded = percent_decode_str(raw_path).decode_utf8_lossy();
    // Not normalised: a `.` or `..` segment.
    if decoded.split('/').any(|segment| segment == "." || segment == "..") {
        return Some(Refusal::Firewall);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_routed_path_drops_parameters_decodes_and_collapses() {
        assert_eq!(routed_path("/api/v1/auth/login"), "/api/v1/auth/login");
        assert_eq!(routed_path("/api/v1/auth;x=1/login"), "/api/v1/auth/login");
        assert_eq!(routed_path("/api/v1//auth/%6Cogin"), "/api/v1/auth/login");
        assert_eq!(routed_path("/"), "");
        assert_eq!(routed_path("/api/v1/auth/login/"), "/api/v1/auth/login");
    }

    #[test]
    fn the_four_urls_the_java_server_refused_in_the_goldens_are_refused_the_same_way() {
        assert_eq!(judge("/api/v1//projects"), Some(Refusal::Firewall));
        assert_eq!(judge("/api/v1/projects;x=1"), Some(Refusal::Firewall));
        assert_eq!(judge("/api/v1/%2e%2e/projects"), Some(Refusal::Firewall));
        assert_eq!(judge("/api/v1/projects%2Fx"), Some(Refusal::Container));
    }

    #[test]
    fn a_broken_escape_is_the_containers_refusal() {
        assert_eq!(judge("/api/v1/%zz"), Some(Refusal::Container));
        assert_eq!(judge("/api/v1/%4"), Some(Refusal::Container));
        assert_eq!(judge("/api/v1/%5C"), Some(Refusal::Container));
    }

    #[test]
    fn what_the_strict_firewall_refuses_by_default_is_refused() {
        assert_eq!(judge("/api/v1/a%25b"), Some(Refusal::Firewall));
        assert_eq!(judge("/api/v1/a%3Bb"), Some(Refusal::Firewall));
        assert_eq!(
            judge("/api/v1/a\\b"),
            Some(Refusal::Unparsed),
            "a raw backslash is the container's, with no path to name"
        );
        assert_eq!(judge("/api/v1/a%01b"), None, "a decoded control character is not refused, measured");
        assert_eq!(judge("/api/v1/a%C3%A9b"), None, "nor a UTF-8 escape");
        assert_eq!(judge("/api/v1/./projects"), Some(Refusal::Firewall));
        assert_eq!(judge("/api/v1/../projects"), Some(Refusal::Firewall));
    }

    #[test]
    fn ordinary_paths_pass() {
        assert_eq!(judge("/"), None);
        assert_eq!(judge("/api/v1/projects/12"), None);
        assert_eq!(judge("/api/v1/auth/%6Cogin"), None);
        assert_eq!(judge("/i18n/en.json"), None);
        assert_eq!(judge("/assets/a.b.c.js"), None);
    }

    #[test]
    fn the_refusals_are_written_by_the_chain_and_name_the_path_as_sent() {
        let problem = Refusal::Firewall.problem("/api/v1//projects");
        assert_eq!(problem.instance(), Some("/api/v1//projects"));
        assert!(problem.detail().starts_with("The request was refused: its URL contains a sequence"));
        assert!(
            Refusal::Container
                .problem("/x")
                .detail()
                .starts_with("The request was refused before it reached the application")
        );
    }
}
