//! `ForgeAddress`: where a forge connection's requests go — the web address an administrator copied from the browser,
//! and the API root derived from it.
//!
//! **The web address, not the API's**: an API path typed anyway is refused with the address to type instead rather
//! than doubled into `/api/v4/api/v4`. **`https` only**: a token over `http` on an internal network is still a token
//! on the wire. A URL carrying credentials, a query or a fragment is refused.

use super::{ForgeEdition, ForgeKind};
use crate::bounded_text::Refused;
use crate::java;
use crate::repository_url::{self, java_uri};

/// The column's width; a forge's address is a host and a short prefix, far below it.
pub const MAX_LENGTH: usize = 512;

/// `^(?:api\.)?([a-z0-9][a-z0-9-]{0,62})\.ghe\.com$`: the subdomain of a data-residency host, written by hand.
fn data_residency(host: &str) -> Option<&str> {
    let label = |text: &str| {
        let bytes = text.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes.first().is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
            && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    };
    let rest = host.strip_suffix(".ghe.com")?;
    match rest.strip_prefix("api.") {
        Some(subdomain) if label(subdomain) => Some(subdomain),
        _ if label(rest) => Some(rest),
        _ => None,
    }
}

const CREDENTIAL: &str =
    "The address carries a user name or a token: type the address alone, the token has a field of its own.";

/// The address, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeAddress {
    pub edition: ForgeEdition,
    /// The web address, trailing slashes trimmed, the host in lower case, a path prefix kept.
    pub base_url: String,
    /// The REST API's root, no trailing slash.
    pub api_root: String,
}

impl ForgeAddress {
    fn new(edition: ForgeEdition, base_url: impl Into<String>, api_root: impl Into<String>) -> ForgeAddress {
        ForgeAddress { edition, base_url: base_url.into(), api_root: api_root.into() }
    }

    /// `ForgeAddress.of`: reads the address an administrator typed; blank for the vendor's cloud.
    pub fn of(kind: ForgeKind, typed: Option<&str>) -> Result<ForgeAddress, Refused> {
        let value = java::trim(typed.unwrap_or(""));
        if value.is_empty() {
            return Ok(match kind {
                ForgeKind::Github => {
                    ForgeAddress::new(ForgeEdition::GithubCom, "https://github.com", "https://api.github.com")
                }
                ForgeKind::Gitlab => {
                    ForgeAddress::new(ForgeEdition::GitlabCom, "https://gitlab.com", "https://gitlab.com/api/v4")
                }
            });
        }
        if java::utf16_len(value) > MAX_LENGTH {
            return Err(Refused(format!("The address is longer than {MAX_LENGTH} characters.")));
        }
        if repository_url::carries_credential(value) {
            return Err(Refused(CREDENTIAL.into()));
        }
        let Ok(uri) = java_uri::parse(value) else {
            return Err(Refused("The address is not a readable URL.".into()));
        };
        let scheme = java::to_lower_root(uri.scheme.as_deref().unwrap_or(""));
        if scheme != "https" {
            return Err(Refused(
                "The address must start with https:// — the token would otherwise cross the network in the clear."
                    .into(),
            ));
        }
        if uri.raw_user_info.is_some() {
            return Err(Refused(CREDENTIAL.into()));
        }
        if uri.raw_query.is_some() || uri.raw_fragment.is_some() {
            return Err(Refused(
                "The address carries a query or a fragment: type the forge's web address alone.".into(),
            ));
        }
        let mut host = java::to_lower_root(uri.host.as_deref().unwrap_or(""));
        while host.ends_with('.') {
            host.pop();
        }
        if host.is_empty() {
            return Err(Refused("The address has no host.".into()));
        }
        let mut path = uri.raw_path.clone().unwrap_or_default();
        while path.ends_with('/') {
            path.pop();
        }
        let lower_path = java::to_lower_root(&path);
        if lower_path.ends_with("/api/v3")
            || lower_path.ends_with("/api/v4")
            || lower_path.contains("/api/v3/")
            || lower_path.contains("/api/v4/")
        {
            return Err(Refused(
                "Type the forge's web address — what the browser shows — not its API's: the API path is added here."
                    .into(),
            ));
        }
        // `URI.getHost` hands an IPv6 literal back in its brackets already.
        let origin = format!(
            "https://{host}{}",
            uri.port.filter(|port| *port > 0).map(|port| format!(":{port}")).unwrap_or_default()
        );
        Ok(match kind {
            ForgeKind::Github => github(&host, &origin, &path),
            ForgeKind::Gitlab => gitlab(&host, &origin, &path),
        })
    }
}

fn github(host: &str, origin: &str, path: &str) -> ForgeAddress {
    if matches!(host, "github.com" | "www.github.com" | "api.github.com") {
        return ForgeAddress::new(ForgeEdition::GithubCom, "https://github.com", "https://api.github.com");
    }
    if let Some(subdomain) = data_residency(host) {
        return ForgeAddress::new(
            ForgeEdition::GithubDataResidency,
            format!("https://{subdomain}.ghe.com"),
            format!("https://api.{subdomain}.ghe.com"),
        );
    }
    // Enterprise Server answers its API under the web address, at /api/v3.
    ForgeAddress::new(ForgeEdition::GithubEnterpriseServer, format!("{origin}{path}"), format!("{origin}{path}/api/v3"))
}

fn gitlab(host: &str, origin: &str, path: &str) -> ForgeAddress {
    if matches!(host, "gitlab.com" | "www.gitlab.com") {
        return ForgeAddress::new(ForgeEdition::GitlabCom, "https://gitlab.com", "https://gitlab.com/api/v4");
    }
    // Self-managed GitLab may live under a relative URL root; the API is under it.
    ForgeAddress::new(ForgeEdition::GitlabSelfManaged, format!("{origin}{path}"), format!("{origin}{path}/api/v4"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_edition_and_the_api() {
        let cases = [
            (ForgeKind::Github, "", ForgeEdition::GithubCom, "https://github.com", "https://api.github.com"),
            (
                ForgeKind::Github,
                "https://github.com/",
                ForgeEdition::GithubCom,
                "https://github.com",
                "https://api.github.com",
            ),
            (
                ForgeKind::Github,
                "https://acme.ghe.com",
                ForgeEdition::GithubDataResidency,
                "https://acme.ghe.com",
                "https://api.acme.ghe.com",
            ),
            (
                ForgeKind::Github,
                "https://api.acme.ghe.com/",
                ForgeEdition::GithubDataResidency,
                "https://acme.ghe.com",
                "https://api.acme.ghe.com",
            ),
            (
                ForgeKind::Github,
                "https://Git.Example.org//",
                ForgeEdition::GithubEnterpriseServer,
                "https://git.example.org",
                "https://git.example.org/api/v3",
            ),
            (ForgeKind::Gitlab, "", ForgeEdition::GitlabCom, "https://gitlab.com", "https://gitlab.com/api/v4"),
            (
                ForgeKind::Gitlab,
                "https://gitlab.com",
                ForgeEdition::GitlabCom,
                "https://gitlab.com",
                "https://gitlab.com/api/v4",
            ),
            (
                ForgeKind::Gitlab,
                "https://example.org/gitlab/",
                ForgeEdition::GitlabSelfManaged,
                "https://example.org/gitlab",
                "https://example.org/gitlab/api/v4",
            ),
            (
                ForgeKind::Gitlab,
                "https://gitlab.internal:8443",
                ForgeEdition::GitlabSelfManaged,
                "https://gitlab.internal:8443",
                "https://gitlab.internal:8443/api/v4",
            ),
            (
                ForgeKind::Gitlab,
                "https://[::1]:8443/",
                ForgeEdition::GitlabSelfManaged,
                "https://[::1]:8443",
                "https://[::1]:8443/api/v4",
            ),
        ];
        for (kind, typed, edition, base, api) in cases {
            let address = ForgeAddress::of(kind, Some(typed)).unwrap();
            assert_eq!(
                (address.edition, address.base_url.as_str(), address.api_root.as_str()),
                (edition, base, api),
                "{typed}"
            );
            assert_eq!(ForgeAddress::of(kind, Some(&address.base_url)).unwrap(), address, "{typed} derives the same");
        }
    }

    #[test]
    fn refuses_what_is_not_a_web_address() {
        for typed in [
            "http://gitlab.example.org",
            "https://user:secret@gitlab.example.org",
            "https://oauth2@gitlab.example.org",
            "https://gitlab.example.org/api/v4",
            "https://gitlab.example.org/gitlab/api/v4/",
            "https://gitlab.example.org/api/v4/projects",
            "https://gitlab.example.org/?private_token=x",
            "https://gitlab.example.org/#top",
            "gitlab.example.org",
            "https://",
        ] {
            assert!(ForgeAddress::of(ForgeKind::Gitlab, Some(typed)).is_err(), "{typed}");
        }
        let http = ForgeAddress::of(ForgeKind::Github, Some("http://git.example.org")).unwrap_err().0;
        assert!(http.contains("https://") && http.contains("in the clear"));
        let api = ForgeAddress::of(ForgeKind::Gitlab, Some("https://gitlab.example.org/api/v4")).unwrap_err().0;
        assert!(api.contains("web address"));
    }
}
