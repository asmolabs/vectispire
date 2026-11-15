//! `GitHostAllowlist`: the forges an installation may clone from (`vectispire.git.allowed-hosts`), `*.` for a
//! domain's subdomains. Empty is unrestricted — **but never Vectispire's own endpoints, listed or not.** The Docker
//! daemon, the database and the cluster's API are refused to every other outbound door (`OutboundUrlGuard`); a
//! repository URL naming one was cloned from — by the built-in worker, inside the control plane, on the database's
//! network — until Java's allow-list asked the guard too. The port had left that question out (Phase 2 security
//! review, 2026-11): [`GitHostAllowlist::refusing`] puts it back, asked first, on the URL's entry and before each scan.

use std::sync::Arc;

use crate::repository_url::{self, InvalidHost};

/// `GitHostAllowlist.Reserved`: why a host and port are one of Vectispire's own endpoints, or `None`.
pub type Reserved = dyn Fn(&str, i32) -> Option<String> + Send + Sync;

#[derive(Clone, Default)]
pub struct GitHostAllowlist {
    pub entries: Vec<String>,
    /// Absent where nothing is reserved — a test's list, or the guard not composed.
    reserved: Option<Arc<Reserved>>,
}

impl std::fmt::Debug for GitHostAllowlist {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitHostAllowlist")
            .field("entries", &self.entries)
            .field("reserved", &self.reserved.is_some())
            .finish()
    }
}

impl GitHostAllowlist {
    /// `parse`: comma-separated, each entry trimmed, lower-cased and normalized as a token's host is; an entry that
    /// is not a host refuses the whole list, at start, rather than letting it allow nothing it was meant to.
    pub fn parse(configured: Option<&str>) -> Result<GitHostAllowlist, InvalidHost> {
        let mut entries: Vec<String> = Vec::new();
        for raw in configured.unwrap_or("").split(',') {
            let entry = crate::java::to_lower_root(crate::java::trim(raw));
            if entry.is_empty() {
                continue;
            }
            let normalized = match entry.strip_prefix("*.") {
                Some(domain) => format!("*.{}", repository_url::normalize_host(domain)?),
                None => repository_url::normalize_host(&entry)?,
            };
            if !entries.contains(&normalized) {
                entries.push(normalized);
            }
        }
        Ok(GitHostAllowlist { entries, reserved: None })
    }

    /// `refusing`: the same list, refusing the endpoints `reserved` names as well.
    #[must_use]
    pub fn refusing(self, reserved: Arc<Reserved>) -> GitHostAllowlist {
        GitHostAllowlist { reserved: Some(reserved), ..self }
    }

    /// Why the URL names one of Vectispire's own endpoints: asked of its host and of the port the clone would use.
    fn reserved_reason(&self, url: &str) -> Option<String> {
        let reserved = self.reserved.as_ref()?;
        let (host, port) = (repository_url::host(url)?, repository_url::port(url)?);
        reserved(&host, port)
    }

    pub fn restricts(&self) -> bool {
        !self.entries.is_empty()
    }

    /// `permits`: never a reserved endpoint; otherwise unrestricted, or the URL's host — normalized; one that cannot
    /// be is refused — equal to an entry, or ending with a `*.` entry's domain.
    pub fn permits(&self, url: &str) -> bool {
        if self.reserved_reason(url).is_some() {
            return false;
        }
        if !self.restricts() {
            return true;
        }
        let host = match repository_url::host(url).map(|host| repository_url::normalize_host(&host)) {
            Some(Ok(host)) => host,
            Some(Err(_)) | None => return false,
        };
        self.entries.iter().any(|entry| match entry.strip_prefix('*') {
            Some(suffix) if entry.starts_with("*.") => host.ends_with(suffix),
            _ => host == *entry,
        })
    }

    /// `refusal`: the sentence a refused URL is answered with, naming the endpoint or the allowed hosts.
    pub fn refusal(&self, url: &str) -> String {
        if let Some(endpoint) = self.reserved_reason(url) {
            return endpoint;
        }
        format!(
            "Cloning from {} is not allowed on this instance; allowed hosts: {}.",
            repository_url::host(url).unwrap_or_else(|| "this host".to_owned()),
            self.entries.join(", ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RepositoryUrl.port`'s answers: the SCP form's 22, a written port, else the scheme's own.
    #[test]
    fn the_port_a_clone_connects_to() {
        for (url, port) in [
            ("git@gitlab.example.org:group/x.git", Some(22)),
            ("ssh://gitlab.example.org/x.git", Some(22)),
            ("ssh://gitlab.example.org:2222/x.git", Some(2222)),
            ("https://gitlab.example.org/x.git", Some(443)),
            ("https://gitlab.example.org:8443/x.git", Some(8443)),
            ("http://gitlab.example.org/x.git", Some(80)),
            ("git://gitlab.example.org/x", Some(9418)),
            ("not a url", None),
        ] {
            assert_eq!(repository_url::port(url), port, "{url}");
        }
    }

    /// Asked first, listed or not, and named in the refusal; asked with the host and the port the clone would use.
    #[test]
    fn a_reserved_endpoint_is_refused_before_the_list_is_read() {
        let reserved: Arc<Reserved> = Arc::new(|host: &str, port: i32| {
            (host == "mysql" && port == 3306).then(|| "mysql:3306 is the database".to_owned())
        });
        let open = GitHostAllowlist::parse(None).unwrap().refusing(reserved.clone());
        assert!(!open.permits("ssh://mysql:3306/x.git"));
        assert_eq!(open.refusal("ssh://mysql:3306/x.git"), "mysql:3306 is the database");
        assert!(open.permits("ssh://mysql:22/x.git"));
        let listed = GitHostAllowlist::parse(Some("mysql")).unwrap().refusing(reserved);
        assert!(!listed.permits("ssh://mysql:3306/x.git"));
        assert!(listed.permits("ssh://mysql/x.git"));
        assert_eq!(
            listed.refusal("https://other.example/x.git"),
            "Cloning from other.example is not allowed on this instance; allowed hosts: mysql."
        );
    }
}
