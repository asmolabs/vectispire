//! `GitHostAllowlist`: the forges an installation may clone from (`vectispire.git.allowed-hosts`), `*.` for a
//! domain's subdomains. Empty is unrestricted.

use crate::repository_url::{self, InvalidHost};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GitHostAllowlist {
    pub entries: Vec<String>,
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
        Ok(GitHostAllowlist { entries })
    }

    pub fn restricts(&self) -> bool {
        !self.entries.is_empty()
    }

    /// `permits`: unrestricted, or the URL's host — normalized; one that cannot be is refused — equal to an entry,
    /// or ending with a `*.` entry's domain.
    pub fn permits(&self, url: &str) -> bool {
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

    /// `refusal`: the sentence a refused URL is answered with, naming the allowed hosts.
    pub fn refusal(&self, url: &str) -> String {
        format!(
            "Cloning from {} is not allowed on this instance; allowed hosts: {}.",
            repository_url::host(url).unwrap_or_else(|| "this host".to_owned()),
            self.entries.join(", ")
        )
    }
}
