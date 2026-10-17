//! `RepositoryIdentity`: one repository, on one branch, under one sub-path — the target a filing names, and the
//! guard (V73) a unique index holds so that it is filed once.

use crate::{fingerprint, java, repository_url};

/// What a repository target is, whatever URL spells it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepositoryIdentity {
    /// `host/path`, as [`repository_url::identity`] writes it.
    pub repository: String,
    /// `main` when none is given — what the clone falls back to.
    pub branch: String,
    /// Trimmed, without its trailing slashes; empty for the root.
    pub sub_path: String,
}

impl RepositoryIdentity {
    /// `RepositoryIdentity.of`: `None` when the URL names no host. A blank branch (`isBlank`) is `main`, another
    /// is `String.trim`-med; the sub-path is read leniently — `trim`, then its trailing `/` — because the rows the
    /// keying reaches predate the sub-path's validation.
    pub fn of(url: &str, branch: Option<&str>, sub_path: Option<&str>) -> Option<RepositoryIdentity> {
        let repository = repository_url::identity(url)?;
        let branch = match branch {
            Some(branch) if !java::is_blank(branch) => java::trim(branch).to_owned(),
            _ => "main".to_owned(),
        };
        let sub_path = java::trim(sub_path.unwrap_or("")).trim_end_matches('/').to_owned();
        Some(RepositoryIdentity { repository, branch, sub_path })
    }

    /// `guard`: `Digests.sha256Fields(repository, branch, subPath)` — the value `t_repository.identity_guard`'s
    /// unique index compares, so it is Java's byte for byte or the two control planes disagree about a twin.
    pub fn guard(&self) -> String {
        fingerprint::sha256_fields(&[Some(&self.repository), Some(&self.branch), Some(&self.sub_path)])
    }
}
