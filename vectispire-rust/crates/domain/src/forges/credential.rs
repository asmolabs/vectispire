//! `ForgeCredential` and `ForgeConnectionRefusal`: what a forge said about a connection's token, judged against the
//! scopes a connection may hold — **an allow-list, not a deny-list**: a scope a forge adds next year is refused until
//! somebody has read what it grants. **Unknown is not "no"**: a GitHub fine-grained token's permissions are not
//! readable, so its scopes and its write access are `None`, not empty and not `false`.

use std::collections::BTreeSet;

use super::ForgeEdition;
use crate::java;

/// Why a connection was refused, as far as a SOC is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The outbound guard refused the address.
    DestinationBlocked,
    /// A scope outside the read-only allow-list, or a credential no connection accepts.
    ScopeRefused,
    /// The forge refused the token: wrong, expired, revoked.
    TokenRejected,
    /// The token lacks what a discovery needs, `read_api` on GitLab.
    ScopeMissing,
    /// The server is older than the oldest version the adapters are written for.
    VersionUnsupported,
    /// The owner a GitHub connection names does not exist, or is not visible with this token.
    OwnerNotFound,
    /// No usable answer: a network failure, a TLS failure, a 5xx, a body that is not the API's.
    Unreachable,
}

impl RefusalReason {
    /// Whether this refusal is signalled to the SIEM as `VECTI-SEC-036`.
    pub const fn signalled(self) -> bool {
        matches!(self, RefusalReason::DestinationBlocked | RefusalReason::ScopeRefused)
    }

    /// The constant's name in lower case, as the audit entry writes it.
    pub const fn lower_name(self) -> &'static str {
        match self {
            RefusalReason::DestinationBlocked => "destination_blocked",
            RefusalReason::ScopeRefused => "scope_refused",
            RefusalReason::TokenRejected => "token_rejected",
            RefusalReason::ScopeMissing => "scope_missing",
            RefusalReason::VersionUnsupported => "version_unsupported",
            RefusalReason::OwnerNotFound => "owner_not_found",
            RefusalReason::Unreachable => "unreachable",
        }
    }
}

/// `ForgeConnectionRefusal`: a connection refused for what its address or its token is — a 400 whose message the
/// form shows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ForgeConnectionRefusal {
    pub reason: RefusalReason,
    pub message: String,
}

impl ForgeConnectionRefusal {
    pub fn new(reason: RefusalReason, message: impl Into<String>) -> ForgeConnectionRefusal {
        ForgeConnectionRefusal { reason, message: message.into() }
    }
}

/// What kind of credential the forge's answers identify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    GithubFineGrained,
    GithubClassic,
    GitlabBot,
    GitlabPersonal,
}

impl CredentialKind {
    pub const fn wire_name(self) -> &'static str {
        match self {
            CredentialKind::GithubFineGrained => "github_fine_grained",
            CredentialKind::GithubClassic => "github_classic",
            CredentialKind::GitlabBot => "gitlab_bot",
            CredentialKind::GitlabPersonal => "gitlab_personal",
        }
    }
}

/// What a GitLab connection must hold.
pub const GITLAB_REQUIRED: &str = "read_api";

/// The GitLab scopes a connection may hold: the read scopes.
pub const GITLAB_ALLOWED: [&str; 4] = ["read_api", "read_repository", "read_registry", "read_user"];

/// The classic GitHub scopes a connection on Enterprise Server may hold; `repo` and `public_repo` write, and are
/// flagged.
pub const GITHUB_CLASSIC_ALLOWED: [&str; 5] = ["repo", "public_repo", "read:org", "read:user", "user:email"];

const GITHUB_CLASSIC_WRITING: [&str; 2] = ["repo", "public_repo"];

/// The judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeCredential {
    pub kind: CredentialKind,
    /// As the forge reported them, sorted; `None` when it reports none.
    pub scopes: Option<Vec<String>>,
    /// Whether the token can write to a repository; `None` when the forge does not say.
    pub can_write: Option<bool>,
}

impl ForgeCredential {
    /// `ForgeCredential.gitlab`: from `GET /personal_access_tokens/self` and `GET /user`.
    pub fn gitlab<'a>(
        scopes: impl IntoIterator<Item = Option<&'a str>>,
        bot: bool,
    ) -> Result<ForgeCredential, ForgeConnectionRefusal> {
        let held = normalised(scopes);
        let refused: Vec<&str> =
            held.iter().map(String::as_str).filter(|scope| !GITLAB_ALLOWED.contains(scope)).collect();
        if !refused.is_empty() {
            return Err(ForgeConnectionRefusal::new(
                RefusalReason::ScopeRefused,
                format!(
                    "GitLab reports this token with the scope(s) {}, which a connection may not hold: it lists \
                     repositories and needs read_api alone. Create a token with read_api only — a group access \
                     token, role Reporter, is preferred.",
                    refused.join(", ")
                ),
            ));
        }
        if !held.contains(GITLAB_REQUIRED) {
            return Err(ForgeConnectionRefusal::new(
                RefusalReason::ScopeMissing,
                "This token lacks the read_api scope, without which GitLab lists no group and no project.",
            ));
        }
        Ok(ForgeCredential {
            kind: if bot { CredentialKind::GitlabBot } else { CredentialKind::GitlabPersonal },
            scopes: Some(held.into_iter().collect()),
            can_write: Some(false),
        })
    }

    /// `ForgeCredential.github`: from the `X-OAuth-Scopes` header of an authenticated answer — absent for a
    /// fine-grained token, present (possibly empty) for a classic one, accepted on Enterprise Server alone.
    pub fn github(
        edition: ForgeEdition,
        oauth_scopes: Option<&str>,
    ) -> Result<ForgeCredential, ForgeConnectionRefusal> {
        let Some(header) = oauth_scopes else {
            return Ok(ForgeCredential { kind: CredentialKind::GithubFineGrained, scopes: None, can_write: None });
        };
        let held = normalised(header.split(',').map(Some));
        if edition.cloud() {
            return Err(ForgeConnectionRefusal::new(
                RefusalReason::ScopeRefused,
                format!(
                    "This is a classic token, which {} does not accept for a connection: the only classic scope that \
                     lists private repositories, repo, can also write to every one of them. Create a fine-grained \
                     token for the owner with the permission Metadata: read, and nothing else.",
                    edition.label()
                ),
            ));
        }
        let refused: Vec<&str> =
            held.iter().map(String::as_str).filter(|scope| !GITHUB_CLASSIC_ALLOWED.contains(scope)).collect();
        if !refused.is_empty() {
            return Err(ForgeConnectionRefusal::new(
                RefusalReason::ScopeRefused,
                format!(
                    "GitHub reports this classic token with the scope(s) {}, which a connection may not hold. Use a \
                     token with repo (or public_repo) and read:org only.",
                    refused.join(", ")
                ),
            ));
        }
        let writes = held.iter().any(|scope| GITHUB_CLASSIC_WRITING.contains(&scope.as_str()));
        Ok(ForgeCredential {
            kind: CredentialKind::GithubClassic,
            scopes: Some(held.into_iter().collect()),
            can_write: Some(writes),
        })
    }
}

/// Trimmed, lower-cased, blanks dropped, sorted as a `TreeSet<String>` sorts — by UTF-16 unit.
fn normalised<'a>(scopes: impl IntoIterator<Item = Option<&'a str>>) -> BTreeSet<String> {
    // Java's TreeSet orders by `String.compareTo` (UTF-16 units); the scopes are ASCII, where both orders agree.
    scopes
        .into_iter()
        .map(|scope| java::to_lower_root(java::trim(scope.unwrap_or(""))))
        .filter(|scope| !scope.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitlab_read_scopes_are_accepted_and_a_bot_preferred() {
        let credential = ForgeCredential::gitlab([Some("read_repository"), Some(" READ_API ")], true).unwrap();
        assert_eq!(credential.kind, CredentialKind::GitlabBot);
        assert_eq!(credential.scopes, Some(vec!["read_api".to_owned(), "read_repository".to_owned()]));
        assert_eq!(credential.can_write, Some(false));
        assert_eq!(ForgeCredential::gitlab([Some("read_api")], false).unwrap().kind, CredentialKind::GitlabPersonal);
    }

    #[test]
    fn gitlab_write_scopes_are_refused_and_signalled() {
        let refused =
            ForgeCredential::gitlab([Some("read_api"), Some("api"), Some("write_repository")], true).unwrap_err();
        assert_eq!(refused.reason, RefusalReason::ScopeRefused);
        assert!(refused.reason.signalled());
        assert!(refused.message.contains("api, write_repository"), "{}", refused.message);
        let missing = ForgeCredential::gitlab([Some("read_repository")], true).unwrap_err();
        assert_eq!(missing.reason, RefusalReason::ScopeMissing);
        assert!(!missing.reason.signalled());
    }

    #[test]
    fn github_fine_grained_is_unknown_not_no() {
        let credential = ForgeCredential::github(ForgeEdition::GithubCom, None).unwrap();
        assert_eq!(
            credential,
            ForgeCredential { kind: CredentialKind::GithubFineGrained, scopes: None, can_write: None }
        );
    }

    #[test]
    fn github_classic_only_on_enterprise_server_and_flagged() {
        assert_eq!(
            ForgeCredential::github(ForgeEdition::GithubCom, Some("read:org")).unwrap_err().reason,
            RefusalReason::ScopeRefused
        );
        let classic = ForgeCredential::github(ForgeEdition::GithubEnterpriseServer, Some("repo, read:org")).unwrap();
        assert_eq!(classic.can_write, Some(true));
        assert_eq!(classic.scopes, Some(vec!["read:org".to_owned(), "repo".to_owned()]));
        let empty = ForgeCredential::github(ForgeEdition::GithubEnterpriseServer, Some("")).unwrap();
        assert_eq!((empty.scopes, empty.can_write), (Some(vec![]), Some(false)));
        let admin = ForgeCredential::github(ForgeEdition::GithubEnterpriseServer, Some("repo, admin:org")).unwrap_err();
        assert!(admin.message.contains("admin:org"));
    }
}
