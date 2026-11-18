//! Forges (decision 0037) — `common.domain.forges`: what a forge connection is, what a forge said about its token,
//! what a discovery found, and how a selection and an import read it. Shared with no other module today, kept here as
//! Java keeps it in `vectispire-common`, so that the tracker integration (`TokenExpiry`) and the checklists read the
//! same words when they are ported.

pub mod address;
pub mod credential;
pub mod discovery;
pub mod expiry;
pub mod mapping;
pub mod selection;

pub use address::ForgeAddress;
pub use credential::{CredentialKind, ForgeConnectionRefusal, ForgeCredential, RefusalReason};
pub use discovery::{DiscoveredRepository, DiscoveryReason, DiscoveryState, ImportSkip, UnreadableNamespace};

use crate::bounded_text::Refused;

/// `ForgeKind`: the forges a connection may name. Bitbucket is lot D8's, and a value it would add is refused until
/// then rather than stored for an adapter that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ForgeKind {
    Github,
    Gitlab,
}

impl ForgeKind {
    pub const ALL: [ForgeKind; 2] = [ForgeKind::Github, ForgeKind::Gitlab];

    pub const fn wire_name(self) -> &'static str {
        match self {
            ForgeKind::Github => "github",
            ForgeKind::Gitlab => "gitlab",
        }
    }

    /// `ForgeKind.parse`: read from a request or a row, refused in words.
    pub fn parse(value: Option<&str>) -> Result<ForgeKind, Refused> {
        let wanted = crate::java::to_lower_root(crate::java::trim(value.unwrap_or("")));
        ForgeKind::ALL.into_iter().find(|kind| kind.wire_name() == wanted).ok_or_else(|| {
            Refused(format!(
                "The forge must be one of {}.",
                ForgeKind::ALL.iter().map(|kind| kind.wire_name()).collect::<Vec<_>>().join(", ")
            ))
        })
    }

    /// `Integration.of(ForgeKind).key()`: the registry's key of its forge.
    pub fn integration_key(self) -> String {
        format!("forge.{}", self.wire_name())
    }
}

/// `ForgeEdition`: which deployment of a forge a connection speaks to — derived from the address typed, never chosen
/// apart from it. A cloud edition has a fixed host nobody types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForgeEdition {
    GithubCom,
    GithubDataResidency,
    GithubEnterpriseServer,
    GitlabCom,
    GitlabSelfManaged,
}

impl ForgeEdition {
    pub const ALL: [ForgeEdition; 5] = [
        ForgeEdition::GithubCom,
        ForgeEdition::GithubDataResidency,
        ForgeEdition::GithubEnterpriseServer,
        ForgeEdition::GitlabCom,
        ForgeEdition::GitlabSelfManaged,
    ];

    pub const fn kind(self) -> ForgeKind {
        match self {
            ForgeEdition::GithubCom | ForgeEdition::GithubDataResidency | ForgeEdition::GithubEnterpriseServer => {
                ForgeKind::Github
            }
            ForgeEdition::GitlabCom | ForgeEdition::GitlabSelfManaged => ForgeKind::Gitlab,
        }
    }

    /// Whether the vendor runs it: a fixed public host, public CAs, no internal network.
    pub const fn cloud(self) -> bool {
        matches!(self, ForgeEdition::GithubCom | ForgeEdition::GithubDataResidency | ForgeEdition::GitlabCom)
    }

    /// How a sentence names it.
    pub const fn label(self) -> &'static str {
        match self {
            ForgeEdition::GithubCom => "github.com",
            ForgeEdition::GithubDataResidency => "GitHub Enterprise Cloud with data residency",
            ForgeEdition::GithubEnterpriseServer => "GitHub Enterprise Server",
            ForgeEdition::GitlabCom => "gitlab.com",
            ForgeEdition::GitlabSelfManaged => "GitLab self-managed or Dedicated",
        }
    }

    /// The value on the wire: lower case, the constant's name.
    pub const fn wire_name(self) -> &'static str {
        match self {
            ForgeEdition::GithubCom => "github_com",
            ForgeEdition::GithubDataResidency => "github_data_residency",
            ForgeEdition::GithubEnterpriseServer => "github_enterprise_server",
            ForgeEdition::GitlabCom => "gitlab_com",
            ForgeEdition::GitlabSelfManaged => "gitlab_self_managed",
        }
    }

    /// `ForgeEdition.valueOf(stored.toUpperCase())`: a stored value read back; `None` for one this version does not
    /// know, which is a fault of the row.
    pub fn of_stored(stored: &str) -> Option<ForgeEdition> {
        ForgeEdition::ALL.into_iter().find(|edition| edition.wire_name() == crate::java::to_lower_root(stored))
    }
}

/// `ForgeConnectionState`: derived from the integrations' registry at every read, never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgeConnectionState {
    Active,
    Suspended,
}

impl ForgeConnectionState {
    pub const fn wire_name(self) -> &'static str {
        match self {
            ForgeConnectionState::Active => "active",
            ForgeConnectionState::Suspended => "suspended",
        }
    }

    pub const fn of(integration_enabled: bool) -> ForgeConnectionState {
        if integration_enabled { ForgeConnectionState::Active } else { ForgeConnectionState::Suspended }
    }
}

/// `ForgeVersion`: the oldest server each adapter is written for.
pub mod version {
    use super::ForgeEdition;

    /// GitLab 16: the keyset pagination and the token self-inspection the adapter relies on.
    pub const GITLAB_MINIMUM_MAJOR: i64 = 16;
    /// GitHub Enterprise Server 3.12.
    pub const GHES_MINIMUM_MAJOR: i64 = 3;
    pub const GHES_MINIMUM_MINOR: i64 = 12;

    /// `ForgeVersion.tooOld`: whether a reported version is too old; `None` when it could not be read — not refused,
    /// since an unreadable version proves nothing. Java's `^\s*v?(\d{1,4})\.(\d{1,4})` with `find`.
    pub fn too_old(edition: ForgeEdition, reported: Option<&str>) -> Option<bool> {
        let (major, minor) = major_minor(reported?)?;
        Some(match edition {
            ForgeEdition::GitlabCom | ForgeEdition::GitlabSelfManaged => major < GITLAB_MINIMUM_MAJOR,
            ForgeEdition::GithubEnterpriseServer => {
                major < GHES_MINIMUM_MAJOR || (major == GHES_MINIMUM_MAJOR && minor < GHES_MINIMUM_MINOR)
            }
            ForgeEdition::GithubCom | ForgeEdition::GithubDataResidency => false,
        })
    }

    fn major_minor(text: &str) -> Option<(i64, i64)> {
        // `\s` in a Java pattern is [ \t\n\x0B\f\r].
        let rest = text.trim_start_matches([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']);
        let rest = rest.strip_prefix('v').unwrap_or(rest);
        let (major, rest) = digits(rest)?;
        let rest = rest.strip_prefix('.')?;
        let (minor, _) = digits(rest)?;
        Some((major, minor))
    }

    /// One to four ASCII digits — greedy, then backing off is never needed since a fifth digit fails `\.`.
    fn digits(text: &str) -> Option<(i64, &str)> {
        let count = text.bytes().take_while(u8::is_ascii_digit).count();
        if count == 0 || count > 4 {
            return None;
        }
        Some((text[..count].parse().ok()?, &text[count..]))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn reads_what_the_servers_report() {
            assert_eq!(too_old(ForgeEdition::GitlabSelfManaged, Some("17.4.1-ee")), Some(false));
            assert_eq!(too_old(ForgeEdition::GitlabSelfManaged, Some("15.11.13")), Some(true));
            assert_eq!(too_old(ForgeEdition::GithubEnterpriseServer, Some("3.11.0")), Some(true));
            assert_eq!(too_old(ForgeEdition::GithubEnterpriseServer, Some("3.12.0")), Some(false));
            assert_eq!(too_old(ForgeEdition::GithubEnterpriseServer, Some(" v4.0")), Some(false));
            assert_eq!(too_old(ForgeEdition::GithubCom, Some("anything.1")), None);
            assert_eq!(too_old(ForgeEdition::GitlabCom, None), None);
            assert_eq!(too_old(ForgeEdition::GitlabCom, Some("12345.1")), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_refused_in_words() {
        assert_eq!(ForgeKind::parse(Some(" GitLab ")), Ok(ForgeKind::Gitlab));
        assert_eq!(
            ForgeKind::parse(Some("bitbucket")),
            Err(Refused("The forge must be one of github, gitlab.".into()))
        );
        assert!(ForgeKind::parse(None).is_err());
    }

    #[test]
    fn only_the_vendors_clouds_are_clouds() {
        assert!(ForgeEdition::GithubCom.cloud());
        assert!(ForgeEdition::GithubDataResidency.cloud());
        assert!(ForgeEdition::GitlabCom.cloud());
        assert!(!ForgeEdition::GithubEnterpriseServer.cloud());
        assert!(!ForgeEdition::GitlabSelfManaged.cloud());
    }
}
