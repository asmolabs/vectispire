//! A discovery's vocabulary: where a run stands ([`DiscoveryState`]), why it ended short ([`DiscoveryReason`]), the
//! namespaces it could not read ([`UnreadableNamespace`]), what it found ([`DiscoveredRepository`]) and why one is not
//! offered or imported ([`ImportSkip`]).

use crate::bounded_text;
use crate::instant::Instant;
use crate::java;

/// `DiscoveryState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryState {
    Pending,
    Running,
    Completed,
    Partial,
    Failed,
}

impl DiscoveryState {
    pub const ALL: [DiscoveryState; 5] = [
        DiscoveryState::Pending,
        DiscoveryState::Running,
        DiscoveryState::Completed,
        DiscoveryState::Partial,
        DiscoveryState::Failed,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            DiscoveryState::Pending => "pending",
            DiscoveryState::Running => "running",
            DiscoveryState::Completed => "completed",
            DiscoveryState::Partial => "partial",
            DiscoveryState::Failed => "failed",
        }
    }

    /// Ended: nothing moves it any more, and the connection may be discovered again.
    pub const fn ended(self) -> bool {
        matches!(self, DiscoveryState::Completed | DiscoveryState::Partial | DiscoveryState::Failed)
    }

    /// A stored value read back; `Err` names a value this version does not know — a fault of the row.
    pub fn of_stored(stored: &str) -> Result<DiscoveryState, String> {
        DiscoveryState::ALL
            .into_iter()
            .find(|state| state.wire_name() == stored)
            .ok_or_else(|| format!("Unknown discovery state \"{stored}\"."))
    }
}

/// `DiscoveryReason`: why a discovery ended short of `completed`, and the state it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryReason {
    TimeBound,
    RepositoryBound,
    RateLimited,
    TokenRejected,
    DestinationBlocked,
    CrossOriginPage,
    ForgeUnavailable,
    ForgeRefused,
    ConnectionUnusable,
    Unsupported,
    ExecutorLost,
    InternalError,
}

impl DiscoveryReason {
    pub const ALL: [DiscoveryReason; 12] = [
        DiscoveryReason::TimeBound,
        DiscoveryReason::RepositoryBound,
        DiscoveryReason::RateLimited,
        DiscoveryReason::TokenRejected,
        DiscoveryReason::DestinationBlocked,
        DiscoveryReason::CrossOriginPage,
        DiscoveryReason::ForgeUnavailable,
        DiscoveryReason::ForgeRefused,
        DiscoveryReason::ConnectionUnusable,
        DiscoveryReason::Unsupported,
        DiscoveryReason::ExecutorLost,
        DiscoveryReason::InternalError,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            DiscoveryReason::TimeBound => "time_bound",
            DiscoveryReason::RepositoryBound => "repository_bound",
            DiscoveryReason::RateLimited => "rate_limited",
            DiscoveryReason::TokenRejected => "token_rejected",
            DiscoveryReason::DestinationBlocked => "destination_blocked",
            DiscoveryReason::CrossOriginPage => "cross_origin_page",
            DiscoveryReason::ForgeUnavailable => "forge_unavailable",
            DiscoveryReason::ForgeRefused => "forge_refused",
            DiscoveryReason::ConnectionUnusable => "connection_unusable",
            DiscoveryReason::Unsupported => "unsupported",
            DiscoveryReason::ExecutorLost => "executor_lost",
            DiscoveryReason::InternalError => "internal_error",
        }
    }

    /// `Partial` or `Failed`.
    pub const fn state(self) -> DiscoveryState {
        match self {
            DiscoveryReason::TimeBound | DiscoveryReason::RepositoryBound | DiscoveryReason::RateLimited => {
                DiscoveryState::Partial
            }
            _ => DiscoveryState::Failed,
        }
    }

    /// A stored value read back; `Ok(None)` for a run that has none.
    pub fn of_stored(stored: Option<&str>) -> Result<Option<DiscoveryReason>, String> {
        let Some(stored) = stored else {
            return Ok(None);
        };
        DiscoveryReason::ALL
            .into_iter()
            .find(|reason| reason.wire_name() == stored)
            .map(Some)
            .ok_or_else(|| format!("Unknown discovery reason \"{stored}\"."))
    }
}

/// `ImportSkip`: why a discovered repository is not offered, or not imported, as a new target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImportSkip {
    AlreadyImported,
    AlreadyPresent,
    NoDefaultBranch,
    NoCloneUrl,
    DuplicateInSelection,
}

impl ImportSkip {
    pub const fn wire_name(self) -> &'static str {
        match self {
            ImportSkip::AlreadyImported => "already_imported",
            ImportSkip::AlreadyPresent => "already_present",
            ImportSkip::NoDefaultBranch => "no_default_branch",
            ImportSkip::NoCloneUrl => "no_clone_url",
            ImportSkip::DuplicateInSelection => "duplicate_in_selection",
        }
    }
}

/// `UnreadableNamespace`: a namespace a discovery could not read with the connection's token. `path` is `None` when
/// the forge withheld namespaces without naming them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableNamespace {
    pub path: Option<String>,
    pub reason: String,
}

impl UnreadableNamespace {
    /// How many a run records; past it the rest are counted in the last one's place.
    pub const MAX_RECORDED: usize = 100;
    /// The longest reason kept.
    pub const REASON_LENGTH: usize = 500;

    /// The record's compact constructor: a blank path is none, both flattened, the reason clipped.
    pub fn new(path: Option<&str>, reason: Option<&str>) -> UnreadableNamespace {
        let path = path.filter(|path| !java::is_blank(path)).map(flat);
        let reason = flat(reason.unwrap_or(""));
        let reason = bounded_text::clip(Some(&reason), Self::REASON_LENGTH).unwrap_or_default().to_owned();
        UnreadableNamespace { path, reason }
    }

    /// The column: one per line, path and reason separated by a tab; `None` for none.
    pub fn encode(namespaces: &[UnreadableNamespace]) -> Option<String> {
        if namespaces.is_empty() {
            return None;
        }
        let mut kept: Vec<UnreadableNamespace> = namespaces.to_vec();
        if kept.len() > Self::MAX_RECORDED {
            let dropped = kept.len() - Self::MAX_RECORDED + 1;
            kept.truncate(Self::MAX_RECORDED - 1);
            kept.push(UnreadableNamespace::new(
                None,
                Some(&format!(
                    "{dropped} more namespaces could not be read; their repositories are not marked gone either."
                )),
            ));
        }
        Some(
            kept.iter()
                .map(|namespace| format!("{}\t{}", namespace.path.as_deref().unwrap_or(""), namespace.reason))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }

    /// The column read back; empty for a run that recorded none.
    pub fn decode(stored: Option<&str>) -> Vec<UnreadableNamespace> {
        let Some(stored) = stored.filter(|stored| !java::is_blank(stored)) else {
            return Vec::new();
        };
        java_split(stored, '\n')
            .into_iter()
            .map(|line| match line.split_once('\t') {
                None => UnreadableNamespace::new(None, Some(line)),
                Some((path, reason)) => UnreadableNamespace::new(Some(path), Some(reason)),
            })
            .collect()
    }
}

/// `String.split(char)`: trailing empty strings removed.
fn java_split(text: &str, separator: char) -> Vec<&str> {
    let mut parts: Vec<&str> = text.split(separator).collect();
    while parts.len() > 1 && parts.last().is_some_and(|last| last.is_empty()) {
        parts.pop();
    }
    if parts.len() == 1 && parts[0].is_empty() && !text.is_empty() {
        parts.clear();
    }
    parts
}

fn flat(value: &str) -> String {
    java::trim(&value.replace(['\t', '\r', '\n'], " ")).to_owned()
}

/// `DiscoveredRepository`: one repository as a forge listed it. **Unknown is not zero**: every optional component is
/// `None` when the forge did not give it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRepository {
    pub forge_id: String,
    pub full_path: String,
    pub namespace_path: String,
    pub personal: bool,
    pub name: String,
    pub default_branch: Option<String>,
    pub archived: Option<bool>,
    pub fork: Option<bool>,
    pub visibility: Option<String>,
    pub last_activity_at: Option<Instant>,
    pub language: Option<String>,
    pub size_bytes: Option<i64>,
    pub http_url: Option<String>,
    pub ssh_url: Option<String>,
    pub web_url: Option<String>,
}

impl DiscoveredRepository {
    pub const FORGE_ID_LENGTH: usize = 64;
    pub const PATH_LENGTH: usize = 1000;
    pub const NAME_LENGTH: usize = 255;
    pub const BRANCH_LENGTH: usize = 255;
    pub const VISIBILITY_LENGTH: usize = 20;
    pub const LANGUAGE_LENGTH: usize = 100;
    pub const URL_LENGTH: usize = 1024;

    /// 1970-01-02T00:00:00Z and 9999-12-30T00:00:00Z: what a timestamp column holds on every engine.
    const EARLIEST: Instant = Instant { epoch_second: 86_400, nano: 0 };
    const LATEST: Instant = Instant { epoch_second: 253_402_128_000, nano: 0 };

    /// Why this repository cannot be kept: an id, a path or a name longer than its column.
    pub fn unstorable(&self) -> Option<String> {
        let len = java::utf16_len;
        if java::is_blank(&self.forge_id) || len(&self.forge_id) > Self::FORGE_ID_LENGTH {
            return Some(format!("its id is empty or longer than {} characters", Self::FORGE_ID_LENGTH));
        }
        if java::is_blank(&self.full_path)
            || len(&self.full_path) > Self::PATH_LENGTH
            || len(&self.namespace_path) > Self::PATH_LENGTH
        {
            return Some(format!("its path is empty or longer than {} characters", Self::PATH_LENGTH));
        }
        if java::is_blank(&self.name) || len(&self.name) > Self::NAME_LENGTH {
            return Some(format!("its name is empty or longer than {} characters", Self::NAME_LENGTH));
        }
        None
    }

    /// Every optional value its column cannot hold made unknown: cut short, it would be a wrong value.
    #[must_use]
    pub fn bounded(self) -> DiscoveredRepository {
        DiscoveredRepository {
            default_branch: within(self.default_branch, Self::BRANCH_LENGTH),
            visibility: within(self.visibility, Self::VISIBILITY_LENGTH),
            last_activity_at: self.last_activity_at.filter(|at| *at >= Self::EARLIEST && *at <= Self::LATEST),
            language: within(self.language, Self::LANGUAGE_LENGTH),
            size_bytes: self.size_bytes.filter(|size| *size >= 0),
            http_url: within(self.http_url, Self::URL_LENGTH),
            ssh_url: within(self.ssh_url, Self::URL_LENGTH),
            web_url: within(self.web_url, Self::URL_LENGTH),
            ..self
        }
    }

    /// What changed since the snapshot's previous reading, in words. **An unknown is not a change.**
    pub fn changes_since(
        &self,
        previous_path: Option<&str>,
        previous_branch: Option<&str>,
        previous_archived: Option<bool>,
        was_gone: bool,
    ) -> Vec<String> {
        let mut changes = Vec::new();
        if was_gone {
            changes.push("seen again after it was gone".to_owned());
        }
        if let Some(previous) = previous_path.filter(|previous| *previous != self.full_path) {
            changes.push(format!("renamed or moved from {previous}"));
        }
        if let (Some(previous), Some(branch)) = (previous_branch, self.default_branch.as_deref())
            && previous != branch
        {
            changes.push(format!("default branch {previous} → {branch}"));
        }
        if let (Some(previous), Some(archived)) = (previous_archived, self.archived)
            && previous != archived
        {
            changes.push(if archived { "archived" } else { "unarchived" }.to_owned());
        }
        changes
    }
}

fn within(value: Option<String>, length: usize) -> Option<String> {
    value.filter(|value| !java::is_blank(value) && java::utf16_len(value) <= length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> DiscoveredRepository {
        DiscoveredRepository {
            forge_id: "42".into(),
            full_path: "acme/api".into(),
            namespace_path: "acme".into(),
            personal: false,
            name: "api".into(),
            default_branch: Some("main".into()),
            archived: Some(false),
            fork: None,
            visibility: Some("private".into()),
            last_activity_at: None,
            language: None,
            size_bytes: Some(-1),
            http_url: Some("x".repeat(1025)),
            ssh_url: Some(" ".into()),
            web_url: None,
        }
    }

    #[test]
    fn bounded_makes_unknown_what_a_column_cannot_hold() {
        let bounded = repository().bounded();
        assert_eq!((bounded.size_bytes, bounded.http_url, bounded.ssh_url), (None, None, None));
        assert_eq!(bounded.default_branch.as_deref(), Some("main"));
        let mut long = repository();
        long.full_path = "a".repeat(1001);
        assert_eq!(long.unstorable().as_deref(), Some("its path is empty or longer than 1000 characters"));
        assert_eq!(repository().unstorable(), None);
    }

    #[test]
    fn the_engines_bounds_are_the_instants_java_names() {
        assert_eq!(Some(DiscoveredRepository::EARLIEST), Instant::of_utc(1970, 1, 2, 0, 0, 0));
        assert_eq!(Some(DiscoveredRepository::LATEST), Instant::of_utc(9999, 12, 30, 0, 0, 0));
    }

    #[test]
    fn an_unknown_is_not_a_change() {
        let mut now = repository();
        now.default_branch = None;
        now.archived = Some(true);
        assert_eq!(
            now.changes_since(Some("acme/old"), Some("master"), Some(false), true),
            vec!["seen again after it was gone", "renamed or moved from acme/old", "archived"]
        );
        assert_eq!(
            repository().changes_since(Some("acme/api"), Some("dev"), None, false),
            vec!["default branch dev → main"]
        );
    }

    #[test]
    fn unreadable_namespaces_round_trip_and_are_capped() {
        let namespaces = vec![
            UnreadableNamespace::new(Some("acme\tx"), Some("refused\nby SSO")),
            UnreadableNamespace::new(Some(" "), Some("withheld")),
        ];
        let stored = UnreadableNamespace::encode(&namespaces).unwrap();
        assert_eq!(stored, "acme x\trefused by SSO\n\twithheld");
        assert_eq!(UnreadableNamespace::decode(Some(&stored)), namespaces);
        let many: Vec<_> = (0..150).map(|n| UnreadableNamespace::new(Some(&format!("g{n}")), Some("no"))).collect();
        let decoded = UnreadableNamespace::decode(UnreadableNamespace::encode(&many).as_deref());
        assert_eq!(decoded.len(), 100);
        assert_eq!(decoded[99].path, None);
        assert!(decoded[99].reason.starts_with("51 more namespaces"));
        assert!(UnreadableNamespace::decode(None).is_empty());
    }

    #[test]
    fn states_and_reasons_read_back() {
        assert_eq!(DiscoveryState::of_stored("partial"), Ok(DiscoveryState::Partial));
        assert!(DiscoveryState::of_stored("lost").is_err());
        assert_eq!(DiscoveryReason::of_stored(Some("rate_limited")), Ok(Some(DiscoveryReason::RateLimited)));
        assert_eq!(DiscoveryReason::RateLimited.state(), DiscoveryState::Partial);
        assert_eq!(DiscoveryReason::ExecutorLost.state(), DiscoveryState::Failed);
        assert_eq!(DiscoveryReason::of_stored(None), Ok(None));
    }
}
