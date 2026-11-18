//! What a tracker reference may be, which tracker is configured and whether it may be called, and whether an inbound
//! tracker webhook really came from it — `common.domain.tickets`, ported (`TicketProvider`, `TrackerState`, the
//! grammar half of `Tickets`, `WebhookAuthenticity`). A ticket's title and body are `cp-tickets`' (they read an issue).

use std::sync::LazyLock;

use regex::Regex;

use crate::integrations::{Integration, IntegrationFamily};
use crate::notifications::signature::{constant_time_equals, hmac_sha256_hex};

/// Where a ticket is opened, if anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TicketProvider {
    None,
    Gitlab,
    Github,
    Jira,
    Servicenow,
}

impl TicketProvider {
    pub const ALL: [TicketProvider; 5] = [
        TicketProvider::None,
        TicketProvider::Gitlab,
        TicketProvider::Github,
        TicketProvider::Jira,
        TicketProvider::Servicenow,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            TicketProvider::None => "none",
            TicketProvider::Gitlab => "gitlab",
            TicketProvider::Github => "github",
            TicketProvider::Jira => "jira",
            TicketProvider::Servicenow => "servicenow",
        }
    }

    /// The enum constant's name, as Java's `provider.name()` and `toString()` write it into messages.
    pub const fn constant(self) -> &'static str {
        match self {
            TicketProvider::None => "NONE",
            TicketProvider::Gitlab => "GITLAB",
            TicketProvider::Github => "GITHUB",
            TicketProvider::Jira => "JIRA",
            TicketProvider::Servicenow => "SERVICENOW",
        }
    }

    pub fn is_enabled(self) -> bool {
        self != TicketProvider::None
    }

    /// `fromWireName`: trimmed and lower-cased; nothing for absent, blank or unknown.
    pub fn from_wire_name(value: Option<&str>) -> Option<TicketProvider> {
        let value = value.filter(|value| !crate::java::is_blank(value))?;
        let normalized = crate::java::to_lower_root(crate::java::trim(value));
        TicketProvider::ALL.into_iter().find(|provider| provider.wire_name() == normalized)
    }

    /// `Integration.of(provider)`: `tracker.<wire name>`; nothing for [`TicketProvider::None`], which is no
    /// integration.
    pub fn integration(self) -> Option<Integration> {
        Integration::all().into_iter().find(|integration| {
            integration.family() == IntegrationFamily::Tracker && integration.name() == self.wire_name()
        })
    }
}

/// Whether the configured tracker may be called (decision 0040 §3), derived from the registry at every read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerState {
    Active,
    Suspended,
}

impl TrackerState {
    pub const fn wire_name(self) -> &'static str {
        match self {
            TrackerState::Active => "active",
            TrackerState::Suspended => "suspended",
        }
    }

    pub fn of(integration_enabled: bool) -> TrackerState {
        if integration_enabled { TrackerState::Active } else { TrackerState::Suspended }
    }
}

pub const DEFAULT_JIRA_ISSUE_TYPE: &str = "Bug";
/// Cap per sweep: a first pass over a mature backlog would otherwise open several hundred tickets at once.
pub const MAX_TICKETS_PER_SWEEP: u32 = 20;

/// `Tickets.parseLabels`: comma-separated, trimmed, empty ones dropped. An empty list is a valid state.
pub fn parse_labels(raw: Option<&str>) -> Vec<String> {
    let Some(raw) = raw.filter(|raw| !crate::java::is_blank(raw)) else { return Vec::new() };
    raw.split(',').map(crate::java::trim).filter(|label| !label.is_empty()).map(str::to_owned).collect()
}

static NUMBERED: LazyLock<Regex> = LazyLock::new(|| compiled("^#?([0-9]{1,10})$"));
static JIRA_KEY: LazyLock<Regex> = LazyLock::new(|| compiled("^([A-Za-z][A-Za-z0-9_]{0,31})-([0-9]{1,10})$"));
static SERVICENOW_ID: LazyLock<Regex> = LazyLock::new(|| compiled("^(?:[0-9a-f]{32}|[A-Z]{2,8}[0-9]{4,12})$"));
static GITHUB_REPOSITORY: LazyLock<Regex> = LazyLock::new(|| compiled("^([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)$"));

#[allow(clippy::expect_used)]
fn compiled(pattern: &str) -> Regex {
    Regex::new(pattern).expect("a constant pattern compiles")
}

/// `Tickets.githubRepositoryPath`: `owner/repository`, each encoded, or nothing — GitHub's own grammar, `.` and `..`
/// refused, so that a project typed as `owner/repo/issues/12/comments#` cannot steer the token's request.
pub fn github_repository_path(project: Option<&str>) -> Option<String> {
    let project = crate::java::trim(project.unwrap_or(""));
    let found = GITHUB_REPOSITORY.captures(project)?;
    let (owner, repository) = (found.get(1)?.as_str(), found.get(2)?.as_str());
    if repository == "." || repository == ".." {
        return None;
    }
    Some(format!("{}/{}", url_encode(owner), url_encode(repository)))
}

/// `Tickets.referencePath`: the path segment a reference becomes in a call to the tracker, or nothing when it is not
/// a reference that tracker issues — digits for GitLab and GitHub, `KEY-123` in the configured project for Jira, a
/// sys_id or an incident number for ServiceNow — and encoded all the same.
pub fn reference_path(provider: TicketProvider, reference: Option<&str>, project: Option<&str>) -> Option<String> {
    let reference = crate::java::trim(reference.unwrap_or(""));
    let segment = match provider {
        TicketProvider::Gitlab | TicketProvider::Github => {
            NUMBERED.captures(reference).and_then(|found| found.get(1)).map(|number| number.as_str().to_owned())
        }
        TicketProvider::Jira => {
            let found = JIRA_KEY.captures(reference)?;
            let key = found.get(1)?.as_str();
            let in_project = match project {
                Some(project) if !crate::java::is_blank(project) => {
                    key.eq_ignore_ascii_case(crate::java::trim(project))
                }
                _ => true,
            };
            in_project.then(|| crate::java::to_upper_root(reference))
        }
        TicketProvider::Servicenow => SERVICENOW_ID.is_match(reference).then(|| reference.to_owned()),
        TicketProvider::None => None,
    }?;
    Some(url_encode(&segment))
}

/// `URLEncoder.encode(value, UTF_8)`: letters, digits and `.-*_` kept, a space as `+`, every other byte `%XX` in
/// upper case.
pub fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(char::from(byte)),
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// What the caller presented, in whichever of the three forms its tracker uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Presented {
    pub gitlab_token: Option<String>,
    pub github_signature: Option<String>,
    pub shared_token: Option<String>,
}

/// `WebhookAuthenticity.Verdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No secret configured: nothing is accepted until one is.
    NotConfigured,
    Accepted,
    Rejected,
}

/// `WebhookAuthenticity.verify`: GitLab's token compared, GitHub's `sha256=` HMAC over the raw body, Jira's and
/// ServiceNow's shared token — each in constant time, since this route answers anybody.
pub fn verify(
    provider: TicketProvider,
    configured_secret: Option<&str>,
    presented: &Presented,
    raw_body: &str,
) -> Verdict {
    let Some(secret) = configured_secret.filter(|secret| !crate::java::is_blank(secret)) else {
        return Verdict::NotConfigured;
    };
    let accepted = match provider {
        TicketProvider::Gitlab => constant_time_equals(secret, presented.gitlab_token.as_deref()),
        TicketProvider::Github => constant_time_equals(
            &format!("sha256={}", hmac_sha256_hex(secret, raw_body)),
            presented.github_signature.as_deref(),
        ),
        _ => constant_time_equals(secret, presented.shared_token.as_deref()),
    };
    if accepted { Verdict::Accepted } else { Verdict::Rejected }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_hold_to_each_trackers_grammar() {
        assert_eq!(reference_path(TicketProvider::Gitlab, Some(" #12 "), None).as_deref(), Some("12"));
        assert_eq!(reference_path(TicketProvider::Github, Some("../12"), None), None);
        assert_eq!(reference_path(TicketProvider::Jira, Some("sec-42"), Some("SEC")).as_deref(), Some("SEC-42"));
        assert_eq!(reference_path(TicketProvider::Jira, Some("OPS-42"), Some("SEC")), None);
        assert_eq!(reference_path(TicketProvider::Servicenow, Some("INC0012345"), None).as_deref(), Some("INC0012345"));
        assert_eq!(reference_path(TicketProvider::None, Some("1"), None), None);
        assert_eq!(github_repository_path(Some("acme/web.app")).as_deref(), Some("acme/web.app"));
        assert_eq!(github_repository_path(Some("acme/..")), None);
        assert_eq!(github_repository_path(Some("acme/web/issues")), None);
        assert_eq!(url_encode("group/sub project"), "group%2Fsub+project");
        assert_eq!(parse_labels(Some(" a, ,b ")), vec!["a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn a_webhook_is_authentic_only_with_the_trackers_own_proof() {
        let body = r#"{"a":1}"#;
        let github = Presented {
            github_signature: Some(format!("sha256={}", hmac_sha256_hex("s", body))),
            ..Presented::default()
        };
        assert_eq!(verify(TicketProvider::Github, Some("s"), &github, body), Verdict::Accepted);
        assert_eq!(verify(TicketProvider::Github, Some("s"), &github, "{}"), Verdict::Rejected);
        assert_eq!(verify(TicketProvider::Jira, Some(" "), &github, body), Verdict::NotConfigured);
        let gitlab = Presented { gitlab_token: Some("s".into()), ..Presented::default() };
        assert_eq!(verify(TicketProvider::Gitlab, Some("s"), &gitlab, body), Verdict::Accepted);
        assert_eq!(verify(TicketProvider::Jira, Some("s"), &gitlab, body), Verdict::Rejected);
    }
}
