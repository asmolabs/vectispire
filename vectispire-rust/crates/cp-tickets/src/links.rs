//! `TicketLinkService`: the tickets an operator attached to an issue by hand — a Jira key, a GitLab URL.
//!
//! **Every method applies the caller's visibility to the issue first**: a hidden issue is refused exactly as an absent
//! one is — "Issue not found." — so the refusal cannot confirm it exists, whatever the rest of the request holds.

use std::sync::Arc;

use serde::Serialize;
use vectispire_cp_audit::{AuditLog, AuditOperation, Clock, Record, RequestActor};
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_issues::{IssueCatalog, IssueView};
use vectispire_cp_settings::Integrations;
use vectispire_domain::bounded_text;
use vectispire_domain::list_window::ListWindow;
use vectispire_domain::tickets::TicketProvider;

use crate::error::TicketError;
use crate::persistence::{self, TicketRow};

/// The widths of `t_issue_ticket`'s provider, key and URL columns.
const MAX_PROVIDER_LENGTH: usize = 32;
const MAX_KEY_LENGTH: usize = 128;
const MAX_URL_LENGTH: usize = 512;

/// `IssueTicketView`: the row's fields, not the row. Every member written, `null` included.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IssueTicketView {
    pub id: Option<i64>,
    pub issue_id: Option<i64>,
    pub provider: String,
    pub ticket_key: String,
    pub ticket_url: String,
    pub status: String,
    /// `Instant.toString`.
    pub created_at: String,
    pub updated_at: String,
}

impl IssueTicketView {
    fn of(row: &TicketRow) -> IssueTicketView {
        IssueTicketView {
            id: Some(row.id),
            issue_id: Some(row.issue_id),
            provider: row.provider.clone(),
            ticket_key: row.ticket_key.clone(),
            ticket_url: row.ticket_url.clone(),
            status: row.status.clone(),
            created_at: vectispire_cp_audit::iso_instant(row.created_at),
            updated_at: vectispire_cp_audit::iso_instant(row.updated_at),
        }
    }
}

/// `TicketingProvider`: who a ticket attached by hand belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TicketingProvider {
    Jira,
    Github,
    Gitlab,
}

impl TicketingProvider {
    const ALL: [TicketingProvider; 3] = [TicketingProvider::Jira, TicketingProvider::Github, TicketingProvider::Gitlab];

    fn name(self) -> &'static str {
        match self {
            TicketingProvider::Jira => "JIRA",
            TicketingProvider::Github => "GITHUB",
            TicketingProvider::Gitlab => "GITLAB",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            TicketingProvider::Jira => "Jira Software",
            TicketingProvider::Github => "GitHub Issues",
            TicketingProvider::Gitlab => "GitLab Issues",
        }
    }

    fn tracker(self) -> TicketProvider {
        match self {
            TicketingProvider::Jira => TicketProvider::Jira,
            TicketingProvider::Github => TicketProvider::Github,
            TicketingProvider::Gitlab => TicketProvider::Gitlab,
        }
    }

    /// `parse`: in any case, refused in words rather than by `valueOf`'s.
    fn parse(value: &str) -> Result<TicketingProvider, TicketError> {
        let trimmed = vectispire_domain::java::trim(value);
        TicketingProvider::ALL.into_iter().find(|provider| provider.name().eq_ignore_ascii_case(trimmed)).ok_or_else(
            || {
                TicketError::InvalidInput(format!(
                    "Unknown ticketing provider \"{trimmed}\". Expected one of: jira, github, gitlab."
                ))
            },
        )
    }
}

/// The service.
pub struct TicketLinkService {
    db: Db,
    issues: IssueCatalog,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock>,
    integrations: Integrations,
}

impl std::fmt::Debug for TicketLinkService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketLinkService").finish_non_exhaustive()
    }
}

/// `RowVisibility.requireVisibleIssue`: absent and hidden alike are "Issue not found.". A row attached to neither
/// target is left to the visibility, as the entity's reading is — seen only by whoever sees everything.
pub(crate) fn require_visible(issue: Option<IssueView>, visibility: &Visibility) -> Result<IssueView, TicketError> {
    let not_found = || TicketError::NotFound("Issue not found.".to_owned());
    let issue = issue.ok_or_else(not_found)?;
    let visible = match (issue.repo_id, issue.container_id) {
        (Some(repository), _) => visibility.permits(ScanTarget::Repository(repository)),
        (None, Some(container)) => visibility.permits(ScanTarget::Container(container)),
        (None, None) => matches!(visibility, Visibility::Everything),
    };
    if visible { Ok(issue) } else { Err(not_found()) }
}

impl TicketLinkService {
    pub fn new(
        db: Db,
        issues: IssueCatalog,
        audit: Arc<AuditLog>,
        clock: Arc<dyn Clock>,
        integrations: Integrations,
    ) -> TicketLinkService {
        TicketLinkService { db, issues, audit, clock, integrations }
    }

    async fn visible_issue(&self, issue_id: i64, visibility: &Visibility) -> Result<IssueView, TicketError> {
        require_visible(self.issues.find_by_id(issue_id).await?, visibility)
    }

    /// The issue's tickets, newest first and by id among those linked in the same instant — all, or one page. The
    /// visibility first, so a refused window says nothing of a hidden issue.
    pub async fn list(
        &self,
        issue_id: i64,
        visibility: &Visibility,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<IssueTicketView>, TicketError> {
        self.visible_issue(issue_id, visibility).await?;
        let window = ListWindow::requested(limit, offset).map_err(TicketError::InvalidInput)?;
        let every: Vec<IssueTicketView> =
            persistence::tickets_of(&self.db, issue_id).await?.iter().map(IssueTicketView::of).collect();
        Ok(match window {
            Some(page) => page.of(&every),
            None => every,
        })
    }

    /// Attaches a ticket to an issue the caller may see: the visibility, the fields present, the provider, the
    /// tracker's switch, then the key and the URL — Java's order.
    pub async fn attach(
        &self,
        issue_id: i64,
        visibility: &Visibility,
        provider: Option<&str>,
        ticket_key: Option<&str>,
        ticket_url: Option<&str>,
        actor: RequestActor,
    ) -> Result<IssueTicketView, TicketError> {
        let issue = self.visible_issue(issue_id, visibility).await?;
        let (Some(provider), Some(ticket_key), Some(ticket_url)) = (provider, ticket_key, ticket_url) else {
            return Err(TicketError::InvalidInput("Provider, ticket key and URL are required.".to_owned()));
        };
        let provider = bounded_text::required(Some(provider), MAX_PROVIDER_LENGTH, "The provider")
            .map_err(|refused| TicketError::InvalidInput(refused.to_string()))?;
        let parsed = TicketingProvider::parse(&provider)?;
        if let Some(integration) = parsed.tracker().integration() {
            self.integrations.require_enabled(integration).await?;
        }
        // Both columns non-null and bounded: a blank key stored a link to nothing, and a long one was a 500.
        let key = bounded_text::required(Some(ticket_key), MAX_KEY_LENGTH, "The ticket key")
            .map_err(|refused| TicketError::InvalidInput(refused.to_string()))?;
        let url = bounded_text::required(Some(ticket_url), MAX_URL_LENGTH, "The ticket URL")
            .map_err(|refused| TicketError::InvalidInput(refused.to_string()))?;

        let now = self.clock.now();
        let now = now.replace_microsecond(now.microsecond()).unwrap_or(now);
        let mut row = TicketRow {
            id: 0,
            issue_id: issue.id,
            provider: parsed.name().to_owned(),
            ticket_key: key,
            ticket_url: url,
            status: "OPEN".to_owned(),
            created_at: now,
            updated_at: now,
        };
        row.id = persistence::insert(&self.db, &row).await?;

        let mut record = Record::of(
            AuditOperation::TicketLinked,
            &issue.id.to_string(),
            &format!("Linked {} ticket: {}", parsed.display_name(), row.ticket_key),
            actor.username.as_deref(),
        );
        record.ip_address = actor.ip_address;
        record.user_agent = actor.user_agent;
        self.audit.record(record).await;
        Ok(IssueTicketView::of(&row))
    }
}
