//! `TicketService`: opening and closing a ticket with GitLab, GitHub, Jira or ServiceNow, the tracker's token and
//! inbound secret, its standing in the integrations' registry and its token's health.
//!
//! - **The token is encrypted at rest** and read through [`TicketService::token`], which refuses while the tracker is
//!   suspended — the backstop, not the gate: every entry asks [`TicketService::is_enabled`] first.
//! - **Every call carries the CA pinned for the tracker**, when one is, checked current at every use, in place of the
//!   runtime's store.
//! - **One ticket per issue, for its whole life**: the reference stored on the issue is the sweep's deduplication key.
//! - **Never fails the tick**: an unreachable tracker logs and answers "nothing", so the jobs sharing the turn run.

use std::sync::Arc;

use base64::Engine as _;
use serde_json::{Map, Value, json};
use vectispire_cp_audit::Clock;
use vectispire_cp_crypto::{Encryption, SecretState};
use vectispire_cp_issues::TicketableIssue;
use vectispire_cp_outbound::{Method, OutboundPolicy, OutboundPost, PostError};
use vectispire_cp_settings::{Integrations, Setting, Settings};
use vectispire_domain::integrations::Integration;
use vectispire_domain::pinned_ca::{PinnedCa, Subject};
use vectispire_domain::tickets::{self, TicketProvider, TrackerState};
use vectispire_domain::token_expiry;

use crate::error::TicketError;
use crate::format;
use crate::token_state::{Health, TrackerTokenState, instant};

/// The token's encryption context, bound to its setting key.
pub const TOKEN_CONTEXT: &str = "setting:ticket_token";
/// The inbound webhook secret's.
pub const WEBHOOK_SECRET_CONTEXT: &str = "setting:ticket_webhook_secret";
/// How the pinned CA's refusals name the field — the forge's rule, in the tracker's words.
pub const CA: Subject = Subject { field: "The tracker CA", server: "the tracker" };
/// How often the tracker is asked about its token: daily.
pub const TOKEN_CHECK_INTERVAL_SECONDS: i64 = 86_400;

/// A ticket the tracker opened: what it calls it, and where a human goes to read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub reference: String,
    pub url: String,
}

/// The configured tracker as the registry knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    pub integration: Integration,
    pub state: TrackerState,
}

/// What the stored inbound secret amounts to — three cases, because two of them refuse differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookSecret {
    /// None set: the route accepts nothing, and says it is not configured.
    Absent,
    /// Set, but no configured key decrypts it: refused as a wrong signature.
    Unreadable,
    Present(String),
}

/// What is pinned, for the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedTrackerCa {
    /// `None` when the stored text no longer reads as a CA.
    pub subject: Option<String>,
    pub not_after: Option<vectispire_domain::instant::Instant>,
}

/// Why a call to the tracker failed — logged, never shown.
#[derive(Debug, thiserror::Error)]
enum CallError {
    #[error(transparent)]
    Post(#[from] PostError),
    #[error("{0}")]
    Refused(String),
    #[error(transparent)]
    Ticket(#[from] TicketError),
}

/// The service.
pub struct TicketService {
    settings: Settings,
    encryption: Arc<Encryption>,
    post: OutboundPost,
    clock: Arc<dyn Clock>,
    token_state: Arc<TrackerTokenState>,
    integrations: Integrations,
}

impl std::fmt::Debug for TicketService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketService").finish_non_exhaustive()
    }
}

impl TicketService {
    pub fn new(
        settings: Settings,
        encryption: Arc<Encryption>,
        post: OutboundPost,
        clock: Arc<dyn Clock>,
        token_state: Arc<TrackerTokenState>,
        integrations: Integrations,
    ) -> TicketService {
        TicketService { settings, encryption, post, clock, token_state, integrations }
    }

    fn now(&self) -> vectispire_domain::instant::Instant {
        instant(self.clock.now())
    }

    /// `caToPin`: the CA an administrator is saving, read and checked as a forge connection's is — `None` for blank.
    pub fn ca_to_pin(&self, pem: Option<&str>) -> Result<Option<PinnedCa>, TicketError> {
        match pem {
            None => Ok(None),
            Some(pem) if vectispire_domain::java::is_blank(pem) => Ok(None),
            Some(pem) => PinnedCa::parse_pasted(Some(pem), self.now(), &CA)
                .map(Some)
                .map_err(|refused| TicketError::InvalidInput(refused.0)),
        }
    }

    /// What is pinned, read without checking the dates: an expired CA is shown, to be replaced.
    pub async fn pinned_ca(&self) -> Result<Option<PinnedTrackerCa>, TicketError> {
        let stored = self.trimmed(Setting::TicketCa).await?;
        if stored.is_empty() {
            return Ok(None);
        }
        Ok(Some(match PinnedCa::read(Some(&stored), &CA) {
            Ok(ca) => PinnedTrackerCa { subject: Some(ca.subject().to_owned()), not_after: Some(ca.not_after()) },
            Err(_) => PinnedTrackerCa { subject: None, not_after: None },
        }))
    }

    /// The stored CA, checked current at every use; a refusal fails the gesture rather than falling back on the
    /// runtime's store.
    async fn trust(&self) -> Result<Option<vectispire_cp_outbound::PinnedCa>, CallError> {
        let stored = self.trimmed(Setting::TicketCa).await?;
        if stored.is_empty() {
            return Ok(None);
        }
        PinnedCa::parse(Some(&stored), self.now(), &CA).map_err(|refused| CallError::Refused(refused.0))?;
        let subject =
            vectispire_cp_outbound::pinned_ca::Subject { field: CA.field.to_owned(), server: CA.server.to_owned() };
        vectispire_cp_outbound::PinnedCa::read(Some(&stored), &subject)
            .map(Some)
            .map_err(|refused| CallError::Refused(refused.0))
    }

    async fn trimmed(&self, setting: Setting) -> Result<String, TicketError> {
        Ok(vectispire_domain::java::trim(&self.settings.get(setting).await?).to_owned())
    }

    pub async fn provider(&self) -> Result<TicketProvider, TicketError> {
        Ok(TicketProvider::from_wire_name(Some(&self.settings.get(Setting::TicketProvider).await?))
            .unwrap_or(TicketProvider::None))
    }

    pub async fn base_url(&self) -> Result<String, TicketError> {
        Ok(self.trimmed(Setting::TicketBaseUrl).await?.trim_end_matches('/').to_owned())
    }

    pub async fn project(&self) -> Result<String, TicketError> {
        self.trimmed(Setting::TicketProject).await
    }

    /// A tracker chosen and everything a call needs set: an address, a project, a readable token.
    pub async fn is_configured(&self) -> Result<bool, TicketError> {
        Ok(self.provider().await?.is_enabled()
            && !self.base_url().await?.is_empty()
            && !self.project().await?.is_empty()
            && self.has_token().await?)
    }

    /// Configured, and its integration not suspended: what every entry that calls the tracker asks first.
    pub async fn is_enabled(&self) -> Result<bool, TicketError> {
        Ok(self.is_configured().await? && !self.suspended().await?)
    }

    pub async fn standing(&self) -> Result<Option<Standing>, TicketError> {
        let Some(integration) = self.provider().await?.integration() else { return Ok(None) };
        let state = TrackerState::of(self.integrations.is_enabled(integration).await?);
        Ok(Some(Standing { integration, state }))
    }

    pub async fn suspended(&self) -> Result<bool, TicketError> {
        Ok(self.standing().await?.is_some_and(|standing| standing.state == TrackerState::Suspended))
    }

    pub async fn has_token(&self) -> Result<bool, TicketError> {
        Ok(!self.stored_token().await?.is_empty())
    }

    /// The decrypted token — refused while the tracker is suspended, whatever path reads it.
    pub async fn token(&self) -> Result<String, TicketError> {
        if let Some(standing) = self.standing().await?
            && standing.state == TrackerState::Suspended
        {
            return Err(TicketError::IntegrationDisabled(standing.integration));
        }
        self.stored_token().await
    }

    /// **Never fails on an undecryptable token**: it disables ticket creation rather than breaking the tick.
    async fn stored_token(&self) -> Result<String, TicketError> {
        let stored = self.trimmed(Setting::TicketToken).await?;
        if stored.is_empty() {
            return Ok(stored);
        }
        Ok(self.encryption.read_secret(&stored, TOKEN_CONTEXT, "The tracker access token").await.expose().to_owned())
    }

    /// The secret the tracker presents. **Unreadable is not absent**: an empty secret meant "not enforced", and a lost
    /// key reopened the only anonymous mutating route.
    pub async fn webhook_secret(&self) -> Result<WebhookSecret, TicketError> {
        let stored = self.trimmed(Setting::TicketWebhookSecret).await?;
        if stored.is_empty() {
            return Ok(WebhookSecret::Absent);
        }
        if !Encryption::is_ciphertext(&stored) {
            // A legacy clear value: still the secret, and `read_secret` says so at warn.
            let secret =
                self.encryption.read_secret(&stored, WEBHOOK_SECRET_CONTEXT, "The inbound webhook secret").await;
            return Ok(WebhookSecret::Present(secret.expose().to_owned()));
        }
        let secret = self.encryption.inspect(&stored, WEBHOOK_SECRET_CONTEXT).await;
        if secret.state() == SecretState::Unreadable {
            tracing::error!(
                "The inbound webhook secret cannot be decrypted by any configured key — the ticket webhook refuses every \
                 call until it is set again."
            );
            return Ok(WebhookSecret::Unreadable);
        }
        Ok(WebhookSecret::Present(secret.plain_text().to_owned()))
    }

    pub async fn has_webhook_secret(&self) -> Result<bool, TicketError> {
        Ok(matches!(self.webhook_secret().await?, WebhookSecret::Present(_)))
    }

    pub async fn token_health(&self) -> Result<Health, TicketError> {
        self.token_state.read().await
    }

    /// The token's state read from the tracker now when it can say, and announced when that changed something. Never
    /// fails; a suspended tracker is not asked and nothing is announced.
    pub async fn check_token_now(&self) -> Result<Health, TicketError> {
        let now = self.now();
        let attempt: Result<(), CallError> = async {
            if self.suspended().await? {
                return Ok(());
            }
            if self.is_enabled().await? {
                self.ask_the_tracker(now).await?;
            }
            self.token_state.announce(now).await?;
            Ok(())
        }
        .await;
        if let Err(failed) = attempt {
            tracing::warn!("The tracker token could not be checked: {failed}");
        }
        self.token_state.read().await
    }

    /// The daily check, from the hourly tick. Skipped whole while the tracker is suspended.
    pub async fn check_token_if_due(&self) {
        let now = self.now();
        let attempt: Result<(), CallError> = async {
            if self.suspended().await? {
                return Ok(());
            }
            let due = match self.token_state.checked_at().await? {
                Some(at) => at.plus_seconds(TOKEN_CHECK_INTERVAL_SECONDS).is_none_or(|next| now >= next),
                None => true,
            };
            if self.is_enabled().await? && due {
                self.ask_the_tracker(now).await?;
            }
            self.token_state.announce(now).await?;
            Ok(())
        }
        .await;
        if let Err(failed) = attempt {
            tracing::warn!("The tracker token could not be checked: {failed}");
        }
    }

    /// GitLab and GitHub say what they know of the token; Jira and ServiceNow are not asked.
    async fn ask_the_tracker(&self, now: vectispire_domain::instant::Instant) -> Result<(), CallError> {
        let provider = self.provider().await?;
        if provider != TicketProvider::Gitlab && provider != TicketProvider::Github {
            return Ok(());
        }
        let base = self.validated_base_url().await?;
        let trust = self.trust().await?;
        let policy = self.policy().await?;
        let answer = if provider == TicketProvider::Gitlab {
            let headers = vec![("PRIVATE-TOKEN".to_owned(), self.token().await?)];
            self.post
                .answer(
                    &format!("{base}/api/v4/personal_access_tokens/self"),
                    policy,
                    "GitLab",
                    &headers,
                    trust.as_ref(),
                )
                .await?
        } else {
            let headers = self.github_headers().await?;
            let repository = self.github_repository().await?;
            self.post.answer(&format!("{base}/repos/{repository}"), policy, "GitHub", &headers, trust.as_ref()).await?
        };
        match answer.status {
            200 => {
                let reported = if provider == TicketProvider::Gitlab {
                    let body: Value = answer
                        .body
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()
                        .map_err(|_| CallError::Refused("GitLab: the answer is not JSON.".to_owned()))?
                        .unwrap_or(Value::Null);
                    body.get("expires_at").and_then(Value::as_str).and_then(|date| token_expiry::of_date(Some(date)))
                } else {
                    token_expiry::of_github_header(answer.header("github-authentication-token-expiration"))
                };
                self.token_state.record_reported(reported, now).await?;
                // Unless what refused it was a 403 on a ticket: describing itself proves nothing of that permission.
                if self.token_state.read().await?.refused.is_none_or(|refusal| refusal.status != 403) {
                    self.token_state.record_accepted(now).await?;
                }
            }
            401 => self.token_state.record_refused(401, now).await?,
            status => tracing::warn!("The tracker answered HTTP {status} when asked about its token; nothing learned."),
        }
        Ok(())
    }

    async fn note_accepted(&self) {
        if let Err(unrecorded) = self.token_state.record_accepted(self.now()).await {
            tracing::warn!("The tracker token's state could not be recorded: {unrecorded}");
        }
    }

    /// A refusal of the token — 401, or 403 that is not GitHub's rate limit — recorded from the failure's type.
    async fn note_failure(&self, failed: &CallError) {
        if let CallError::Post(PostError::Status { status, rate_limited: false, .. }) = failed
            && (*status == 401 || *status == 403)
            && let Err(unrecorded) = self.token_state.record_refused(i32::from(*status), self.now()).await
        {
            tracing::warn!("The tracker token's state could not be recorded: {unrecorded}");
        }
    }

    /// Opens a ticket; `None` on any failure, after logging it.
    pub async fn create_for_issue(&self, issue: &TicketableIssue, target_name: &str) -> Option<Ticket> {
        match self.is_enabled().await {
            Ok(true) => {}
            Ok(false) => return None,
            Err(failed) => {
                tracing::warn!("Ticket creation failed for issue {} — will be retried: {failed}", issue.id);
                return None;
            }
        }
        let prepared: Result<(String, Option<vectispire_cp_outbound::PinnedCa>), CallError> =
            async { Ok((self.validated_base_url().await?, self.trust().await?)) }.await;
        let (base, trust) = match prepared {
            Ok(prepared) => prepared,
            Err(refused) => {
                tracing::error!("Ticket not created: {refused}");
                return None;
            }
        };
        let title = format::title(issue, target_name);
        let body = format::body(issue, target_name);
        let created: Result<Option<Ticket>, CallError> = async {
            Ok(match self.provider().await? {
                TicketProvider::Gitlab => Some(self.create_gitlab(&base, &title, &body, trust.as_ref()).await?),
                TicketProvider::Github => Some(self.create_github(&base, &title, &body, trust.as_ref()).await?),
                TicketProvider::Jira => Some(self.create_jira(&base, &title, &body, trust.as_ref()).await?),
                TicketProvider::Servicenow => Some(self.create_servicenow(&base, &title, &body, trust.as_ref()).await?),
                TicketProvider::None => None,
            })
        }
        .await;
        match created {
            Ok(Some(ticket)) => {
                self.note_accepted().await;
                Some(ticket)
            }
            Ok(None) => None,
            Err(failed) => {
                self.note_failure(&failed).await;
                tracing::warn!("Ticket creation failed for issue {} — will be retried: {failed}", issue.id);
                None
            }
        }
    }

    /// Closes the ticket of an issue verified resolved.
    pub async fn close_ticket(&self, reference: Option<&str>, resolution: &str) -> bool {
        let Some(reference) = reference.filter(|reference| !vectispire_domain::java::is_blank(reference)) else {
            return false;
        };
        if !matches!(self.is_enabled().await, Ok(true)) {
            return false;
        }
        let prepared: Result<(String, Option<vectispire_cp_outbound::PinnedCa>), CallError> =
            async { Ok((self.validated_base_url().await?, self.trust().await?)) }.await;
        let (base, trust) = match prepared {
            Ok(prepared) => prepared,
            Err(refused) => {
                tracing::error!("Ticket closure failed: {refused}");
                return false;
            }
        };
        let (Ok(provider), Ok(project)) = (self.provider().await, self.project().await) else { return false };
        // Never the reference as typed: it is pasted into a URL sent with the integration's token.
        let Some(segment) = tickets::reference_path(provider, Some(reference), Some(&project)) else {
            tracing::warn!(
                "Ticket {reference} not closed: it is not a {} reference in project \"{project}\".",
                provider.constant()
            );
            return false;
        };
        let closed: Result<(), CallError> = async {
            match provider {
                TicketProvider::Gitlab => self.close_gitlab(&base, &segment, trust.as_ref()).await,
                TicketProvider::Github => self.close_github(&base, &segment, trust.as_ref()).await,
                TicketProvider::Jira => self.close_jira(&base, &segment, trust.as_ref()).await,
                TicketProvider::Servicenow => self.close_servicenow(&base, &segment, resolution, trust.as_ref()).await,
                TicketProvider::None => Ok(()),
            }
        }
        .await;
        match closed {
            Ok(()) => {
                tracing::info!("Successfully closed ticket {reference} on {}", provider.constant());
                self.note_accepted().await;
                true
            }
            Err(failed) => {
                self.note_failure(&failed).await;
                tracing::warn!("Failed to close ticket {reference} on {}: {failed}", provider.constant());
                false
            }
        }
    }

    /// The base URL, validated here too: a setting written straight into the database must not become an unchecked
    /// destination. **Private allowed by default**: a self-hosted tracker commonly lives on an internal network.
    async fn validated_base_url(&self) -> Result<String, CallError> {
        let policy = self.policy().await?;
        let url = self.base_url().await?;
        let checked =
            self.post.validate(&url, policy, "tracker URL").await.map_err(|refused| CallError::Refused(refused.0))?;
        Ok(checked.trim_end_matches('/').to_owned())
    }

    /// One policy for the base URL and the call after it.
    async fn policy(&self) -> Result<OutboundPolicy, TicketError> {
        Ok(if self.settings.is_enabled(Setting::TicketAllowPrivateUrl).await? {
            OutboundPolicy::InternalAllowed
        } else {
            OutboundPolicy::PublicOnly
        })
    }

    async fn labels(&self) -> Result<Vec<String>, TicketError> {
        Ok(tickets::parse_labels(Some(&self.settings.get(Setting::TicketLabels).await?)))
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        body: &Value,
        label: &str,
        headers: &[(String, String)],
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<String, CallError> {
        let policy = self.policy().await?;
        let encoded = vectispire_domain::wire::to_wire_string(body);
        Ok(self.post.send(method, url, Some(&encoded), policy, label, headers, trust).await?)
    }

    async fn get(
        &self,
        url: &str,
        label: &str,
        headers: &[(String, String)],
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<Option<Value>, CallError> {
        let policy = self.policy().await?;
        let Some(text) = self.post.get(url, policy, label, headers, trust).await? else { return Ok(None) };
        serde_json::from_str(&text).map(Some).map_err(|unreadable| CallError::Refused(format!("{label}: {unreadable}")))
    }

    fn read(answer: &str) -> Result<Value, CallError> {
        serde_json::from_str(answer)
            .map_err(|_| CallError::Refused("The tracker answered with something that is not JSON".to_owned()))
    }

    async fn create_gitlab(
        &self,
        base: &str,
        title: &str,
        body: &str,
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<Ticket, CallError> {
        let url = format!("{base}/api/v4/projects/{}/issues", tickets::url_encode(&self.project().await?));
        let payload = json!({"title": title, "description": body, "labels": self.labels().await?.join(",")});
        let headers = vec![("PRIVATE-TOKEN".to_owned(), self.token().await?)];
        let answer = Self::read(&self.send(Method::Post, &url, &payload, "GitLab", &headers, trust).await?)?;
        Ok(Ticket { reference: format!("#{}", as_text(answer.get("iid"))), url: as_text(answer.get("web_url")) })
    }

    async fn close_gitlab(
        &self,
        base: &str,
        iid: &str,
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<(), CallError> {
        let url = format!("{base}/api/v4/projects/{}/issues/{iid}", tickets::url_encode(&self.project().await?));
        let headers = vec![("PRIVATE-TOKEN".to_owned(), self.token().await?)];
        // PUT, GitLab's "edit an issue": a POST on this path is not routed.
        self.send(Method::Put, &url, &json!({"state_event": "close"}), "GitLab", &headers, trust).await.map(|_| ())
    }

    async fn github_headers(&self) -> Result<Vec<(String, String)>, TicketError> {
        Ok(vec![
            ("Authorization".to_owned(), format!("Bearer {}", self.token().await?)),
            ("Accept".to_owned(), "application/vnd.github+json".to_owned()),
        ])
    }

    /// The configured repository as a path, or a refusal: a value stored before the check must not steer the token's
    /// request either.
    async fn github_repository(&self) -> Result<String, CallError> {
        let project = self.project().await?;
        tickets::github_repository_path(Some(&project)).ok_or_else(|| {
            CallError::Refused(format!("the GitHub project \"{project}\" is not an owner/repository pair"))
        })
    }

    async fn create_github(
        &self,
        base: &str,
        title: &str,
        body: &str,
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<Ticket, CallError> {
        let url = format!("{base}/repos/{}/issues", self.github_repository().await?);
        let mut payload = Map::new();
        payload.insert("title".into(), title.into());
        payload.insert("body".into(), body.into());
        let labels = self.labels().await?;
        if !labels.is_empty() {
            payload.insert("labels".into(), labels.into());
        }
        let headers = self.github_headers().await?;
        let answer =
            Self::read(&self.send(Method::Post, &url, &Value::Object(payload), "GitHub", &headers, trust).await?)?;
        Ok(Ticket { reference: format!("#{}", as_text(answer.get("number"))), url: as_text(answer.get("html_url")) })
    }

    async fn close_github(
        &self,
        base: &str,
        number: &str,
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<(), CallError> {
        let url = format!("{base}/repos/{}/issues/{number}", self.github_repository().await?);
        let headers = self.github_headers().await?;
        let body = json!({"state": "closed", "state_reason": "completed"});
        self.send(Method::Patch, &url, &body, "GitHub", &headers, trust).await.map(|_| ())
    }

    async fn basic(&self) -> Result<Option<String>, TicketError> {
        let user = self.trimmed(Setting::TicketUser).await?;
        if user.is_empty() {
            return Ok(None);
        }
        let token = self.token().await?;
        Ok(Some(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}")))))
    }

    async fn jira_headers(&self) -> Result<Vec<(String, String)>, TicketError> {
        let mut headers = vec![("Accept".to_owned(), "application/json".to_owned())];
        if let Some(basic) = self.basic().await? {
            headers.push(("Authorization".to_owned(), basic));
        }
        Ok(headers)
    }

    async fn servicenow_headers(&self) -> Result<Vec<(String, String)>, TicketError> {
        let authorization = match self.basic().await? {
            Some(basic) => basic,
            None => format!("Bearer {}", self.token().await?),
        };
        Ok(vec![("Accept".to_owned(), "application/json".to_owned()), ("Authorization".to_owned(), authorization)])
    }

    async fn create_jira(
        &self,
        base: &str,
        title: &str,
        body: &str,
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<Ticket, CallError> {
        let mut fields = Map::new();
        fields.insert("project".into(), json!({"key": self.project().await?}));
        fields.insert("summary".into(), title.into());
        fields.insert(
            "issuetype".into(),
            json!({"name": self.settings.get(Setting::TicketIssueType).await.map_err(TicketError::from)?}),
        );
        fields.insert("description".into(), format::atlassian_document(body));
        let labels = self.labels().await?;
        if !labels.is_empty() {
            fields.insert("labels".into(), labels.into());
        }
        let headers = self.jira_headers().await?;
        let answer = Self::read(
            &self
                .send(
                    Method::Post,
                    &format!("{base}/rest/api/3/issue"),
                    &json!({"fields": fields}),
                    "Jira",
                    &headers,
                    trust,
                )
                .await?,
        )?;
        let key = as_text(answer.get("key"));
        let url = if key.is_empty() { String::new() } else { format!("{base}/browse/{key}") };
        Ok(Ticket { reference: key, url })
    }

    /// Moves the issue to a "done" status by the transition its own workflow offers — asked for, never assumed.
    async fn close_jira(
        &self,
        base: &str,
        key: &str,
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<(), CallError> {
        let url = format!("{base}/rest/api/3/issue/{key}/transitions");
        let headers = self.jira_headers().await?;
        let offered = self
            .get(&url, "Jira", &headers, trust)
            .await?
            .ok_or_else(|| CallError::Refused(format!("Jira lists no transitions for {key}.")))?;
        let transition = offered
            .get("transitions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|candidate| {
                candidate.pointer("/to/statusCategory/key").and_then(Value::as_str) == Some("done")
                    || as_text(candidate.pointer("/to/statusCategory/key")) == "done"
            })
            .map(|candidate| as_text(candidate.get("id")));
        let Some(transition) =
            transition.filter(|id| (1..=10).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit()))
        else {
            return Err(CallError::Refused(format!(
                "No transition to a done status is available for {key} in its workflow; it was left open."
            )));
        };
        self.send(Method::Post, &url, &json!({"transition": {"id": transition}}), "Jira", &headers, trust)
            .await
            .map(|_| ())
    }

    async fn create_servicenow(
        &self,
        base: &str,
        title: &str,
        body: &str,
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<Ticket, CallError> {
        let mut payload = Map::new();
        payload.insert("short_description".into(), title.into());
        payload.insert("description".into(), body.into());
        payload.insert("category".into(), "Security".into());
        payload.insert("urgency".into(), "1".into());
        payload.insert("impact".into(), "1".into());
        let headers = self.servicenow_headers().await?;
        let answer = Self::read(
            &self
                .send(
                    Method::Post,
                    &format!("{base}/api/now/table/incident"),
                    &Value::Object(payload),
                    "ServiceNow",
                    &headers,
                    trust,
                )
                .await?,
        )?;
        let number = as_text(answer.pointer("/result/number"));
        let sys_id = as_text(answer.pointer("/result/sys_id"));
        let url =
            format!("{base}/nav_to.do?uri=incident.do?sys_id={}", if sys_id.is_empty() { &number } else { &sys_id });
        Ok(Ticket { reference: if number.is_empty() { sys_id } else { number }, url })
    }

    /// Closes an incident by its `sys_id`, resolving a number first: the Table API addresses a record by `sys_id`.
    async fn close_servicenow(
        &self,
        base: &str,
        incident: &str,
        resolution: &str,
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<(), CallError> {
        let sys_id = if is_sys_id(incident) {
            incident.to_owned()
        } else {
            self.servicenow_sys_id(base, incident, trust).await?
        };
        let headers = self.servicenow_headers().await?;
        let body = json!({
            "state": "6",
            "close_code": "Solved (Permanently)",
            "close_notes": format!("Resolved by Vectispire: {resolution}"),
        });
        self.send(
            Method::Patch,
            &format!("{base}/api/now/table/incident/{sys_id}"),
            &body,
            "ServiceNow",
            &headers,
            trust,
        )
        .await
        .map(|_| ())
    }

    /// The `sys_id` of the incident with this number — checked before it becomes a path segment.
    async fn servicenow_sys_id(
        &self,
        base: &str,
        number: &str,
        trust: Option<&vectispire_cp_outbound::PinnedCa>,
    ) -> Result<String, CallError> {
        let url = format!(
            "{base}/api/now/table/incident?sysparm_query={}&sysparm_fields=sys_id&sysparm_limit=1",
            tickets::url_encode(&format!("number={number}"))
        );
        let headers = self.servicenow_headers().await?;
        let found = self
            .get(&url, "ServiceNow", &headers, trust)
            .await?
            .ok_or_else(|| CallError::Refused(format!("ServiceNow does not know incident {number}.")))?;
        let sys_id = as_text(found.pointer("/result/0/sys_id"));
        if !is_sys_id(&sys_id) {
            return Err(CallError::Refused(format!("ServiceNow returned no usable sys_id for incident {number}.")));
        }
        Ok(sys_id)
    }
}

/// The token and the inbound secret, for the encryption census.
impl vectispire_cp_crypto::SealedStore for TicketService {
    fn census(&self) -> vectispire_cp_crypto::CensusFuture<'_> {
        Box::pin(async move {
            let token = self.settings.get(Setting::TicketToken).await.map_err(|e| e.to_string())?;
            let secret = self.settings.get(Setting::TicketWebhookSecret).await.map_err(|e| e.to_string())?;
            Ok(vec![
                vectispire_cp_crypto::Counter::new(
                    "Tracker access token",
                    "set the token again on the ticketing settings",
                )
                .count(self.encryption.seal_of(Some(&token), TOKEN_CONTEXT).await)
                .done(),
                vectispire_cp_crypto::Counter::new(
                    "Inbound tracker webhook secret",
                    "set the secret again on the ticketing settings, and in the tracker",
                )
                .count(self.encryption.seal_of(Some(&secret), WEBHOOK_SECRET_CONTEXT).await)
                .done(),
            ])
        })
    }
}

/// Jackson's `path(…).asText("")`.
fn as_text(node: Option<&Value>) -> String {
    vectispire_domain::java::as_text(node, Some("")).unwrap_or_default()
}

/// 32 lower-case hex digits, nothing a path could carry.
fn is_sys_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
