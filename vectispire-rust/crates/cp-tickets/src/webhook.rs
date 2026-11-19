//! `TicketingWebhookService` and `WebhookRefusals`: what an issue tracker's webhook may change, and how its payload is
//! read — the system's only anonymous door.
//!
//! - **Shut until a secret is set**, and a secret no key can read refuses like a wrong signature.
//! - **Once per body**: a signed delivery captured on the wire was valid for ever; the body's hash is remembered thirty
//!   days, and a replay answers "already processed".
//! - **A suspended tracker's delivery is accepted and ignored** — after the secret, before anything is read.
//! - **A tracker's refusal is queued for approval, never settled**: `will_not_fix`, or `not_affected` for an explicit
//!   false positive only (decision 0041); a person's settled decision is not moved, and a disagreement is audited.
//! - **The author is the integration**; the name the tracker reports goes into the comment, as reported data.
//! - **Refusals are audited sparingly** ([`WebhookRefusals`]): the chained log is not anybody's to fill.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use vectispire_cp_access::independence::ApproverIndependence;
use vectispire_cp_audit::{AuditLog, AuditOperation, Clock, Record, RequestActor};
use vectispire_cp_db::{Db, Mode};
use vectispire_cp_issues::{IssueCatalog, IssueTriageService, IssueView, Triage, TriageRequest, VexJustification};
use vectispire_cp_settings::Integrations;
use vectispire_domain::bounded_text;
use vectispire_domain::integrations::Integration;
use vectispire_domain::tickets::{self, Presented, TicketProvider, TrackerState, Verdict};
use vectispire_domain::triage_status::TriageStatus;

use crate::error::TicketError;
use crate::persistence;
use crate::service::{TicketService, WebhookSecret};
use crate::sweep::one_line;

/// How much of the user name a tracker reports is kept in an audit description.
const CLAIMED_AUTHOR_LENGTH: usize = 200;
/// The review date proposed with a tracker's refusal: a proposal, granted by a person with their own date.
const PROPOSED_ACCEPTANCE_REVIEW_DAYS: i64 = 90;
/// How long a delivery's body is remembered for the replay check.
const REPLAY_WINDOW: Duration = Duration::days(30);

/// What a delivery came to — each a different answer to the tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The secret is configured and the call does not carry it, or the secret cannot be read.
    Rejected,
    /// No secret is configured, so nothing is accepted.
    NotConfigured,
    Malformed,
    NoReference,
    /// This exact body was already acted on.
    AlreadyProcessed,
    /// Authenticated, and read no further: the tracker's integration is switched off.
    IgnoredIntegrationDisabled(Integration),
    NoMatchingIssue(String),
    /// Every issue carrying the reference, oldest first — never empty.
    Synced {
        issue_ids: Vec<i64>,
        ticket_ref: String,
        action_taken: String,
    },
}

/// The service.
pub struct TicketingWebhookService {
    db: Db,
    issues: IssueCatalog,
    audit: Arc<AuditLog>,
    tickets: Arc<TicketService>,
    refusals: Arc<WebhookRefusals>,
    independence: ApproverIndependence,
    clock: Arc<dyn Clock>,
    integrations: Integrations,
    /// The trackers whose deliveries were last found ignored: the log says when a suspension begins and ends.
    ignoring: Mutex<BTreeSet<String>>,
}

impl std::fmt::Debug for TicketingWebhookService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketingWebhookService").finish_non_exhaustive()
    }
}

/// What the event says, for one tracker's payload.
struct Event {
    ticket_ref: String,
    status: String,
    comment: String,
    author: String,
    refused_or_false_positive: bool,
    false_positive: bool,
    /// The ticket's own address — GitHub and GitLab only.
    url: Option<String>,
    /// Its repository — GitHub and GitLab only.
    project: Option<String>,
}

fn text(node: Option<&Value>) -> String {
    vectispire_domain::java::as_text(node, Some("")).unwrap_or_default()
}

fn text_or_none(node: Option<&Value>) -> Option<String> {
    vectispire_domain::java::as_text(node, None)
}

fn path<'a>(root: &'a Value, fields: &[&str]) -> Option<&'a Value> {
    fields.iter().try_fold(root, |node, field| vectispire_domain::java::path(Some(node), field))
}

fn lower(value: &str) -> String {
    vectispire_domain::java::to_lower_root(value)
}

fn extract(provider: TicketProvider, root: &Value) -> Option<Event> {
    match provider {
        TicketProvider::Gitlab => {
            let state = text(path(root, &["object_attributes", "state"]));
            let title = lower(&text(path(root, &["object_attributes", "title"])));
            let comment = text(path(root, &["object_attributes", "description"]));
            let false_positive = title.contains("false positive") || lower(&comment).contains("false positive");
            let wont_fix = state.eq_ignore_ascii_case("closed")
                && (title.contains("wontfix") || title.contains("won't fix") || false_positive);
            Some(Event {
                ticket_ref: text(path(root, &["object_attributes", "iid"])),
                status: state,
                comment,
                author: text(path(root, &["user", "username"])),
                refused_or_false_positive: wont_fix || false_positive,
                false_positive,
                url: text_or_none(path(root, &["object_attributes", "url"])),
                project: text_or_none(path(root, &["project", "path_with_namespace"])),
            })
        }
        TicketProvider::Github => {
            let body = text(path(root, &["issue", "body"]));
            let state_reason = text(path(root, &["issue", "state_reason"]));
            // `not_planned` says nothing of reachability: a refusal. Only the words make a false positive.
            let false_positive = lower(&body).contains("false positive");
            Some(Event {
                ticket_ref: text(path(root, &["issue", "number"])),
                status: text(path(root, &["issue", "state"])),
                comment: body,
                author: text(path(root, &["sender", "login"])),
                refused_or_false_positive: false_positive || state_reason.eq_ignore_ascii_case("not_planned"),
                false_positive,
                url: text_or_none(path(root, &["issue", "html_url"])),
                project: text_or_none(path(root, &["repository", "full_name"])),
            })
        }
        TicketProvider::Jira => {
            let resolution = lower(&text(path(root, &["issue", "fields", "resolution", "name"])));
            let false_positive = resolution.contains("false positive") || resolution.contains("cannot reproduce");
            let wont_fix = false_positive
                || ["won't fix", "wontfix", "declined", "rejected"].iter().any(|word| resolution.contains(word));
            Some(Event {
                ticket_ref: text(path(root, &["issue", "key"])),
                status: text(path(root, &["issue", "fields", "status", "name"])),
                comment: text(path(root, &["comment", "body"])),
                author: text(path(root, &["user", "displayName"])),
                refused_or_false_positive: wont_fix,
                false_positive,
                url: None,
                project: None,
            })
        }
        TicketProvider::Servicenow => {
            let number = text(path(root, &["number"]));
            let sys_id = text(path(root, &["sys_id"]));
            let code = lower(&text(path(root, &["close_code"])));
            let false_positive = code.contains("false positive") || code.contains("not an issue");
            let wont_fix =
                false_positive || ["won't fix", "risk accepted", "withdrawn"].iter().any(|word| code.contains(word));
            Some(Event {
                ticket_ref: if number.is_empty() { sys_id } else { number },
                status: text(path(root, &["state"])),
                comment: text(path(root, &["close_notes"])),
                author: text(path(root, &["closed_by"])),
                refused_or_false_positive: wont_fix,
                false_positive,
                url: None,
                project: None,
            })
        }
        TicketProvider::None => None,
    }
}

/// `Sessions.hashOf`: lower-case hex SHA-256 of the UTF-8 bytes.
fn hash_of(value: &str) -> String {
    Sha256::digest(value.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn without_trailing_slash(url: &str) -> &str {
    let trimmed = vectispire_domain::java::trim(url);
    trimmed.strip_suffix('/').unwrap_or(trimmed)
}

impl TicketingWebhookService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        issues: IssueCatalog,
        audit: Arc<AuditLog>,
        tickets: Arc<TicketService>,
        refusals: Arc<WebhookRefusals>,
        independence: ApproverIndependence,
        clock: Arc<dyn Clock>,
        integrations: Integrations,
    ) -> TicketingWebhookService {
        TicketingWebhookService {
            db,
            issues,
            audit,
            tickets,
            refusals,
            independence,
            clock,
            integrations,
            ignoring: Mutex::new(BTreeSet::new()),
        }
    }

    async fn record_refusal(&self, origin: &RequestActor, description: String) {
        if let Some(note) = self.refusals.refused(origin.ip_address.as_deref(), self.clock.now()) {
            self.audit
                .record(Record::of(
                    AuditOperation::LoginBlocked,
                    "ticket_webhook",
                    &format!("{description}{note}"),
                    Some("anonymous"),
                ))
                .await;
        }
    }

    pub async fn handle(
        &self,
        provider: TicketProvider,
        raw: &str,
        presented: &Presented,
        origin: &RequestActor,
    ) -> Result<Outcome, TicketError> {
        let address = origin.ip_address.clone().unwrap_or_else(|| "null".to_owned());
        let name = provider.constant();
        let secret = self.tickets.webhook_secret().await?;
        if secret == WebhookSecret::Absent {
            self.record_refusal(
                origin,
                format!("Refused {name} webhook from {address}: no webhook secret is configured"),
            )
            .await;
            return Ok(Outcome::NotConfigured);
        }
        let verdict = match &secret {
            WebhookSecret::Present(value) => tickets::verify(provider, Some(value), presented, raw),
            _ => Verdict::Rejected,
        };
        if verdict != Verdict::Accepted {
            let description = if secret == WebhookSecret::Unreadable {
                format!("Refused {name} webhook: the stored secret cannot be decrypted, from {address}")
            } else {
                format!("Rejected unsigned or wrongly signed {name} webhook from {address}")
            };
            self.record_refusal(origin, description).await;
            return Ok(Outcome::Rejected);
        }

        // **Once per body**, by the hash of what the signature covers.
        let now = self.clock.now();
        let now = now.replace_microsecond(now.microsecond()).unwrap_or(now);
        persistence::delete_deliveries_before(&self.db, now.saturating_sub(REPLAY_WINDOW)).await?;
        let body_hash = hash_of(&format!("{}:{raw}", provider.wire_name()));
        if let Err(refused) = persistence::insert_delivery(&self.db, &body_hash, provider.wire_name(), now).await {
            // Asked rather than trusting the error's kind: a database that is down is not a replay.
            if !persistence::delivery_exists(&self.db, &body_hash).await? {
                return Err(refused.into());
            }
            tracing::info!("{name} webhook body already processed; ignored.");
            return Ok(Outcome::AlreadyProcessed);
        }

        // The configured tracker's suspension counts whatever path the delivery came by: one secret authenticates
        // every provider's path.
        let integration = match self.tickets.standing().await? {
            Some(standing) if standing.state == TrackerState::Suspended => standing.integration,
            _ => provider.integration().ok_or_else(|| TicketError::Failed("no integration".to_owned()))?,
        };
        let key = integration.key();
        if !self.integrations.is_enabled(integration).await? {
            if self.ignoring.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(key.clone()) {
                tracing::info!(
                    "Ticket webhook: the {key} integration is disabled. Its deliveries are authenticated, answered 200 and \
                     ignored — no triage and no ticket state is changed — until a platform governor re-enables it with \
                     PUT /api/v1/integrations/{key}/enabled."
                );
            }
            return Ok(Outcome::IgnoredIntegrationDisabled(integration));
        }
        if self.ignoring.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&key) {
            tracing::info!("Ticket webhook: the {key} integration is enabled again; its deliveries are applied again.");
        }

        let Ok(payload) = serde_json::from_str::<Value>(raw) else { return Ok(Outcome::Malformed) };
        let Some(event) =
            extract(provider, &payload).filter(|event| !vectispire_domain::java::is_blank(&event.ticket_ref))
        else {
            return Ok(Outcome::NoReference);
        };

        // **Every issue carrying the reference**: one ticket may stand for several findings.
        let configured_provider = self.tickets.provider().await?;
        let project = self.tickets.project().await?;
        let matching: Vec<IssueView> = self
            .issues
            .with_ticket(&event.ticket_ref)
            .await?
            .into_iter()
            .filter(|issue| same_ticket(issue, &event, provider, configured_provider, &project))
            .collect();
        if matching.is_empty() {
            tracing::info!(
                "Received webhook for ticket {} from {name} but no corresponding Vectispire issue found.",
                one_line(&event.ticket_ref)
            );
            return Ok(Outcome::NoMatchingIssue(event.ticket_ref));
        }
        let mut actions = Vec::new();
        for issue in &matching {
            let action = self.sync(issue, &event, provider, origin).await?;
            actions.push(if matching.len() == 1 { action } else { format!("issue {}: {action}", issue.id) });
        }
        Ok(Outcome::Synced {
            issue_ids: matching.iter().map(|issue| issue.id).collect(),
            ticket_ref: event.ticket_ref,
            action_taken: actions.join("; "),
        })
    }

    /// What one issue carrying the ticket becomes, as the tracker's event says.
    async fn sync(
        &self,
        issue: &IssueView,
        event: &Event,
        provider: TicketProvider,
        origin: &RequestActor,
    ) -> Result<String, TicketError> {
        let name = provider.constant();
        let author = format!("{name}_webhook");
        let entry = |operation, description: String| {
            let mut record = Record::of(operation, &issue.id.to_string(), &description, Some(&author));
            record.ip_address = origin.ip_address.clone();
            record.user_agent = origin.user_agent.clone();
            record
        };
        if !event.refused_or_false_positive {
            let action = format!("Ticket updated on {name} (status: {})", event.status);
            let claimed = if vectispire_domain::java::is_blank(&event.author) {
                String::new()
            } else {
                format!(
                    " (reported by the tracker as: {})",
                    bounded_text::clip(Some(&event.author), CLAIMED_AUTHOR_LENGTH).unwrap_or_default()
                )
            };
            self.audit
                .record(entry(
                    AuditOperation::TicketSynced,
                    format!(
                        "Ticket update received from {name} for {} (status: {}){claimed}",
                        event.ticket_ref, event.status
                    ),
                ))
                .await;
            return Ok(action);
        }

        let status = if event.false_positive { TriageStatus::NotAffected } else { TriageStatus::WillNotFix };
        let justification = event.false_positive.then_some(VexJustification::VulnerableCodeNotInExecutePath);
        let claimed = if vectispire_domain::java::is_blank(&event.author) {
            String::new()
        } else {
            format!(" (reported by the tracker as: {})", event.author)
        };
        let said = if vectispire_domain::java::is_blank(&event.comment) {
            format!("Status updated from {name} ticket {}", event.ticket_ref)
        } else {
            event.comment.clone()
        };
        // Clipped, not refused: the tracker wrote it, and a refusal would drop the decision it carries.
        let comment = bounded_text::clip(Some(&format!("{said}{claimed}")), Triage::MAX_COMMENT_LENGTH)
            .unwrap_or_default()
            .to_owned();

        // **A person's settled decision is not moved by a payload**: the tracker's word is recorded beside it.
        if let Some(settled) = TriageStatus::from_wire_name(&issue.triage_status).filter(TriageStatus::is_settled) {
            let agrees = settled == status;
            let action = if agrees {
                format!("Tracker agrees with the settled decision {}; nothing changed", settled.wire_name())
            } else {
                format!("Tracker says {}, the issue stays {}; nothing changed", status.wire_name(), settled.wire_name())
            };
            self.audit
                .record(entry(
                    if agrees { AuditOperation::TicketSynced } else { AuditOperation::TriageContradictedByTracker },
                    format!("{name} ticket {}: {action} — {comment}", event.ticket_ref),
                ))
                .await;
            return Ok(action);
        }

        // **Queued, never settled**: a tracker's decision goes to approval like any dismissal; an accepted risk
        // needs a review date, so one is proposed.
        let request = TriageRequest {
            status: Some(status),
            actor: Some(author.clone()),
            justification,
            comment: Some(comment),
            expires_in_days: (status == TriageStatus::WillNotFix).then_some(PROPOSED_ACCEPTANCE_REVIEW_DAYS),
        };
        let mut tx = self.db.begin(Mode::ReadWrite).await.map_err(TicketError::failed)?;
        let triaged = IssueTriageService::triage(&mut tx, issue.id, &request, false, &self.independence).await?;
        tx.commit().await.map_err(TicketError::failed)?;
        let action = format!(
            "Queued as {} ({}{}) from {author}",
            triaged.triage_status,
            status.wire_name(),
            justification.map(|j| format!(", {}", j.wire_name())).unwrap_or_default()
        );
        self.audit
            .record(entry(
                AuditOperation::TicketSynced,
                format!("Issue triage automatically synchronized from {name} ticket {}: {action}", event.ticket_ref),
            ))
            .await;
        Ok(action)
    }
}

/// Whether the issue's ticket is the event's, and not merely one with the same number: a GitHub or GitLab number is a
/// repository's, so it matches the ticket's own URL, or — attached without one — the configured repository.
fn same_ticket(
    issue: &IssueView,
    event: &Event,
    provider: TicketProvider,
    configured: TicketProvider,
    project: &str,
) -> bool {
    if provider != TicketProvider::Github && provider != TicketProvider::Gitlab {
        return true;
    }
    if let Some(url) = issue.ticket_url.as_deref().filter(|url| !vectispire_domain::java::is_blank(url)) {
        return event.url.as_deref().is_some_and(|event_url| {
            equals_ignore_case(without_trailing_slash(url), without_trailing_slash(event_url))
        });
    }
    configured == provider
        && !vectispire_domain::java::is_blank(project)
        && event.project.as_deref().is_some_and(|event_project| equals_ignore_case(project, event_project))
}

fn equals_ignore_case(left: &str, right: &str) -> bool {
    left.chars().count() == right.chars().count()
        && left
            .chars()
            .zip(right.chars())
            .all(|(a, b)| a == b || a.to_uppercase().eq(b.to_uppercase()) || a.to_lowercase().eq(b.to_lowercase()))
}

/// `WebhookRefusals`: which refused deliveries earn an audit entry — the first from an address in ten minutes, once
/// more at the twentieth, and never more than a hundred per window across every address. In memory, per instance.
#[derive(Debug, Default)]
pub struct WebhookRefusals {
    state: Mutex<RefusalState>,
}

#[derive(Debug, Default)]
struct RefusalState {
    tallies: HashMap<String, Tally>,
    /// Access order, for the eviction of the least recently refused address.
    touched: u64,
    budget_window_start: Option<OffsetDateTime>,
    budget_spent: u32,
}

#[derive(Debug)]
struct Tally {
    start: OffsetDateTime,
    count: u32,
    touched: u64,
}

impl WebhookRefusals {
    pub const WINDOW: Duration = Duration::minutes(10);
    pub const CEILING: u32 = 20;
    pub const GLOBAL_BUDGET: u32 = 100;
    const MAX_ADDRESSES: usize = 10_000;

    /// Counts one refusal; what to append to the entry's description, or `None` when no entry is to be written.
    pub fn refused(&self, address: Option<&str>, now: OffsetDateTime) -> Option<String> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = address.unwrap_or("").to_owned();
        state.touched = state.touched.saturating_add(1);
        let touched = state.touched;
        let fresh = state.tallies.get(&key).is_none_or(|tally| now >= tally.start.saturating_add(Self::WINDOW));
        if fresh {
            state.tallies.insert(key.clone(), Tally { start: now, count: 0, touched });
            if state.tallies.len() > Self::MAX_ADDRESSES
                && let Some(eldest) =
                    state.tallies.iter().min_by_key(|(_, tally)| tally.touched).map(|(k, _)| k.clone())
            {
                state.tallies.remove(&eldest);
            }
        }
        let count = {
            let tally = state.tallies.get_mut(&key)?;
            tally.count = tally.count.saturating_add(1);
            tally.touched = touched;
            tally.count
        };
        let minutes = Self::WINDOW.whole_minutes();
        let note = if count == 1 {
            format!(" (first in {minutes} min from this address; more are counted, not recorded)")
        } else if count == Self::CEILING {
            format!(" ({} refusals from this address in {minutes} min)", Self::CEILING)
        } else {
            return None;
        };
        if state.budget_window_start.is_none_or(|start| now >= start.saturating_add(Self::WINDOW)) {
            state.budget_window_start = Some(now);
            state.budget_spent = 0;
        }
        if state.budget_spent >= Self::GLOBAL_BUDGET {
            return None;
        }
        state.budget_spent = state.budget_spent.saturating_add(1);
        Some(if state.budget_spent == Self::GLOBAL_BUDGET {
            format!("{note}; webhook refusals are not recorded again for {minutes} min")
        } else {
            note
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_recorded_first_and_at_the_ceiling() {
        let refusals = WebhookRefusals::default();
        let at = OffsetDateTime::UNIX_EPOCH;
        assert!(refusals.refused(Some("a"), at).unwrap().starts_with(" (first in 10 min"));
        for _ in 2..WebhookRefusals::CEILING {
            assert_eq!(refusals.refused(Some("a"), at), None);
        }
        assert_eq!(refusals.refused(Some("a"), at).as_deref(), Some(" (20 refusals from this address in 10 min)"));
        assert!(refusals.refused(Some("a"), at.saturating_add(WebhookRefusals::WINDOW)).is_some());
    }
}
