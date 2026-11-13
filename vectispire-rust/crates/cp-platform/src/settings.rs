//! The rules behind the settings screen — `SettingsAdministrationService`: what a reader may see of the catalog,
//! and what a save may change.
//!
//! **The catalog decides everything.** A key that is not in it is refused on write, so the table cannot fill with
//! keys no service reads — the exact state that makes an operator believe they configured something.
//!
//! **Every write is audited**, like any administration action: moving the notification threshold from high to
//! critical changes what the organisation sees, and that is a decision one wants to be able to date.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::future::BoxFuture;
use time::OffsetDateTime;
use vectispire_cp_audit::{AuditLog, AuditOperation, Clock, RequestActor, Signal};
use vectispire_cp_db::{Db, Mode, Tx};
use vectispire_cp_settings::{Integrations, IntegrationsError, Setting, Settings, SettingsError};
use vectispire_domain::integrations::Integration;

use crate::forms::{is_github, is_github_repository, is_iso_local_date, is_truthy, java_trim};

/// `SecurityEventType.SECURITY_SETTING_CHANGED` (VECTI-SEC-019), by its constant's name: a save of a setting that
/// decides what the deployment protects is forwarded to the SOC; the SLA windows and retention periods are not.
pub const SECURITY_SETTING_CHANGED: Signal = Signal("SECURITY_SETTING_CHANGED");

/// What a seam answered with when it failed: the save stops, and nothing was written.
pub type CollaboratorError = Box<dyn std::error::Error + Send + Sync>;

/// Who reads or saves: the name a save's acceptance record carries, and the two role properties the rules ask —
/// resolved from the account by `access` (`Role.isAdministrative`, `Role.governsPlatform`), which this module does
/// not depend on yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub username: String,
    pub administrative: bool,
    pub governs_platform: bool,
}

/// `access`' `TriageApprovers`: whether four-eyes could be honoured.
pub trait Approvers: Send + Sync {
    /// An active account that may approve a triage.
    fn any_active(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>>;
    /// Two active accounts that may publish a checklist template — its author may not, under four-eyes.
    fn two_can_publish_templates(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>>;
    /// Two active accounts that may sign off a project checklist — none of its authors may.
    fn two_can_sign_off_checklists(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>>;
}

/// `tickets`' `TicketService.caToPin`: a pinned tracker CA is read as a forge connection's is.
pub trait Tracker: Send + Sync {
    /// `None` when the PEM is a CA this deployment would pin; otherwise the refusal, in the words the form shows.
    fn refuse_ca(&self, pem: &str) -> Option<String>;
}

/// The AI destination a save will produce: the provider and URLs as this save leaves them — `None` for a URL the
/// save does not touch, which `ai` reads from what is stored, or its default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AiAfter<'a> {
    pub provider: &'a str,
    pub openai_url: Option<&'a str>,
    pub ollama_url: Option<&'a str>,
    pub allow_remote: bool,
}

/// `ai`'s `AiReviewService`: the guard that keeps code on the internal network unless sending it off-site was
/// acknowledged, and the record of whose acknowledgement it was.
pub trait AiDestination: Send + Sync {
    /// `requireLocalUnlessAcknowledged`: `Some(refusal)` when the URL the save produces is public and the remote
    /// switch is off — the outbound guard's words (`UnsafeUrlException`).
    fn refuse_destination<'a>(&'a self, after: AiAfter<'a>)
    -> BoxFuture<'a, Result<Option<String>, CollaboratorError>>;
    /// Stamps who turned the public endpoint on, and when — by the server, never from the wire — in the save's
    /// transaction, so the record describes a configuration that was written with it.
    fn record_risk_acknowledgement<'a>(
        &'a self,
        tx: &'a mut Tx,
        by: &'a str,
        at: OffsetDateTime,
    ) -> BoxFuture<'a, Result<(), CollaboratorError>>;
    /// Erases that record when the switch goes off, in the save's transaction.
    fn clear_risk_acknowledgement<'a>(&'a self, tx: &'a mut Tx) -> BoxFuture<'a, Result<(), CollaboratorError>>;
}

/// `ai`'s `AiReviewService`, as far as the endpoint check reads it: the configured provider, model and address, and
/// what the endpoint answers. The AI module is not ported; the binary fills this when it is.
pub trait AiEndpoint: Send + Sync {
    /// `provider().wireName()`: `ollama` or `openai`, an unknown stored value read as `ollama` (`AiProvider.of`).
    fn provider(&self) -> BoxFuture<'_, Result<String, CollaboratorError>>;
    /// `selectedModel()`.
    fn selected_model(&self) -> BoxFuture<'_, Result<String, CollaboratorError>>;
    /// `allowRemote()`: whether sending code off-site was acknowledged.
    fn allow_remote(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>>;
    /// `validatedUrl()`: the address the provider is called at, or the outbound guard's refusal — which quotes it.
    fn validated_url(&self) -> BoxFuture<'_, Result<Result<String, String>, CollaboratorError>>;
    /// `baseUrl()`: the configured address, unchecked.
    fn base_url(&self) -> BoxFuture<'_, Result<String, CollaboratorError>>;
    /// `hasOpenAiKey()`.
    fn has_openai_key(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>>;
    /// The models the endpoint answers with, or `None` when it did not answer — where Java's `availableModels` falls
    /// back to its suggestion lists, which `checkAiEndpoint` then tells apart by comparing.
    fn available_models(&self) -> BoxFuture<'_, Result<Option<Vec<String>>, CollaboratorError>>;
}

/// `AiReviewService.UNAVAILABLE`: what opens the refusal of a feature whose provider is disabled.
pub const AI_UNAVAILABLE: &str =
    "AI unavailable — provider disabled. Nothing is sent to the other provider in its place.";

/// `EndpointCheck`: the configured AI endpoint's answer to "are you there, and do you hold the model?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointCheck {
    pub reachable: bool,
    pub model_installed: bool,
    pub model: String,
    /// `None` for a caller who may not read the address.
    pub url: Option<String>,
    pub models: Vec<String>,
    pub detail: String,
    pub provider: String,
    pub remote_allowed: bool,
}

/// Why a save was refused, or failed.
#[derive(Debug, thiserror::Error)]
pub enum AdministrationError {
    /// `InvalidInputException`: a 400, in words the form shows.
    #[error("{0}")]
    InvalidInput(String),
    /// `AccessDeniedException`: a 403 — this caller may not change this setting.
    #[error("{0}")]
    AccessDenied(String),
    /// `IntegrationDisabledException`: 409 `integration-disabled`, naming the integration in the member `integration`
    /// — opened by what the caller cannot have because of it (`lead`, empty for a save).
    #[error("{}", .integration.disabled_message(.lead))]
    IntegrationDisabled { integration: Integration, lead: &'static str },
    /// `UnsafeUrlException`: the AI destination the save would produce is refused by the outbound guard.
    #[error("{0}")]
    UnsafeUrl(String),
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error("the settings could not be written: {0}")]
    Storage(CollaboratorError),
    #[error("a module consulted by the save failed: {0}")]
    Collaborator(CollaboratorError),
}

/// One catalog entry as this reader may see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub setting: Setting,
    /// The effective value, default included, or `None` when it may not leave.
    pub value: Option<String>,
    /// Whether the key has a row of its own.
    pub configured: bool,
    /// The setting decides a rule rather than a parameter, and only the platform governor may write it.
    pub governor_only: bool,
    /// Only an administrator may change it.
    pub administrator_only: bool,
}

/// What a save changed, in the words its audit entry uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub count: usize,
    /// The changed keys, comma-separated — the audit entry's resource.
    pub keys: String,
    /// Each change as `key = value` — never a credential's value: those are refused before they get here.
    pub description: String,
}

/// What the settings screen's service is made of: the modules a save consults, behind their seams.
pub struct SettingsParts {
    pub db: Db,
    pub audit: AuditLog,
    pub approvers: Arc<dyn Approvers>,
    pub tracker: Arc<dyn Tracker>,
    pub ai: Arc<dyn AiDestination>,
    pub endpoint: Arc<dyn AiEndpoint>,
    /// The integrations' registry (decision 0040): a tracker, an AI provider or a notification channel a save starts
    /// using must be enabled.
    pub integrations: Integrations,
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SettingsParts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SettingsParts").field("integrations", &self.integrations).finish_non_exhaustive()
    }
}

/// The settings screen's service.
#[derive(Clone)]
pub struct SettingsAdministration {
    db: Db,
    settings: Settings,
    audit: AuditLog,
    approvers: Arc<dyn Approvers>,
    tracker: Arc<dyn Tracker>,
    ai: Arc<dyn AiDestination>,
    endpoint: Arc<dyn AiEndpoint>,
    integrations: Integrations,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SettingsAdministration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SettingsAdministration").field("audit", &self.audit).finish_non_exhaustive()
    }
}

struct Change {
    setting: Setting,
    value: String,
}

impl SettingsAdministration {
    pub fn new(parts: SettingsParts) -> SettingsAdministration {
        let SettingsParts { db, audit, approvers, tracker, ai, endpoint, integrations, clock } = parts;
        SettingsAdministration {
            settings: Settings::new(db.clone()),
            db,
            audit,
            approvers,
            tracker,
            ai,
            endpoint,
            integrations,
            clock,
        }
    }

    /// Every setting, as this reader may see it.
    ///
    /// **A sensitive setting's value only leaves for an administrator**: a webhook URL is a bearer capability, and
    /// whoever reads it can post where the team awaits the alerts. **A credential's value leaves for nobody**, an
    /// administrator included: what is stored is a ciphertext, of no use to a form that cannot re-submit it, and a
    /// liability in a browser tab and a proxy log. The catalog itself stays readable — the screen needs the labels.
    pub async fn catalog(&self, reader: Option<&Caller>) -> Result<Vec<Entry>, AdministrationError> {
        let stored = self.settings.stored().await?;
        let is_admin = reader.is_some_and(|reader| reader.administrative);
        Ok(Setting::ALL
            .into_iter()
            .map(|setting| Entry {
                setting,
                value: (!(setting.is_encrypted() || (setting.is_secret() && !is_admin)))
                    .then(|| stored.get(setting.key()).cloned().unwrap_or_else(|| setting.default_value().to_owned())),
                configured: stored.contains_key(setting.key()),
                governor_only: setting.governor_only(),
                administrator_only: setting.administrator_only(),
            })
            .collect())
    }

    /// Validates every change, then writes them all — **all validated before any is written**, since a partial
    /// write would leave the configuration half-way between two intended states; and the writes in one
    /// transaction, so a failure among them cannot either.
    ///
    /// `body` is the request's object in its order — the order the audit entry lists the changes in — with a JSON
    /// `null` as `None`, which is saved as empty. The first refusal, in that order, is the answer.
    pub async fn update(
        &self,
        body: &[(String, Option<String>)],
        writer: Option<&Caller>,
        actor: &RequestActor,
    ) -> Result<Applied, AdministrationError> {
        if body.is_empty() {
            return Err(AdministrationError::InvalidInput("No setting supplied.".to_owned()));
        }
        let mut changes: Vec<Change> = Vec::with_capacity(body.len());
        for (key, value) in body {
            let Some(setting) = Setting::by_key(key) else {
                return Err(AdministrationError::InvalidInput(format!("Unknown setting: \"{key}\".")));
            };
            let value = java_trim(value.as_deref().unwrap_or("")).to_owned();
            self.admit(setting, &value, writer).await?;
            changes.push(Change { setting, value });
        }

        let pending: HashMap<Setting, &str> =
            changes.iter().map(|change| (change.setting, change.value.as_str())).collect();

        // **The AI destination is checked against the state this save will produce**, not the stored one: half of
        // it may be in this very request.
        let previous_acknowledgement = self.settings.get(Setting::AiReviewAllowRemote).await?;
        let remote_after =
            pending.get(&Setting::AiReviewAllowRemote).copied().unwrap_or(previous_acknowledgement.as_str()) == "true";
        // **A disabled AI provider is not chosen** (decision 0040, lot I5): 409 integration-disabled, naming it, when
        // the provider moves to it or model review is turned on over it. Only on those changes: a provider the governor
        // switches off while it is configured is a state the switch makes on purpose — the features say "AI
        // unavailable" — and a screen sending the section back unchanged must not be refused for it. Checked, not
        // held: nothing is lost if a switch lands between this check and the write.
        let provider_now = ai_provider(&self.settings.get(Setting::AiReviewProvider).await?);
        let provider_after = pending.get(&Setting::AiReviewProvider).map_or(provider_now, |typed| ai_provider(typed));
        let provider_moves = pending.contains_key(&Setting::AiReviewProvider) && provider_after != provider_now;
        let review_turns_on = pending.get(&Setting::AiReviewEnabled).is_some_and(|value| *value == "true")
            && !self.settings.is_enabled(Setting::AiReviewEnabled).await?;
        if provider_moves || review_turns_on {
            self.require_enabled(integration("ai", provider_after)?).await?;
        }
        // **Nor is a disabled notification channel configured** (lot I6): a URL, recipients or a switch that would send
        // to it. Asked once, by the hold in the write's transaction below, which refuses a channel that is off before a
        // value is written — a check here as well would read a state the hold reads again.
        let channels_configured = self.channels_configured_by(&pending).await?;

        self.refuse_github_project(&pending).await?;
        // **A save that takes the acknowledgement away is never refused.** Refusing it named a URL the operator had
        // not touched, and stopped the configuration becoming *safer*; every review runs the same guard anyway, so
        // `openai` with the acknowledgement off simply sends nowhere.
        let withdraws_acknowledgement = !remote_after && previous_acknowledgement == "true";
        if !withdraws_acknowledgement {
            let provider = match pending.get(&Setting::AiReviewProvider) {
                Some(provider) => (*provider).to_owned(),
                None => self.settings.get(Setting::AiReviewProvider).await?,
            };
            let after = AiAfter {
                provider: &provider,
                openai_url: pending.get(&Setting::AiReviewOpenaiUrl).copied(),
                ollama_url: pending.get(&Setting::AiReviewOllamaUrl).copied(),
                allow_remote: remote_after,
            };
            if let Some(refusal) = self.ai.refuse_destination(after).await.map_err(AdministrationError::Collaborator)? {
                return Err(AdministrationError::UnsafeUrl(refusal));
            }
        }

        // **One transaction for the writes**: the notification channels this save configures are held in it
        // (`Integrations::hold_enabled`), so a governor's switch arriving meanwhile waits for the write and then reads
        // the channel as in use — and a save arriving after the switch reads it off and is refused, nothing written. In
        // the enum's order, so two saves holding two channels take their rows alike. The audit entry is recorded after
        // it commits. A refusal or a failure drops the transaction, which rolls it back.
        let mut tx =
            self.db.begin(Mode::ReadWrite).await.map_err(|failure| AdministrationError::Storage(failure.into()))?;
        for channel in channels_configured {
            self.integrations.hold_enabled(&mut tx, channel).await.map_err(refused_by_registry)?;
        }
        for change in &changes {
            self.settings.set(&mut tx, change.setting, &change.value).await?;
        }
        // **The acceptance is stamped here, by the server, or erased here** — after the write, so it describes a
        // configuration that exists, and only on the transition: saving an unrelated setting while the switch is on
        // must not rewrite whose decision it was.
        if let Some(switch) = pending.get(&Setting::AiReviewAllowRemote)
            && *switch != previous_acknowledgement
        {
            if remote_after {
                let by = writer.map_or("", |writer| writer.username.as_str());
                self.ai.record_risk_acknowledgement(&mut tx, by, self.clock.now()).await
            } else {
                self.ai.clear_risk_acknowledgement(&mut tx).await
            }
            .map_err(AdministrationError::Collaborator)?;
        }
        tx.commit().await.map_err(|failure| AdministrationError::Storage(failure.into()))?;

        let applied = Applied {
            count: changes.len(),
            keys: changes.iter().map(|change| change.setting.key()).collect::<Vec<_>>().join(","),
            description: changes.iter().map(describe).collect::<Vec<_>>().join("; "),
        };
        let entry = actor.entry(AuditOperation::SettingUpdated, &applied.keys, &applied.description);
        // Forwarded when one of the settings saved decides what the deployment protects (`Setting::governs_security`).
        self.audit
            .record(if changes.iter().any(|change| change.setting.governs_security()) {
                entry.signalling(SECURITY_SETTING_CHANGED)
            } else {
                entry
            })
            .await;
        Ok(applied)
    }

    /// The checks one change passes, in Java's order: the first that refuses is the answer.
    async fn admit(&self, setting: Setting, value: &str, writer: Option<&Caller>) -> Result<(), AdministrationError> {
        // **The acceptance record is written by this server or not at all.** Accepting it on the wire would let
        // whoever opened the public endpoint also choose whose name and date sit against that decision.
        if matches!(setting, Setting::AiReviewRiskAcknowledgedBy | Setting::AiReviewRiskAcknowledgedAt) {
            return Err(AdministrationError::InvalidInput(format!(
                "{} is recorded by the server when the public endpoint is turned on, and cannot be set here.",
                setting.label()
            )));
        }
        // **The settings that decide rules, reserved to the governor** — the one role that cannot act under them.
        // Four-eyes was bypassable by anyone who could both switch it off and triage: off, settle alone, on again,
        // one audit entry for a trace. Breaking the conjunction closes it.
        if setting.governor_only() && !writer.is_some_and(|writer| writer.governs_platform) {
            return Err(AdministrationError::AccessDenied(format!(
                "{} decides a rule rather than a setting: only a platform governor may change it, because it is the \
                 one role that cannot act under it.",
                setting.label()
            )));
        }
        // **A credential's destination moves only in the hands of whoever may set the credential**, and the reach of
        // the SIEM export and the notification channels only in an administrator's. Only on a change: a screen that
        // saves every field it shows sends these back unchanged, and refusing that would lock a CISO out of the
        // rest of the section.
        //
        // **But never for a secret one.** "Unchanged is accepted, changed is refused" answered whether a value sent was
        // the stored one: for a setting withheld from a security lead — the tracker's address, its pinned CA — that
        // was a way to test guesses of it, one 200 or 403 at a time. A secret administrator-only key is refused from
        // anyone else whatever it holds; the screen sends only what changed, so it never sends one back. Asked before
        // the stored value is read, so a refusal reads nothing.
        if setting.administrator_only()
            && !writer.is_some_and(|writer| writer.administrative)
            && (setting.is_secret() || value != self.settings.get(setting).await?)
        {
            return Err(AdministrationError::AccessDenied(match setting.directs_credential() {
                Some(credential) => format!(
                    "{} decides where {} is sent, and only an administrator — who alone may set that credential — \
                     may change it.",
                    setting.label(),
                    credential.label().to_lowercase()
                ),
                None if setting == Setting::TicketTokenExpiresOn => format!(
                    "{} describes the tracker token, which only an administrator sets, and only an administrator may \
                     change it.",
                    setting.label()
                ),
                None if setting == Setting::AiReviewOllamaUrl => format!(
                    "{} decides which host receives the findings sent for review, and only an administrator may \
                     change it.",
                    setting.label()
                ),
                None => format!(
                    "{} decides how far a channel configured by a security lead may reach, and only an administrator \
                     may change it.",
                    setting.label()
                ),
            }));
        }
        if setting == Setting::FourEyesApprovalRequired && is_truthy(value) {
            self.refuse_four_eyes_without_people().await?;
        }
        // **A credential has one door, and this is not it.** Each has a route that encrypts the value; this path
        // stores what it is handed, and its audit description would carry the value into a log never purged.
        if setting.is_encrypted() {
            return Err(AdministrationError::InvalidInput(format!(
                "{} is a credential and is written by its own route, which encrypts it. Setting it here would store \
                 it in the clear.",
                setting.label()
            )));
        }
        if let Some(problem) = setting.validate(Some(value)) {
            return Err(AdministrationError::InvalidInput(format!("{} — {problem}", setting.label())));
        }
        // **A pinned CA is read as a forge connection's is**, and refused here in the same words rather than at the
        // next sweep. Only on a change: a stored CA that has since expired, sent back unchanged, is the calls' to
        // refuse.
        if setting == Setting::TicketCa
            && !value.is_empty()
            && value != java_trim(&self.settings.get(setting).await?)
            && let Some(refusal) = self.tracker.refuse_ca(value)
        {
            return Err(AdministrationError::InvalidInput(refusal));
        }
        // **A tracker whose integration is disabled is not chosen** (decision 0040 §1): 409 `integration-disabled`,
        // naming it. `none` is always saved — it uses nothing. Only on a change of tracker: the configured one switched
        // off is *suspended* (0040 §3), a state the governor's switch makes on purpose, and refusing its value sent
        // back unchanged would refuse the project, the labels and the CA beside it. Checked, not held: a switch landing
        // between this check and the write leaves a configured tracker suspended, which is not a loss.
        if setting == Setting::TicketProvider
            && let Some(chosen) = tracker(value)
            && Some(chosen) != tracker(&self.settings.get(setting).await?)
        {
            self.require_enabled(integration("tracker", chosen)?).await?;
        }
        // A date the screen announces from, so a typo is refused here rather than read as "unknown".
        if setting == Setting::TicketTokenExpiresOn && !value.is_empty() && !is_iso_local_date(value) {
            return Err(AdministrationError::InvalidInput(format!(
                "{} — a date, written as 2027-01-31.",
                setting.label()
            )));
        }
        Ok(())
    }

    /// **Switching on a two-person control requires that there be two.** Without it, a decision queue nobody can
    /// empty — a control that blocks instead of controlling, whose failure shows only at the first triage.
    async fn refuse_four_eyes_without_people(&self) -> Result<(), AdministrationError> {
        let collaborator = AdministrationError::Collaborator;
        if !self.approvers.any_active().await.map_err(collaborator)? {
            return Err(AdministrationError::InvalidInput(
                "No active account can approve a triage: switching four-eyes on would put every decision in a queue \
                 nobody can empty. Create an administrator, a CISO or a security lead first."
                    .to_owned(),
            ));
        }
        // A template is published by someone other than its author: with one writer, no draft is ever published.
        if !self.approvers.two_can_publish_templates().await.map_err(collaborator)? {
            return Err(AdministrationError::InvalidInput(
                "Fewer than two active accounts can publish a checklist template: under four-eyes its author may not \
                 publish it, so no draft could ever be published. Create a second platform governor, administrator \
                 or CISO first."
                    .to_owned(),
            ));
        }
        // A checklist is signed off by an approver who wrote none of it: with one, whatever it answered stays open.
        if !self.approvers.two_can_sign_off_checklists().await.map_err(collaborator)? {
            return Err(AdministrationError::InvalidInput(
                "Fewer than two active accounts can sign off a project checklist: under four-eyes none of its \
                 authors may sign it off, so a checklist its only approver filled in could never be signed off. \
                 Create a second administrator, CISO or security champion first."
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// **A GitHub repository is two names, checked against the state this save will produce**: it goes into the
    /// path of every call made with the tracker token, and was pasted there as typed. Only on a change, so a screen
    /// sending back what is stored is not refused for it; a value stored before this check is refused at the send.
    async fn refuse_github_project(&self, pending: &HashMap<Setting, &str>) -> Result<(), AdministrationError> {
        let provider_now = self.settings.get(Setting::TicketProvider).await?;
        let project_now = self.settings.get(Setting::TicketProject).await?;
        let provider_after = pending.get(&Setting::TicketProvider).copied().unwrap_or(provider_now.as_str());
        let project_after = pending.get(&Setting::TicketProject).copied().unwrap_or(project_now.as_str());
        if is_github(provider_after)
            && !vectispire_cp_settings::types::is_blank(project_after)
            && (provider_after != provider_now || project_after != project_now)
            && !is_github_repository(project_after)
        {
            return Err(AdministrationError::InvalidInput(format!(
                "{} — a GitHub repository is \"owner/repository\": letters, digits and hyphens for the owner, \
                 letters, digits, dots, underscores and hyphens for the repository, and nothing after it.",
                Setting::TicketProject.label()
            )));
        }
        Ok(())
    }
}

impl SettingsAdministration {
    /// `Integrations.requireEnabled`, answered as the save answers it.
    async fn require_enabled(&self, integration: Integration) -> Result<(), AdministrationError> {
        self.integrations.require_enabled(integration).await.map_err(refused_by_registry)
    }

    /// `NotificationDestinations.configuredBy`: the channels a save configures — one of their settings changed to a
    /// value that sends: a URL or a recipient written, a switch turned on. Clearing one, or sending back the stored
    /// value, configures nothing: a disabled channel is always emptied, and a screen saving its whole section is not
    /// refused for a channel this save does not move. **A secret is never compared with what is stored**: a writer who
    /// may not read it would learn from a 200 that a guess matched, and the screen never sends a secret back, so any
    /// value sent is a configuration. In `NotificationChannelKind`'s order.
    ///
    /// The notifications module is not ported (wave 2): this is its reading of the settings, here until it lands and
    /// answers the switch's "in use" from the same list.
    async fn channels_configured_by(
        &self,
        pending: &HashMap<Setting, &str>,
    ) -> Result<Vec<Integration>, AdministrationError> {
        let mut configured = Vec::new();
        for (channel, read) in CHANNEL_SETTINGS {
            for &setting in read {
                let Some(value) = pending.get(&setting).copied() else { continue };
                if !vectispire_cp_settings::types::is_blank(value)
                    && value != "false"
                    && (setting.is_secret() || value != java_trim(&self.settings.get(setting).await?))
                {
                    configured.push(integration("notification", channel)?);
                    break;
                }
            }
        }
        Ok(configured)
    }

    /// `checkAiEndpoint`: asks the configured endpoint what it holds. It reports rather than throws — "unreachable" is
    /// an answer to the question the test button asks — and runs the same URL validation as a real call.
    ///
    /// **The test is a call like any other** (decision 0040, lot I5): a provider switched off is not asked, and the
    /// answer is the refusal every feature gives — not "unreachable", which would send the operator to check a network
    /// path that is fine.
    ///
    /// **The endpoint is named to an administrator only.** `ai_review_ollama_url` is a secret the catalog withholds
    /// from a security lead, and this check is theirs to run: answering with the URL, or quoting it in a sentence — the
    /// guard's refusals quote the address they refused — handed back the value withheld one screen away. `url` is
    /// `None` for them, and every sentence says "the configured endpoint".
    pub async fn check_ai_endpoint(&self, caller: Option<&Caller>) -> Result<EndpointCheck, AdministrationError> {
        let collaborator = AdministrationError::Collaborator;
        let provider = ai_provider(&self.endpoint.provider().await.map_err(collaborator)?);
        self.integrations.require_enabled(integration("ai", provider)?).await.map_err(|refused| match refused {
            IntegrationsError::Disabled(integration) => {
                AdministrationError::IntegrationDisabled { integration, lead: AI_UNAVAILABLE }
            }
            other => refused_by_registry(other),
        })?;
        let named = caller.is_some_and(|caller| caller.administrative);

        let model = self.endpoint.selected_model().await.map_err(collaborator)?;
        // Two forms on purpose: `name` goes into sentences a person reads, the wire name into the field a client
        // compares against.
        let name = if provider == "openai" { "OpenAI" } else { "Ollama" };
        let remote_allowed = self.endpoint.allow_remote().await.map_err(collaborator)?;
        let check = |reachable, url: Option<String>, detail: String| EndpointCheck {
            reachable,
            model_installed: false,
            model: model.clone(),
            url,
            models: Vec::new(),
            detail,
            provider: provider.to_owned(),
            remote_allowed,
        };
        let url = match self.endpoint.validated_url().await.map_err(collaborator)? {
            Ok(url) => url,
            // A public URL with no acknowledgement lands here. A configuration answer, and the operator needs the
            // reason — but the reason quotes the address, so only the person allowed to read the address gets it.
            Err(refusal) => {
                return Ok(if named {
                    check(false, Some(self.endpoint.base_url().await.map_err(collaborator)?), refusal)
                } else {
                    check(
                        false,
                        None,
                        "The configured URL is refused by the outbound policy; an administrator can see why."
                            .to_owned(),
                    )
                });
            }
        };
        let (where_, answered_url) =
            if named { (url.clone(), Some(url)) } else { ("the configured endpoint".to_owned(), None) };

        // **Checked before the call, not after it fails**: OpenAI answers an unauthenticated request with a 401 that
        // reads as "unreachable" — sending the operator to check a network path that is fine, over a key never set.
        if provider == "openai" && !self.endpoint.has_openai_key().await.map_err(collaborator)? {
            return Ok(check(
                false,
                answered_url,
                format!(
                    "No API key is stored for {where_}. Set one, or point this at a local endpoint that authenticates \
                     nobody."
                ),
            ));
        }
        let Some(models) = self.endpoint.available_models().await.map_err(collaborator)? else {
            return Ok(check(
                false,
                answered_url,
                format!("No answer from {where_}. Is {name} running, and reachable from this process?"),
            ));
        };
        let installed = models.contains(&model);
        let detail = if installed {
            format!("Reachable, and \"{model}\" is available.")
        } else {
            format!("Reachable, but \"{model}\" is not available there. Pick one of the {} it offers.", models.len())
        };
        Ok(EndpointCheck {
            reachable: true,
            model_installed: installed,
            models,
            detail,
            ..check(true, answered_url, String::new())
        })
    }
}

/// `NotificationDestinations.SETTINGS`: the settings each channel's destination is read from, in
/// `NotificationChannelKind`'s order. The checklist reminders are mail's: they need no recipient, but switching mail
/// off under them would stop them in silence.
const CHANNEL_SETTINGS: [(&str, &[Setting]); 5] = [
    ("webhook", &[Setting::WebhookUrl]),
    ("teams", &[Setting::TeamsEnabled, Setting::TeamsWebhookUrl]),
    ("slack", &[Setting::SlackWebhookUrl]),
    ("discord", &[Setting::DiscordWebhookUrl]),
    ("mail", &[Setting::MailRecipients, Setting::ChecklistRemindersEnabled]),
];

/// `AiProvider.of(value).wireName()`: trimmed, lower-cased, and anything unknown read as `ollama`.
fn ai_provider(value: &str) -> &'static str {
    if java_trim(value).to_lowercase() == "openai" { "openai" } else { "ollama" }
}

/// `TicketProvider.fromWireName`, for a tracker that is one (`isEnabled`): `None` for `none`, blank or unknown.
fn tracker(value: &str) -> Option<&'static str> {
    let normalized = java_trim(value).to_lowercase();
    ["gitlab", "github", "jira", "servicenow"].into_iter().find(|name| *name == normalized)
}

/// `Integration.of(…)`: the integration a family's value names. Every value passed is one `Integration::all` lists.
fn integration(family: &str, name: &str) -> Result<Integration, AdministrationError> {
    let key = format!("{family}.{name}");
    Integration::by_key(&key)
        .ok_or_else(|| AdministrationError::Collaborator(format!("no integration is named {key}").into()))
}

/// The registry's refusal as the save answers it: `integration-disabled` is a 409; anything else is a failure.
fn refused_by_registry(refused: IntegrationsError) -> AdministrationError {
    match refused {
        IntegrationsError::Disabled(integration) => AdministrationError::IntegrationDisabled { integration, lead: "" },
        other => AdministrationError::Storage(Box::new(other)),
    }
}

/// One change as the audit entry says it. **A secret's value stays out of the entry**: a webhook URL posts in a
/// channel, a tracker or model URL maps the internal network, and the entry is read by auditors, forwarded to the
/// SIEM, copied to the mirror and the evidence bundle, and kept for ever.
fn describe(change: &Change) -> String {
    if change.setting == Setting::FourEyesApprovalRequired {
        return format!(
            "Double validation (Four-Eyes Approval) for VEX triage set to {}",
            if change.value.eq_ignore_ascii_case("true") { "ENABLED" } else { "DISABLED" }
        );
    }
    if change.setting.is_secret() {
        return format!("{}{}", change.setting.key(), if change.value.is_empty() { " cleared" } else { " changed" });
    }
    format!("{} = {}", change.setting.key(), if change.value.is_empty() { "(empty)" } else { &change.value })
}
