//! The five channels: the generic webhook (`NotificationService`), Teams, Slack, Discord (`*NotificationChannel`) and
//! mail (`MailNotificationChannel`) — each an outbox channel under its own message type, and each a destination a
//! token's alert can reach (`AlertChannel`).
//!
//! Every send asks the registry first and reads its destination at the send. A delivery **fails on failure**: the
//! relay turns that into a retry, and a swallowed failure is one never retried.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use vectispire_cp_outbox::{Delivery, DeliveryError, NotificationChannel};
use vectispire_cp_settings::Setting;
use vectispire_domain::notifications::{
    MailContent, NotificationChannelKind, NotificationPayload, TokenAlert, mail, renderers, token_alert_messages,
};

use crate::error::NotificationError;
use crate::internal::{data_access, instant, policy, post_failure, trimmed, unreadable};
use crate::service::NotificationService;
use crate::{NotificationsConfig, gate};

/// What the routing, the alerts and the centre ask of a channel.
pub trait Channel: Send + Sync {
    fn kind(&self) -> NotificationChannelKind;

    /// Whether this deployment has somewhere to send. An unconfigured channel is queued nothing.
    fn configured(&self) -> BoxFuture<'_, Result<bool, NotificationError>>;

    /// A scan's delta, as the relay or the test button hands it.
    fn deliver_payload<'a>(&'a self, payload: &'a NotificationPayload) -> Delivery<'a>;

    /// A token's change of state; `message_id` is the outbox row's, what a receiver deduplicates on.
    fn deliver_alert<'a>(&'a self, alert: &'a TokenAlert, message_id: &'a str) -> Delivery<'a>;
}

/// The stored payload read back, as Java's relay maps it before calling a channel.
fn parsed(payload: &str) -> Result<NotificationPayload, DeliveryError> {
    serde_json::from_str(payload).map_err(|error| unreadable(&error))
}

/// The generic webhook: global, or a team's own. Keeps the legacy type `scan_delta`, so rows queued before the other
/// channels existed keep routing here.
#[derive(Debug)]
pub struct WebhookChannel {
    service: Arc<NotificationService>,
}

impl WebhookChannel {
    pub fn new(service: Arc<NotificationService>) -> WebhookChannel {
        WebhookChannel { service }
    }
}

impl Channel for WebhookChannel {
    fn kind(&self) -> NotificationChannelKind {
        NotificationChannelKind::Webhook
    }

    fn configured(&self) -> BoxFuture<'_, Result<bool, NotificationError>> {
        Box::pin(async move { Ok(!vectispire_domain::java::is_blank(&self.service.webhook_url().await?)) })
    }

    fn deliver_payload<'a>(&'a self, payload: &'a NotificationPayload) -> Delivery<'a> {
        Box::pin(self.service.deliver(payload, None))
    }

    fn deliver_alert<'a>(&'a self, alert: &'a TokenAlert, message_id: &'a str) -> Delivery<'a> {
        Box::pin(self.service.deliver_alert(alert, message_id))
    }
}

impl NotificationChannel for WebhookChannel {
    fn message_type(&self) -> &str {
        NotificationChannelKind::Webhook.outbox_type()
    }

    fn deliver<'a>(&'a self, payload: &'a str, team_id: Option<i64>) -> Delivery<'a> {
        Box::pin(async move { self.service.deliver(&parsed(payload)?, team_id).await })
    }
}

/// Teams, Slack or Discord: an incoming webhook whose URL is a setting, the card built in the domain.
pub struct ChatChannel {
    kind: NotificationChannelKind,
    url: Setting,
    label: &'static str,
    config: NotificationsConfig,
}

impl std::fmt::Debug for ChatChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatChannel").field("kind", &self.kind).finish_non_exhaustive()
    }
}

impl ChatChannel {
    /// Microsoft Teams, through a Power Automate workflow: an Adaptive Card in an attachment envelope.
    pub fn teams(config: NotificationsConfig) -> ChatChannel {
        ChatChannel {
            kind: NotificationChannelKind::Teams,
            url: Setting::TeamsWebhookUrl,
            label: "Teams webhook URL",
            config,
        }
    }

    /// Slack's incoming webhooks: Block Kit.
    pub fn slack(config: NotificationsConfig) -> ChatChannel {
        ChatChannel {
            kind: NotificationChannelKind::Slack,
            url: Setting::SlackWebhookUrl,
            label: "Slack webhook URL",
            config,
        }
    }

    /// Discord's webhooks: a rich embed.
    pub fn discord(config: NotificationsConfig) -> ChatChannel {
        ChatChannel {
            kind: NotificationChannelKind::Discord,
            url: Setting::DiscordWebhookUrl,
            label: "Discord webhook URL",
            config,
        }
    }

    /// Posts what was built. The callers have asked the gate first.
    async fn post(&self, body: serde_json::Value) -> Result<(), DeliveryError> {
        let policy = policy(&self.config.settings).await?;
        let url = trimmed(&self.config.settings, self.url).await.map_err(data_access)?;
        self.config
            .post
            .post_json(&url, &vectispire_domain::wire::to_wire_string(&body), policy, self.label)
            .await
            .map(|_| ())
            .map_err(|failed| post_failure(&failed))
    }

    fn render(&self, payload: &NotificationPayload) -> serde_json::Value {
        let public = self.config.public_url.as_deref();
        match self.kind {
            NotificationChannelKind::Teams => renderers::teams(payload, public),
            NotificationChannelKind::Slack => renderers::slack(payload, public),
            _ => renderers::discord(payload, public, instant(self.config.clock.now())),
        }
    }

    fn render_alert(&self, alert: &TokenAlert) -> serde_json::Value {
        let public = self.config.public_url.as_deref();
        match self.kind {
            NotificationChannelKind::Teams => token_alert_messages::teams(alert, public),
            NotificationChannelKind::Slack => token_alert_messages::slack(alert, public),
            _ => token_alert_messages::discord(alert, public),
        }
    }

    fn name(&self) -> &'static str {
        match self.kind {
            NotificationChannelKind::Teams => "Teams",
            NotificationChannelKind::Slack => "Slack",
            _ => "Discord",
        }
    }
}

impl Channel for ChatChannel {
    fn kind(&self) -> NotificationChannelKind {
        self.kind
    }

    fn configured(&self) -> BoxFuture<'_, Result<bool, NotificationError>> {
        Box::pin(async move {
            // Teams needs its own switch and its URL, as it does to send.
            if self.kind == NotificationChannelKind::Teams
                && !self.config.settings.is_enabled(Setting::TeamsEnabled).await?
            {
                return Ok(false);
            }
            Ok(!vectispire_domain::java::is_blank(&trimmed(&self.config.settings, self.url).await?))
        })
    }

    fn deliver_payload<'a>(&'a self, payload: &'a NotificationPayload) -> Delivery<'a> {
        Box::pin(async move {
            // Before anything is read or built: nothing of a disabled channel runs (decision 0040, lot I6).
            gate::require_deliverable(&self.config.integrations, self.kind).await?;
            self.post(self.render(payload)).await?;
            tracing::info!(
                "{} notified for scan {}, message {}.",
                self.name(),
                payload.scan_id,
                payload.message_id.as_deref().unwrap_or("null")
            );
            Ok(())
        })
    }

    fn deliver_alert<'a>(&'a self, alert: &'a TokenAlert, message_id: &'a str) -> Delivery<'a> {
        Box::pin(async move {
            gate::require_deliverable(&self.config.integrations, self.kind).await?;
            self.post(self.render_alert(alert)).await?;
            tracing::info!(
                "{} notified of a token's change ({}), message {message_id}.",
                self.name(),
                alert.notice.wire_name()
            );
            Ok(())
        })
    }
}

impl NotificationChannel for ChatChannel {
    fn message_type(&self) -> &str {
        self.kind.outbox_type()
    }

    fn deliver<'a>(&'a self, payload: &'a str, _team_id: Option<i64>) -> Delivery<'a> {
        Box::pin(async move { Channel::deliver_payload(self, &parsed(payload)?).await })
    }
}

/// Mail: the relay is the deployment's, the recipients a setting. **Configured only with both**: either alone sends
/// nothing, and would fill the outbox with rows whose backoff runs to exhaustion.
pub struct MailChannel {
    config: NotificationsConfig,
}

impl std::fmt::Debug for MailChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailChannel").field("relay", &self.config.mail.is_some()).finish_non_exhaustive()
    }
}

const NO_RELAY: &str = "No mail relay is configured on this deployment.";

impl MailChannel {
    pub fn new(config: NotificationsConfig) -> MailChannel {
        MailChannel { config }
    }

    /// Whether a relay is configured — what a message to its own addressees needs.
    pub fn has_relay(&self) -> bool {
        self.config.mail.is_some()
    }

    /// Whether `notification.mail` is on: what a caller with no queue asks before it prepares a send.
    pub async fn is_switched_on(&self) -> Result<bool, NotificationError> {
        gate::is_on(&self.config.integrations, NotificationChannelKind::Mail).await
    }

    pub fn public_url(&self) -> Option<String> {
        self.config.public_url.clone()
    }

    async fn recipients(&self) -> Result<Vec<String>, NotificationError> {
        let stored = self.config.settings.get(Setting::MailRecipients).await?;
        Ok(stored
            .split(',')
            .map(vectispire_domain::java::trim)
            .filter(|address| !address.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// `sendText`: a message this channel did not build — the weekly posture report — to the recipients. Refused
    /// 409 while mail is off: it has no queue.
    pub async fn send_text(&self, subject: &str, body: &str) -> Result<(), MailError> {
        gate::require_enabled(&self.config.integrations, NotificationChannelKind::Mail).await?;
        let relay = self.config.mail.as_ref().ok_or_else(|| MailError::Failed(NO_RELAY.to_owned()))?;
        let to = self.recipients().await?;
        if to.is_empty() {
            return Err(MailError::Failed("No recipient is configured for e-mail notifications.".to_owned()));
        }
        relay.send(&self.config.mail_from, &to, subject, body).await.map_err(MailError::Failed)?;
        tracing::info!("Mail sent to {} recipient(s): {subject}", to.len());
        Ok(())
    }

    /// `sendTextTo`: to the addresses given — the checklist reminder, each to an account's own address.
    pub async fn send_text_to(&self, to: &[String], subject: &str, body: &str) -> Result<(), MailError> {
        gate::require_enabled(&self.config.integrations, NotificationChannelKind::Mail).await?;
        let relay = self.config.mail.as_ref().ok_or_else(|| MailError::Failed(NO_RELAY.to_owned()))?;
        if to.is_empty() {
            return Err(MailError::Failed("A message needs an addressee.".to_owned()));
        }
        relay.send(&self.config.mail_from, to, subject, body).await.map_err(MailError::Failed)?;
        tracing::info!("Mail sent to {} addressee(s): {subject}", to.len());
        Ok(())
    }

    async fn deliver_content(&self, content: &MailContent) -> Result<usize, DeliveryError> {
        let relay =
            self.config.mail.as_ref().ok_or_else(|| DeliveryError::failed("IllegalStateException", NO_RELAY))?;
        let to = self.recipients().await.map_err(data_access)?;
        if to.is_empty() {
            return Err(DeliveryError::failed(
                "IllegalStateException",
                "No recipient is configured for e-mail notifications.",
            ));
        }
        relay
            .send(&self.config.mail_from, &to, &content.subject, &content.body)
            .await
            .map_err(|failed| DeliveryError::failed("MailException", failed))?;
        Ok(to.len())
    }
}

/// Why a mail outside the outbox was not sent.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// 409 `integration-disabled`.
    #[error(transparent)]
    Refused(#[from] NotificationError),
    #[error("{0}")]
    Failed(String),
}

impl Channel for MailChannel {
    fn kind(&self) -> NotificationChannelKind {
        NotificationChannelKind::Mail
    }

    fn configured(&self) -> BoxFuture<'_, Result<bool, NotificationError>> {
        Box::pin(async move { Ok(self.has_relay() && !self.recipients().await?.is_empty()) })
    }

    fn deliver_payload<'a>(&'a self, payload: &'a NotificationPayload) -> Delivery<'a> {
        Box::pin(async move {
            gate::require_deliverable(&self.config.integrations, NotificationChannelKind::Mail).await?;
            let content = mail::of(payload, self.config.public_url.as_deref());
            let sent = self.deliver_content(&content).await?;
            tracing::info!(
                "Mail sent to {sent} recipient(s) for scan {}, message {}.",
                payload.scan_id,
                payload.message_id.as_deref().unwrap_or("null")
            );
            Ok(())
        })
    }

    fn deliver_alert<'a>(&'a self, alert: &'a TokenAlert, message_id: &'a str) -> Delivery<'a> {
        Box::pin(async move {
            // Held, not refused: this one came from the outbox, and waits there for the channel to be on again.
            gate::require_deliverable(&self.config.integrations, NotificationChannelKind::Mail).await?;
            let content = token_alert_messages::mail(alert, self.config.public_url.as_deref(), message_id);
            self.deliver_content(&content).await.map(|_| ())
        })
    }
}

impl NotificationChannel for MailChannel {
    fn message_type(&self) -> &str {
        NotificationChannelKind::Mail.outbox_type()
    }

    fn deliver<'a>(&'a self, payload: &'a str, _team_id: Option<i64>) -> Delivery<'a> {
        Box::pin(async move { Channel::deliver_payload(self, &parsed(payload)?).await })
    }
}
