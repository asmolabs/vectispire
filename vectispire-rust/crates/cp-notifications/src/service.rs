//! `NotificationService` — the generic webhook's settings, its signing secret and its delivery — and
//! `NotificationTestService`, the notification centre's channel list and test message.

use std::sync::Arc;

use serde::Serialize;
use time::OffsetDateTime;
use vectispire_cp_access::teams::TeamChannels;
use vectispire_cp_db::Mode;
use vectispire_cp_outbox::DeliveryError;
use vectispire_cp_settings::Setting;
use vectispire_domain::Severity;
use vectispire_domain::notifications::payload::{Delta, NotifiableIssue, NotificationPayload};
use vectispire_domain::notifications::selection::{self, Options};
use vectispire_domain::notifications::{NotificationChannelKind, TokenAlert, token_alert_messages};

use crate::NotificationsConfig;
use crate::channels::Channel;
use crate::error::NotificationError;
use crate::gate;
use crate::internal::{data_access, instant, policy, post_failure, trimmed};

/// The associated data binding the signing secret's ciphertext to its own setting row.
pub const SIGNING_SECRET_CONTEXT: &str = "setting:notification_webhook_secret";

/// The generic webhook: what to say, and how — the outbox relay owns when a message gets another chance.
pub struct NotificationService {
    config: NotificationsConfig,
}

impl std::fmt::Debug for NotificationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationService").finish_non_exhaustive()
    }
}

impl NotificationService {
    pub fn new(config: NotificationsConfig) -> NotificationService {
        NotificationService { config }
    }

    /// The decrypted signing secret, or an empty string when none is configured.
    ///
    /// **A configured secret that does not decrypt fails the delivery** — the opposite of the tracker's token, and the
    /// difference is the point: an unreadable tracker token disables ticket creation, fail-closed; an unreadable
    /// signing secret treated the same way would send the message **unsigned**, a security control switching itself
    /// off after a key rotation, silently. The relay retries, then abandons with this sentence.
    pub async fn signing_secret(&self) -> Result<String, DeliveryError> {
        let stored = trimmed(&self.config.settings, Setting::WebhookSigningSecret).await.map_err(data_access)?;
        if stored.is_empty() {
            return Ok(stored);
        }
        let secret = self.config.encryption.inspect(&stored, SIGNING_SECRET_CONTEXT).await;
        if secret.state() == vectispire_cp_crypto::SecretState::Unreadable {
            return Err(DeliveryError::failed(
                "IllegalStateException",
                "A webhook signing secret is configured but cannot be decrypted by any configured key. Refusing to \
                 send unsigned: a receiver that checks the signature would reject the message and one that does not \
                 would accept an unprovable one. Restore the previous encryption key, or clear the signing secret to \
                 send unsigned deliberately.",
            ));
        }
        Ok(secret.plain_text().to_owned())
    }

    /// Whether messages are signed, for a screen that must not show the secret.
    pub async fn is_signing(&self) -> Result<bool, NotificationError> {
        Ok(!trimmed(&self.config.settings, Setting::WebhookSigningSecret).await?.is_empty())
    }

    pub async fn webhook_url(&self) -> Result<String, NotificationError> {
        Ok(trimmed(&self.config.settings, Setting::WebhookUrl).await?)
    }

    /// Whether the webhook channel may be sent to — a team's own webhook is this channel.
    pub async fn is_switched_on(&self) -> Result<bool, NotificationError> {
        gate::is_on(&self.config.integrations, NotificationChannelKind::Webhook).await
    }

    /// The threshold. `Severity.of` falls back to `UNKNOWN`, which ranks last and would let everything through: a
    /// misspelled setting must not silently turn the threshold off.
    pub async fn min_severity(&self) -> Result<Severity, NotificationError> {
        let configured = Severity::of(Some(&self.config.settings.get(Setting::NotificationMinSeverity).await?));
        Ok(if configured == Severity::Unknown { selection::DEFAULT_MIN_SEVERITY } else { configured })
    }

    /// `buildScanDelta`: the payload, or nothing when there is nothing to say. Whether anybody listens is the router's
    /// question.
    pub async fn build_scan_delta(
        &self,
        target_name: &str,
        scan_id: i64,
        new_issues: &[NotifiableIssue],
        reopened_issues: &[NotifiableIssue],
        resolved_count: i32,
    ) -> Result<Option<NotificationPayload>, NotificationError> {
        let options = Options {
            min_severity: self.min_severity().await?,
            always_on_kev: self.config.settings.is_enabled(Setting::NotifyOnKev).await?,
        };
        let notable_new = selection::notable(new_issues, options);
        let notable_reopened = selection::notable(reopened_issues, options);
        if notable_new.is_empty() && notable_reopened.is_empty() {
            return Ok(None);
        }
        Ok(Some(NotificationPayload::of(&Delta {
            target_name: target_name.to_owned(),
            scan_id,
            new_issues: notable_new,
            reopened_issues: notable_reopened,
            resolved_count,
            min_severity: options.min_severity,
        })))
    }

    /// Posts a payload to the global webhook or a team's. **Fails on failure**, so the relay can retry it; the URL is
    /// re-read and validated here, not captured at queue time.
    pub async fn deliver(&self, payload: &NotificationPayload, team_id: Option<i64>) -> Result<(), DeliveryError> {
        // Before the destination is read: nothing of a disabled channel runs, a team's copy included.
        gate::require_deliverable(&self.config.integrations, NotificationChannelKind::Webhook).await?;
        let policy = policy(&self.config.settings).await?;
        let destination = self.destination_for(team_id).await?;
        let label = if team_id.is_none() { "webhook URL" } else { "team webhook URL" };
        // One secret for the global channel and every team's: the accepted limit of this first form.
        let secret = self.signing_secret().await?;
        self.config
            .post
            .post_signed_json(&destination, &payload.to_json(), policy, label, &secret, self.now().unix_timestamp())
            .await
            .map_err(|failed| post_failure(&failed))?;
        tracing::info!(
            "Webhook notified for scan {} ({} new, {} reopened), message {}, destination {}, {}.",
            payload.scan_id,
            payload.new_count,
            payload.reopened_count,
            payload.message_id.as_deref().unwrap_or("null"),
            team_id.map_or_else(|| "global".to_owned(), |team| format!("team {team}")),
            if secret.is_empty() { "unsigned" } else { "signed" }
        );
        Ok(())
    }

    /// A token's change of state, to the global webhook alone, signed as a delta is.
    pub async fn deliver_alert(&self, alert: &TokenAlert, message_id: &str) -> Result<(), DeliveryError> {
        gate::require_deliverable(&self.config.integrations, NotificationChannelKind::Webhook).await?;
        let policy = policy(&self.config.settings).await?;
        let secret = self.signing_secret().await?;
        let destination = self.destination_for(None).await?;
        let body = vectispire_domain::wire::to_wire_string(&token_alert_messages::webhook(alert, message_id));
        self.config
            .post
            .post_signed_json(&destination, &body, policy, "webhook URL", &secret, self.now().unix_timestamp())
            .await
            .map_err(|failed| post_failure(&failed))?;
        tracing::info!(
            "Webhook notified of a token's change ({}), message {message_id}, {}.",
            alert.notice.wire_name(),
            if secret.is_empty() { "unsigned" } else { "signed" }
        );
        Ok(())
    }

    /// The URL this message is for, read now. **A destination that has disappeared is gone, not failing**: retried
    /// twelve times it fills the log with an error nobody can fix.
    async fn destination_for(&self, team_id: Option<i64>) -> Result<String, DeliveryError> {
        let Some(team_id) = team_id else {
            let global = trimmed(&self.config.settings, Setting::WebhookUrl).await.map_err(data_access)?;
            if global.is_empty() {
                return Err(DeliveryError::Gone("the global webhook URL has been cleared".to_owned()));
            }
            return Ok(global);
        };
        let mut tx = self.config.db.begin(Mode::ReadOnly).await.map_err(data_access)?;
        let url = TeamChannels::webhook_url(&mut tx, team_id).await.map_err(data_access)?;
        tx.commit().await.map_err(data_access)?;
        url.filter(|url| !vectispire_domain::java::is_blank(url)).ok_or_else(|| {
            DeliveryError::Gone(format!("team {team_id} no longer has a webhook — deleted, or its channel was cleared"))
        })
    }

    fn now(&self) -> OffsetDateTime {
        self.config.clock.now()
    }
}

/// The signing secret, for the encryption census: which key it is sealed under, never what it holds.
impl vectispire_cp_crypto::SealedStore for NotificationService {
    fn census(&self) -> vectispire_cp_crypto::CensusFuture<'_> {
        Box::pin(async move {
            let stored = self.config.settings.get(Setting::WebhookSigningSecret).await.map_err(|e| e.to_string())?;
            let seal = self.config.encryption.seal_of(Some(&stored), SIGNING_SECRET_CONTEXT).await;
            Ok(vec![
                vectispire_cp_crypto::Counter::new(
                    "Notification webhook signing secret",
                    "set the secret again on the notification settings, and in the receiver",
                )
                .count(seal)
                .done(),
            ])
        })
    }
}

/// `NotificationChannelStatus`: a channel as the centre lists it — its destination masked.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStatus {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub destination: String,
    pub configured: bool,
    pub supported_events: Vec<String>,
}

/// `NotificationTestResult`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TestResult {
    #[serde(rename = "type")]
    pub kind: String,
    pub success: bool,
    pub message: String,
    /// `Instant.toString`.
    pub tested_at: String,
}

/// What the test answers when the message did not get through — **and nothing of why**: quoting the sender's words
/// ("Connection refused", the guard naming the internal address a name resolved to) made the button a scanner of the
/// internal network. The cause goes to the server log.
pub const NOT_DELIVERED: &str = "The test message was not delivered: the destination is refused by the outbound \
policy, could not be reached, or did not accept it. The cause is in the server log.";

const DEFAULT_EVENTS: [&str; 4] =
    ["GATE_FAILED", "CRITICAL_KEV_DETECTED", "FOUR_EYES_APPROVAL_REQUIRED", "WEEKLY_POSTURE_REPORT"];

/// `NotificationTestService`. **A channel the governor switched off is not offered**: absent from the list, and its
/// test refused 409 before anything is built.
pub struct NotificationTestService {
    config: NotificationsConfig,
    channels: Vec<Arc<dyn Channel>>,
}

impl std::fmt::Debug for NotificationTestService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationTestService").finish_non_exhaustive()
    }
}

impl NotificationTestService {
    pub fn new(config: NotificationsConfig, channels: Vec<Arc<dyn Channel>>) -> NotificationTestService {
        NotificationTestService { config, channels }
    }

    /// `getChannelsStatus`.
    pub async fn channels_status(&self) -> Result<Vec<ChannelStatus>, NotificationError> {
        let mut list = Vec::new();
        for channel in &self.channels {
            let kind = channel.kind();
            if !gate::is_on(&self.config.integrations, kind).await? {
                continue;
            }
            let (name, setting) = match kind {
                NotificationChannelKind::Webhook => ("Generic webhook / SIEM", Setting::WebhookUrl),
                NotificationChannelKind::Teams => ("Microsoft Teams (Adaptive Cards)", Setting::TeamsWebhookUrl),
                NotificationChannelKind::Slack => ("Slack (Block Kit)", Setting::SlackWebhookUrl),
                NotificationChannelKind::Discord => ("Discord (Rich Embeds)", Setting::DiscordWebhookUrl),
                NotificationChannelKind::Mail => ("Email / SMTP", Setting::MailRecipients),
            };
            let raw = self.config.settings.get(setting).await?;
            list.push(ChannelStatus {
                kind: kind.outbox_type().to_owned(),
                name: name.to_owned(),
                destination: mask(&raw),
                configured: channel.configured().await?,
                supported_events: DEFAULT_EVENTS.iter().map(|event| (*event).to_owned()).collect(),
            });
        }
        Ok(list)
    }

    /// `testChannel`: the type exactly, in any case, or a channel whose type ends with `_<type>`.
    pub async fn test_channel(&self, requested: &str) -> Result<TestResult, NotificationError> {
        let suffix = format!("_{}", vectispire_domain::java::to_lower_root(requested));
        let Some(channel) = self.channels.iter().find(|channel| {
            let kind = channel.kind().outbox_type();
            equals_ignore_case(kind, requested) || kind.ends_with(&suffix)
        }) else {
            return Ok(self.result(requested, false, format!("Unknown notification channel type: {requested}")));
        };
        let kind = channel.kind();
        // Before "not configured": a disabled channel is not one to configure either, and the refusal says why.
        gate::require_enabled(&self.config.integrations, kind).await?;
        if !channel.configured().await? {
            return Ok(self.result(
                kind.outbox_type(),
                false,
                "Channel is not configured with a destination URL/recipient.".to_owned(),
            ));
        }
        let payload = self.test_payload();
        match channel.deliver_payload(&payload).await {
            Ok(()) => Ok(self.result(
                kind.outbox_type(),
                true,
                format!("Test payload successfully dispatched to {}", kind.outbox_type()),
            )),
            Err(failed) => {
                tracing::warn!("Notification test failed for {}: {failed}", kind.outbox_type());
                Ok(self.result(kind.outbox_type(), false, NOT_DELIVERED.to_owned()))
            }
        }
    }

    fn result(&self, kind: &str, success: bool, message: String) -> TestResult {
        TestResult {
            kind: kind.to_owned(),
            success,
            message,
            tested_at: vectispire_cp_audit::iso_instant(self.config.clock.now()),
        }
    }

    fn test_payload(&self) -> NotificationPayload {
        let millis = instant(self.config.clock.now()).to_epoch_milli().unwrap_or_default();
        NotificationPayload {
            text: Some("🔔 Vectispire Connectivity Test — All systems operational".to_owned()),
            target: Some("test-target:main".to_owned()),
            scan_id: 999,
            new_count: 1,
            reopened_count: 0,
            resolved_count: 0,
            kev_count: 1,
            min_severity: Some("CRITICAL".to_owned()),
            issues: vec![vectispire_domain::notifications::Detail {
                id: 999,
                identifier: Some("CVE-2021-44228".to_owned()),
                kind: Some("sca".to_owned()),
                severity: Some("CRITICAL".to_owned()),
                is_kev: true,
                epss_score: Some(0.975),
                package_name: Some("org.apache.logging.log4j:log4j-core".to_owned()),
                file_path: Some("pom.xml".to_owned()),
                fix_versions: Some("2.17.1".to_owned()),
                link: None,
            }],
            truncated: 0,
            message_id: Some(format!("test-msg-{millis}")),
        }
    }
}

/// `String.equalsIgnoreCase`: char by char, upper then lower case compared.
fn equals_ignore_case(left: &str, right: &str) -> bool {
    left.chars().count() == right.chars().count()
        && left
            .chars()
            .zip(right.chars())
            .all(|(a, b)| a == b || a.to_uppercase().eq(b.to_uppercase()) || a.to_lowercase().eq(b.to_lowercase()))
}

/// `maskDestination`: an address shown whole, a URL of twenty characters or fewer as `***`, a longer one by its
/// first twelve and last eight — the destination is a bearer capability.
pub fn mask(destination: &str) -> String {
    if vectispire_domain::java::is_blank(destination) {
        return String::new();
    }
    if destination.contains('@') {
        return destination.to_owned();
    }
    let units: Vec<u16> = destination.encode_utf16().collect();
    if units.len() <= 20 {
        return "***".to_owned();
    }
    let head = units.get(..12).unwrap_or_default();
    let tail = units.get(units.len().saturating_sub(8)..).unwrap_or_default();
    format!("{}...{}", vectispire_domain::java::from_utf16(head), vectispire_domain::java::from_utf16(tail))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destinations_are_masked_as_java_masks_them() {
        assert_eq!(mask(""), "");
        assert_eq!(mask("ops@example.com,sec@example.com"), "ops@example.com,sec@example.com");
        assert_eq!(mask("https://x.example/a"), "***");
        assert_eq!(mask("https://hooks.slack.com/services/T000/B000/XXXX"), "https://hook...000/XXXX");
        assert!(equals_ignore_case("SCAN_DELTA", "scan_delta"));
    }
}
