//! `NotificationDestinations` and `NotificationChannelInUse`: where each channel sends, read as the integrations'
//! registry needs it (decision 0040 §3, lot I6) — whether a channel has a destination, and so may not be switched
//! off, and which channels a settings save configures, and so must be on. **One list of settings for both
//! questions**: answered by two, a sixth setting giving a channel somewhere to send would be learnt by one and not the
//! other.
//!
//! A team's own webhook is the webhook channel too: written on the team (`access`), read here as a use.

use std::collections::HashMap;

use vectispire_cp_access::teams::TeamChannels;
use vectispire_cp_db::Tx;
use vectispire_cp_settings::{InUse, InUseFuture, Setting, Settings};
use vectispire_domain::integrations::{Integration, IntegrationFamily};
use vectispire_domain::notifications::NotificationChannelKind;

use crate::error::NotificationError;

/// The settings each channel's destination is read from. The checklist reminders are mail's: they need no recipient,
/// but switching mail off under them would stop them in silence.
pub fn settings_of(kind: NotificationChannelKind) -> &'static [Setting] {
    match kind {
        NotificationChannelKind::Webhook => &[Setting::WebhookUrl],
        NotificationChannelKind::Teams => &[Setting::TeamsEnabled, Setting::TeamsWebhookUrl],
        NotificationChannelKind::Slack => &[Setting::SlackWebhookUrl],
        NotificationChannelKind::Discord => &[Setting::DiscordWebhookUrl],
        NotificationChannelKind::Mail => &[Setting::MailRecipients, Setting::ChecklistRemindersEnabled],
    }
}

/// The reading.
#[derive(Debug, Clone)]
pub struct NotificationDestinations {
    settings: Settings,
}

fn set(value: &str) -> bool {
    !vectispire_domain::java::is_blank(value)
}

impl NotificationDestinations {
    pub fn new(settings: Settings) -> NotificationDestinations {
        NotificationDestinations { settings }
    }

    /// What gives the channel somewhere to send today, as phrases the refusal lists; empty when nothing does. Read
    /// without the registry: a channel switched off by hand under a destination is still in use. `tx` is the switch's,
    /// for the teams' channels.
    pub async fn uses(&self, tx: &mut Tx, kind: NotificationChannelKind) -> Result<Vec<String>, NotificationError> {
        let value = |setting| self.settings.get(setting);
        let mut uses = Vec::new();
        match kind {
            NotificationChannelKind::Webhook => {
                if set(&value(Setting::WebhookUrl).await?) {
                    uses.push("the global webhook URL is set".to_owned());
                }
                let with_one = TeamChannels::count_with_channel(tx)
                    .await
                    .map_err(|failed| NotificationError::Failed(failed.to_string()))?;
                if with_one > 0 {
                    uses.push(if with_one == 1 {
                        "a team has a webhook of its own".to_owned()
                    } else {
                        format!("{with_one} teams have a webhook of their own")
                    });
                }
            }
            NotificationChannelKind::Teams => {
                if value(Setting::TeamsEnabled).await? == "true" && set(&value(Setting::TeamsWebhookUrl).await?) {
                    uses.push("the Microsoft Teams URL is set".to_owned());
                }
            }
            NotificationChannelKind::Slack => {
                if set(&value(Setting::SlackWebhookUrl).await?) {
                    uses.push("the Slack URL is set".to_owned());
                }
            }
            NotificationChannelKind::Discord => {
                if set(&value(Setting::DiscordWebhookUrl).await?) {
                    uses.push("the Discord URL is set".to_owned());
                }
            }
            NotificationChannelKind::Mail => {
                if set(&value(Setting::MailRecipients).await?) {
                    uses.push("e-mail recipients are set".to_owned());
                }
                if value(Setting::ChecklistRemindersEnabled).await? == "true" {
                    uses.push("the weekly checklist reminders are on".to_owned());
                }
            }
        }
        Ok(uses)
    }

    /// The channels a save configures: one of their settings changed to a value that sends. Clearing one, or sending
    /// back the stored value, configures nothing. **A secret is never compared with what is stored** — a writer who may
    /// not read it would learn from a 200 that a guess matched. `changes` are the values the save writes, trimmed. In
    /// the enum's order.
    pub async fn configured_by(
        &self,
        changes: &HashMap<Setting, String>,
    ) -> Result<Vec<NotificationChannelKind>, NotificationError> {
        let mut configured = Vec::new();
        for kind in NotificationChannelKind::ALL {
            for &setting in settings_of(kind) {
                let Some(value) = changes.get(&setting) else { continue };
                if set(value)
                    && value != "false"
                    && (setting.is_secret()
                        || *value != vectispire_domain::java::trim(&self.settings.get(setting).await?))
                {
                    configured.push(kind);
                    break;
                }
            }
        }
        Ok(configured)
    }
}

/// The notifications' answer to the registry: a channel with a destination is in use, and the governor may not switch
/// it off. **Refused rather than suspended**, like a SIEM transport: with the channel off the alerts meant for it would
/// be queued nowhere — the security lead reading a quiet channel as a quiet estate.
#[derive(Debug, Clone)]
pub struct NotificationChannelInUse {
    destinations: NotificationDestinations,
}

impl NotificationChannelInUse {
    pub fn new(destinations: NotificationDestinations) -> NotificationChannelInUse {
        NotificationChannelInUse { destinations }
    }
}

/// The refusal's end.
pub fn sentence(uses: &[String]) -> String {
    format!(
        "it is a channel the alerts are sent to — {}. Empty it first, in the notification settings or on the team: the \
         alerts queued for it would otherwise have nowhere to go, and be lost in silence.",
        uses.join(", ")
    )
}

impl InUse for NotificationChannelInUse {
    fn in_use<'a>(&'a self, tx: &'a mut Tx, integration: Integration) -> InUseFuture<'a> {
        Box::pin(async move {
            if integration.family() != IntegrationFamily::Notification {
                return Ok(None);
            }
            let Some(kind) = NotificationChannelKind::of_integration(integration) else { return Ok(None) };
            let uses = self.destinations.uses(tx, kind).await?;
            Ok((!uses.is_empty()).then(|| sentence(&uses)))
        })
    }
}
