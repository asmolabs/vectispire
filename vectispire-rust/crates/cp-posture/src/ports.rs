//! What posture needs of a module not ported yet: the weekly report's two channels, which are the notifications
//! module's (`NotificationService`'s webhook, `MailNotificationChannel`, `OutboundPost`'s signed delivery).
//!
//! Behind a port so that the digest's own tests run without a channel: [`ChannelsDigest`] is the notifications
//! module's (what the binary composes), [`NotificationsStandIn`] answers that **no destination is configured** — the
//! absent answer, never a send that did not happen — for the module's tests. With no destination the digest returns
//! before counting anything and writes no audit entry, exactly as a Java deployment that switched the report on and
//! configured no channel does.

use time::OffsetDateTime;
use vectispire_cp_http::credentials::BoxFuture;

use crate::digest::PostureDigest;

/// Where the weekly report can go now: each channel configured **and** switched on by the platform governor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Destinations {
    pub webhook: bool,
    pub mail: bool,
}

/// The notifications module's half of the weekly report.
pub trait DigestChannels: Send + Sync + std::fmt::Debug {
    fn destinations(&self) -> BoxFuture<'_, Result<Destinations, String>>;

    /// Posts the report to the webhook, signed with the webhook's secret, under the outbound policy the settings
    /// choose — `OutboundPost.postSignedJson`.
    fn post_webhook<'a>(&'a self, digest: &'a PostureDigest, at: OffsetDateTime) -> BoxFuture<'a, Result<(), String>>;

    /// Sends the report by mail — `MailNotificationChannel.sendText`.
    fn send_mail<'a>(&'a self, subject: &'a str, text: &'a str) -> BoxFuture<'a, Result<(), String>>;
}

/// No channel: for the module's tests, which compose no notifications.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotificationsStandIn;

impl DigestChannels for NotificationsStandIn {
    fn destinations(&self) -> BoxFuture<'_, Result<Destinations, String>> {
        Box::pin(async { Ok(Destinations::default()) })
    }

    fn post_webhook<'a>(&'a self, _: &'a PostureDigest, _: OffsetDateTime) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Err("no webhook: the notifications module is not ported".to_owned()) })
    }

    fn send_mail<'a>(&'a self, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Err("no mail: the notifications module is not ported".to_owned()) })
    }
}

/// The notifications module's webhook and mail — `PostureDigestService`'s use of `NotificationService`,
/// `OutboundPost.postSignedJson` and `MailNotificationChannel.sendText`.
pub struct ChannelsDigest {
    pub config: vectispire_cp_notifications::NotificationsConfig,
    pub channels: vectispire_cp_notifications::Channels,
}

impl std::fmt::Debug for ChannelsDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelsDigest").finish_non_exhaustive()
    }
}

impl DigestChannels for ChannelsDigest {
    fn destinations(&self) -> BoxFuture<'_, Result<Destinations, String>> {
        Box::pin(async move {
            use vectispire_cp_notifications::channels::Channel;
            let service = &self.channels.service;
            // A channel the governor switched off is not a destination: it cannot be switched off while configured, so
            // this reads the registry for a row written by hand.
            let webhook = !service.webhook_url().await.map_err(|e| e.to_string())?.is_empty()
                && service.is_switched_on().await.map_err(|e| e.to_string())?;
            let mail = self.channels.mail.configured().await.map_err(|e| e.to_string())?
                && self.channels.mail.is_switched_on().await.map_err(|e| e.to_string())?;
            Ok(Destinations { webhook, mail })
        })
    }

    fn post_webhook<'a>(&'a self, digest: &'a PostureDigest, at: OffsetDateTime) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let service = &self.channels.service;
            let url = service.webhook_url().await.map_err(|e| e.to_string())?;
            let private = self
                .config
                .settings
                .is_enabled(vectispire_cp_settings::Setting::NotificationAllowPrivateUrl)
                .await
                .map_err(|e| e.to_string())?;
            let policy = if private {
                vectispire_cp_outbound::OutboundPolicy::InternalAllowed
            } else {
                vectispire_cp_outbound::OutboundPolicy::PublicOnly
            };
            // Signed like every webhook message: a report saying "nothing is late" is the one somebody would forge.
            let secret = service.signing_secret().await.map_err(|e| e.to_string())?;
            self.config
                .post
                .post_signed_json(
                    &url,
                    &vectispire_domain::wire::to_wire_string(digest),
                    policy,
                    "weekly report webhook URL",
                    &secret,
                    at.unix_timestamp(),
                )
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn send_mail<'a>(&'a self, subject: &'a str, text: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move { self.channels.mail.send_text(subject, text).await.map_err(|e| e.to_string()) })
    }
}
