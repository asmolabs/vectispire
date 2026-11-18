//! The control plane's notifications — the Rust of `core.notifications` (wave 2).
//!
//! - **Five channels** ([`channels`]): the generic webhook (global, or a team's own), Microsoft Teams, Slack, Discord
//!   and mail. Each is an outbox [`NotificationChannel`](vectispire_cp_outbox::NotificationChannel) under its own
//!   message type, re-reads its destination at the send — an operator fixing a URL flushes what waits — and asks the
//!   integrations' registry first ([`gate`]): a channel the platform governor switched off is **held**, never failed,
//!   when the message came from the outbox, and refused 409 `integration-disabled` otherwise (decision 0040, lot I6).
//! - **The routing of a scan's delta** ([`routing::ScanDeltaNotifier`]), `issues`' `ScanDeltaSink`: one outbox row per
//!   listening channel, and one webhook copy per owning team with a channel of its own, inside the scan's transaction.
//! - **A token's change of state** ([`alerts`]): its audit entry and one message per configured channel, queued in the
//!   transaction that records the change as said — `tickets` and `forges` raise it through [`alerts::TokenAlerts`].
//! - **What uses a channel** ([`destinations`]): the registry's in-use refusal, and the channels a settings save
//!   configures.
//! - **The notification centre's two routes** ([`web::routes`]): the channels' status, and a test message.
//!
//! **Mail has no relay in this build.** Java sends through Spring's `JavaMailSender` when `vectispire.mail.host` is
//! set; this workspace has no SMTP client yet, so [`MailRelay`] is a port the binary hands `None` to — mail is then
//! "not configured", exactly as a Java deployment with no mail host: nothing is queued for it, and its test says so.
//! README.md names it.

#![forbid(unsafe_code)]

pub mod alerts;
pub mod channels;
pub mod destinations;
mod error;
pub mod gate;
mod internal;
pub mod routing;
pub mod service;
mod web;

use std::sync::Arc;

use futures_util::future::BoxFuture;
use vectispire_cp_audit::Clock;
use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::Db;
use vectispire_cp_outbound::OutboundPost;
use vectispire_cp_settings::{Integrations, Settings};

pub use alerts::{TokenAlertAudit, TokenAlertDelivery, TokenAlerts};
pub use channels::{ChatChannel, MailChannel, WebhookChannel};
pub use destinations::{NotificationChannelInUse, NotificationDestinations};
pub use error::NotificationError;
pub use routing::ScanDeltaNotifier;
pub use service::{NotificationService, NotificationTestService};
pub use web::routes;

/// A mail relay: the deployment's SMTP server — Java's `JavaMailSender`. Throws on failure, so a caller with a queue
/// retries and one without records nothing as sent.
pub trait MailRelay: Send + Sync {
    fn send<'a>(
        &'a self,
        from: &'a str,
        to: &'a [String],
        subject: &'a str,
        body: &'a str,
    ) -> BoxFuture<'a, Result<(), String>>;
}

/// What every part of the module reads: the settings, the registry, the door out, the keys, the clock.
#[derive(Clone)]
pub struct NotificationsConfig {
    pub db: Db,
    pub settings: Settings,
    pub integrations: Integrations,
    pub encryption: Arc<Encryption>,
    pub post: OutboundPost,
    /// `ExportProperties.publicUrl`: where a message links back to, when the deployment knows its address.
    pub public_url: Option<String>,
    /// `None` when no relay is configured — a deployment that sends no mail carries no channel for it.
    pub mail: Option<Arc<dyn MailRelay>>,
    /// `vectispire.mail.from`, `vectispire@localhost` by default.
    pub mail_from: String,
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for NotificationsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationsConfig")
            .field("public_url", &self.public_url)
            .field("mail", &self.mail.is_some())
            .field("mail_from", &self.mail_from)
            .finish_non_exhaustive()
    }
}

/// The channels: [`Channels::all`] says their order.
pub fn channels(config: &NotificationsConfig) -> Channels {
    let service = Arc::new(NotificationService::new(config.clone()));
    Channels {
        webhook: Arc::new(WebhookChannel::new(service.clone())),
        teams: Arc::new(ChatChannel::teams(config.clone())),
        slack: Arc::new(ChatChannel::slack(config.clone())),
        discord: Arc::new(ChatChannel::discord(config.clone())),
        mail: Arc::new(MailChannel::new(config.clone())),
        service,
    }
}

/// The module's channels, built once and shared by the outbox registry, the routing, the alerts and the centre.
#[derive(Clone)]
pub struct Channels {
    pub service: Arc<NotificationService>,
    pub webhook: Arc<WebhookChannel>,
    pub teams: Arc<ChatChannel>,
    pub slack: Arc<ChatChannel>,
    pub discord: Arc<ChatChannel>,
    pub mail: Arc<MailChannel>,
}

impl std::fmt::Debug for Channels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channels").finish_non_exhaustive()
    }
}

impl Channels {
    /// Every [`channels::Channel`], in the order Spring hands Java's `List<NotificationChannel>` — the beans as the
    /// classpath scan finds them, `notifications` before `notifications.internal`, each by class name: what the centre
    /// lists, and the order a delta's and an alert's rows are queued in.
    pub fn all(&self) -> Vec<Arc<dyn channels::Channel>> {
        vec![
            self.mail.clone() as Arc<dyn channels::Channel>,
            self.webhook.clone(),
            self.discord.clone(),
            self.slack.clone(),
            self.teams.clone(),
        ]
    }

    /// The outbox's channels, by message type.
    pub fn outbox_channels(&self) -> Vec<Arc<dyn vectispire_cp_outbox::NotificationChannel>> {
        vec![
            self.webhook.clone() as Arc<dyn vectispire_cp_outbox::NotificationChannel>,
            self.teams.clone(),
            self.slack.clone(),
            self.discord.clone(),
            self.mail.clone(),
        ]
    }
}
