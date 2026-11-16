//! What posture needs of a module not ported yet: the weekly report's two channels, which are the notifications
//! module's (`NotificationService`'s webhook, `MailNotificationChannel`, `OutboundPost`'s signed delivery).
//!
//! Behind a port so that this module stays whole and the notifications port plugs in without touching it; until then
//! [`NotificationsStandIn`] answers that **no destination is configured** — the absent answer, never a send that did
//! not happen. With no destination the digest returns before counting anything and writes no audit entry, exactly as
//! a Java deployment that switched the report on and configured no channel does.

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

/// No channel: the notifications module is not ported (wave 2). Named in `golden/deferred/notifications.txt`.
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
