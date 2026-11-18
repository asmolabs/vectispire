//! The notifications module in the binary: its channels in the outbox's registry, its two handlers, its answer to the
//! integrations' registry, the routing of a scan's delta into the issues' backlog. Posture's weekly report and the
//! checklists' reminders send through it from their own crates (`cp-posture`'s `ChannelsDigest`, `cp-checklists`' mail
//! port), which list `notifications` among their edges as Java's modules do.

use std::sync::Arc;

use vectispire_cp_notifications::{Channels, NotificationsConfig, TokenAlertAudit, TokenAlertDelivery};
use vectispire_cp_outbound::OutboundPost;

/// `vectispire.mail.from`'s default: the runtime reads no sender of its own yet, and Java's default is this.
pub const DEFAULT_MAIL_FROM: &str = "vectispire@localhost";

/// What the module is built from at start.
pub struct NotificationParts {
    pub db: vectispire_cp_db::Db,
    pub encryption: Arc<vectispire_cp_crypto::Encryption>,
    pub post: OutboundPost,
    pub public_url: Option<String>,
    /// `vectispire.mail.host` named: Java then has a relay. This build has no SMTP client (README of
    /// `cp-notifications`), so a deployment that names one is told at start that mail stays unconfigured.
    pub mail_host_named: bool,
    pub clock: Arc<dyn vectispire_cp_audit::Clock>,
}

impl std::fmt::Debug for NotificationParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationParts").field("public_url", &self.public_url).finish_non_exhaustive()
    }
}

/// The module's configuration and channels.
pub fn compose(parts: NotificationParts) -> (NotificationsConfig, Channels) {
    if parts.mail_host_named {
        tracing::warn!(
            "vectispire.mail.host is set, and this build has no mail relay: e-mail notifications, the weekly report by \
             e-mail and the checklist reminders are not sent. The other channels are unaffected."
        );
    }
    let config = NotificationsConfig {
        db: parts.db.clone(),
        settings: vectispire_cp_settings::Settings::new(parts.db.clone()),
        integrations: crate::registry::integrations(&parts.db),
        encryption: parts.encryption,
        post: parts.post,
        public_url: parts.public_url,
        mail: None,
        mail_from: DEFAULT_MAIL_FROM.to_owned(),
        clock: parts.clock,
    };
    let channels = vectispire_cp_notifications::channels(&config);
    (config, channels)
}

/// The module's two outbox handlers: a token alert's message to one channel, and its audit entry.
pub fn handlers(
    channels: &Channels,
    audit: Arc<vectispire_cp_audit::AuditLog>,
) -> Vec<Arc<dyn vectispire_cp_outbox::OutboxHandler>> {
    vec![Arc::new(TokenAlertDelivery::new(channels.all())), Arc::new(TokenAlertAudit::new(audit))]
}

/// The routing of a scan's delta, handed to the issues' backlog.
pub fn scan_deltas(
    config: &NotificationsConfig,
    channels: &Channels,
    outbox: Arc<vectispire_cp_outbox::Outbox>,
    targets: Arc<vectispire_cp_targets::Targets>,
) -> Arc<vectispire_cp_notifications::ScanDeltaNotifier> {
    Arc::new(vectispire_cp_notifications::ScanDeltaNotifier::new(
        channels.service.clone(),
        channels.all(),
        outbox,
        Arc::new(vectispire_cp_notifications::routing::TargetsDirectory::new(targets, config.db.clone())),
        config.integrations.clone(),
    ))
}

/// The listener a token's owner raises its alerts through.
pub fn token_alerts(
    config: &NotificationsConfig,
    channels: &Channels,
    outbox: Arc<vectispire_cp_outbox::Outbox>,
) -> Arc<vectispire_cp_notifications::TokenAlerts> {
    Arc::new(vectispire_cp_notifications::TokenAlerts::new(outbox, channels.all(), config.integrations.clone()))
}

/// The centre's two routes.
pub fn routes(config: &NotificationsConfig, channels: &Channels) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    vectispire_cp_notifications::routes(Arc::new(vectispire_cp_notifications::NotificationTestService::new(
        config.clone(),
        channels.all(),
    )))
}

/// The module over a guard that reserves nothing and the built-in trust, with no public address — for the tests and
/// the replay, which compose the same registry as the binary.
pub fn compose_plain(
    db: &vectispire_cp_db::Db,
    encryption: Arc<vectispire_cp_crypto::Encryption>,
) -> (NotificationsConfig, Channels) {
    compose(NotificationParts {
        db: db.clone(),
        encryption,
        post: OutboundPost::new(
            vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
            vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        ),
        public_url: None,
        mail_host_named: false,
        clock: Arc::new(vectispire_cp_audit::SystemClock),
    })
}
