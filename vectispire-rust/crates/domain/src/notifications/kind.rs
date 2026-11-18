//! `NotificationChannelKind`: the five destinations a scan's delta can be announced to, each an integration the
//! platform governor switches (decision 0040) and each with an outbox type of its own.

use crate::integrations::{Integration, IntegrationFamily};

/// In Java's declaration order, which is the registry's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NotificationChannelKind {
    /// The generic JSON POST, global or per team.
    Webhook,
    Teams,
    Slack,
    Discord,
    Mail,
}

impl NotificationChannelKind {
    pub const ALL: [NotificationChannelKind; 5] = [
        NotificationChannelKind::Webhook,
        NotificationChannelKind::Teams,
        NotificationChannelKind::Slack,
        NotificationChannelKind::Discord,
        NotificationChannelKind::Mail,
    ];

    /// The integration's name in the registry, `notification.<this>`; also a token alert's channel key.
    pub const fn wire_name(self) -> &'static str {
        match self {
            NotificationChannelKind::Webhook => "webhook",
            NotificationChannelKind::Teams => "teams",
            NotificationChannelKind::Slack => "slack",
            NotificationChannelKind::Discord => "discord",
            NotificationChannelKind::Mail => "mail",
        }
    }

    /// The outbox `message_type` a delivery to this channel is queued under. Stored: it does not move.
    pub const fn outbox_type(self) -> &'static str {
        match self {
            NotificationChannelKind::Webhook => "scan_delta",
            NotificationChannelKind::Teams => "scan_delta_teams",
            NotificationChannelKind::Slack => "scan_delta_slack",
            NotificationChannelKind::Discord => "scan_delta_discord",
            NotificationChannelKind::Mail => "scan_delta_mail",
        }
    }

    /// `byOutboxType`: exact, or nothing.
    pub fn by_outbox_type(message_type: &str) -> Option<NotificationChannelKind> {
        NotificationChannelKind::ALL.into_iter().find(|kind| kind.outbox_type() == message_type)
    }

    /// The channel a token alert's key names, exactly.
    pub fn by_wire_name(name: &str) -> Option<NotificationChannelKind> {
        NotificationChannelKind::ALL.into_iter().find(|kind| kind.wire_name() == name)
    }

    /// `Integration.of(kind)`.
    pub fn integration(self) -> Integration {
        Integration::all()
            .into_iter()
            .find(|integration| {
                integration.family() == IntegrationFamily::Notification && integration.name() == self.wire_name()
            })
            // Every kind is in the registry's notification family; `the_registry_names_every_kind` holds it.
            .unwrap_or_else(|| unreachable_integration(self))
    }

    /// The kind an integration of the notification family is, if any.
    pub fn of_integration(integration: Integration) -> Option<NotificationChannelKind> {
        NotificationChannelKind::ALL.into_iter().find(|kind| kind.integration() == integration)
    }
}

#[allow(clippy::panic)]
fn unreachable_integration(kind: NotificationChannelKind) -> Integration {
    panic!("the registry has no notification.{} integration", kind.wire_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_names_every_kind() {
        let names: Vec<String> = Integration::all()
            .into_iter()
            .filter(|integration| integration.family() == IntegrationFamily::Notification)
            .map(|integration| integration.name().to_owned())
            .collect();
        let kinds: Vec<String> = NotificationChannelKind::ALL.iter().map(|kind| kind.wire_name().to_owned()).collect();
        assert_eq!(names, kinds);
        for kind in NotificationChannelKind::ALL {
            assert_eq!(kind.integration().key(), format!("notification.{}", kind.wire_name()));
            assert_eq!(NotificationChannelKind::by_outbox_type(kind.outbox_type()), Some(kind));
        }
        assert_eq!(NotificationChannelKind::by_outbox_type("scan_delta_fax"), None);
    }
}
