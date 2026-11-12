//! The integrations a platform governor switches on and off (decision 0040) — `common.domain.integrations`:
//! [`Integration`], [`IntegrationFamily`], and the two refusals' sentences (`IntegrationDisabledException`,
//! `IntegrationInUseException`), which every module owning an adapter raises and none of them owns.
//!
//! **The key is a contract.** `<family>.<name>`, lowercase — `forge.gitlab`, `siem.syslog_tls`. It is the stored row's
//! identity (`t_integration`), the route's path and what an audit entry and a refusal name; renaming one would silently
//! turn an integration a governor enabled into a new one that reads disabled.
//!
//! **The list is Java's, in its order.** Java derives it from the adapters' enums (`ForgeKind`, `SiemProtocol`,
//! `AiProvider`, `NotificationChannelKind`, `TicketProvider` but `NONE`); only `SiemProtocol` has a Rust half yet, so the
//! SIEM family is derived from it and the others are written out — a value added to one of those enums on the Java
//! side is added here by the module that ports it. `vectispire-cp-settings`' engine suite holds the list to V94's
//! seed.

use crate::siem::SiemProtocol;

/// What kind of outside system an integration talks to: the first segment of every key, which is what keeps
/// `gitlab` the forge and `gitlab` the tracker two switches rather than one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IntegrationFamily {
    Forge,
    Siem,
    Ai,
    Notification,
    Tracker,
}

impl IntegrationFamily {
    pub const ALL: [IntegrationFamily; 5] = [
        IntegrationFamily::Forge,
        IntegrationFamily::Siem,
        IntegrationFamily::Ai,
        IntegrationFamily::Notification,
        IntegrationFamily::Tracker,
    ];

    /// The key's first segment and the form the API answers. Stored in every key: it does not move.
    pub const fn wire_name(self) -> &'static str {
        match self {
            IntegrationFamily::Forge => "forge",
            IntegrationFamily::Siem => "siem",
            IntegrationFamily::Ai => "ai",
            IntegrationFamily::Notification => "notification",
            IntegrationFamily::Tracker => "tracker",
        }
    }
}

/// One outside system Vectispire may talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Integration {
    family: IntegrationFamily,
    name: &'static str,
}

/// `IntegrationDisabledException.CAUSE`: the token the problem's `type` ends with, stated in the API's reference.
pub const DISABLED_CAUSE: &str = "integration-disabled";

/// `IntegrationInUseException.CAUSE`: its own cause, since the gesture that resolves it is another one.
pub const IN_USE_CAUSE: &str = "integration-in-use";

/// The longest key the column holds, `integration_key varchar(64)`.
pub const MAX_KEY_LENGTH: usize = 64;

const FORGES: [&str; 2] = ["github", "gitlab"];
const AI_PROVIDERS: [&str; 2] = ["ollama", "openai"];
const NOTIFICATION_CHANNELS: [&str; 5] = ["webhook", "teams", "slack", "discord", "mail"];
const TRACKERS: [&str; 4] = ["gitlab", "github", "jira", "servicenow"];

impl Integration {
    pub const fn family(self) -> IntegrationFamily {
        self.family
    }

    pub const fn name(self) -> &'static str {
        self.name
    }

    /// `<family>.<name>`: what the row, the route and the audit entry name.
    pub fn key(self) -> String {
        format!("{}.{}", self.family.wire_name(), self.name)
    }

    /// `Integration.of(SiemProtocol)`: the constant's name, lower-cased.
    pub const fn of_siem(protocol: SiemProtocol) -> Integration {
        let name = match protocol {
            SiemProtocol::Webhook => "webhook",
            SiemProtocol::SyslogUdp => "syslog_udp",
            SiemProtocol::SyslogTcp => "syslog_tcp",
            SiemProtocol::SyslogTls => "syslog_tls",
        };
        Integration { family: IntegrationFamily::Siem, name }
    }

    /// Every integration this version knows, by family in the order of [`IntegrationFamily`], then by the order of
    /// the family's enum.
    pub fn all() -> Vec<Integration> {
        let of = |family, names: &[&'static str]| -> Vec<Integration> {
            names.iter().map(|name| Integration { family, name }).collect()
        };
        let mut all = of(IntegrationFamily::Forge, &FORGES);
        all.extend(SiemProtocol::ALL.into_iter().map(Integration::of_siem));
        all.extend(of(IntegrationFamily::Ai, &AI_PROVIDERS));
        all.extend(of(IntegrationFamily::Notification, &NOTIFICATION_CHANNELS));
        all.extend(of(IntegrationFamily::Tracker, &TRACKERS));
        all
    }

    /// The integration a key names, exactly — no trimming, no case folding: a key is an identifier, not prose.
    pub fn by_key(key: &str) -> Option<Integration> {
        Integration::all().into_iter().find(|integration| integration.key() == key)
    }

    /// `IntegrationDisabledException`'s sentence, opened by `lead` — what the caller cannot have because of it, a
    /// sentence of its own with its full stop, or empty. **It names the route, not a screen**: it named one no
    /// release had, and a reader was sent to look for a page that does not exist.
    pub fn disabled_message(self, lead: &str) -> String {
        let key = self.key();
        format!(
            "{}The integration \"{key}\" is disabled on this installation; a platform governor enables it with PUT \
             /api/v1/integrations/{key}/enabled.",
            if lead.is_empty() { String::new() } else { format!("{lead} ") }
        )
    }

    /// `IntegrationInUseException`'s sentence: `using` says what uses it and what to change first.
    pub fn in_use_message(self, using: &str) -> String {
        format!("The integration \"{}\" is in use and cannot be disabled: {using}", self.key())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_key_is_a_lowercase_token_within_the_column() {
        for integration in Integration::all() {
            let key = integration.key();
            assert!(key.len() <= MAX_KEY_LENGTH, "{key}");
            let (family, name) = key.split_once('.').unwrap();
            assert_eq!(family, integration.family().wire_name());
            assert!(
                !name.is_empty() && !name.starts_with('_') && !name.ends_with('_') && !name.contains("__"),
                "{key}"
            );
            assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'), "{key}");
            assert_eq!(Integration::by_key(&key), Some(integration));
        }
        assert_eq!(Integration::by_key(" siem.webhook"), None, "a key is not trimmed");
        assert_eq!(Integration::by_key("SIEM.WEBHOOK"), None, "nor folded");
        assert_eq!(Integration::of_siem(SiemProtocol::SyslogTls).key(), "siem.syslog_tls");
    }

    #[test]
    fn the_sentences_are_java_s() {
        let tls = Integration::of_siem(SiemProtocol::SyslogTls);
        assert_eq!(
            tls.disabled_message(""),
            "The integration \"siem.syslog_tls\" is disabled on this installation; a platform governor enables it \
             with PUT /api/v1/integrations/siem.syslog_tls/enabled."
        );
        assert!(tls.disabled_message("AI unavailable.").starts_with("AI unavailable. The integration"));
        assert_eq!(
            tls.in_use_message("the SIEM export sends over it."),
            "The integration \"siem.syslog_tls\" is in use and cannot be disabled: the SIEM export sends over it."
        );
    }
}
