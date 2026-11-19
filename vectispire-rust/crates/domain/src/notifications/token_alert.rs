//! `TokenAlert`: an integration token's change of state — the tracker's, or a forge connection's — said once where
//! it has to be said: the audit log, through it the SIEM, and the notification channels.
//!
//! **Raised by the module that owns the token**, in the transaction that records it as said (`tickets`, `forges`),
//! and queued by `notifications`. It lives here, beside the messages it is rendered into, so that neither owner
//! depends on the channels — Java publishes it as an application event declared in `common.domain`.
//!
//! **No secret, by construction**: names, dates and a status — never the token, a header or (for the tracker) its
//! address, which is a secret setting.
//!
//! Stored in the outbox (`token_alert_audit`, and inside `token_alert`'s `Queued`), so its JSON is a data contract
//! with the Java control plane: the record's component names, the enums' constant names, instants as
//! `Instant.toString`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::instant::Instant;
use crate::siem::SecurityEventType;
use crate::token_expiry::Standing;

/// Whose token it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Credential {
    TrackerToken,
    ForgeConnection,
}

impl Credential {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Credential::TrackerToken => "tracker_token",
            Credential::ForgeConnection => "forge_connection",
        }
    }

    const fn consequence(self) -> &'static str {
        match self {
            Credential::TrackerToken => "no ticket is opened or closed",
            Credential::ForgeConnection => "the connection can neither discover repositories nor read change reviews",
        }
    }

    /// The interface's page where the token is replaced, relative to the deployment's public address.
    pub const fn screen(self) -> &'static str {
        match self {
            Credential::TrackerToken => "/settings",
            Credential::ForgeConnection => "/forge-connections",
        }
    }
}

/// What there is to say about a token. The wire names are stored as "what was last said": they do not move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Notice {
    None,
    ExpiresSoon,
    Expired,
    Refused,
}

impl Notice {
    pub const ALL: [Notice; 4] = [Notice::None, Notice::ExpiresSoon, Notice::Expired, Notice::Refused];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Notice::None => "none",
            Notice::ExpiresSoon => "expires_soon",
            Notice::Expired => "expired",
            Notice::Refused => "refused",
        }
    }

    /// What a stored value says: absent, blank or unknown is [`Notice::None`] — what was said of a new token.
    pub fn read(stored: Option<&str>) -> Notice {
        let Some(stored) = stored.filter(|value| !crate::java::is_blank(value)) else { return Notice::None };
        let trimmed = crate::java::trim(stored);
        Notice::ALL.into_iter().find(|notice| notice.wire_name() == trimmed).unwrap_or(Notice::None)
    }

    /// The refusal first: a refused token's date no longer matters.
    pub fn of(refused: bool, standing: Standing) -> Notice {
        if refused {
            return Notice::Refused;
        }
        match standing {
            Standing::Soon => Notice::ExpiresSoon,
            Standing::Expired => Notice::Expired,
            Standing::Unknown | Standing::Valid => Notice::None,
        }
    }

    /// Whether the token no longer works.
    pub fn stopped(self) -> bool {
        matches!(self, Notice::Expired | Notice::Refused)
    }
}

/// The alert. `reference` is what the audit entry names (`ticket_token`, or the connection's id); `name` the
/// connection's name or the tracker's label; `where_` the server for a reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAlert {
    pub credential: Credential,
    pub reference: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "where")]
    pub where_: Option<String>,
    pub notice: Notice,
    pub previous: Notice,
    #[serde(with = "java_instant")]
    pub expires_at: Option<Instant>,
    pub refused_status: Option<i32>,
    #[serde(with = "java_instant")]
    pub refused_since: Option<Instant>,
    #[serde(with = "java_instant")]
    pub observed_at: Option<Instant>,
}

impl TokenAlert {
    /// The audit operation's name, one per event, so that the audit log's hook signals each without its writer
    /// naming it.
    pub fn operation_name(&self) -> &'static str {
        self.signal().wire_name()
    }

    /// The SIEM event the audit entry stands for.
    pub fn signal(&self) -> SecurityEventType {
        match self.notice {
            Notice::ExpiresSoon => SecurityEventType::IntegrationTokenExpiring,
            Notice::Expired | Notice::Refused => SecurityEventType::IntegrationTokenStopped,
            Notice::None => SecurityEventType::IntegrationTokenRestored,
        }
    }

    /// Who the token is, in words.
    pub fn subject(&self) -> String {
        match self.credential {
            Credential::TrackerToken => format!("The tracker token ({})", one_line(self.where_.as_deref())),
            Credential::ForgeConnection => format!(
                "The token of forge connection \"{}\" ({})",
                one_line(self.name.as_deref()),
                one_line(self.where_.as_deref())
            ),
        }
    }

    /// What happened, in a few words — a mail's subject, a card's title.
    pub fn headline(&self) -> String {
        self.headline_of(&match self.credential {
            Credential::TrackerToken => "tracker token".to_owned(),
            Credential::ForgeConnection => format!("forge connection \"{}\"", one_line(self.name.as_deref())),
        })
    }

    /// Without the connection's name, for Slack's header, which has no escape of its own.
    pub fn anonymous_headline(&self) -> String {
        self.headline_of(match self.credential {
            Credential::TrackerToken => "tracker token",
            Credential::ForgeConnection => "forge connection",
        })
    }

    fn headline_of(&self, who: &str) -> String {
        let what = match self.notice {
            Notice::ExpiresSoon => "token expires soon",
            Notice::Expired => "token expired",
            Notice::Refused => "token refused",
            Notice::None if self.previous == Notice::ExpiresSoon => "token no longer about to expire",
            Notice::None => "token working again",
        };
        format!("Vectispire · {who} · {what}")
    }

    /// The sentence every message carries, and the audit entry's description.
    pub fn sentence(&self) -> String {
        let consequence = self.credential.consequence();
        let subject = self.subject();
        match self.notice {
            Notice::ExpiresSoon => {
                format!("{subject} expires on {}: replace it before then, or {consequence}.", date(self.expires_at))
            }
            Notice::Expired => {
                format!("{subject} expired on {}: {consequence} until it is replaced.", date(self.expires_at))
            }
            Notice::Refused => format!(
                "{subject} is refused by the server{} since {}: it is expired, revoked or lacks a permission, and \
                 {consequence} until it is replaced.",
                self.refused_status.map(|status| format!(" (HTTP {status})")).unwrap_or_default(),
                date(self.refused_since)
            ),
            Notice::None if self.previous == Notice::ExpiresSoon => format!("{subject} is no longer about to expire."),
            Notice::None => format!("{subject} works again."),
        }
    }
}

fn date(instant: Option<Instant>) -> String {
    instant.and_then(Instant::to_java_string).unwrap_or_else(|| "an unknown date".to_owned())
}

/// A name an administrator typed, on one line: every ISO control a space, then `trim`.
pub fn one_line(value: Option<&str>) -> String {
    let Some(value) = value else { return String::new() };
    let line: String = value.chars().map(|c| if crate::java::is_iso_control(c) { ' ' } else { c }).collect();
    crate::java::trim(&line).to_owned()
}

/// An optional instant as Jackson's `JavaTimeModule` writes and reads it: `Instant.toString`, or `null`.
pub mod java_instant {
    use super::*;

    pub fn serialize<S: Serializer>(value: &Option<Instant>, serializer: S) -> Result<S::Ok, S::Error> {
        match value.and_then(Instant::to_java_string) {
            Some(text) => serializer.serialize_str(&text),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Instant>, D::Error> {
        let text: Option<String> = Option::deserialize(deserializer)?;
        match text {
            None => Ok(None),
            Some(text) => Instant::parse_java(&text)
                .map(Some)
                .ok_or_else(|| serde::de::Error::custom(format!("not an instant: {text}"))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn alert(notice: Notice, previous: Notice) -> TokenAlert {
        TokenAlert {
            credential: Credential::ForgeConnection,
            reference: Some("7".into()),
            name: Some("main\nforge".into()),
            where_: Some("GitLab at https://gitlab.example.com".into()),
            notice,
            previous,
            expires_at: Instant::of_utc(2026, 12, 1, 0, 0, 0),
            refused_status: Some(401),
            refused_since: Instant::of_utc(2026, 11, 1, 10, 0, 0),
            observed_at: Instant::of_utc(2026, 11, 2, 10, 0, 0),
        }
    }

    #[test]
    fn the_sentences_name_who_what_and_since_when() {
        assert_eq!(
            alert(Notice::Refused, Notice::None).sentence(),
            "The token of forge connection \"main forge\" (GitLab at https://gitlab.example.com) is refused by the \
             server (HTTP 401) since 2026-11-01T10:00:00Z: it is expired, revoked or lacks a permission, and the \
             connection can neither discover repositories nor read change reviews until it is replaced."
        );
        assert_eq!(
            alert(Notice::None, Notice::ExpiresSoon).anonymous_headline(),
            "Vectispire · forge connection · token no longer about to expire"
        );
        assert_eq!(alert(Notice::Expired, Notice::None).operation_name(), "INTEGRATION_TOKEN_STOPPED");
    }

    #[test]
    fn the_json_is_the_records() {
        let json = serde_json::to_string(&alert(Notice::ExpiresSoon, Notice::None)).unwrap();
        assert!(json.starts_with(r#"{"credential":"FORGE_CONNECTION","reference":"7","name":"main\nforge","where":"#));
        assert!(json.contains(r#""notice":"EXPIRES_SOON","previous":"NONE","expiresAt":"2026-12-01T00:00:00Z""#));
        let back: TokenAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(back, alert(Notice::ExpiresSoon, Notice::None));
        assert_eq!(Notice::read(Some(" refused ")), Notice::Refused);
        assert_eq!(Notice::read(Some("gone")), Notice::None);
    }
}
