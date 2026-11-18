//! `TokenAlert` (`common.domain.notifications`): an integration token's change of state — the tracker's, or a forge
//! connection's — said once: the audit log, through it the SIEM, and the notification channels.
//!
//! **Published by the module that owns the token**, in the transaction that records it as said, and heard by
//! `notifications`. It is here so that neither owner depends on the channels and the channels on neither owner.
//! **No secret, by construction**: the name an administrator gave, the server's label, the dates, a status.

use crate::instant::Instant;
use crate::siem::SecurityEventType;

/// Whose token it is. Stored in the outbox payload: the names are a data contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// The interface's page where the token is replaced.
    pub const fn screen(self) -> &'static str {
        match self {
            Credential::TrackerToken => "/settings",
            Credential::ForgeConnection => "/forge-connections",
        }
    }
}

/// What there is to say about a token. The wire names are stored as "what was last said": they must not move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    None,
    ExpiresSoon,
    Expired,
    Refused,
}

impl Notice {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Notice::None => "none",
            Notice::ExpiresSoon => "expires_soon",
            Notice::Expired => "expired",
            Notice::Refused => "refused",
        }
    }

    /// What a stored value says; absent, blank or unknown is [`Notice::None`].
    pub fn read(stored: Option<&str>) -> Notice {
        let Some(stored) = stored.filter(|stored| !crate::java::is_blank(stored)) else {
            return Notice::None;
        };
        let wanted = crate::java::trim(stored);
        [Notice::None, Notice::ExpiresSoon, Notice::Expired, Notice::Refused]
            .into_iter()
            .find(|notice| notice.wire_name() == wanted)
            .unwrap_or(Notice::None)
    }

    /// The refusal first: a refused token's date no longer matters.
    pub fn of(refused: bool, standing: crate::forges::expiry::Standing) -> Notice {
        use crate::forges::expiry::Standing;
        if refused {
            return Notice::Refused;
        }
        match standing {
            Standing::Soon => Notice::ExpiresSoon,
            Standing::Expired => Notice::Expired,
            Standing::Unknown | Standing::Valid => Notice::None,
        }
    }

    pub const fn stopped(self) -> bool {
        matches!(self, Notice::Expired | Notice::Refused)
    }
}

/// The alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAlert {
    pub credential: Credential,
    /// What the audit entry names: `ticket_token`, or the connection's identifier.
    pub reference: String,
    pub name: String,
    pub where_: String,
    pub notice: Notice,
    pub previous: Notice,
    pub expires_at: Option<Instant>,
    pub refused_status: Option<i32>,
    pub refused_since: Option<Instant>,
    pub observed_at: Instant,
}

impl TokenAlert {
    /// The audit operation's name: one per event.
    pub const fn operation(&self) -> &'static str {
        match self.notice {
            Notice::ExpiresSoon => "INTEGRATION_TOKEN_EXPIRING",
            Notice::Expired | Notice::Refused => "INTEGRATION_TOKEN_STOPPED",
            Notice::None => "INTEGRATION_TOKEN_RESTORED",
        }
    }

    /// The SIEM event the audit entry stands for.
    pub const fn signal(&self) -> SecurityEventType {
        match self.notice {
            Notice::ExpiresSoon => SecurityEventType::IntegrationTokenExpiring,
            Notice::Expired | Notice::Refused => SecurityEventType::IntegrationTokenStopped,
            Notice::None => SecurityEventType::IntegrationTokenRestored,
        }
    }

    /// Who the token is, in words.
    pub fn subject(&self) -> String {
        match self.credential {
            Credential::TrackerToken => format!("The tracker token ({})", one_line(Some(&self.where_))),
            Credential::ForgeConnection => format!(
                "The token of forge connection \"{}\" ({})",
                one_line(Some(&self.name)),
                one_line(Some(&self.where_))
            ),
        }
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

/// A name an administrator typed, on one line: every ISO control character a space, then trimmed.
pub fn one_line(value: Option<&str>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    let line: String = value.chars().map(|c| if crate::java::is_iso_control(c) { ' ' } else { c }).collect();
    crate::java::trim(&line).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(notice: Notice, previous: Notice) -> TokenAlert {
        TokenAlert {
            credential: Credential::ForgeConnection,
            reference: "c".into(),
            name: "Internal\nGitLab".into(),
            where_: "GitLab self-managed or Dedicated at https://gitlab.example.org".into(),
            notice,
            previous,
            expires_at: Instant::of_utc(2027, 1, 31, 0, 0, 0),
            refused_status: None,
            refused_since: None,
            observed_at: Instant::of_epoch_second(0),
        }
    }

    #[test]
    fn sentences_say_who_what_and_what_it_stops() {
        assert_eq!(
            alert(Notice::ExpiresSoon, Notice::None).sentence(),
            "The token of forge connection \"Internal GitLab\" (GitLab self-managed or Dedicated at \
             https://gitlab.example.org) expires on 2027-01-31T00:00:00Z: replace it before then, or the connection \
             can neither discover repositories nor read change reviews."
        );
        assert!(alert(Notice::None, Notice::ExpiresSoon).sentence().ends_with("is no longer about to expire."));
        assert!(alert(Notice::None, Notice::Expired).sentence().ends_with("works again."));
        assert_eq!(alert(Notice::Expired, Notice::None).operation(), "INTEGRATION_TOKEN_STOPPED");
    }

    #[test]
    fn a_stored_notice_reads_back_and_an_unknown_one_is_none() {
        assert_eq!(Notice::read(Some(" expired ")), Notice::Expired);
        assert_eq!(Notice::read(Some("lost")), Notice::None);
        assert_eq!(Notice::read(None), Notice::None);
    }
}
