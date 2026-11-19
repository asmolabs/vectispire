//! `TrackerTokenState`: what is known of the tracker token's life — the expiry the tracker reported, the one an
//! administrator declared, and whether the tracker stopped accepting it — and its announcement, **once per change**.
//!
//! Rows of their own, outside the catalog (`setInternal`): what the tracker said is not a setting anybody writes. The
//! record that a change was said is moved by a conditional update in a transaction of its own (`REQUIRES_NEW`), in
//! which the alert is queued too — so of two instances noticing one change one announces it, and the record and the
//! alert commit together.

use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Mode};
use vectispire_cp_outbox::TokenAlertSink;
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::instant::Instant;
use vectispire_domain::notifications::{Credential, Notice, TokenAlert};
use vectispire_domain::tickets::TicketProvider;
use vectispire_domain::token_expiry::{self, Standing};

use crate::error::TicketError;

/// The expiry the tracker reported, an instant; empty when it reported none. Absent: never asked.
pub const REPORTED_EXPIRY: &str = "ticket_token_reported_expiry";
/// `<status> <instant>` of the first refusal since the token was last accepted; empty otherwise.
pub const REFUSED: &str = "ticket_token_refused";
/// When the tracker last answered the token check.
pub const CHECKED_AT: &str = "ticket_token_checked_at";
/// The standing last announced, so that it is announced once.
pub const ANNOUNCED: &str = "ticket_token_announced";
/// What `TokenAlert.reference` names for the tracker: its token's setting.
pub const REFERENCE: &str = "ticket_token";

/// Where the known expiry comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpirySource {
    /// The tracker said, when asked — GitLab's token description, GitHub's response header.
    Reported,
    /// An administrator wrote it: Jira and ServiceNow say nothing.
    Declared,
    Unknown,
}

impl ExpirySource {
    pub fn wire_name(self) -> &'static str {
        match self {
            ExpirySource::Reported => "reported",
            ExpirySource::Declared => "declared",
            ExpirySource::Unknown => "unknown",
        }
    }
}

/// A tracker that refused a call made with the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub status: i32,
    pub since: Instant,
}

/// Everything known of the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    pub expires_at: Option<Instant>,
    pub expiry_source: ExpirySource,
    pub refused: Option<Refusal>,
    pub checked_at: Option<Instant>,
}

impl Health {
    /// What the screen and the log say, the refusal first: a refused token's date no longer matters.
    pub fn announcement(&self, now: Instant) -> Notice {
        Notice::of(self.refused.is_some(), Standing::of(self.expires_at, now))
    }
}

/// The state.
pub struct TrackerTokenState {
    db: Db,
    settings: Settings,
    alerts: Arc<dyn TokenAlertSink>,
}

impl std::fmt::Debug for TrackerTokenState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackerTokenState").finish_non_exhaustive()
    }
}

pub(crate) fn instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}

fn java_string(at: Instant) -> String {
    at.to_java_string().unwrap_or_default()
}

impl TrackerTokenState {
    pub fn new(db: Db, settings: Settings, alerts: Arc<dyn TokenAlertSink>) -> TrackerTokenState {
        TrackerTokenState { db, settings, alerts }
    }

    async fn internal(&self, key: &str) -> Result<String, TicketError> {
        Ok(self
            .settings
            .internal_value(key)
            .await?
            .map(|value| vectispire_domain::java::trim(&value).to_owned())
            .unwrap_or_default())
    }

    async fn set_internal(&self, key: &str, value: &str) -> Result<(), TicketError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await.map_err(TicketError::failed)?;
        self.settings.set_internal(&mut tx, key, value).await?;
        tx.commit().await.map_err(TicketError::failed)?;
        Ok(())
    }

    pub async fn read(&self) -> Result<Health, TicketError> {
        let reported = parse_instant(&self.internal(REPORTED_EXPIRY).await?);
        let declared = token_expiry::of_date(Some(&self.settings.get(Setting::TicketTokenExpiresOn).await?));
        let expiry_source = if reported.is_some() {
            ExpirySource::Reported
        } else if declared.is_some() {
            ExpirySource::Declared
        } else {
            ExpirySource::Unknown
        };
        Ok(Health {
            expires_at: reported.or(declared),
            expiry_source,
            refused: refusal(&self.internal(REFUSED).await?),
            checked_at: parse_instant(&self.internal(CHECKED_AT).await?),
        })
    }

    pub(crate) async fn checked_at(&self) -> Result<Option<Instant>, TicketError> {
        Ok(parse_instant(&self.internal(CHECKED_AT).await?))
    }

    /// The tracker answered the check: what it says of the expiry — nothing, possibly — replaces what it said.
    pub(crate) async fn record_reported(&self, expires_at: Option<Instant>, now: Instant) -> Result<(), TicketError> {
        let value = expires_at.map(java_string).unwrap_or_default();
        if value != self.internal(REPORTED_EXPIRY).await? {
            self.set_internal(REPORTED_EXPIRY, &value).await?;
        }
        self.set_internal(CHECKED_AT, &java_string(now)).await
    }

    /// The tracker refused the token. The first refusal's date is kept: a refusal met every hour is one change.
    pub(crate) async fn record_refused(&self, status: i32, now: Instant) -> Result<(), TicketError> {
        if self.internal(REFUSED).await?.is_empty() {
            self.set_internal(REFUSED, &format!("{status} {}", java_string(now))).await?;
        }
        self.announce(now).await.map(|_| ())
    }

    /// A call made with the token succeeded: a refusal recorded before is over.
    pub(crate) async fn record_accepted(&self, now: Instant) -> Result<(), TicketError> {
        if !self.internal(REFUSED).await?.is_empty() {
            self.set_internal(REFUSED, "").await?;
        }
        self.announce(now).await.map(|_| ())
    }

    /// A new token, or none: what was known of the previous one says nothing of it. **What was announced is kept**,
    /// so the replacement of a token said to have stopped is said to work again.
    pub async fn reset(&self) -> Result<(), TicketError> {
        for key in [REPORTED_EXPIRY, REFUSED, CHECKED_AT] {
            if self.settings.internal_value(key).await?.is_some() {
                self.set_internal(key, "").await?;
            }
        }
        Ok(())
    }

    /// Announces what there is to say when it changed since it was last said, and records that it was. Nothing while no
    /// token is configured. What was announced, or nothing when it had been already — here or by another instance.
    pub(crate) async fn announce(&self, now: Instant) -> Result<Option<Notice>, TicketError> {
        if vectispire_domain::java::is_blank(&self.settings.get(Setting::TicketToken).await?) {
            return Ok(None);
        }
        let health = self.read().await?;
        let current = health.announcement(now);
        let mut stored = self.settings.internal_value(ANNOUNCED).await?;
        if stored.is_none() {
            // The conditional update needs a row to arbitrate on; whoever inserts it, it starts as "nothing said".
            self.settings.store_internal_if_absent(ANNOUNCED, "").await?;
            stored = self.settings.internal_value(ANNOUNCED).await?;
        }
        let expected = stored.unwrap_or_default();
        let previous = Notice::read(Some(&expected));
        if previous == current {
            return Ok(None);
        }
        let label = provider_label(&self.settings.get(Setting::TicketProvider).await?);
        let alert = TokenAlert {
            credential: Credential::TrackerToken,
            reference: Some(REFERENCE.to_owned()),
            name: Some(label.to_owned()),
            // Its kind alone, never its address: the URL is a secret setting, and the alert is copied where that
            // protection does not follow — the audit trail, the SIEM, every chat.
            where_: Some(label.to_owned()),
            notice: current,
            previous,
            expires_at: health.expires_at,
            refused_status: health.refused.map(|refusal| refusal.status),
            refused_since: health.refused.map(|refusal| refusal.since),
            observed_at: Some(now),
        };
        let mut tx = self.db.begin(Mode::ReadWrite).await.map_err(TicketError::failed)?;
        if !self.settings.replace_internal(&mut tx, ANNOUNCED, &expected, current.wire_name()).await? {
            // Another instance said it first, or something moved since the read: the next turn reads again.
            tx.rollback().await.map_err(TicketError::failed)?;
            return Ok(None);
        }
        self.alerts.changed(&mut tx, &alert).await.map_err(|failed| TicketError::Failed(failed.to_string()))?;
        tx.commit().await.map_err(TicketError::failed)?;
        let date = |at: Option<Instant>| at.map(java_string).unwrap_or_default();
        match current {
            Notice::ExpiresSoon => tracing::warn!(
                "The tracker token expires on {} ({}): replace it before then, or no ticket will be opened or closed.",
                date(health.expires_at),
                health.expiry_source.wire_name()
            ),
            Notice::Expired => tracing::warn!(
                "The tracker token expired on {} ({}): no ticket is opened or closed until it is replaced.",
                date(health.expires_at),
                health.expiry_source.wire_name()
            ),
            Notice::Refused => tracing::warn!(
                "The tracker refused its token (HTTP {}) since {}: it is expired, revoked or lacks a permission, and no \
                 ticket is opened or closed until it is replaced.",
                health.refused.map(|refusal| refusal.status).unwrap_or_default(),
                date(health.refused.map(|refusal| refusal.since))
            ),
            Notice::None => tracing::info!("The tracker token is no longer refused nor about to expire."),
        }
        Ok(Some(current))
    }
}

/// The tracker for a reader: its kind alone.
pub fn provider_label(stored: &str) -> &'static str {
    match TicketProvider::from_wire_name(Some(stored)).unwrap_or(TicketProvider::None) {
        TicketProvider::Gitlab => "GitLab",
        TicketProvider::Github => "GitHub",
        TicketProvider::Jira => "Jira",
        TicketProvider::Servicenow => "ServiceNow",
        TicketProvider::None => "no tracker",
    }
}

fn parse_instant(value: &str) -> Option<Instant> {
    if value.is_empty() { None } else { Instant::parse_java(value) }
}

fn refusal(value: &str) -> Option<Refusal> {
    let (status, since) = value.split_once(' ')?;
    let status = vectispire_domain::java::parse_int(status).ok()?;
    Some(Refusal { status, since: parse_instant(since)? })
}
