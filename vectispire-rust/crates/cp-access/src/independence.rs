//! Whether the second pair of eyes is somebody else's — `ApproverIndependence` (#126, option 1): under four-eyes, an
//! approval is refused when the requester created the approver's account, reset its password or changed its role
//! within the window the platform governor sets — thirty days unless it says otherwise.
//!
//! **Why two identities are not two people.** Four-eyes compared the requester's name with the approver's, and an
//! administrator who wanted a decision through could make the second name: create an account with an approving role,
//! or reset the password of one that holds it, sign in with the password just typed and approve. This asks the
//! question the name comparison could not: did the requester hold the approver's account in their hands recently?
//!
//! **What it reads**: `t_account_administration`, written in the transaction of each gesture (V100) — not the audit
//! log, whose entries say which gesture in a sentence. **With four-eyes off, nothing**, and a window of zero switches
//! the check off as well.
//!
//! Over the database and the settings rather than the account store, so that `issues` asks it of a triage's approver
//! as `access` asks it of an account request's.

use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use vectispire_cp_db::Db;
use vectispire_cp_settings::rules::MAX_INDEPENDENCE_DAYS;
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::java;

use crate::persistence::four_eyes;
use crate::persistence::model::{Gesture, StoreError};

/// `ApproverNotIndependentException.CAUSE`.
pub const APPROVER_NOT_INDEPENDENT: &str = "approver-not-independent";
/// `PasswordKnownException.CAUSE`.
pub const PASSWORD_KNOWN: &str = "password-known-to-administrator";

/// Why an approval was refused, or could not be judged.
#[derive(Debug, thiserror::Error)]
pub enum IndependenceError {
    /// 409, type `urn:vectispire:problem:approver-not-independent`, the members `gesture` and `windowDays`.
    #[error("{sentence}")]
    NotIndependent { sentence: String, gesture: Gesture, window_days: i32 },
    /// 409, type `urn:vectispire:problem:password-known-to-administrator`, the members `gesture` and `windowDays`.
    #[error("{sentence}")]
    PasswordKnown { sentence: String, gesture: Gesture, window_days: i32 },
    /// The gestures or the settings could not be read: a 500, never "independent" (decision 0007).
    #[error("the approver's independence could not be read: {0}")]
    Failed(String),
}

impl IndependenceError {
    /// The token the problem's `type` ends with, and its code.
    pub fn cause(&self) -> Option<&'static str> {
        match self {
            IndependenceError::NotIndependent { .. } => Some(APPROVER_NOT_INDEPENDENT),
            IndependenceError::PasswordKnown { .. } => Some(PASSWORD_KNOWN),
            IndependenceError::Failed(_) => None,
        }
    }
}

impl From<StoreError> for IndependenceError {
    fn from(error: StoreError) -> IndependenceError {
        IndependenceError::Failed(error.to_string())
    }
}

impl From<vectispire_cp_settings::SettingsError> for IndependenceError {
    fn from(error: vectispire_cp_settings::SettingsError) -> IndependenceError {
        IndependenceError::Failed(error.to_string())
    }
}

/// An account behind the work being approved, by its id and the name the work records — `Author`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    pub account_id: i64,
    pub username: String,
}

/// `ApproverIndependence`.
#[derive(Clone)]
pub struct ApproverIndependence {
    db: Db,
    settings: Arc<Settings>,
}

impl std::fmt::Debug for ApproverIndependence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ApproverIndependence")
    }
}

impl ApproverIndependence {
    pub fn new(db: Db, settings: Arc<Settings>) -> ApproverIndependence {
        ApproverIndependence { db, settings }
    }

    /// By name, as a triage's history records its requester. A name that is no account any more has administered
    /// nothing this table can show, and is let through: the name comparison before this one still refuses the same
    /// name.
    pub async fn require(
        &self,
        requester: Option<&str>,
        approver: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), IndependenceError> {
        let (Some(requester), Some(approver)) = (requester, approver) else { return Ok(()) };
        let Some(window) = self.applying_window().await? else { return Ok(()) };
        let requester = four_eyes::account_named(&self.db, java::trim(requester)).await?;
        let approver = four_eyes::account_named(&self.db, java::trim(approver)).await?;
        if let (Some((requester_id, requester_name)), Some((approver_id, _))) = (requester, approver) {
            self.refuse(requester_id, &requester_name, approver_id, window, now).await?;
        }
        Ok(())
    }

    /// By account, as an account request records its requester.
    pub async fn require_by_id(
        &self,
        requester_id: i64,
        requester_name: &str,
        approver_id: i64,
        now: OffsetDateTime,
    ) -> Result<(), IndependenceError> {
        match self.applying_window().await? {
            Some(window) => self.refuse(requester_id, requester_name, approver_id, window, now).await,
            None => Ok(()),
        }
    }

    /// Both ways, for account requests only: an administrator whose creation another one filed and the first approved
    /// may be the filer's own second name.
    pub async fn require_mutual(
        &self,
        requester_id: i64,
        requester_name: &str,
        approver_id: i64,
        now: OffsetDateTime,
    ) -> Result<(), IndependenceError> {
        let Some(window) = self.applying_window().await? else { return Ok(()) };
        self.refuse(requester_id, requester_name, approver_id, window, now).await?;
        if let Some(gesture) = self.newest(requester_id, approver_id, window, now).await? {
            return Err(not_independent(of_requester(requester_name, gesture, window), gesture, window));
        }
        Ok(())
    }

    /// Both ways, for the approval of work — a checklist's sign-off, a template version's publication or retirement, a
    /// report plugin manifest's approval. `under_four_eyes` false checks nothing.
    pub async fn require_independent_of_authors(
        &self,
        authors: &[Author],
        approver_id: i64,
        under_four_eyes: bool,
        now: OffsetDateTime,
    ) -> Result<(), IndependenceError> {
        let window = self.window_days().await?;
        if !under_four_eyes || window <= 0 {
            return Ok(());
        }
        for author in authors {
            if author.account_id == approver_id {
                // The same account is the same person: the callers refuse it in their own words first.
                continue;
            }
            if let Some(gesture) = self.newest(approver_id, author.account_id, window, now).await? {
                return Err(not_independent(of_author(&author.username, gesture, window), gesture, window));
            }
            if let Some(gesture) = self.newest(author.account_id, approver_id, window, now).await? {
                return Err(not_independent(of_approver_of_author(&author.username, gesture, window), gesture, window));
            }
        }
        Ok(())
    }

    /// Refuses a raise to a role that approves when this administrator created the account or reset its password
    /// within the window: it may know the password, and the raise would hand it an approver.
    pub async fn require_password_unknown(
        &self,
        account_id: i64,
        account_name: &str,
        administrator_id: i64,
        administrator_name: &str,
        now: OffsetDateTime,
    ) -> Result<(), IndependenceError> {
        let Some(window) = self.applying_window().await? else { return Ok(()) };
        if account_id == administrator_id {
            return Ok(());
        }
        let made = four_eyes::gestures_since(&self.db, account_id, administrator_id, since(now, window)).await?;
        let known =
            made.iter().filter_map(|stored| Gesture::from_wire_name(stored)).find(|g| *g != Gesture::RoleChanged);
        match known {
            Some(gesture) => Err(IndependenceError::PasswordKnown {
                sentence: format!(
                    "{administrator_name} {} within the last {window} days and may know its password, so \
                     {account_name} cannot be given a role that approves through a request {administrator_name} \
                     filed or approves. Another administrator has to file and approve it, or it waits until the \
                     window has passed.",
                    done(gesture, account_name)
                ),
                gesture,
                window_days: window,
            }),
            None => Ok(()),
        }
    }

    /// Whether an account other than this one left an administrative role within the window — at least thirty days,
    /// whatever the window: counting the administrators there are now let one lower the others and act "alone".
    pub async fn another_administrator_lowered_recently(
        &self,
        excluding: i64,
        administrative_roles: &[&str],
        now: OffsetDateTime,
    ) -> Result<bool, IndependenceError> {
        let days = self.window_days().await?.max(30);
        Ok(four_eyes::any_changed_from_since(
            &self.db,
            Gesture::RoleChanged,
            administrative_roles,
            since(now, days),
            excluding,
        )
        .await?)
    }

    /// Whether four-eyes is on — the setting every four-eyes gesture reads.
    pub async fn four_eyes_required(&self) -> Result<bool, IndependenceError> {
        Ok(self.settings.is_enabled(Setting::FourEyesApprovalRequired).await?)
    }

    /// The window when the check applies: four-eyes on and a window above zero.
    async fn applying_window(&self) -> Result<Option<i32>, IndependenceError> {
        if !self.four_eyes_required().await? {
            return Ok(None);
        }
        let window = self.window_days().await?;
        Ok((window > 0).then_some(window))
    }

    /// The setting's own validation bounds it; a row written around it is read at its bound.
    async fn window_days(&self) -> Result<i32, IndependenceError> {
        Ok(self.settings.as_int(Setting::FourEyesIndependenceDays).await?.clamp(0, MAX_INDEPENDENCE_DAYS))
    }

    async fn refuse(
        &self,
        requester_id: i64,
        requester_name: &str,
        approver_id: i64,
        window: i32,
        now: OffsetDateTime,
    ) -> Result<(), IndependenceError> {
        if requester_id == approver_id {
            // The same account is the same person: the callers refuse it in their own words first.
            return Ok(());
        }
        match self.newest(approver_id, requester_id, window, now).await? {
            Some(gesture) => Err(not_independent(of_approver(requester_name, gesture, window), gesture, window)),
            None => Ok(()),
        }
    }

    /// The newest gesture this administrator made on this account within the window.
    async fn newest(
        &self,
        account_id: i64,
        administrator_id: i64,
        window: i32,
        now: OffsetDateTime,
    ) -> Result<Option<Gesture>, IndependenceError> {
        if account_id == administrator_id {
            return Ok(None);
        }
        let made = four_eyes::gestures_since(&self.db, account_id, administrator_id, since(now, window)).await?;
        Ok(made.iter().find_map(|stored| Gesture::from_wire_name(stored)))
    }
}

/// `clock.instant().minus(Duration.ofDays(days))`. The window is bounded at ten years, so the subtraction holds; were it
/// ever not to, the earliest instant there is counts every gesture, which refuses rather than admits.
fn since(now: OffsetDateTime, days: i32) -> OffsetDateTime {
    now.checked_sub(Duration::days(i64::from(days))).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn not_independent(sentence: String, gesture: Gesture, window_days: i32) -> IndependenceError {
    IndependenceError::NotIndependent { sentence, gesture, window_days }
}

/// `ApproverNotIndependentException.done`.
fn done(gesture: Gesture, account: &str) -> String {
    match gesture {
        Gesture::Created => format!("created {account}"),
        Gesture::PasswordReset => format!("reset the password of {account}"),
        Gesture::RoleChanged => format!("changed the role of {account}"),
    }
}

/// The requester administered the approver.
fn of_approver(requester: &str, gesture: Gesture, window: i32) -> String {
    format!(
        "{requester} {} within the last {window} days, so you cannot approve what {requester} asked for: four-eyes \
         needs an approver {requester} did not administer. Somebody else has to approve it.",
        done(gesture, "your account")
    )
}

/// The approver administered the requester, who may be the approver's own second name.
fn of_requester(requester: &str, gesture: Gesture, window: i32) -> String {
    format!(
        "You {} within the last {window} days, so you cannot approve {requester}'s account requests: an \
         administrator you made could be your own second name. Somebody else has to approve it.",
        done(gesture, &format!("{requester}'s account"))
    )
}

/// An author of the work being approved administered the approver.
fn of_author(author: &str, gesture: Gesture, window: i32) -> String {
    format!(
        "{author} {} within the last {window} days, so you cannot approve what {author} wrote: four-eyes needs an \
         approver {author} did not administer. Somebody else has to approve it.",
        done(gesture, "your account")
    )
}

/// The approver administered an author of the work.
fn of_approver_of_author(author: &str, gesture: Gesture, window: i32) -> String {
    format!(
        "You {} within the last {window} days, so you cannot approve what {author} wrote: an account you \
         administered could be your own second name. Somebody else has to approve it.",
        done(gesture, &format!("{author}'s account"))
    )
}
