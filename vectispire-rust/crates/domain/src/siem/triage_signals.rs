//! `TriageSignals`: which triage decisions a SOC hears about.
//!
//! Not every triage: "under review" is housekeeping, and a queue of requests awaiting approval is the control
//! working. What is forwarded is what takes a finding out of the gate's way, and the answer to a four-eyes
//! request:
//!
//! - a settling status reached directly: [`SecurityEventType::TriageSettled`];
//! - the same reached from `pending_approval`: [`SecurityEventType::TriageApproved`];
//! - `pending_approval` sent back to a status that settles nothing: [`SecurityEventType::TriageRefused`].
//!
//! Settling is asked of [`TriageStatus::is_settled`] rather than listed: a settling status added later is
//! forwarded the day it is marked settling.

use crate::siem::event_type::SecurityEventType;
use crate::triage_status::TriageStatus;

/// `previous` are the statuses the issues had before the decision, by wire name — one for a single triage,
/// several for a bulk one, where a single request among them makes the decision an answer to a request. `result`
/// is the status the decision left, which for an author who cannot approve is `pending_approval` whatever was
/// asked, and signals nothing.
pub fn of(previous: &[Option<&str>], result: Option<&str>) -> Option<SecurityEventType> {
    let after = TriageStatus::from_wire_name(result?)?;
    let answers_a_request = previous
        .iter()
        .any(|status| status.and_then(TriageStatus::from_wire_name) == Some(TriageStatus::PendingApproval));
    if after.is_settled() {
        return Some(if answers_a_request {
            SecurityEventType::TriageApproved
        } else {
            SecurityEventType::TriageSettled
        });
    }
    (answers_a_request && after != TriageStatus::PendingApproval).then_some(SecurityEventType::TriageRefused)
}
