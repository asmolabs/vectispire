//! `OutboundJson`: every JSON call the control plane makes to the outside, through one door — the guard, the pinned
//! address, no redirect, a deadline. A forge's probe reads one answer whatever its status ([`OutboundJson::answer`]);
//! a listing reads page after page through [`crate::pager::OutboundPager`].

use std::time::Duration;

use serde_json::Value;

use crate::failure::OutboundFailure;
use crate::guard::{OutboundUrlGuard, UnsafeUrl};
use crate::pinned_ca::PinnedCa;
use crate::policy::OutboundPolicy;
use crate::sender::{DEFAULT_MAX_BODY_BYTES, Method, PinnedHttpSender, Response};

/// Every request's bound: a silent server holds nobody for longer.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// An answer whatever its status, with its headers by lower-case name; the body is read as JSON on a 2xx only.
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    pub status: u16,
    pub body: Option<Value>,
    pub headers: Vec<(String, Vec<String>)>,
}

impl Answer {
    /// The first value of a header, by name in any case; `None` when the answer did not carry it.
    pub fn header(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.headers.iter().find(|(key, _)| *key == wanted).and_then(|(_, values)| values.first()).map(String::as_str)
    }

    /// Every value of a header joined by commas, as `String.join(",", values)`.
    pub fn joined(&self, name: &str) -> Option<String> {
        let wanted = name.to_ascii_lowercase();
        self.headers.iter().find(|(key, _)| *key == wanted).map(|(_, values)| values.join(","))
    }
}

/// Why a JSON call produced nothing to read.
#[derive(Debug, thiserror::Error)]
pub enum JsonError {
    /// The guard refused the URL (`UnsafeUrlException`).
    #[error(transparent)]
    Unsafe(#[from] UnsafeUrl),
    /// No answer, or a 2xx that is not JSON (`OutboundFailureException`).
    #[error(transparent)]
    Failure(#[from] OutboundFailure),
    /// An answer whose status is not a success, for [`OutboundJson::get`] (`OutboundStatusException`).
    #[error("{label}: HTTP {status}{}", if *rate_limited { ", rate-limited." } else { "." })]
    Status { label: String, status: u16, rate_limited: bool },
}

/// The door.
#[derive(Clone, Debug)]
pub struct OutboundJson {
    sender: PinnedHttpSender,
    guard: OutboundUrlGuard,
}

impl OutboundJson {
    pub fn new(sender: PinnedHttpSender, guard: OutboundUrlGuard) -> OutboundJson {
        OutboundJson { sender, guard }
    }

    /// Fetches a JSON document: `None` on a 404 — "not in the catalogue" is an answer — and a failure on any other
    /// status that is not a success.
    pub async fn get(
        &self,
        url: &str,
        policy: OutboundPolicy,
        label: &str,
        headers: &[(&str, &str)],
        trust: Option<&PinnedCa>,
    ) -> Result<Option<Value>, JsonError> {
        self.get_bounded(url, policy, label, headers, DEFAULT_MAX_BODY_BYTES, trust).await
    }

    /// [`OutboundJson::get`] for a document larger than an ordinary answer — a catalogue: at most `max_body_bytes` of
    /// it is read, and an answer past that is the sender's failure, in its words.
    pub async fn get_bounded(
        &self,
        url: &str,
        policy: OutboundPolicy,
        label: &str,
        headers: &[(&str, &str)],
        max_body_bytes: u64,
        trust: Option<&PinnedCa>,
    ) -> Result<Option<Value>, JsonError> {
        let response = self.send(url, policy, label, headers, trust, TIMEOUT, max_body_bytes).await?;
        if response.status == 404 {
            return Ok(None);
        }
        if response.status / 100 != 2 {
            // GitHub's primary limit spends x-ratelimit-remaining; its secondary limits send retry-after.
            let rate_limited = response.status == 429
                || (response.status == 403
                    && (response.header("x-ratelimit-remaining").is_some_and(|value| value.trim() == "0")
                        || response.header("retry-after").is_some()));
            return Err(JsonError::Status { label: label.to_owned(), status: response.status, rate_limited });
        }
        serde_json::from_str(&response.body)
            .map(Some)
            .map_err(|unreadable| JsonError::Failure(OutboundFailure::new(format!("{label}: {unreadable}"))))
    }

    /// An answer whatever its status, with its headers — for a caller to whom a 401 or a 403 means something of its
    /// own. Only an exchange that produced no answer, or a 2xx that is not JSON, is a failure.
    pub async fn answer(
        &self,
        url: &str,
        policy: OutboundPolicy,
        label: &str,
        headers: &[(&str, &str)],
        trust: Option<&PinnedCa>,
        timeout: Duration,
    ) -> Result<Answer, JsonError> {
        let response = self.send(url, policy, label, headers, trust, timeout, DEFAULT_MAX_BODY_BYTES).await?;
        if response.status / 100 != 2 {
            return Ok(Answer { status: response.status, body: None, headers: response.headers });
        }
        match serde_json::from_str(&response.body) {
            Ok(body) => Ok(Answer { status: response.status, body: Some(body), headers: response.headers }),
            Err(_) => Err(JsonError::Failure(OutboundFailure::new(format!("{label}: the answer is not JSON.")))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send(
        &self,
        url: &str,
        policy: OutboundPolicy,
        label: &str,
        headers: &[(&str, &str)],
        trust: Option<&PinnedCa>,
        timeout: Duration,
        max_body_bytes: u64,
    ) -> Result<Response, JsonError> {
        let destination = self.guard.validate_and_resolve(url, policy, label)?;
        // Accept last: a caller cannot quietly turn this into a request for something else.
        let mut all: Vec<(&str, &str)> =
            headers.iter().copied().filter(|(name, _)| !name.eq_ignore_ascii_case("accept")).collect();
        all.push(("Accept", "application/json"));
        Ok(self
            .sender
            .send_bounded(Method::Get, &destination, &all, None, timeout, label, max_body_bytes, trust)
            .await?)
    }
}
