//! A JSON body to a destination a setting names, and a JSON document from one — Java's `OutboundPost` and the
//! lookups of `OutboundJson` the notification channels and the tracker make.
//!
//! **The guard and the sender as one gesture**: the URL is validated and resolved under the caller's policy, and the
//! request goes to the address checked — so a base URL is never validated by one component and posted to by another.
//! The guard resolves the name, which blocks, so it runs off the runtime's threads.
//!
//! **The body is taken encoded**, never as an object to serialise here: a signature is computed over the bytes sent
//! ([`OutboundPost::post_signed_json`]), and two serialisations of one value are a signature that verifies nowhere.
//!
//! The failures carry Java's exception names (`UnsafeUrlException`, `OutboundFailureException`,
//! `OutboundStatusException`) and messages, so that an outbox row's `last_error` reads the same whichever control
//! plane wrote it, and a `401` is read from [`PostError::Status`]'s value — never from its words.

use std::time::Duration;

use vectispire_domain::notifications::signature;

use crate::failure::OutboundFailure;
use crate::guard::{Destination, OutboundUrlGuard, UnsafeUrl};
use crate::pinned_ca::PinnedCa;
use crate::policy::OutboundPolicy;
use crate::sender::{DEFAULT_MAX_BODY_BYTES, Method, PinnedHttpSender, Response};

/// A webhook or a tracker that has not answered in ten seconds is one to retry, not to wait on.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// Why nothing useful came back.
#[derive(Debug, thiserror::Error)]
pub enum PostError {
    /// `UnsafeUrlException`: the guard refused the destination under the policy.
    #[error("{}", .0.0)]
    Refused(UnsafeUrl),
    /// `OutboundFailureException`: no answer — a connection refused, a timeout, an answer past its ceiling, a 2xx that
    /// is not JSON.
    #[error("{0}")]
    Failed(OutboundFailure),
    /// `OutboundStatusException`: an answer whose status is not a success. `rate_limited` when the destination said
    /// "slow down" (429, or GitHub's 403 with its rate-limit headers) rather than "no".
    #[error("{label}: HTTP {status}{}", if *.rate_limited { ", rate-limited." } else { "." })]
    Status { label: String, status: u16, rate_limited: bool },
}

impl PostError {
    /// The simple name of the exception Java throws for the same failure.
    pub fn kind(&self) -> &'static str {
        match self {
            PostError::Refused(_) => "UnsafeUrlException",
            PostError::Failed(_) => "OutboundFailureException",
            PostError::Status { .. } => "OutboundStatusException",
        }
    }

    /// `OutboundStatusException.of`: the status, and whether the headers say it is a rate limit.
    pub fn of_status(label: &str, response: &Response) -> PostError {
        let rate_limited = response.status == 429
            || (response.status == 403
                && (response
                    .header("x-ratelimit-remaining")
                    .is_some_and(|left| vectispire_domain::java::strip(left) == "0")
                    || response.header("retry-after").is_some()));
        PostError::Status { label: label.to_owned(), status: response.status, rate_limited }
    }
}

/// `OutboundJson.Answer`: an answer whatever its status, the body on a 2xx only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub body: Option<String>,
    pub headers: Vec<(String, Vec<String>)>,
}

impl Answer {
    /// The first value of a header, by name in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        let wanted = name.to_lowercase();
        self.headers.iter().find(|(key, _)| *key == wanted).and_then(|(_, values)| values.first()).map(String::as_str)
    }
}

/// The door, for a JSON exchange.
#[derive(Debug, Clone)]
pub struct OutboundPost {
    guard: OutboundUrlGuard,
    sender: PinnedHttpSender,
}

impl OutboundPost {
    pub fn new(guard: OutboundUrlGuard, sender: PinnedHttpSender) -> OutboundPost {
        OutboundPost { guard, sender }
    }

    /// Validates a URL without calling it: the normalised URL, or the guard's refusal.
    pub async fn validate(&self, url: &str, policy: OutboundPolicy, label: &str) -> Result<String, UnsafeUrl> {
        let (guard, url, label) = (self.guard.clone(), url.to_owned(), label.to_owned());
        tokio::task::spawn_blocking(move || guard.validate(&url, policy, &label))
            .await
            .unwrap_or_else(|stopped| Err(UnsafeUrl(format!("the destination check stopped ({stopped})."))))
    }

    async fn destination(&self, url: &str, policy: OutboundPolicy, label: &str) -> Result<Destination, PostError> {
        let (guard, url, label) = (self.guard.clone(), url.to_owned(), label.to_owned());
        tokio::task::spawn_blocking(move || guard.validate_and_resolve(&url, policy, &label))
            .await
            .map_err(|stopped| {
                PostError::Failed(OutboundFailure::new(format!("the destination check stopped ({stopped}).")))
            })?
            .map_err(PostError::Refused)
    }

    /// `postJson`: a 2xx or an error.
    pub async fn post_json(
        &self,
        url: &str,
        body: &str,
        policy: OutboundPolicy,
        label: &str,
    ) -> Result<String, PostError> {
        self.send(Method::Post, url, Some(body), policy, label, &[], None).await
    }

    /// `postSignedJson`: signed over the bytes sent, the timestamp inside the MAC. A blank secret sends unsigned —
    /// what a deployment that configured none keeps doing.
    pub async fn post_signed_json(
        &self,
        url: &str,
        body: &str,
        policy: OutboundPolicy,
        label: &str,
        secret: &str,
        epoch_second: i64,
    ) -> Result<(), PostError> {
        let headers = signature::headers(secret, epoch_second, body);
        self.send(Method::Post, url, Some(body), policy, label, &headers, None).await.map(|_| ())
    }

    /// `send`: the verb named, the server verified against `trust` when one is pinned — for that request alone and in
    /// place of the runtime's store. The answer's body on a 2xx.
    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &self,
        method: Method,
        url: &str,
        body: Option<&str>,
        policy: OutboundPolicy,
        label: &str,
        headers: &[(String, String)],
        trust: Option<&PinnedCa>,
    ) -> Result<String, PostError> {
        let destination = self.destination(url, policy, label).await?;
        let pairs: Vec<(&str, &str)> = headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
        let response = self
            .sender
            .send_bounded(method, &destination, &pairs, body, TIMEOUT, label, DEFAULT_MAX_BODY_BYTES, trust)
            .await
            .map_err(PostError::Failed)?;
        if response.status / 100 != 2 {
            return Err(PostError::of_status(label, &response));
        }
        Ok(response.body)
    }

    /// `OutboundJson.get`: a document, **404 as nothing** — "not there" is an answer — and any other non-2xx a
    /// failure. `Accept: application/json` last, so a caller cannot turn it into a request for something else. The
    /// body is returned as text; [`parse`] reads it with Java's failure.
    pub async fn get(
        &self,
        url: &str,
        policy: OutboundPolicy,
        label: &str,
        headers: &[(String, String)],
        trust: Option<&PinnedCa>,
    ) -> Result<Option<String>, PostError> {
        let response = self.fetch(url, policy, label, headers, trust).await?;
        if response.status == 404 {
            return Ok(None);
        }
        if response.status / 100 != 2 {
            return Err(PostError::of_status(label, &response));
        }
        Ok(Some(response.body))
    }

    /// `OutboundJson.answer`: whatever the status, with the headers — for a caller to whom a 401 means something of
    /// its own. Only a 2xx's body is kept.
    pub async fn answer(
        &self,
        url: &str,
        policy: OutboundPolicy,
        label: &str,
        headers: &[(String, String)],
        trust: Option<&PinnedCa>,
    ) -> Result<Answer, PostError> {
        let response = self.fetch(url, policy, label, headers, trust).await?;
        let success = response.status / 100 == 2;
        Ok(Answer { status: response.status, body: success.then_some(response.body), headers: response.headers })
    }

    async fn fetch(
        &self,
        url: &str,
        policy: OutboundPolicy,
        label: &str,
        headers: &[(String, String)],
        trust: Option<&PinnedCa>,
    ) -> Result<Response, PostError> {
        let destination = self.destination(url, policy, label).await?;
        let mut pairs: Vec<(&str, &str)> = headers
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("accept"))
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        pairs.push(("Accept", "application/json"));
        self.sender
            .send_bounded(Method::Get, &destination, &pairs, None, TIMEOUT, label, DEFAULT_MAX_BODY_BYTES, trust)
            .await
            .map_err(PostError::Failed)
    }
}
