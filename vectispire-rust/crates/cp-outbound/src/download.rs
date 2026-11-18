//! `OutboundDownload`: every file the control plane downloads from the outside, through the same door as its JSON
//! calls — the address resolved, checked against the policy, and connected to as checked.
//!
//! **One redirect, to the same origin, and checked again.** FIRST publishes its daily EPSS file at one stable address
//! that answers `302` to the day's dated file on the same host; a mirror behind a load balancer may do the same.
//! [`crate::json::OutboundJson`] refuses every redirect because a client that follows one has validated nothing — the
//! destination checked is not the destination reached. Here the target is resolved against the address asked, must
//! keep its scheme, host and port, and goes through the guard and the pin a second time as a request of its own. A
//! redirect to another host, a second redirect, or one the guard refuses is a failure that names the address, so that
//! the operator configures the final one.
//!
//! **The body is bytes, bounded.** A text decoding would corrupt an archive, and an unbounded read would let whoever
//! answers exhaust the memory; the ceiling is the caller's, counted as the bytes arrive.

use std::time::Duration;

use vectispire_domain::repository_url::java_uri;

use crate::failure::OutboundFailure;
use crate::guard::OutboundUrlGuard;
use crate::json::JsonError;
use crate::policy::OutboundPolicy;
use crate::sender::{Download, PinnedHttpSender};

/// The door for files.
#[derive(Clone, Debug)]
pub struct OutboundDownload {
    sender: PinnedHttpSender,
    guard: OutboundUrlGuard,
}

impl OutboundDownload {
    pub fn new(sender: PinnedHttpSender, guard: OutboundUrlGuard) -> OutboundDownload {
        OutboundDownload { sender, guard }
    }

    /// The file at `url`, or `None` when the server answers 404. Any other answer that is not a file, a redirect this
    /// does not follow, and a file past `max_bytes` are failures. `timeout` is each read's, and half the exchange's.
    pub async fn get(
        &self,
        url: &str,
        policy: OutboundPolicy,
        label: &str,
        max_bytes: u64,
        timeout: Duration,
    ) -> Result<Option<Vec<u8>>, JsonError> {
        let answer = self.fetch(url, policy, label, max_bytes, timeout).await?;
        if !is_redirect(answer.status) {
            return body(answer, label);
        }
        let Some(location) = answer.location.as_deref() else {
            return Err(failure(format!("{label}: HTTP {} without a Location.", answer.status)));
        };
        let target = same_origin(url, location, label)?;
        let redirected = self.fetch(&target, policy, label, max_bytes, timeout).await?;
        if is_redirect(redirected.status) {
            return Err(failure(format!(
                "{label}: {target} redirects again; only one redirect is followed — configure the final address."
            )));
        }
        body(redirected, label)
    }

    async fn fetch(
        &self,
        url: &str,
        policy: OutboundPolicy,
        label: &str,
        max_bytes: u64,
        timeout: Duration,
    ) -> Result<Download, JsonError> {
        let destination = self.guard.validate_and_resolve(url, policy, label)?;
        Ok(self.sender.download(&destination, &[], timeout, label, max_bytes).await?)
    }
}

fn failure(message: String) -> JsonError {
    JsonError::Failure(OutboundFailure::new(message))
}

fn body(answer: Download, label: &str) -> Result<Option<Vec<u8>>, JsonError> {
    if answer.status == 404 {
        return Ok(None);
    }
    if answer.status / 100 != 2 {
        return Err(failure(format!("{label}: HTTP {}.", answer.status)));
    }
    Ok(Some(answer.body))
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// `sameOrigin`: the redirect's target, resolved against the address asked, when it keeps the scheme, the host and the
/// port, and names no user.
pub fn same_origin(asked: &str, location: &str, label: &str) -> Result<String, JsonError> {
    let location = location.trim();
    let unreadable = || failure(format!("{label}: the redirect's target \"{location}\" is not an address."));
    let from = java_uri::parse(asked).map_err(|_| unreadable())?;
    java_uri::parse(location).map_err(|_| unreadable())?;
    let resolved = crate::pager::resolve(asked, location);
    let to = java_uri::parse(&resolved).map_err(|_| unreadable())?;
    let same = match (&to.scheme, &from.scheme, &to.host, &from.host) {
        (Some(to_scheme), Some(from_scheme), Some(to_host), Some(from_host)) => {
            to_scheme.eq_ignore_ascii_case(from_scheme)
                && to_host.to_lowercase() == from_host.to_lowercase()
                && port(&to) == port(&from)
                && to.raw_user_info.is_none()
        }
        _ => false,
    };
    if !same {
        let named = to.host.clone().unwrap_or_else(|| location.to_owned());
        return Err(failure(format!(
            "{label}: {asked} redirects to another origin ({named}); a redirect is followed only on the same host — \
             configure the final address."
        )));
    }
    Ok(resolved)
}

fn port(uri: &java_uri::Parsed) -> i32 {
    match uri.port {
        Some(port) if port >= 0 => port,
        _ if uri.scheme.as_deref().is_some_and(|scheme| scheme.eq_ignore_ascii_case("http")) => 80,
        _ => 443,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(asked: &str, location: &str) -> String {
        match same_origin(asked, location, "EPSS file") {
            Err(error) => error.to_string(),
            Ok(target) => panic!("followed to {target}"),
        }
    }

    #[test]
    fn a_redirect_on_the_same_origin_is_resolved() {
        let asked = "https://epss.example/epss_scores-current.csv.gz";
        assert_eq!(
            same_origin(asked, "/epss_scores-2026-09-27.csv.gz", "EPSS file").ok().as_deref(),
            Some("https://epss.example/epss_scores-2026-09-27.csv.gz")
        );
        assert_eq!(
            same_origin(asked, "https://EPSS.example:443/a.csv.gz", "EPSS file").ok().as_deref(),
            Some("https://EPSS.example:443/a.csv.gz")
        );
        assert_eq!(
            same_origin("http://mirror.local/f", "http://mirror.local:80/g", "EPSS file").ok().as_deref(),
            Some("http://mirror.local:80/g")
        );
    }

    #[test]
    fn another_origin_is_refused_by_name() {
        assert_eq!(
            refused("https://epss.example/f", "https://elsewhere.example/f"),
            "EPSS file: https://epss.example/f redirects to another origin (elsewhere.example); a redirect is \
             followed only on the same host — configure the final address."
        );
        assert!(refused("https://epss.example/f", "http://epss.example/f").contains("another origin"));
        assert!(refused("https://epss.example/f", "https://epss.example:8443/f").contains("another origin"));
        assert!(refused("https://epss.example/f", "https://user@epss.example/f").contains("another origin"));
    }

    #[test]
    fn only_the_listed_statuses_are_redirects() {
        for status in [301, 302, 303, 307, 308] {
            assert!(is_redirect(status));
        }
        for status in [200, 300, 304, 305, 306, 404] {
            assert!(!is_redirect(status));
        }
    }

    #[test]
    fn a_file_is_a_2xx_and_404_is_absent() {
        let answer = |status| Download { status, body: vec![1, 2], location: None };
        assert_eq!(body(answer(200), "EPSS file").ok(), Some(Some(vec![1, 2])));
        assert_eq!(body(answer(404), "EPSS file").ok(), Some(None));
        assert_eq!(
            body(answer(500), "EPSS file").err().map(|e| e.to_string()).as_deref(),
            Some("EPSS file: HTTP 500.")
        );
    }
}
