//! `OutboundPager`: a listing read page by page through [`OutboundJson`]'s door, with what a listing adds (decision
//! 0037 §3). Opened for one origin, used by one task.
//!
//! **The next page is followed on the pager's own origin, or not at all** — scheme, host and port compared before
//! anything is sent — **and under the API's path**, dot segments removed, an encoded dot refused: a `Link` to a
//! neighbour behind a shared name would otherwise carry the token there. The credential is attached here, after
//! that comparison, and never to a request of the caller's own making.
//!
//! **Rate limits are waited out within a bound, never raced**: up to `max_wait` slept inside the run, longer is
//! [`PagerError::RateLimited`] naming when the limit lifts. **A failing server is retried three times** with back-off
//! (one, two, four seconds) on a 5xx or an exchange that produced no answer. **A deadline for the whole listing**,
//! checked before each request and each wait.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use vectispire_domain::instant::Instant;
use vectispire_domain::repository_url::java_uri;

use crate::json::{Answer, JsonError, OutboundJson};
use crate::pinned_ca::PinnedCa;
use crate::policy::OutboundPolicy;

/// How many times a page that failed is sent again before its failure is the caller's.
pub const RETRIES: u32 = 3;

/// The first back-off; each next one doubles it.
pub const FIRST_BACK_OFF: Duration = Duration::from_secs(1);

/// What a pager reads the time from, and sleeps with — a test's moves its clock instead.
pub trait PagerClock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Called before every request, retries and waits included: where a listing that runs for minutes renews its lease,
/// and stops — `Err` with why — when it has lost it.
pub trait Heartbeat: Send + Sync {
    fn beat(&self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;
}

/// The requests a run's pagers sent and the time they slept on rate limits, shared by them all.
#[derive(Debug, Default)]
pub struct PagerCounters {
    requests: AtomicI64,
    waited_nanos: AtomicI64,
}

impl PagerCounters {
    pub fn requests(&self) -> i64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Whole seconds slept on rate limits, as `Duration.toSeconds` truncates.
    pub fn waited_seconds(&self) -> i64 {
        self.waited_nanos.load(Ordering::Relaxed) / 1_000_000_000
    }
}

/// What a pager is opened with. Its `Debug` names the credential's headers, never their values.
pub struct Settings {
    /// The API's root: its origin is what the pager may reach, its path the prefix every URL must stay under.
    pub origin: String,
    pub policy: OutboundPolicy,
    pub label: String,
    /// The headers that authenticate to that origin, attached to its requests and to no other.
    pub credential: Vec<(String, String)>,
    pub trust: Option<PinnedCa>,
    /// After it, no request is sent and no wait begun.
    pub deadline: Instant,
    pub max_wait: Duration,
    pub timeout: Duration,
    pub heartbeat: Option<Arc<dyn Heartbeat>>,
    pub counters: Arc<PagerCounters>,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.credential.iter().map(|(name, _)| name.as_str()).collect();
        write!(
            formatter,
            "Settings[origin={}, policy={:?}, label={}, credential={names:?} (values withheld), trust={}, deadline={:?}, \
             maxWait={:?}, timeout={:?}]",
            self.origin,
            self.policy,
            self.label,
            self.trust.is_some(),
            self.deadline,
            self.max_wait,
            self.timeout
        )
    }
}

/// Why a page was not answered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PagerError {
    /// The next request would have left the pager's origin or root; nothing was sent. A security event.
    #[error("{0}")]
    CrossOrigin(String),
    /// A rate limit asked for longer than the listing waits.
    #[error("{message}")]
    RateLimited { message: String, lifts_at: Instant },
    /// The deadline passed, or a wait would have crossed it.
    #[error("{0}")]
    DeadlineReached(String),
    /// The page failed its retries, or answered something that is not JSON (`OutboundFailureException`).
    #[error("{0}")]
    Failure(String),
    /// The guard refused the address (`UnsafeUrlException`).
    #[error("{0}")]
    Unsafe(String),
    /// The heartbeat said stop.
    #[error("{0}")]
    Stopped(String),
}

/// How a forge names its next page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextPage {
    /// RFC 8288's `Link: <…>; rel="next"` — GitHub, GitLab's keyset listings.
    Link,
    /// GitLab: `Link` when it is there, and otherwise `X-Next-Page`, the page number its offset listings state.
    Gitlab,
}

impl NextPage {
    fn target(self, answer: &Answer, url: &str) -> Option<String> {
        let link = vectispire_domain::rate_limit::link_target(answer.joined("link").as_deref(), "next");
        match self {
            NextPage::Link => link,
            NextPage::Gitlab => link.or_else(|| {
                answer
                    .header("x-next-page")
                    .map(str::trim)
                    .filter(|page| !page.is_empty() && page.len() <= 9 && page.bytes().all(|b| b.is_ascii_digit()))
                    .map(|page| with_query_parameter(url, "page", page))
            }),
        }
    }
}

/// The pager.
pub struct OutboundPager {
    outbound: OutboundJson,
    settings: Settings,
    clock: Arc<dyn PagerClock>,
    origin: Origin,
    root: String,
}

impl std::fmt::Debug for OutboundPager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OutboundPager").field("settings", &self.settings).finish_non_exhaustive()
    }
}

impl OutboundJson {
    /// A listing read page by page through this door.
    pub fn pager(&self, settings: Settings, clock: Arc<dyn PagerClock>) -> Result<OutboundPager, String> {
        let origin = Origin::of(&settings.origin)
            .ok_or_else(|| format!("A pager is opened for an absolute URL: {}", settings.origin))?;
        let root = path_of(&settings.origin)
            .map(|path| path.trim_end_matches('/').to_owned())
            .ok_or_else(|| format!("A pager is opened for a plain path: {}", settings.origin))?;
        Ok(OutboundPager { outbound: self.clone(), settings, clock, origin, root })
    }
}

impl OutboundPager {
    /// Fetches one page — or any document — of the pager's origin, the credential attached: the answer whatever its
    /// status but a 5xx or a rate limit.
    pub async fn get(&self, url: &str) -> Result<Answer, PagerError> {
        self.require_same_origin(url)?;
        let mut failures = 0u32;
        loop {
            self.require_before_deadline(Duration::ZERO)?;
            if let Some(heartbeat) = &self.settings.heartbeat {
                heartbeat.beat().await.map_err(PagerError::Stopped)?;
            }
            self.settings.counters.requests.fetch_add(1, Ordering::Relaxed);
            let credential: Vec<(&str, &str)> =
                self.settings.credential.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
            let answered = self
                .outbound
                .answer(
                    url,
                    self.settings.policy,
                    &self.settings.label,
                    &credential,
                    self.settings.trust.as_ref(),
                    self.settings.timeout,
                )
                .await;
            let answer = match answered {
                Ok(answer) => answer,
                Err(JsonError::Unsafe(refused)) => return Err(PagerError::Unsafe(refused.0)),
                Err(unanswered) => {
                    failures = self.back_off(failures, unanswered.to_string()).await?;
                    continue;
                }
            };
            if answer.status / 100 == 5 {
                failures = self.back_off(failures, format!("{}: HTTP {}.", self.settings.label, answer.status)).await?;
                continue;
            }
            if vectispire_domain::rate_limit::limited(answer.status, |name| answer.header(name)) {
                let now = self.clock.now();
                let wait = vectispire_domain::rate_limit::wait_of(|name| answer.header(name), now)
                    .unwrap_or(self.settings.max_wait);
                if wait > self.settings.max_wait {
                    return Err(PagerError::RateLimited {
                        message: format!(
                            "{}: rate limited for {} s, longer than the {} s a listing waits.",
                            self.settings.label,
                            wait.as_secs(),
                            self.settings.max_wait.as_secs()
                        ),
                        lifts_at: now.plus(wait).unwrap_or(now),
                    });
                }
                // At least a second: a limit lifting "now" by the server's clock is often a second ahead of ours.
                let slept = wait.max(Duration::from_secs(1));
                self.require_before_deadline(slept)?;
                self.clock.sleep(slept).await;
                self.settings
                    .counters
                    .waited_nanos
                    .fetch_add(i64::try_from(slept.as_nanos()).unwrap_or(i64::MAX), Ordering::Relaxed);
                continue;
            }
            return Ok(answer);
        }
    }

    /// The next page's URL, resolved against `url` when the forge wrote it relative; `None` on the last page. Not
    /// checked here: [`OutboundPager::get`] refuses it if it leads elsewhere, before anything is sent.
    pub fn next(&self, answer: &Answer, url: &str, next_page: NextPage) -> Option<String> {
        next_page.target(answer, url).map(|target| resolve(url, &target))
    }

    async fn back_off(&self, failures: u32, failure: String) -> Result<u32, PagerError> {
        if failures >= RETRIES {
            return Err(PagerError::Failure(failure));
        }
        let pause = FIRST_BACK_OFF.saturating_mul(1u32.checked_shl(failures).unwrap_or(u32::MAX));
        self.require_before_deadline(pause)?;
        self.clock.sleep(pause).await;
        Ok(failures.saturating_add(1))
    }

    fn require_before_deadline(&self, ahead: Duration) -> Result<(), PagerError> {
        let at = self.clock.now().plus(ahead);
        if at.is_none_or(|at| at >= self.settings.deadline) {
            return Err(PagerError::DeadlineReached(format!(
                "{}: the listing reached its time bound.",
                self.settings.label
            )));
        }
        Ok(())
    }

    fn require_same_origin(&self, url: &str) -> Result<(), PagerError> {
        if Origin::of(url).is_none_or(|target| target != self.origin) {
            let described = Origin::of(url).map_or_else(|| "an unreadable address".to_owned(), |o| o.to_string());
            return Err(PagerError::CrossOrigin(format!(
                "{}: the forge pointed the next request at {described}, which is not {}; nothing was sent there.",
                self.settings.label, self.origin
            )));
        }
        let under = path_of(url).is_some_and(|path| path == self.root || path.starts_with(&format!("{}/", self.root)));
        if !under {
            return Err(PagerError::CrossOrigin(format!(
                "{}: the forge pointed the next request outside {}{}; nothing was sent there.",
                self.settings.label,
                self.origin,
                if self.root.is_empty() { "/" } else { &self.root }
            )));
        }
        Ok(())
    }
}

/// Scheme, host and port — the default port spelled out, so that `:443` and nothing are one origin.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: i32,
}

impl Origin {
    fn of(url: &str) -> Option<Origin> {
        let parsed = java_uri::parse(url).ok()?;
        if parsed.raw_user_info.is_some() {
            return None;
        }
        let scheme = parsed.scheme?.to_ascii_lowercase();
        let mut host = parsed.host?.to_ascii_lowercase();
        while host.ends_with('.') {
            host.pop();
        }
        let port = parsed.port.filter(|port| *port > 0).unwrap_or(match scheme.as_str() {
            "https" => 443,
            "http" => 80,
            _ => -1,
        });
        Some(Origin { scheme, host, port })
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// The raw path with its dot segments removed (`URI.normalize`), or `None` when it cannot be compared: unreadable, or
/// carrying an encoded dot the server may decode into a segment this never removed.
fn path_of(url: &str) -> Option<String> {
    let parsed = java_uri::parse(url).ok()?;
    let path = normalize(&parsed.raw_path?);
    if path.to_ascii_lowercase().contains("%2e")
        || path == ".."
        || path.starts_with("../")
        || path.contains("/../")
        || path.ends_with("/..")
    {
        return None;
    }
    Some(path)
}

/// `URI.normalize`'s path: `.` segments dropped, each `x/..` pair removed; a `..` with nothing before it kept.
fn normalize(path: &str) -> String {
    if !path.contains('.') {
        return path.to_owned();
    }
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..") || path == "." || path == "..";
    let mut kept: Vec<&str> = Vec::new();
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        match segment {
            "." => {}
            ".." if kept.last().is_some_and(|last| *last != "..") => {
                kept.pop();
            }
            _ => kept.push(segment),
        }
    }
    let mut normalized = String::new();
    if absolute {
        normalized.push('/');
    }
    normalized.push_str(&kept.join("/"));
    if trailing && !kept.is_empty() {
        normalized.push('/');
    }
    normalized
}

/// `new URI(base).resolve(new URI(target))` for what forges write: an absolute URL, a path, a query.
pub(crate) fn resolve(base: &str, target: &str) -> String {
    let Ok(parsed) = java_uri::parse(target) else {
        // Handed on as written: `get` reads no origin in it and refuses it.
        return target.to_owned();
    };
    if parsed.scheme.is_some() {
        return target.to_owned();
    }
    let Ok(base_uri) = java_uri::parse(base) else {
        return target.to_owned();
    };
    let scheme = base_uri.scheme.clone().unwrap_or_default();
    if let Some(rest) = target.strip_prefix("//") {
        return format!("{scheme}://{rest}");
    }
    let authority = authority_of(base);
    if target.starts_with('/') {
        return format!("{scheme}://{authority}{}", normalize(target));
    }
    let base_path = base_uri.raw_path.unwrap_or_default();
    if target.starts_with('?') {
        return format!("{scheme}://{authority}{base_path}{target}");
    }
    let directory = base_path.rsplit_once('/').map_or_else(|| "/".to_owned(), |(before, _)| format!("{before}/"));
    format!("{scheme}://{authority}{}", normalize(&format!("{directory}{target}")))
}

fn authority_of(url: &str) -> &str {
    let after = url.split_once("://").map_or(url, |(_, rest)| rest);
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    after.split_at_checked(end).map_or(after, |(authority, _)| authority)
}

/// `url` with `name` set to `value`, replacing it where the query has it already.
pub fn with_query_parameter(url: &str, name: &str, value: &str) -> String {
    let base = url.split_once('#').map_or(url, |(base, _)| base);
    let (path, query) = base.split_once('?').map_or((base, None), |(path, query)| (path, Some(query)));
    let mut pairs: Vec<&str> = query
        .map(|query| {
            query
                .split('&')
                .filter(|pair| !pair.is_empty() && *pair != name && !pair.starts_with(&format!("{name}=")))
                .collect()
        })
        .unwrap_or_default();
    let set = format!("{name}={value}");
    pairs.push(&set);
    format!("{path}?{}", pairs.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_spell_the_default_port() {
        assert_eq!(Origin::of("https://Git.Example.org./api"), Origin::of("https://git.example.org:443/x"));
        assert_ne!(Origin::of("https://git.example.org:8443/api"), Origin::of("https://git.example.org/api"));
        assert_eq!(Origin::of("https://user@git.example.org/"), None);
    }

    #[test]
    fn paths_lose_their_dot_segments_and_an_encoded_dot_is_refused() {
        assert_eq!(path_of("https://h/gitlab/api/v4/projects/../user").as_deref(), Some("/gitlab/api/v4/user"));
        assert_eq!(path_of("https://h/gitlab/api/v4/../../wiki").as_deref(), Some("/gitlab/wiki"));
        assert_eq!(path_of("https://h/a/%2e%2e/b"), None);
        assert_eq!(path_of("https://h/../b"), None);
        assert_eq!(path_of("https://h/a/./b/").as_deref(), Some("/a/b/"));
    }

    #[test]
    fn relative_targets_resolve_against_the_page() {
        assert_eq!(
            resolve("https://h/api/v4/projects?page=1", "https://h/api/v4/projects?page=2"),
            "https://h/api/v4/projects?page=2"
        );
        assert_eq!(resolve("https://h/api/v4/projects?page=1", "/api/v4/groups"), "https://h/api/v4/groups");
        assert_eq!(resolve("https://h:8443/api/v4/projects", "?page=3"), "https://h:8443/api/v4/projects?page=3");
        assert_eq!(resolve("https://h/api/v4/projects", "groups?x=1"), "https://h/api/v4/groups?x=1");
        assert_eq!(resolve("https://h/api/v4/projects", "//other/x"), "https://other/x");
    }

    #[test]
    fn a_query_parameter_is_replaced_where_it_is() {
        assert_eq!(
            with_query_parameter("https://h/p?per_page=100&page=1#x", "page", "2"),
            "https://h/p?per_page=100&page=2"
        );
        assert_eq!(with_query_parameter("https://h/p", "page", "2"), "https://h/p?page=2");
    }
}
