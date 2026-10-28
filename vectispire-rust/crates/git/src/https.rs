//! Git's smart HTTP protocol over HTTPS, on rustls — the transport libgit2 hands every `https://`
//! clone to, in place of its own.
//!
//! **Why this crate speaks HTTP itself rather than letting libgit2 do it.** Three properties of the
//! Java clone are contract, and libgit2's own HTTP stack gives none of them a typed hook:
//!
//! 1. **Every redirect is refused, to any host** (`RedirectRefusingConnections`): a repository URL
//!    anybody may set could otherwise walk the clone to `169.254.169.254` or an internal address that
//!    was never checked. Here the client follows nothing, and a 3xx is a refusal naming only the
//!    destination's host.
//! 2. **The token is answered only for the host it is bound to** (`HostBoundCredentials`, decision
//!    0022): sent after the forge's 401, and only when the request goes to that host.
//! 3. **A 401 and a 403 are numbers, not words**: the status decides the scan's fate (an
//!    authentication refused fails at once, a passing error retries), and libgit2 reports both as
//!    text. Here every status is recorded where it is read.
//!
//! It also puts TLS on rustls with the agent's one trust ([`vectispire_tls::TlsTrust`]) — the
//! authorities compiled in, or the operator's bundle alone — instead of the OpenSSL libgit2 would
//! link.

use crate::{CloneError, Kind};
use git2::transport::{Service, SmartSubtransport, SmartSubtransportStream};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use vectispire_domain::repository_url;
use vectispire_domain::secret::Secret;

/// What a token is sent as when the forge wants no particular user name — `GitClone.TOKEN_USER`.
pub const TOKEN_USER: &str = "x-access-token";

/// Sent by every git client the forges know; some answer the smart protocol only to `git/…`.
const USER_AGENT: &str = concat!("git/2.0 (vectispire-agent ", env!("CARGO_PKG_VERSION"), ")");

/// An HTTPS token and the one host it is for.
#[derive(Debug, Clone)]
pub struct HttpsCredential {
    /// As `RepositoryUrl.normalizeHost` wrote it at entry.
    pub host: String,
    pub username: Option<String>,
    pub token: Secret,
}

impl HttpsCredential {
    pub fn has_token(&self) -> bool {
        !self.token.is_blank()
    }

    fn user(&self) -> &str {
        self.username.as_deref().filter(|name| !name.trim().is_empty()).unwrap_or(TOKEN_USER)
    }
}

/// What the transport saw, for the diagnosis: typed, so the scan's fate never hangs on a sentence.
#[derive(Debug, Default)]
pub(crate) struct Observed {
    pub last_status: u16,
    pub refusal: Option<CloneError>,
    pub timed_out: bool,
    pub unreachable: bool,
    pub tls: Option<String>,
    /// The forge has asked for the credential once: later requests of this clone carry it from the
    /// start, as JGit's session does — still only to the bound host.
    pub asked_for_credentials: bool,
}

/// One clone's HTTPS state, reached by the transport through the thread the clone runs on.
pub(crate) struct HttpsContext {
    pub validated_host: String,
    pub credential: Option<HttpsCredential>,
    pub client: reqwest::blocking::Client,
    pub observed: Mutex<Observed>,
}

impl HttpsContext {
    pub(crate) fn observe<T>(&self, change: impl FnOnce(&mut Observed) -> T) -> T {
        let mut guard = self.observed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        change(&mut guard)
    }

    fn refuse(&self, error: CloneError) -> std::io::Error {
        let message = error.message.clone();
        self.observe(|observed| observed.refusal.get_or_insert(error).clone());
        std::io::Error::other(message)
    }
}

thread_local! {
    /// The clone running on this thread. libgit2 calls its transport on the thread that called fetch,
    /// so this is how a process-wide transport registration reaches one clone's credential and trust.
    static ACTIVE: RefCell<Option<Arc<HttpsContext>>> = const { RefCell::new(None) };
}

/// Makes `context` the active clone's for the life of the guard.
pub(crate) struct Activation;

impl Activation {
    pub(crate) fn new(context: Arc<HttpsContext>) -> Activation {
        ACTIVE.with(|active| *active.borrow_mut() = Some(context));
        Activation
    }
}

impl Drop for Activation {
    fn drop(&mut self) {
        ACTIVE.with(|active| *active.borrow_mut() = None);
    }
}

/// The subtransport libgit2 is given for `https://`.
pub(crate) struct Https;

impl SmartSubtransport for Https {
    fn action(&self, url: &str, action: Service) -> Result<Box<dyn SmartSubtransportStream>, git2::Error> {
        let context = ACTIVE
            .with(|active| active.borrow().clone())
            .ok_or_else(|| git2::Error::from_str("an HTTPS fetch outside a Vectispire clone is refused"))?;
        // The host libgit2 is about to reach, against the one every check before decided on: the
        // two readings of the URL must agree, or the checks were made for another host.
        let host = repository_url::host(url).map(|host| host.to_lowercase());
        if host.as_deref() != Some(context.validated_host.as_str()) {
            let refused = context.refuse(CloneError::new(
                Kind::UrlRefused,
                "Repository URL refused: its host part reads differently to the clone than to the checks. Use the \
                 address the forge gives for cloning.",
            ));
            return Err(git2::Error::from_str(&refused.to_string()));
        }
        let base = url.trim_end_matches('/').to_owned();
        match action {
            Service::UploadPackLs | Service::UploadPack => {
                Ok(Box::new(Stream { context, base, service: action, body: Vec::new(), response: None }))
            }
            // A scan reads; nothing here ever pushes.
            Service::ReceivePackLs | Service::ReceivePack => Err(git2::Error::from_str("push is not supported")),
        }
    }

    fn close(&self) -> Result<(), git2::Error> {
        Ok(())
    }
}

/// The one request of a smart-protocol step: written to, then read from.
struct Stream {
    context: Arc<HttpsContext>,
    base: String,
    service: Service,
    body: Vec<u8>,
    response: Option<reqwest::blocking::Response>,
}

impl Write for Stream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.body.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.response.is_none() {
            let response = match self.service {
                Service::UploadPackLs => send(
                    &self.context,
                    reqwest::Method::GET,
                    &format!("{}/info/refs?service=git-upload-pack", self.base),
                    None,
                    "application/x-git-upload-pack-advertisement",
                )?,
                _ => send(
                    &self.context,
                    reqwest::Method::POST,
                    &format!("{}/git-upload-pack", self.base),
                    Some(std::mem::take(&mut self.body)),
                    "application/x-git-upload-pack-result",
                )?,
            };
            self.response = Some(response);
        }
        match self.response.as_mut() {
            Some(response) => response.read(buffer).inspect_err(|error| {
                self.context.observe(|observed| observed.timed_out |= error.kind() == std::io::ErrorKind::TimedOut);
            }),
            None => Ok(0),
        }
    }
}

/// One request, the token added only after the forge asked for one and only for its bound host, no
/// redirect followed, every status recorded.
fn send(
    context: &HttpsContext,
    method: reqwest::Method,
    url: &str,
    body: Option<Vec<u8>>,
    accept: &str,
) -> std::io::Result<reqwest::blocking::Response> {
    let mut authenticated = context.observe(|observed| observed.asked_for_credentials) && bound_to_url(context, url);
    loop {
        let mut request = context
            .client
            .request(method.clone(), url)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, accept);
        if let Some(body) = &body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/x-git-upload-pack-request")
                .body(body.clone());
        }
        if authenticated && let Some(credential) = &context.credential {
            request = request.basic_auth(credential.user(), Some(credential.token.expose()));
        }
        let response = request.send().map_err(|error| transport_failure(context, error))?;
        let status = response.status().as_u16();
        context.observe(|observed| observed.last_status = status);
        if (300..400).contains(&status) {
            let destination = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|location| location.to_str().ok())
                .and_then(location_host)
                .map(|host| format!(" to {host}"))
                .unwrap_or_default();
            return Err(context.refuse(CloneError::new(
                Kind::UrlRefused,
                format!(
                    "The repository at {} answered with a redirect ({status}){destination}. A clone follows no redirect, \
                     because the host it would reach was never checked: use the address the forge redirects to as the \
                     repository URL.",
                    response.url().host_str().unwrap_or_default()
                ),
            )));
        }
        if status == 401 && !authenticated && bound_to(context, response.url()) {
            context.observe(|observed| observed.asked_for_credentials = true);
            authenticated = true;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(std::io::Error::other(format!("the forge answered {status}")));
        }
        return Ok(response);
    }
}

/// Whether the credential is for the host this request goes to — `HostBoundCredentials.get`.
fn bound_to(context: &HttpsContext, url: &reqwest::Url) -> bool {
    match (&context.credential, url.host_str()) {
        (Some(credential), Some(host)) => credential.has_token() && credential.host.eq_ignore_ascii_case(host),
        _ => false,
    }
}

fn bound_to_url(context: &HttpsContext, url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|url| bound_to(context, &url))
}

/// The host of a `Location`, as `URI.create(location).getHost()` reads it — never its path or query,
/// which may carry what nobody should find in a log.
fn location_host(location: &str) -> Option<String> {
    repository_url::java_uri::parse(location.trim()).ok()?.host
}

fn transport_failure(context: &HttpsContext, error: reqwest::Error) -> std::io::Error {
    let tls = tls_cause(&error);
    context.observe(|observed| {
        observed.timed_out |= error.is_timeout();
        observed.unreachable |= error.is_connect() && tls.is_none();
        if let Some(cause) = &tls {
            observed.tls = Some(cause.clone());
        }
    });
    // Without the URL: it is the forge's, and the scan's sentence already names it, masked.
    std::io::Error::other(error.without_url().to_string())
}

/// The TLS failure in an error's chain, as text, if there is one.
///
/// **Read from words, and only to choose between two transient kinds** — "unreachable" and "nothing
/// typed says which" — and the detail: rustls's error is not re-exported by reqwest to downcast to. The
/// Java side lands a refused certificate in the same unclassified kind.
fn tls_cause(error: &reqwest::Error) -> Option<String> {
    let mut cause: Option<&dyn std::error::Error> = std::error::Error::source(error);
    while let Some(current) = cause {
        let text = current.to_string();
        if text.contains("certificate") || text.contains("tls") || text.contains("TLS") || text.contains("handshake") {
            return Some(text);
        }
        cause = current.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(credential_host: &str) -> HttpsContext {
        HttpsContext {
            validated_host: credential_host.to_owned(),
            credential: Some(HttpsCredential {
                host: credential_host.to_owned(),
                username: None,
                token: Secret::new("invented"),
            }),
            client: reqwest::blocking::Client::new(),
            observed: Mutex::new(Observed::default()),
        }
    }

    /// The transport's own binding, behind the clone's checks before the network — defence in depth
    /// the end-to-end tests cannot reach, since those checks refuse first.
    #[test]
    fn the_token_is_answered_for_its_own_host_only() {
        let bound = context("gitlab.example.org");
        assert!(bound_to(&bound, &reqwest::Url::parse("https://GitLab.example.org/x").unwrap()));
        assert!(!bound_to(&bound, &reqwest::Url::parse("https://evil.example/x").unwrap()));
        assert!(!bound_to(&bound, &reqwest::Url::parse("https://gitlab.example.org.evil.example/x").unwrap()));
        let blank = HttpsContext {
            credential: Some(HttpsCredential { token: Secret::new(" "), ..bound.credential.clone().unwrap() }),
            ..context("gitlab.example.org")
        };
        assert!(
            !bound_to(&blank, &reqwest::Url::parse("https://gitlab.example.org/x").unwrap()),
            "a blank token is no token"
        );
    }
}
