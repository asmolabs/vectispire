//! The clone, its checks before the network, and the diagnosis of its failures — `GitClone.clone`,
//! `fetch`, `diagnose` and `sentence`.

use crate::https::{Activation, HttpsContext, HttpsCredential, Observed};
use crate::known_hosts::{self, Verdict};
use crate::{CloneError, Kind, deploy_key, init};
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vectispire_domain::secret::Secret;
use vectispire_domain::{net, repository_url};
use vectispire_tls::TlsTrust;

/// Clone depth. A scan looks at the current tree, not at the history.
const DEPTH: i32 = 1;

/// How host keys are checked — `GitClone.HostKeyPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Accept an unknown host on first contact and record it, **refuse one whose key has changed**;
    /// a file this process cannot write is the operator's pin, only matched against. A legitimately
    /// rotated key blocks scans until an operator clears the entry: a blocked scan is visible, an
    /// intercepted one is not.
    AcceptNew(PathBuf),
    /// Accept anything, every time — no interception detection at all, named plainly so that a
    /// deployment that wants it has to write the word.
    TrustEveryHost,
}

/// What to do when no deployment key came with the task — `GitClone.WithoutKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithoutKey {
    /// No identity: a public repository clones, a private one is refused — a key lying around on the
    /// host cannot clone a repository nobody attached it to.
    None,
    /// The host's own SSH agent, checked against the host's own `~/.ssh/known_hosts` and nothing
    /// else: every target is then reachable with whatever the host's key can reach.
    HostSsh,
}

/// One clone.
#[derive(Debug, Clone)]
pub struct CloneRequest {
    pub url: String,
    pub branch: String,
    pub into: PathBuf,
    /// The key in the clear, or `None` for a public repository.
    pub private_key: Option<Secret>,
    /// For each HTTPS request, and libgit2's own socket timeout on the other transports.
    pub timeout: Duration,
    pub host_keys: HostKeyPolicy,
    pub without_key: WithoutKey,
    pub https: Option<HttpsCredential>,
    pub trust: TlsTrust,
}

impl CloneRequest {
    fn has_key(&self) -> bool {
        self.private_key.as_ref().is_some_and(|key| !key.is_blank())
    }

    fn has_token(&self) -> bool {
        self.https.as_ref().is_some_and(HttpsCredential::has_token)
    }
}

/// Clones `request.branch` of `request.url` into `request.into`, at depth one, without submodules.
///
/// Blocking: run it off the async runtime (`spawn_blocking`).
pub fn clone(request: &CloneRequest) -> Result<(), CloneError> {
    if let Some(refused) = repository_url::validate(&request.url) {
        return Err(CloneError::new(Kind::UrlRefused, format!("Repository URL refused: {refused}")));
    }
    let host = connect_host(&request.url)?;
    // The literal was refused above; a name is only known to point there once resolved, and resolving
    // is this machine's business — the agent's network, not the control plane's.
    if net::resolves_to_link_local(&host) {
        return Err(CloneError::new(
            Kind::UrlRefused,
            "Repository URL refused: its host resolves to a link-local or cloud metadata address, where the instance \
             metadata lives.",
        ));
    }
    if let Some(credential) = request.https.as_ref().filter(|credential| credential.has_token()) {
        // Refused before the network, with the reason: the transport would otherwise just withhold
        // the token, and the forge answer "authentication required".
        if !repository_url::is_https(&request.url) || !repository_url::has_host(&request.url, &credential.host) {
            return Err(CloneError::new(
                Kind::Credential,
                format!(
                    "The HTTPS token is issued for {} and is sent to no other host; {} names another.",
                    credential.host,
                    repository_url::redact(&request.url)
                ),
            ));
        }
    }
    let key = match request.private_key.as_ref().filter(|key| !key.is_blank()) {
        Some(key) => Some(Secret::new(deploy_key::readable(key.expose())?)),
        None => None,
    };
    if let HostKeyPolicy::AcceptNew(file) = &request.host_keys {
        known_hosts::prepare(file).map_err(|error| {
            CloneError::new(Kind::Unclassified, format!("The known-hosts file could not be prepared: {error}"))
        })?;
    }
    if !git2::Reference::is_valid_name(&format!("refs/heads/{}", request.branch)) {
        // No ref can have that name, so no forge can have that branch: said before the network.
        return Err(CloneError::new(Kind::BranchAbsent, sentence(request, Kind::BranchAbsent)));
    }

    init::ensure();
    let created = !request.into.exists();
    let outcome = fetch(request, &host, key.as_ref());
    if outcome.is_err() && created {
        // As the Java clone leaves no half-made directory behind.
        let _ = std::fs::remove_dir_all(&request.into);
    }
    outcome
}

/// The host the clone connects to — refused unless it is the host every check decided on.
///
/// The Java side asks JGit's own URL reading (`URIish`) for it; libgit2 offers none to ask. Here the
/// question is asked where it can be answered: the HTTPS transport and the SSH host-key callback both
/// compare the host libgit2 is about to reach with this one, and refuse a difference.
fn connect_host(url: &str) -> Result<String, CloneError> {
    repository_url::host(url).map(|host| host.to_lowercase()).ok_or_else(|| {
        CloneError::new(
            Kind::UrlRefused,
            "Repository URL refused: its host part reads differently to the clone than to the checks. Use the address \
             the forge gives for cloning.",
        )
    })
}

/// The SSH port and login a URL names: `ssh://user@host:port/…`, or the SCP form on 22.
fn ssh_endpoint(url: &str) -> (u16, Option<String>) {
    let Some((_, rest)) = url.split_once("://") else {
        return (22, url.split_once('@').map(|(user, _)| user.to_owned()));
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let (user, host_port) = match authority.rsplit_once('@') {
        Some((user, host_port)) => (Some(user.to_owned()), host_port),
        None => (None, authority),
    };
    let port = if host_port.starts_with('[') {
        host_port.rsplit_once("]:").and_then(|(_, port)| port.parse().ok())
    } else {
        host_port.rsplit_once(':').and_then(|(_, port)| port.parse().ok())
    };
    (port.unwrap_or(22), user)
}

/// What the SSH side saw, for the diagnosis.
#[derive(Debug, Default)]
struct SshObserved {
    host_key: Option<CloneError>,
    identities_offered: u32,
    identity_refused: bool,
}

fn fetch(request: &CloneRequest, host: &str, key: Option<&Secret>) -> Result<(), CloneError> {
    let https = repository_url::is_https(&request.url).then(|| {
        let client = request
            .trust
            .blocking_client()
            .connect_timeout(Duration::from_secs(30).min(request.timeout))
            .timeout(request.timeout)
            .build();
        client.map(|client| {
            Arc::new(HttpsContext {
                validated_host: host.to_owned(),
                credential: request.https.clone().filter(HttpsCredential::has_token),
                client,
                observed: Mutex::new(Observed::default()),
            })
        })
    });
    let https = match https {
        Some(Ok(context)) => Some(context),
        Some(Err(error)) => {
            return Err(CloneError::new(Kind::Unclassified, sentence(request, Kind::Unclassified))
                .with_detail(error.to_string()));
        }
        None => None,
    };
    let _activation = https.clone().map(Activation::new);
    let ssh = RefCell::new(SshObserved::default());

    let result = run_fetch(request, host, key, &ssh);
    match result {
        Ok(()) => Ok(()),
        Err(Failure::Diagnosed(error)) => Err(error),
        Err(Failure::Git(error)) => Err(diagnose(request, &error, https.as_deref(), &ssh.borrow())),
    }
}

enum Failure {
    Diagnosed(CloneError),
    Git(git2::Error),
}

impl From<git2::Error> for Failure {
    fn from(error: git2::Error) -> Failure {
        Failure::Git(error)
    }
}

fn run_fetch(
    request: &CloneRequest,
    host: &str,
    key: Option<&Secret>,
    ssh: &RefCell<SshObserved>,
) -> Result<(), Failure> {
    let repository = git2::Repository::init(&request.into)?;
    // Named `origin` with the URL as given — never a token: the token travels in a header, only.
    let mut remote = repository.remote("origin", &request.url)?;

    let (port, url_user) = ssh_endpoint(&request.url);
    let attempts = Cell::new(0u32);
    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks.credentials(|_url, username_from_url, allowed| {
        let user =
            username_from_url.map(str::to_owned).or_else(|| url_user.clone()).unwrap_or_else(|| "git".to_owned());
        if allowed.contains(git2::CredentialType::USERNAME) {
            return git2::Cred::username(&user);
        }
        if !allowed.contains(git2::CredentialType::SSH_KEY) && !allowed.contains(git2::CredentialType::SSH_MEMORY) {
            return Err(git2::Error::from_str("the forge asked for a credential the clone does not hold"));
        }
        attempts.set(attempts.get() + 1);
        if attempts.get() > 1 {
            // libgit2 asks again after a refusal: the one identity this scan holds has been refused.
            ssh.borrow_mut().identity_refused = true;
            return Err(git2::Error::from_str("the deployment key was refused"));
        }
        ssh.borrow_mut().identities_offered += 1;
        match (key, request.without_key) {
            (Some(key), _) => git2::Cred::ssh_key_from_memory(&user, None, key.expose(), None),
            (None, WithoutKey::HostSsh) => git2::Cred::ssh_key_from_agent(&user),
            (None, WithoutKey::None) => {
                ssh.borrow_mut().identity_refused = true;
                Err(git2::Error::from_str("no SSH key is attached to this repository"))
            }
        }
    });
    callbacks.certificate_check(|certificate, connected_host| {
        let Some(hostkey) = certificate.as_hostkey() else {
            // A TLS certificate: only libgit2's own HTTPS would ask, and it is never used.
            return Ok(git2::CertificateCheckStatus::CertificatePassthrough);
        };
        match check_host_key(request, host, connected_host, port, hostkey) {
            Ok(()) => Ok(git2::CertificateCheckStatus::CertificateOk),
            Err(refused) => {
                let message = refused.message.clone();
                ssh.borrow_mut().host_key = Some(refused);
                Err(git2::Error::from_str(&message))
            }
        }
    });

    let mut options = git2::FetchOptions::new();
    options
        .remote_callbacks(callbacks)
        .depth(DEPTH)
        .follow_redirects(git2::RemoteRedirect::None)
        .download_tags(git2::AutotagOption::None);
    let branch = &request.branch;
    remote.fetch(&[format!("+refs/heads/{branch}:refs/remotes/origin/{branch}")], Some(&mut options), None)?;

    // **The absent branch is told by what the fetch brought, not by a sentence**: the Java side has
    // to match JGit's own wording for it, the one kind no type carries there.
    let fetched = match repository.find_reference(&format!("refs/remotes/origin/{branch}")) {
        Ok(reference) => reference,
        Err(error) if error.code() == git2::ErrorCode::NotFound => {
            return Err(Failure::Diagnosed(CloneError::new(Kind::BranchAbsent, sentence(request, Kind::BranchAbsent))));
        }
        Err(error) => return Err(error.into()),
    };
    let commit = fetched.peel_to_commit()?;
    repository.branch(branch, &commit, true)?;
    repository.set_head(&format!("refs/heads/{branch}"))?;
    repository.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))?;
    Ok(())
}

/// The host key, against the policy — `AcceptNewDatabase`, or the host's own file in `HostSsh` mode.
fn check_host_key(
    request: &CloneRequest,
    validated_host: &str,
    connected_host: &str,
    port: u16,
    hostkey: &git2::cert::CertHostkey<'_>,
) -> Result<(), CloneError> {
    if !connected_host.eq_ignore_ascii_case(validated_host) {
        return Err(CloneError::new(
            Kind::UrlRefused,
            "Repository URL refused: its host part reads differently to the clone than to the checks. Use the address \
             the forge gives for cloning.",
        ));
    }
    let (Some(blob), Some(key_type)) = (hostkey.hostkey(), hostkey.hostkey_type()) else {
        return Err(CloneError::new(Kind::HostKey, sentence(request, Kind::HostKey)));
    };
    let key_type = key_type.name();
    let refused = || CloneError::new(Kind::HostKey, sentence(request, Kind::HostKey));
    if request.private_key.is_none() && request.without_key == WithoutKey::HostSsh {
        let own = std::env::var_os("HOME").map(|home| Path::new(&home).join(".ssh/known_hosts"));
        return match own.map(|file| known_hosts::check(&file, validated_host, port, key_type, blob)) {
            Some(Verdict::Known) => Ok(()),
            _ => Err(refused()),
        };
    }
    match &request.host_keys {
        HostKeyPolicy::TrustEveryHost => Ok(()),
        HostKeyPolicy::AcceptNew(file) => match known_hosts::check(file, validated_host, port, key_type, blob) {
            Verdict::Known => Ok(()),
            Verdict::Changed => Err(refused()),
            Verdict::Unknown if known_hosts::is_pinned(file) => Err(refused()),
            Verdict::Unknown => known_hosts::record(file, validated_host, port, key_type, blob).map_err(|error| {
                CloneError::new(Kind::Unclassified, format!("The known-hosts file could not be prepared: {error}"))
            }),
        },
    }
}

/// The kind from what is typed, the sentence from the kind — `GitClone.diagnose`.
fn diagnose(
    request: &CloneRequest,
    error: &git2::Error,
    https: Option<&HttpsContext>,
    ssh: &SshObserved,
) -> CloneError {
    let detail = error.message().replace(&request.url, &repository_url::redact(&request.url));
    if let Some(refused) = &ssh.host_key {
        return refused.clone().with_detail(detail);
    }
    if let Some(context) = https {
        let observed = context.observe(|observed| {
            (
                observed.refusal.clone(),
                observed.last_status,
                observed.timed_out,
                observed.unreachable,
                observed.tls.clone(),
            )
        });
        let (refusal, status, timed_out, unreachable, tls) = observed;
        if let Some(refusal) = refusal {
            return refusal.with_detail(detail);
        }
        let kind = match status {
            401 | 403 => Kind::Authentication,
            404 | 410 => Kind::NotFound,
            429 => Kind::Unavailable,
            status if status >= 500 => Kind::Unavailable,
            _ if timed_out => Kind::Timeout,
            _ if unreachable => Kind::Network,
            _ => Kind::Unclassified,
        };
        let detail = match tls {
            Some(tls) => format!("{detail} ({tls})"),
            None => detail,
        };
        return CloneError::new(kind, sentence(request, worded(request, kind, error))).with_detail(detail);
    }
    let kind = if ssh.identity_refused || error.code() == git2::ErrorCode::Auth {
        Kind::Authentication
    } else if forge_says_not_found(error) || git_daemon_refused(request, error) {
        Kind::NotFound
    } else {
        match error.class() {
            // The socket's own failures: no route, no name, refused, reset — or silent too long.
            git2::ErrorClass::Net | git2::ErrorClass::Os if is_timeout(error) => Kind::Timeout,
            git2::ErrorClass::Net | git2::ErrorClass::Os => Kind::Network,
            _ => Kind::Unclassified,
        }
    };
    CloneError::new(kind, sentence(request, worded(request, kind, error))).with_detail(detail)
}

/// Whether an SSH forge answered that the repository is not there.
///
/// **The one kind told by words on this side, and JGit's own rule**: over SSH the server's refusal is
/// a line of its standard error, and JGit turns the same lines into the `NoRemoteRepositoryException`
/// the Java diagnosis reads as typed. Matching them here keeps a missing repository permanent on both
/// agents — unclassified, it would be retried for a quarter of an hour.
fn forge_says_not_found(error: &git2::Error) -> bool {
    if !matches!(error.class(), git2::ErrorClass::Ssh | git2::ErrorClass::Net) {
        return false;
    }
    let message = error.message().to_lowercase();
    ["does not appear to be a git repository", "repository not found", "no such repository", "does not exist"]
        .iter()
        .any(|phrase| message.contains(phrase))
}

/// **git daemon's refusal, on its own transport only.** It answers a path it does not serve — absent,
/// not exported, a service it does not run — with an `ERR` line, which libgit2 raises as a network error
/// reading `remote error: …`: the Java side's `RemoteRepositoryException`, which `typedKind` reads as
/// "not found" for `git://` alone. Unclassified, a missing repository over `git://` was retried three
/// times, a quarter of an hour, before failing as "the clone failed". Over SSH or HTTPS an `ERR` line is
/// whatever the forge chose to say, a passing condition among others, and stays unclassified.
fn git_daemon_refused(request: &CloneRequest, error: &git2::Error) -> bool {
    request.url.trim().to_ascii_lowercase().starts_with("git://")
        && error.class() == git2::ErrorClass::Net
        && error.message().starts_with("remote error:")
}

/// Between the two transient kinds of a dead socket, the words say which; both retry.
fn is_timeout(error: &git2::Error) -> bool {
    let message = error.message().to_lowercase();
    message.contains("timed out") || message.contains("timeout")
}

/// The kind the words suggest, **for the sentence only**, where nothing typed decided — `wordedKind`.
fn worded(request: &CloneRequest, kind: Kind, error: &git2::Error) -> Kind {
    if kind != Kind::Unclassified {
        return kind;
    }
    let message = error.message();
    if message.contains("not found") || message.contains("Remote branch") {
        return if message.contains("Remote branch") || message.contains("branch") {
            Kind::BranchAbsent
        } else {
            Kind::NotFound
        };
    }
    if request.has_token() && (message.contains("not authorized") || message.contains("401") || message.contains("403"))
    {
        return Kind::Authentication;
    }
    if message.contains("Auth fail") || message.contains("publickey") || message.contains("not authorized") {
        return Kind::Authentication;
    }
    if message.contains("host key") || message.contains("hostkey") {
        return Kind::HostKey;
    }
    Kind::Unclassified
}

/// A kind as a sentence that says what to do — `GitClone.sentence`, word for word. Every one names the
/// URL masked: each reaches the scan's error, the agent's log and the screen.
pub(crate) fn sentence(request: &CloneRequest, kind: Kind) -> String {
    let url = repository_url::redact(&request.url);
    match kind {
        Kind::BranchAbsent => format!("Branch \"{}\" does not exist on {url}.", request.branch),
        Kind::NotFound => format!("{url} could not be found."),
        Kind::Authentication => {
            if request.has_token() {
                format!(
                    "Authentication refused by {url}. Is the HTTPS token still valid, and allowed to read this repository?"
                )
            } else if request.has_key() {
                format!(
                    "Authentication refused by {url}. Is the deployment key attached to it declared with the provider?"
                )
            } else {
                let what = if repository_url::is_https(&request.url) { "an HTTPS token" } else { "an SSH key" };
                format!("{url} requires authentication. Attach {what} to this repository.")
            }
        }
        Kind::HostKey => {
            if !request.has_key() && request.without_key == WithoutKey::HostSsh {
                format!(
                    "The host key of {url} was refused by this machine's own known_hosts: the host is not listed there, or \
                     its key has changed. Check it is the right server, then add its key."
                )
            } else if let HostKeyPolicy::AcceptNew(file) = &request.host_keys
                && known_hosts::is_pinned(file)
            {
                format!(
                    "The host key of {url} is not the one listed in {}, or the host is not listed there: that file is \
                     read-only, so it is matched against and never added to.",
                    file.display()
                )
            } else {
                format!(
                    "The host key of {url} has changed since the last clone. Check it is the same server before running again."
                )
            }
        }
        Kind::Timeout => {
            format!("The clone of {url} timed out. Is the repository reachable from this machine?")
        }
        Kind::Network => {
            format!("The clone of {url} could not reach its host. Is the repository reachable from this machine?")
        }
        Kind::Unavailable => {
            format!("The forge answered the clone of {url} with an error of its own; the next attempt may succeed.")
        }
        Kind::Credential | Kind::UrlRefused | Kind::Unclassified => {
            format!("The clone of {url} failed.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ssh_endpoint_is_read_from_both_forms() {
        assert_eq!(ssh_endpoint("ssh://git@gitlab.example.org:2222/team/api.git"), (2222, Some("git".to_owned())));
        assert_eq!(ssh_endpoint("ssh://gitlab.example.org/team/api.git"), (22, None));
        assert_eq!(ssh_endpoint("git@gitlab.example.org:team/api.git"), (22, Some("git".to_owned())));
        assert_eq!(ssh_endpoint("ssh://git@[::1]:2200/x"), (2200, Some("git".to_owned())));
    }

    fn request(url: &str) -> CloneRequest {
        CloneRequest {
            url: url.to_owned(),
            branch: "main".to_owned(),
            into: PathBuf::from("/nowhere"),
            private_key: None,
            timeout: Duration::from_secs(1),
            host_keys: HostKeyPolicy::TrustEveryHost,
            without_key: WithoutKey::None,
            https: None,
            trust: TlsTrust::BuiltIn,
        }
    }

    #[test]
    fn a_refusal_of_git_daemon_is_a_missing_repository_on_git_alone() {
        // What libgit2 raises for the daemon's ERR line, measured against a real `git daemon`.
        let refusal = git2::Error::new(
            git2::ErrorCode::GenericError,
            git2::ErrorClass::Net,
            "remote error: access denied or repository not exported: /missing.git",
        );
        let over_git = diagnose(&request("git://fixture/missing.git"), &refusal, None, &SshObserved::default());
        assert_eq!(
            (over_git.kind, over_git.kind.failure_kind()),
            (Kind::NotFound, vectispire_domain::FailureKind::Permanent)
        );
        // The same line from an SSH forge is whatever it chose to say: a passing condition, retried.
        let over_ssh = diagnose(&request("ssh://git@forge/x.git"), &refusal, None, &SshObserved::default());
        assert_eq!(over_ssh.kind.failure_kind(), vectispire_domain::FailureKind::Transient);
        assert_ne!(over_ssh.kind, Kind::NotFound);
        let timeout =
            git2::Error::new(git2::ErrorCode::GenericError, git2::ErrorClass::Net, "failed to resolve address");
        assert_eq!(
            diagnose(&request("git://nowhere/x.git"), &timeout, None, &SshObserved::default()).kind,
            Kind::Network
        );
    }
}
