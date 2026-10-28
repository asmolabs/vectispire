//! The clone against a real forge — sshd with git-shell, and git's http-backend behind TLS signed by
//! an authority made for the run (`crates/testkit/forge/`). Needs Docker, and fails without it.
//!
//! What each test pins is a property of the Java clone that is contract: the kind a failure is
//! classified as decides whether the scan is retried, and the sentence is what the operator reads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;
use vectispire_domain::secret::Secret;
use vectispire_git::{CloneError, CloneRequest, HostKeyPolicy, HttpsCredential, Kind, WithoutKey, clone};
use vectispire_testkit::forge::Forge;
use vectispire_tls::TlsTrust;

fn request(url: &str, into: &Path, known_hosts: &Path) -> CloneRequest {
    CloneRequest {
        url: url.to_owned(),
        branch: "main".to_owned(),
        into: into.to_owned(),
        private_key: None,
        timeout: Duration::from_secs(60),
        host_keys: HostKeyPolicy::AcceptNew(known_hosts.to_owned()),
        without_key: WithoutKey::None,
        https: None,
        trust: TlsTrust::BuiltIn,
    }
}

fn trusting(forge: &Forge, dir: &Path) -> TlsTrust {
    let bundle = dir.join("forge-ca.pem");
    std::fs::write(&bundle, &forge.ca_pem).unwrap();
    TlsTrust::from_bundle(&bundle).unwrap()
}

fn token(forge: &Forge) -> HttpsCredential {
    HttpsCredential { host: "localhost".to_owned(), username: None, token: Secret::new(forge.token.clone()) }
}

fn failed(result: Result<(), CloneError>) -> CloneError {
    result.expect_err("the clone should have failed")
}

fn pin(file: &Path, line: &str) {
    std::fs::write(file, format!("{line}\n")).unwrap();
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o444)).unwrap();
}

// ------------------------------------------------------------------------------------------- SSH

#[test]
fn over_ssh_a_pinned_host_and_the_deployment_key_clone_and_a_first_contact_is_recorded() {
    let forge = Forge::start();
    let dir = tempfile::tempdir().unwrap();

    // Pinned: the operator's read-only file names the host and its key.
    let pinned = dir.path().join("pinned_known_hosts");
    pin(&pinned, &format!("[localhost]:{} {}", forge.ssh_port, forge.host_key));
    let mut pinned_clone = request(&forge.ssh_url("team/api.git"), &dir.path().join("pinned"), &pinned);
    pinned_clone.private_key = Some(Secret::new(forge.deploy_key.clone()));
    clone(&pinned_clone).unwrap();
    assert_eq!(std::fs::read_to_string(dir.path().join("pinned/README.md")).unwrap(), "a tree to scan\n");

    // Accept-new: an empty writable file learns the host, and the second clone is checked against it.
    let learning = dir.path().join("known_hosts");
    let mut first = request(&forge.ssh_url("team/api.git"), &dir.path().join("first"), &learning);
    first.private_key = Some(Secret::new(forge.deploy_key.clone()));
    clone(&first).unwrap();
    let recorded = std::fs::read_to_string(&learning).unwrap();
    assert_eq!(
        recorded,
        format!("[localhost]:{} {}\n", forge.ssh_port, forge.host_key),
        "an unhashed line an operator can read"
    );
    let mut second = first.clone();
    second.into = dir.path().join("second");
    second.branch = "feature".to_owned();
    clone(&second).unwrap();
    assert_eq!(std::fs::read_to_string(&learning).unwrap(), recorded, "nothing recorded twice");

    // Every key type a deployment key comes in is read and accepted.
    for (name, key) in [("rsa", &forge.rsa_key), ("rsa-pem", &forge.rsa_pem_key), ("ecdsa", &forge.ecdsa_key)] {
        let mut typed = first.clone();
        typed.into = dir.path().join(name);
        typed.private_key = Some(Secret::new(key.clone()));
        clone(&typed).unwrap_or_else(|error| panic!("{name}: {error:?}"));
    }

    // The deployment key never reached the file system, and the remote is the URL as given.
    let config = std::fs::read_to_string(dir.path().join("first/.git/config")).unwrap();
    assert!(config.contains(&forge.ssh_url("team/api.git")));
    assert!(!config.contains("PRIVATE KEY"));
}

#[test]
fn over_ssh_a_changed_or_unlisted_host_key_is_refused() {
    let forge = Forge::start();
    let dir = tempfile::tempdir().unwrap();
    let other_host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    let changed = dir.path().join("changed");
    std::fs::write(&changed, format!("[localhost]:{} {other_host_key}\n", forge.ssh_port)).unwrap();
    let mut attempt = request(&forge.ssh_url("team/api.git"), &dir.path().join("a"), &changed);
    attempt.private_key = Some(Secret::new(forge.deploy_key.clone()));
    let refused = failed(clone(&attempt));
    assert_eq!(refused.kind, Kind::HostKey);
    assert!(refused.message.contains("has changed since the last clone"), "{}", refused.message);
    assert!(!dir.path().join("a").exists(), "no half-made clone is left behind");

    let pinned = dir.path().join("pinned");
    pin(&pinned, &format!("gitlab.example.org {other_host_key}"));
    attempt.host_keys = HostKeyPolicy::AcceptNew(pinned.clone());
    let refused = failed(clone(&attempt));
    assert_eq!(refused.kind, Kind::HostKey);
    assert!(refused.message.contains("that file is read-only"), "{}", refused.message);
    assert_eq!(std::fs::read_to_string(&pinned).unwrap().lines().count(), 1, "the operator's pin is never added to");
}

#[test]
fn over_ssh_a_missing_or_refused_key_is_an_authentication_failure_and_a_bad_one_never_leaves() {
    let forge = Forge::start();
    let dir = tempfile::tempdir().unwrap();
    let known = dir.path().join("known_hosts");

    let without = request(&forge.ssh_url("team/api.git"), &dir.path().join("a"), &known);
    let refused = failed(clone(&without));
    assert_eq!(
        (refused.kind, refused.kind.failure_kind()),
        (Kind::Authentication, vectispire_domain::FailureKind::Permanent)
    );
    assert!(
        refused.message.ends_with("requires authentication. Attach an SSH key to this repository."),
        "{}",
        refused.message
    );

    let mut wrong = without.clone();
    wrong.private_key = Some(Secret::new(forge.other_key.clone()));
    let refused = failed(clone(&wrong));
    assert_eq!(refused.kind, Kind::Authentication);
    assert!(
        refused.message.contains("Is the deployment key attached to it declared with the provider?"),
        "{}",
        refused.message
    );

    let untouched = dir.path().join("untouched_known_hosts");
    let mut unreadable = request(&forge.ssh_url("team/api.git"), &dir.path().join("c"), &untouched);
    unreadable.private_key = Some(Secret::new("not a key at all"));
    let refused = failed(clone(&unreadable));
    assert_eq!(refused.kind, Kind::Credential);
    assert!(refused.message.contains("Expected an OpenSSH or PEM private key."), "{}", refused.message);
    assert!(!untouched.exists(), "refused before the network: the host was never contacted");
}

#[test]
fn over_ssh_an_absent_branch_and_injection_shaped_input_are_refused() {
    let forge = Forge::start();
    let dir = tempfile::tempdir().unwrap();
    let known = dir.path().join("known_hosts");
    let mut absent = request(&forge.ssh_url("team/api.git"), &dir.path().join("a"), &known);
    absent.private_key = Some(Secret::new(forge.deploy_key.clone()));
    absent.branch = "no-such-branch".to_owned();
    let refused = failed(clone(&absent));
    assert_eq!(refused.kind, Kind::BranchAbsent, "{refused:?}");
    assert_eq!(
        refused.message,
        format!("Branch \"no-such-branch\" does not exist on {}.", forge.ssh_url("team/api.git"))
    );

    let mut option = absent.clone();
    option.branch = "--upload-pack=touch /tmp/pwned".to_owned();
    assert_eq!(failed(clone(&option)).kind, Kind::BranchAbsent);

    for url in [
        "ssh://-oProxyCommand=touch%20/tmp/pwned/x",
        "ext::sh -c touch% /tmp/pwned",
        "file:///srv/git/team/api.git",
        "git@-oProxyCommand=x:team/api.git",
    ] {
        let mut injected = absent.clone();
        injected.url = url.to_owned();
        injected.branch = "main".to_owned();
        let refused = failed(clone(&injected));
        assert_eq!(refused.kind, Kind::UrlRefused, "{url}: {refused:?}");
    }
    assert!(forge.container.exec(&["sh", "-c", "ls /tmp/pwned 2>/dev/null || echo absent"]).contains("absent"));

    let mut missing = absent.clone();
    missing.url = forge.ssh_url("team/nope.git");
    missing.branch = "main".to_owned();
    let refused = failed(clone(&missing));
    assert_eq!(
        (refused.kind, refused.message.clone()),
        (Kind::NotFound, format!("{} could not be found.", forge.ssh_url("team/nope.git")))
    );
}

// ----------------------------------------------------------------------------------------- HTTPS

#[test]
fn over_https_a_token_clones_and_is_sent_once_asked_and_written_nowhere() {
    let forge = Forge::start();
    let dir = tempfile::tempdir().unwrap();
    let mut with_token = request(&forge.https_url("team/api.git"), &dir.path().join("a"), &dir.path().join("kh"));
    with_token.https = Some(token(&forge));
    with_token.trust = trusting(&forge, dir.path());

    let logs = capture_logs(|| clone(&with_token));
    logs.0.unwrap();
    assert!(!logs.1.contains(&forge.token), "the token is in no log line");
    assert_eq!(std::fs::read_to_string(dir.path().join("a/README.md")).unwrap(), "a tree to scan\n");
    assert!(no_file_contains(&dir.path().join("a"), &forge.token), "the token is nowhere in the clone, .git included");

    let requests = forge.requests();
    assert_eq!(
        requests.first().map(String::as_str),
        Some("GET /team/api.git/info/refs?service=git-upload-pack auth=none")
    );
    assert!(
        requests.iter().skip(1).all(|line| line.ends_with("auth=token")),
        "after the forge's 401, the token: {requests:?}"
    );

    let public = request(&forge.https_url("public/api.git"), &dir.path().join("b"), &dir.path().join("kh"));
    let public = CloneRequest { trust: trusting(&forge, dir.path()), ..public };
    clone(&public).unwrap();
}

#[test]
fn over_https_the_forges_answers_are_classified_by_their_status() {
    let forge = Forge::start();
    let dir = tempfile::tempdir().unwrap();
    let base = |path: &str, name: &str| {
        let mut attempt = request(&forge.https_url(path), &dir.path().join(name), &dir.path().join("kh"));
        attempt.trust = trusting(&forge, dir.path());
        attempt
    };

    let anonymous = failed(clone(&base("team/api.git", "a")));
    assert_eq!(anonymous.kind, Kind::Authentication);
    assert!(
        anonymous.message.ends_with("requires authentication. Attach an HTTPS token to this repository."),
        "{}",
        anonymous.message
    );

    let mut wrong = base("team/api.git", "b");
    wrong.https = Some(HttpsCredential { token: Secret::new("not-the-token"), ..token(&forge) });
    let refused = failed(clone(&wrong));
    assert_eq!(refused.kind, Kind::Authentication);
    assert!(refused.message.contains("Is the HTTPS token still valid"), "{}", refused.message);

    let mut forbidden = base("forbidden/api.git", "c");
    forbidden.https = Some(token(&forge));
    assert_eq!(failed(clone(&forbidden)).kind, Kind::Authentication, "a 403 is an authentication failure too");

    let missing = failed(clone(&base("missing/api.git", "d")));
    assert_eq!(
        (missing.kind, missing.message.clone()),
        (Kind::NotFound, format!("{} could not be found.", forge.https_url("missing/api.git")))
    );

    let flaky = failed(clone(&base("flaky/api.git", "e")));
    assert_eq!((flaky.kind, flaky.kind.failure_kind()), (Kind::Unavailable, vectispire_domain::FailureKind::Transient));
}

#[test]
fn over_https_a_redirect_is_refused_to_any_host_and_names_only_its_host() {
    let forge = Forge::start();
    let dir = tempfile::tempdir().unwrap();
    let mut moved = request(&forge.https_url("moved/api.git"), &dir.path().join("a"), &dir.path().join("kh"));
    moved.trust = trusting(&forge, dir.path());
    moved.https = Some(token(&forge));
    let refused = failed(clone(&moved));
    assert_eq!(refused.kind, Kind::UrlRefused);
    assert_eq!(
        refused.message,
        "The repository at localhost answered with a redirect (302) to elsewhere.example. A clone follows no redirect, \
         because the host it would reach was never checked: use the address the forge redirects to as the repository URL."
    );
    assert!(!refused.message.contains("never-logged") && !refused.detail.contains("never-logged"));
    assert_eq!(forge.requests().len(), 1, "one request, never repeated with the token against the redirect");
}

#[test]
fn over_https_a_token_for_another_host_is_refused_before_any_request() {
    let forge = Forge::start();
    let dir = tempfile::tempdir().unwrap();
    let mut elsewhere = request(&forge.https_url("team/api.git"), &dir.path().join("a"), &dir.path().join("kh"));
    elsewhere.trust = trusting(&forge, dir.path());
    elsewhere.https = Some(HttpsCredential { host: "gitlab.example.org".to_owned(), ..token(&forge) });
    let refused = failed(clone(&elsewhere));
    assert_eq!(refused.kind, Kind::Credential);
    assert_eq!(
        refused.message,
        format!(
            "The HTTPS token is issued for gitlab.example.org and is sent to no other host; {} names another.",
            forge.https_url("team/api.git")
        )
    );
    let mut over_ssh = elsewhere.clone();
    over_ssh.url = forge.ssh_url("team/api.git");
    over_ssh.https = Some(token(&forge));
    assert_eq!(failed(clone(&over_ssh)).kind, Kind::Credential, "a token is for https:// only");
    assert!(forge.requests().is_empty(), "nothing reached the forge: {:?}", forge.requests());
}

#[test]
fn over_https_an_authority_the_agent_does_not_trust_is_refused_and_the_bundle_replaces_the_built_in_ones() {
    let forge = Forge::start();
    let dir = tempfile::tempdir().unwrap();
    let mut untrusted = request(&forge.https_url("public/api.git"), &dir.path().join("a"), &dir.path().join("kh"));
    untrusted.trust = TlsTrust::BuiltIn;
    let refused = failed(clone(&untrusted));
    assert_eq!(refused.kind, Kind::Unclassified, "as the Java clone classifies a refused certificate: {refused:?}");
    assert!(refused.detail.to_lowercase().contains("certificate"), "{}", refused.detail);
    assert!(forge.requests().is_empty(), "no request was sent over an untrusted connection");

    let trusted = CloneRequest { trust: trusting(&forge, dir.path()), into: dir.path().join("b"), ..untrusted };
    clone(&trusted).unwrap();
}

// ------------------------------------------------------------------------------------- helpers

fn no_file_contains(root: &Path, needle: &str) -> bool {
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(std::fs::read_dir(&path).unwrap().map(|entry| entry.unwrap().path()));
        } else if let Ok(bytes) = std::fs::read(&path)
            && bytes.windows(needle.len()).any(|window| window == needle.as_bytes())
        {
            return false;
        }
    }
    true
}

/// Runs `body` with every log line at every level captured, and returns them.
fn capture_logs<T>(body: impl FnOnce() -> T) -> (T, String) {
    use std::sync::{Arc, Mutex};
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber =
        tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).with_writer(move || writer.clone()).finish();
    let result = tracing::subscriber::with_default(subscriber, body);
    let text = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    (result, text)
}
