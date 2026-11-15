//! **A repository URL never names one of Vectispire's own endpoints** — the allow-list the binary composes
//! (`clone_hosts::allowlist`) asks the outbound guard's reserved endpoints first, whether a list is set or not, as
//! Java's `OutboundGuardConfiguration.gitHostAllowlist` does (`GitHostAllowlistTest`'s reserved cases). The port had
//! composed the list alone, so the built-in worker cloned from the database or the Docker daemon on a URL's say-so
//! (Phase 2 security review, 2026-11). The list is what repository creation, update, import and the dispatch-time
//! check all ask (`permits`, `refusal`), so holding the composition holds the four.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vectispire_cp_app::clone_hosts;
use vectispire_cp_outbound::address::Raw;
use vectispire_cp_outbound::{OutboundUrlGuard, ReservedEndpoint};

/// `mysql` and `db.internal` are one container; `docker-proxy` another. Nothing else resolves.
fn guard() -> OutboundUrlGuard {
    let resolver = |host: &str| match host {
        "mysql" | "db.internal" => vec![Raw::V4([172, 18, 0, 3])],
        "docker-proxy" => vec![Raw::V4([172, 18, 0, 4])],
        _ => Vec::new(),
    };
    OutboundUrlGuard::with_resolver(
        resolver,
        vec![
            ReservedEndpoint::new("mysql", 3306, "the database"),
            ReservedEndpoint::new("docker-proxy", 2375, "the Docker daemon"),
            ReservedEndpoint::on_every_host(6443, "the cluster's API"),
        ],
    )
}

#[test]
fn a_reserved_endpoint_is_refused_with_no_list_set() {
    let hosts = clone_hosts::allowlist("", &guard()).unwrap();
    assert!(!hosts.restricts());
    for url in [
        "ssh://mysql:3306/x.git",
        "git://docker-proxy:2375/x",
        "https://kubernetes.default.svc:6443/x.git",
        // By address: another name for the database's container.
        "ssh://db.internal:3306/x.git",
    ] {
        assert!(!hosts.permits(url), "{url} is one of Vectispire's own endpoints");
    }
    assert_eq!(
        hosts.refusal("ssh://mysql:3306/x.git"),
        "Repository URL: mysql:3306 is the database, which no setting may send requests to."
    );
    // The same host on a port nobody reserved, and every other forge, as before.
    assert!(hosts.permits("ssh://mysql/x.git"));
    assert!(hosts.permits("https://gitlab.example.org/group/x.git"));
    assert!(hosts.permits("git@gitlab.example.org:group/x.git"));
}

#[test]
fn a_reserved_endpoint_is_refused_even_when_listed() {
    let hosts = clone_hosts::allowlist("mysql,gitlab.example.org", &guard()).unwrap();
    assert!(!hosts.permits("ssh://mysql:3306/x.git"), "listing the host does not lift the reservation");
    assert!(hosts.refusal("ssh://mysql:3306/x.git").contains("is the database"));
    assert!(hosts.permits("https://gitlab.example.org/group/x.git"));
    assert!(!hosts.permits("https://elsewhere.example.org/x.git"), "the list still restricts");
}
