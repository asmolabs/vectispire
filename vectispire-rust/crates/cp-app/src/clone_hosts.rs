//! The hosts a repository may be cloned from, as the binary composes them — Java's
//! `OutboundGuardConfiguration.gitHostAllowlist`: the operator's list, **refusing the outbound guard's reserved
//! endpoints whether a list is set or not**. The port had composed the list alone, so a repository URL naming the
//! Docker daemon, the database or the cluster's API was accepted and cloned from by the built-in worker, inside the
//! control plane (Phase 2 security review, 2026-11). Here rather than in `main`, so that a test holds the composition.

use std::sync::Arc;

use vectispire_cp_outbound::guard::OutboundUrlGuard;
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::repository_url::InvalidHost;

/// The label the guard's refusal names the setting by, as Java's.
pub const LABEL: &str = "Repository URL";

/// `vectispire.git.allowed-hosts` parsed, asking `guard` about every URL first.
pub fn allowlist(configured: &str, guard: &OutboundUrlGuard) -> Result<GitHostAllowlist, InvalidHost> {
    let guard = guard.clone();
    Ok(GitHostAllowlist::parse(Some(configured))?
        .refusing(Arc::new(move |host: &str, port: i32| guard.reserved_reason(host, port, LABEL))))
}
