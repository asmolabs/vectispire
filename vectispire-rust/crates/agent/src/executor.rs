//! What runs the scanners on this agent, chosen once at start (decision 0045) — `ExecutorChoice.choose`: the Docker
//! daemon it reaches, or a pod per run in the scans' namespace.
//!
//! **Before the hello**, as on the Java agent: a misconfigured executor stops the start here rather than failing the
//! first scan, and the hello carries what the chosen one can run.

use std::path::{Path, PathBuf};
use vectispire_container::{ContainerRunner, Executor, ScannerLimits};
use vectispire_kubernetes::api::KubernetesApi;
use vectispire_kubernetes::{address, choice};

/// The executor `kind` names: `docker` or `kubernetes`, already lower-cased; anything else is refused.
pub async fn choose(
    kind: &str,
    kubernetes: &choice::KubernetesConfig,
    work: &Path,
    home: &Path,
    matcher_database: PathBuf,
) -> Result<Executor, String> {
    match kind {
        "docker" => ContainerRunner::for_scans(home, ScannerLimits::default_for_this_host()).map(Executor::new),
        "kubernetes" => {
            let context = choice::Context { matcher_database, own_user: own_user(work) };
            let executor =
                choice::kubernetes(kubernetes, &context, KubernetesApi::in_cluster, address::from_environment).await?;
            Ok(Executor::new(executor))
        }
        other => Err(choice::unknown_kind(other)),
    }
}

/// This process's `uid:gid`, read off a file it creates where it clones: the owner of every workspace, so the default
/// for a run that names none. Where the work directory sits, not in a temporary directory the image does not have.
fn own_user(work: &Path) -> Option<String> {
    std::fs::create_dir_all(work).ok()?;
    let probe = tempfile::Builder::new().prefix("vectispire-owner").tempfile_in(work).ok()?;
    vectispire_container::owner_of(probe.path())
}
