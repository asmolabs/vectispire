//! One claimed scan, run — delegates to `vectispire_runner::Runner`.

use std::path::PathBuf;
use std::sync::Arc;
use vectispire_protocol::AgentClient;
#[cfg(test)]
use vectispire_runner::scan_root;
pub use vectispire_runner::{BoxFuture, ExecutionFailure, Images, Places, RuleProvider, Runner};
use vectispire_scanners::rules::StoredFile;
use vectispire_tls::TlsTrust;

use crate::serve::Execute;

/// The agent's rule provider: fetches rules via `AgentClient`.
struct AgentRuleProvider {
    client: Arc<AgentClient>,
}

impl RuleProvider for AgentRuleProvider {
    fn fetch_rule_set<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<Vec<StoredFile>, String>> {
        let client = self.client.clone();
        Box::pin(async move {
            client.rule_set(hash).await.map_err(|error| error.to_string()).map(|files| {
                files
                    .into_iter()
                    .map(|file| StoredFile {
                        path: file.path,
                        original_name: file.original_name.unwrap_or_default(),
                        content: file.content,
                    })
                    .collect()
            })
        })
    }
}

pub struct ScanRunner {
    inner: Runner,
}

impl std::fmt::Debug for ScanRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ScanRunner").field("inner", &self.inner).finish()
    }
}

impl ScanRunner {
    pub fn new(
        client: Arc<AgentClient>,
        images: Images,
        places: Places,
        vulnerability_root: Option<PathBuf>,
        trust: TlsTrust,
    ) -> Result<ScanRunner, String> {
        let rule_provider = Arc::new(AgentRuleProvider { client });
        let inner = Runner::new(Some(rule_provider), images, places, vulnerability_root, trust)?;
        Ok(ScanRunner { inner })
    }

    pub async fn run(
        &self,
        task: vectispire_protocol::ScanTask,
    ) -> Result<vectispire_protocol::ScanArtifacts, ExecutionFailure> {
        self.inner.run(task).await
    }
}

impl Execute for ScanRunner {
    fn execute(
        &self,
        task: vectispire_protocol::ScanTask,
    ) -> impl std::future::Future<Output = Result<vectispire_protocol::ScanArtifacts, ExecutionFailure>> + Send {
        self.run(task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| pairs.iter().find(|(key, _)| *key == name).map(|(_, value)| (*value).to_owned())
    }

    #[test]
    fn the_places_are_read_where_the_java_agent_reads_them() {
        let composition = Places::from_lookup(lookup(&[(
            "JDK_JAVA_OPTIONS",
            "-Djava.io.tmpdir=/var/lib/vectispire/agent-work -Duser.home=/var/lib/vectispire/agent-work/home",
        )]));
        assert_eq!(composition.work, PathBuf::from("/var/lib/vectispire/agent-work"));
        assert_eq!(composition.home, PathBuf::from("/var/lib/vectispire/agent-work/home"));
        let explicit = Places::from_lookup(lookup(&[("VECTISPIRE_WORK_DIR", "/w"), ("HOME", "/h")]));
        assert_eq!((explicit.work, explicit.home), (PathBuf::from("/w"), PathBuf::from("/h")));
    }

    #[test]
    fn a_blank_image_override_keeps_the_pinned_digest() {
        let images =
            Images::from_lookup(lookup(&[("VECTISPIRE_IMAGE_SYFT", "  "), ("VECTISPIRE_IMAGE_GRYPE", "r/g@sha256:1")]));
        assert_eq!(images.syft, vectispire_scanners::images::SYFT);
        assert_eq!(images.grype, "r/g@sha256:1");
    }

    #[test]
    fn a_sub_path_out_of_the_clone_or_absent_from_it_fails_the_scan_for_good() {
        let clone = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(clone.path().join("services/api")).unwrap();
        std::fs::write(clone.path().join("file"), "").unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), clone.path().join("out")).unwrap();

        assert!(scan_root(clone.path(), "services/api", "main").is_ok());
        assert!(scan_root(clone.path(), "", "main").is_ok());
        for (sub, said) in [
            ("missing", "The sub-path \"missing\" is not a directory of branch \"main\"."),
            ("file", "The sub-path \"file\" is not a directory of branch \"main\"."),
            ("out", "The sub-path \"out\" leads outside the repository."),
        ] {
            let failure = scan_root(clone.path(), sub, "main").unwrap_err();
            assert_eq!(
                (failure.message.as_str(), failure.kind),
                (said, vectispire_domain::FailureKind::Permanent),
                "{sub}"
            );
        }
    }
}
