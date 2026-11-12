//! Real IaC and SAST scans: the pinned checkov and semgrep images, run by this crate's runner through
//! the socket proxy configured as the composition configures it, over a workspace laid out as the
//! agent lays it out — the bundled rules placed by `RulePlacement`.
//!
//! Needs Docker, and fails without it — a suite that skips itself reports green having checked nothing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use vectispire_container::{ContainerRunner, ScannerLimits};
use vectispire_scanners::rules::{self, RulePlacement};
use vectispire_scanners::{iac, images, sast};
use vectispire_testkit::proxy::SocketProxy;

fn workspace(files: &[(&str, &str)]) -> tempfile::TempDir {
    let workspace = tempfile::Builder::new().prefix("vs-rs-scan-").tempdir().unwrap();
    std::fs::set_permissions(workspace.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, content) in files {
        let path = workspace.path().join("source").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    let bundled = rules::materialise().unwrap();
    RulePlacement::new(bundled.tree()).place_bundled(&workspace.path().join("rules")).unwrap();
    workspace
}

#[tokio::test(flavor = "multi_thread")]
async fn checkov_reports_a_public_bucket_through_the_proxy() {
    let proxy = SocketProxy::start();
    let runner = ContainerRunner::connect(Some(&proxy.address), ScannerLimits::default_for_this_host()).unwrap();
    let workspace = workspace(&[(
        "deploy/main.tf",
        "resource \"aws_s3_bucket\" \"reports\" {\n  bucket = \"example-reports\"\n  acl    = \"public-read\"\n}\n",
    )]);
    let findings = iac::scan(&runner, workspace.path(), Some("deploy"), images::CHECKOV).await.expect("a report");
    assert!(
        findings
            .iter()
            .any(|finding| finding.file == "main.tf" && finding.resource.as_deref() == Some("aws_s3_bucket.reports")),
        "{findings:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn semgrep_runs_the_bundled_rule_through_the_proxy() {
    let proxy = SocketProxy::start();
    let runner = ContainerRunner::connect(Some(&proxy.address), ScannerLimits::default_for_this_host()).unwrap();
    let workspace = workspace(&[("app.py", "def handle(expression):\n    return eval(expression)\n")]);
    let findings = sast::scan(&runner, workspace.path(), None, images::SEMGREP).await.unwrap().expect("a report");
    assert_eq!(findings.len(), 1, "{findings:?}");
    let finding = &findings[0];
    assert_eq!(finding.rule_id, "vectispire.python.eval-on-input");
    assert_eq!((finding.file.as_str(), finding.line), ("app.py", 2));
    assert_eq!(finding.severity, sast::Severity::High);
    assert_eq!(finding.owasp_category.as_deref(), Some("A03"));
}
