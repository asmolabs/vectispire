//! Real plugins: the pinned cosign image verifying a real signature against Sigstore, then the plugin run by this
//! crate's runner through the socket proxy configured as the composition configures it — holder, bounded tmpfs
//! volume, `fsize`, the archive read back, every container and volume removed.
//!
//! **The plugin is a publicly keyless-signed image**: Chainguard's busybox, by the digest of its index, signed by its
//! release workflow — so the verification is cosign's own against the real transparency log and trust root, not a
//! stand-in. The same image declared with another signer is refused, and an image nobody signed (the holder's busybox)
//! is refused, and neither is run. Then the confinement: a plugin writing past the directory's ceiling is refused, not
//! truncated, and a sparse terabyte beside the report kills the plugin on `SIGXFSZ`.
//!
//! Needs Docker and the network (the registries and Sigstore), and fails without them — a suite that skips itself
//! reports green having checked nothing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;
use vectispire_container::{ContainerRunner, ScannerLimits};
use vectispire_protocol::{PluginRef, PluginStep, Refusal, Signature};
use vectispire_scanners::plugins::{self, PluginScanner, Settings};
use vectispire_testkit::docker::docker;
use vectispire_testkit::proxy::SocketProxy;

const SIGNED: &str =
    "cgr.dev/chainguard/busybox@sha256:9ea14a743061993ca9fbf5f5ad7215ede3646d142754398f456250e51c23175a";
const IDENTITY: &str = "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main";
const ISSUER: &str = "https://token.actions.githubusercontent.com";

/// One SARIF result per file of the tree holding `eval(` — a plugin that reads what it is given.
const FINDER: &str = r#"cd {source} && o={output} && printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"eval-finder","version":"1.0"}},"results":[' > $o && sep= && for f in $(grep -rl 'eval(' . | sort); do printf '%s{"ruleId":"EVAL001","level":"error","message":{"text":"eval"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"%s"}}}]}' "$sep" "$f" >> $o; sep=,; done && printf ']}]}' >> $o"#;

fn manifest(id: &str, image: &str, script: &str, signer: Option<(&str, &str)>) -> Value {
    let mut manifest = json!({
        "id": id, "name": id, "image": image, "languages": ["python"],
        "arguments": ["sh", "-c", script], "output": "results.sarif", "exit_codes": [0], "timeout_seconds": 120,
    });
    if let Some((identity, issuer)) = signer {
        manifest["signature"] = json!({"identity": identity, "issuer": issuer});
    }
    manifest
}

struct Manifests(Vec<Value>);

impl plugins::PluginProvider for Manifests {
    async fn manifest(&self, reference: &PluginRef) -> Result<Value, String> {
        Ok(self.0.iter().find(|manifest| manifest["id"] == reference.id.as_str()).cloned().unwrap_or(Value::Null))
    }
}

/// A workspace as the agent lays it out, 0700, with a tree in `source/`.
fn workspace() -> tempfile::TempDir {
    let workspace = tempfile::Builder::new().prefix("vs-rs-plugin-").tempdir().unwrap();
    std::fs::set_permissions(workspace.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir_all(workspace.path().join("source/app")).unwrap();
    std::fs::write(workspace.path().join("source/app/a.py"), "eval(input())\n").unwrap();
    std::fs::write(workspace.path().join("source/app/b.py"), "print('fine')\n").unwrap();
    workspace
}

async fn run(limits: ScannerLimits, settings: Settings, manifests: Vec<(Value, bool)>) -> Vec<PluginStep> {
    let proxy = SocketProxy::start();
    let runner = ContainerRunner::connect(Some(&proxy.address), limits).unwrap();
    assert!(runner.is_available().await, "the runner reaches the daemon through the proxy");
    let workspace = workspace();
    let references: Vec<PluginRef> = manifests
        .iter()
        .map(|(manifest, waived)| PluginRef {
            id: manifest["id"].as_str().unwrap().to_owned(),
            digest: plugins::digest_of(manifest).unwrap(),
            runs_unsigned: *waived,
        })
        .collect();
    let provider = Manifests(manifests.into_iter().map(|(manifest, _)| manifest).collect());
    let scanner = PluginScanner::new(&runner, settings);
    let source = workspace.path().join("source");
    let steps = plugins::run_steps(&scanner, &provider, &references, workspace.path(), Some(&source), |_| true).await;
    assert_nothing_left(workspace.path());
    steps
}

/// No container and no volume of a plugin is left on the host, and no registry login in the workspace.
fn assert_nothing_left(workspace: &Path) {
    let containers = docker(&["ps", "-a", "--filter", "label=dev.vectispire.scanner", "--format", "{{.Labels}}"]);
    assert!(!containers.contains("plugin "), "every plugin container was removed: {containers}");
    let volumes = docker(&["volume", "ls", "--filter", "label=dev.vectispire.scanner", "-q"]);
    assert!(volumes.trim().is_empty(), "every holder's volume was removed: {volumes}");
    let logins = walk(workspace).into_iter().filter(|path| path.contains("registry-login")).collect::<Vec<_>>();
    assert!(logins.is_empty(), "no registry login outlives its run: {logins:?}");
}

fn walk(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root).into_iter().flatten().flatten() {
        let path = entry.path();
        found.push(path.display().to_string());
        if path.is_dir() {
            found.extend(walk(&path));
        }
    }
    found
}

fn limits() -> ScannerLimits {
    ScannerLimits { timeout: Duration::from_secs(300), ..ScannerLimits::default_for_this_host() }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_plugin_is_verified_runs_confined_and_reports_what_it_read() {
    let signed = manifest("eval-finder", SIGNED, FINDER, Some((IDENTITY, ISSUER)));
    let steps = run(limits(), Settings::default(), vec![(signed, false)]).await;
    let [PluginStep::Produced { tool_name, findings, signature, .. }] = steps.as_slice() else {
        panic!("produced, not {steps:?}");
    };
    assert_eq!((tool_name.as_deref(), *signature), (Some("eval-finder"), Some(Signature::Verified)));
    let findings = serde_json::to_value(findings).unwrap();
    assert_eq!(
        findings,
        json!([{"ruleId": "EVAL001", "severity": "HIGH", "file": "app/a.py", "line": null, "message": "eval"}])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn another_signer_and_no_signature_are_refused_and_never_run() {
    let impostor = manifest(
        "impostor",
        SIGNED,
        FINDER,
        Some(("https://github.com/someone/else/.github/workflows/release.yml@refs/heads/main", ISSUER)),
    );
    let unsigned = manifest("unsigned", plugins::OUTPUT_HOLDER, FINDER, Some((IDENTITY, ISSUER)));
    let undeclared = manifest("undeclared", SIGNED, FINDER, None);
    let steps =
        run(limits(), Settings::default(), vec![(impostor, false), (unsigned, false), (undeclared, false)]).await;
    for (step, expected) in
        steps.iter().zip([Refusal::SignatureUnverified, Refusal::SignatureUnverified, Refusal::Unsigned])
    {
        let PluginStep::Refused { refusal, reason, .. } = step else { panic!("refused, not {step:?}") };
        assert_eq!(*refusal, expected, "{reason}");
        if expected == Refusal::SignatureUnverified {
            assert!(reason.contains("cosign: "), "cosign's own words: {reason}");
        }
    }
    assert_eq!(steps.len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_writing_past_its_ceiling_is_refused_not_truncated() {
    // The ceiling is the executor's output ceiling: one MiB here. Two MiB written beside the report.
    let small = ScannerLimits { output_bytes: 1024 * 1024, ..limits() };
    let flood = "head -c 2097152 /dev/zero > {output}.pad; printf '{\"version\":\"2.1.0\",\"runs\":[]}' > {output}";
    // The report is written only if the sparse terabyte was: `fsize` must refuse it, or kill the plugin for it.
    let sparse = "truncate -s 1T {output}.sparse && printf '{\"version\":\"2.1.0\",\"runs\":[]}' > {output}";
    let steps = run(
        small,
        Settings::new(None, false).unwrap(),
        vec![(manifest("flood", SIGNED, flood, None), false), (manifest("sparse", SIGNED, sparse, None), false)],
    )
    .await;
    let reasons: Vec<&str> = steps
        .iter()
        .map(|step| match step {
            PluginStep::Absent { reason, .. } => reason.as_str(),
            other => panic!("absent, not {other:?}"),
        })
        .collect();
    assert!(reasons[0].starts_with("It filled its output directory — 1048576 bytes"), "{}", reasons[0]);
    assert!(
        reasons[1].starts_with("It was stopped for writing a file larger than 1048576 bytes")
            || reasons[1].starts_with("Scanner \"plugin sparse\" exited with 1."),
        "{}",
        reasons[1]
    );
}
