//! The two tools as `DependencyScannerTest` checks them, with the runner replaced by a fake that
//! records what it was asked and answers what a test needs: the requests, the absent cases, and what
//! is left on disk afterwards.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use vectispire_container::{ContainerResult, ContainerRun, RunnerError, ScannerLimits, create_body};
use vectispire_scanners::dependencies::{
    self, DependencyFinding, ExportImages, MountableDatabase, RunContainers, Severity, StepError,
};
use vectispire_scanners::failure::ScannerError;
use vectispire_scanners::images;

const GENERATION: &str = "/var/cache/vectispire-vulnerability-db/generations/1790000000000-0a1b2c3d";

type Answer = Box<dyn Fn(&ContainerRun) -> Result<ContainerResult, RunnerError> + Send + Sync>;

struct Fake {
    answer: Answer,
    runs: Mutex<Vec<ContainerRun>>,
    exported: Mutex<Vec<(String, String, PathBuf)>>,
}

impl Fake {
    fn answering(
        answer: impl Fn(&ContainerRun) -> Result<ContainerResult, RunnerError> + Send + Sync + 'static,
    ) -> Fake {
        Fake { answer: Box::new(answer), runs: Mutex::default(), exported: Mutex::default() }
    }

    fn printing(stdout: &str, stderr: &str, exit_code: i64) -> Fake {
        let result = ContainerResult { stdout: stdout.to_owned(), stderr: stderr.to_owned(), exit_code };
        Fake::answering(move |_| Ok(result.clone()))
    }

    fn runs(&self) -> Vec<ContainerRun> {
        self.runs.lock().unwrap().clone()
    }
}

impl RunContainers for Fake {
    async fn run(&self, run: &ContainerRun) -> Result<ContainerResult, RunnerError> {
        self.runs.lock().unwrap().push(run.clone());
        (self.answer)(run)
    }
}

impl ExportImages for Fake {
    async fn export_image(&self, reference: &str, platform: &str, destination: &Path) -> Result<(), ScannerError> {
        std::fs::write(destination, "an image several hundred megabytes long").unwrap();
        self.exported.lock().unwrap().push((reference.to_owned(), platform.to_owned(), destination.to_path_buf()));
        Ok(())
    }
}

struct Database(Result<PathBuf, String>);

impl MountableDatabase for Database {
    async fn mountable(&self) -> Result<PathBuf, ScannerError> {
        self.0.clone().map_err(|message| ScannerError::of("grype", message))
    }
}

fn database() -> Database {
    Database(Ok(PathBuf::from(GENERATION)))
}

fn workspace() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("vs-rs-deps-").tempdir().unwrap()
}

// ----------------------------------------------------------------------- reading the matcher's report

#[test]
fn a_match_becomes_a_finding_with_the_severity_in_vectispire_s_vocabulary_and_the_fixes_joined() {
    let findings = dependencies::findings(&json!({"matches": [{
        "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "fix": {"versions": ["4.17.22", "", "5.0.1"]},
            "description": "Prototype pollution", "dataSource": "https://nvd.example/CVE-2026-0001"},
        "artifact": {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
    }]}))
    .unwrap();
    assert_eq!(
        findings,
        vec![DependencyFinding {
            identifier: "CVE-2026-0001".into(),
            // "High" read literally would match no threshold, and the finding would enter no gate.
            severity: Severity::High,
            package_name: "lodash".into(),
            installed_version: "4.17.21".into(),
            fix_versions: "4.17.22, 5.0.1".into(),
            description: Some("Prototype pollution".into()),
            reference_url: Some("https://nvd.example/CVE-2026-0001".into()),
            purl: Some("pkg:npm/lodash@4.17.21".into()),
        }]
    );
}

#[test]
fn no_published_fix_is_an_empty_string_the_value_the_gate_reads_as_not_fixable() {
    let finding =
        dependencies::findings(&json!({"matches": [{"vulnerability": {"id": "CVE-1", "fix": {"state": "not-fixed"}},
        "artifact": {"name": "openssl"}}]}))
        .unwrap()
        .remove(0);
    assert_eq!(finding.fix_versions, "");
    assert_eq!(finding.severity, Severity::Unknown);
    assert_eq!(finding.installed_version, "");
    assert_eq!(finding.description, None);
    assert_eq!(finding.purl, None);
}

#[test]
fn a_report_with_no_matches_is_a_clean_analysis() {
    assert_eq!(dependencies::findings(&json!({"matches": []})).unwrap(), Vec::new());
}

/// Decision 0007: a document that is not a matcher's report fails the step — it never reads "no
/// vulnerabilities", which would resolve the target's whole dependency backlog.
#[test]
fn a_document_without_matches_fails_the_step() {
    for document in
        [json!({}), json!({"descriptor": {}}), json!({"matches": null}), json!({"matches": {}}), json!([]), json!(42)]
    {
        let error = dependencies::findings(&document).expect_err(&document.to_string());
        assert_eq!(error.to_string(), dependencies::NO_MATCHES, "{document}");
    }
    let error = dependencies::findings(&json!({"matches": [1]})).expect_err("a match that is not an object");
    assert_eq!(error.to_string(), dependencies::MATCH_NOT_AN_OBJECT);
}

#[test]
fn every_reference_document_without_matches_fails_end_to_end() {
    for name in
        ["13-no-matches-key", "14-matches-null", "15-matches-object", "16-top-level-array", "17-top-level-scalar"]
    {
        let printed = vectispire_testkit::read(&format!("dependencies/matches/{name}.json"));
        let error = dependencies::read_match_output(&printed).expect_err(name);
        assert_eq!(error.to_string(), dependencies::NO_MATCHES, "{name}");
    }
}

#[test]
fn a_cataloguer_output_that_is_no_catalogue_is_refused() {
    for document in [json!([]), json!("text"), json!({"source": {}}), json!({"artifacts": null})] {
        assert!(!dependencies::is_catalogue(&document), "{document}");
    }
    assert!(dependencies::is_catalogue(&json!({"artifacts": []})));
}

// ------------------------------------------------------------------------------ running the two tools

#[tokio::test]
async fn both_tools_run_offline_on_read_only_mounts_the_matcher_reading_the_host_s_database() {
    // One document both tools accept: the cataloguer's `artifacts`, the matcher's `matches`.
    let runner = Fake::printing(r#"{"artifacts": [], "matches": []}"#, "", 0);
    let workspace = workspace();

    let sbom =
        dependencies::sbom_of_directory(&runner, images::SYFT, workspace.path(), Some("services/api/")).await.unwrap();
    assert_eq!(sbom, Some(json!({"artifacts": [], "matches": []})));
    dependencies::match_sbom(&runner, &database(), images::GRYPE, workspace.path(), "{}").await.unwrap();

    let runs = runner.runs();
    let owner =
        vectispire_container::ContainerRun::new("x", vec![], vec![], "x").running_as_owner_of(workspace.path()).user;
    let [syft, grype] = runs.as_slice() else { panic!("two runs: {runs:?}") };
    assert_eq!(syft.image, images::SYFT);
    assert_eq!(syft.command, ["dir:/repo/source/services/api", "-o", "json"]);
    assert!(!syft.network);
    assert!(syft.mounts.iter().all(|mount| mount.read_only));
    assert_eq!(syft.user, owner);

    assert_eq!(grype.image, images::GRYPE);
    assert_eq!(grype.command, ["sbom:/repo/sbom.json", "-o", "json"]);
    // It downloaded its database at every scan, which is what it had the network for; it is the host's now.
    assert!(!grype.network);
    // As the workspace's owner, not root: it reads the 0700 workspace and the 0700 generation.
    assert!(!grype.as_root);
    assert_eq!(grype.user, owner);
    assert!(grype.mounts.iter().all(|mount| mount.read_only), "nothing writable: {:?}", grype.mounts);
    let database_mount: Vec<_> =
        grype.mounts.iter().filter(|mount| mount.target == dependencies::DATABASE_CACHE).collect();
    assert_eq!(database_mount.len(), 1);
    assert_eq!(database_mount[0].source, GENERATION);
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("sbom.json")).unwrap(),
        "{}",
        "the SBOM is left for export"
    );
}

#[tokio::test]
async fn the_database_is_mounted_where_the_runner_tells_the_matcher_to_look() {
    let workspace = workspace();
    let request =
        dependencies::match_request(workspace.path(), Path::new(GENERATION), images::GRYPE, dependencies::MATCH_LABEL);
    let body = create_body(&request, &ScannerLimits::default_for_this_host());
    let env = body.env.unwrap();
    assert!(env.contains(&format!("GRYPE_DB_CACHE_DIR={}", dependencies::DATABASE_CACHE)), "{env:?}");
    assert!(env.contains(&"GRYPE_DB_AUTO_UPDATE=false".to_owned()), "{env:?}");
    let host = body.host_config.unwrap();
    let binds = host.binds.unwrap();
    assert!(binds.contains(&format!("{GENERATION}:{}:ro", dependencies::DATABASE_CACHE)), "{binds:?}");
    assert_eq!(host.network_mode.as_deref(), Some("none"), "the matcher runs offline");
}

#[tokio::test]
async fn no_database_to_be_had_fails_the_step_and_the_matcher_is_not_even_started() {
    let runner = Fake::printing("", "", 0);
    let error = dependencies::match_standalone_sbom(
        &runner,
        &Database(Err("no network to fetch it".into())),
        images::GRYPE,
        "{}",
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "no network to fetch it");
    assert!(runner.runs().is_empty());
}

#[tokio::test]
async fn a_matcher_that_prints_nothing_usable_did_not_analyse_absent_not_an_empty_list() {
    let runner = Fake::printing("database does not exist", "", 0);
    assert_eq!(dependencies::match_standalone_sbom(&runner, &database(), images::GRYPE, "{}").await.unwrap(), None);
    let runner = Fake::printing("  \n", "", 0);
    assert_eq!(dependencies::match_standalone_sbom(&runner, &database(), images::GRYPE, "{}").await.unwrap(), None);
}

#[tokio::test]
async fn a_matcher_that_fails_is_reported_not_read_as_a_clean_analysis() {
    let runner = Fake::printing("", "no space left on device", 1);
    let error = dependencies::match_standalone_sbom(&runner, &database(), images::GRYPE, "{}").await.unwrap_err();
    assert_eq!(error.to_string(), "Scanner \"grype (image SBOM analysis)\" exited with 1. no space left on device");
}

#[tokio::test]
async fn a_standalone_sbom_is_staged_in_a_directory_that_is_gone_afterwards_failure_included() {
    let staged = std::sync::Arc::new(Mutex::new(Vec::<PathBuf>::new()));
    let seen = std::sync::Arc::clone(&staged);
    let runner = Fake::answering(move |run| {
        let mounted = PathBuf::from(&run.mounts[0].source);
        assert_eq!(std::fs::read_to_string(mounted.join("sbom.json")).unwrap(), r#"{"artifacts": []}"#);
        assert!(mounted.file_name().unwrap().to_string_lossy().starts_with("vectispire-sbom-"));
        seen.lock().unwrap().push(mounted);
        Ok(ContainerResult { stdout: String::new(), stderr: "boom".into(), exit_code: 2 })
    });

    let error = dependencies::match_standalone_sbom(&runner, &database(), images::GRYPE, r#"{"artifacts": []}"#).await;

    assert!(matches!(error, Err(ScannerError::Exited { code: 2, .. })), "{error:?}");
    let staged = staged.lock().unwrap();
    assert_eq!(staged.len(), 1);
    assert!(!staged[0].exists(), "{} is gone", staged[0].display());
}

#[tokio::test]
async fn an_exported_image_is_deleted_as_soon_as_its_sbom_is_read_even_when_the_read_fails() {
    let runner = Fake::printing("", "unexpected EOF", 1);
    let workspace = workspace();

    let error = dependencies::sbom_of_image(
        &runner,
        images::SYFT,
        workspace.path(),
        "registry.example.invalid/shop:1.4.2",
        dependencies::DEFAULT_PLATFORM,
    )
    .await;

    assert!(matches!(error, Err(ScannerError::Exited { .. })), "{error:?}");
    let exported = runner.exported.lock().unwrap().clone();
    assert_eq!(
        exported,
        [(
            "registry.example.invalid/shop:1.4.2".to_owned(),
            "linux/amd64".to_owned(),
            workspace.path().join("image.tar")
        )]
    );
    assert!(!workspace.path().join("image.tar").exists());
    let runs = runner.runs();
    assert_eq!(runs[0].command, ["docker-archive:/repo/image.tar", "-o", "json"]);
    assert_eq!(runs[0].label, "syft (SBOM of image registry.example.invalid/shop:1.4.2)");
    assert!(!runs[0].network && runs[0].mounts.iter().all(|mount| mount.read_only));
}

// ----------------------------------------------------------------------------------- the step

#[tokio::test]
async fn the_step_says_which_tool_produced_nothing_and_keeps_the_sbom_it_took() {
    let workspace = workspace();
    let no_sbom = Fake::printing("", "", 0);
    let (result, sbom) =
        dependencies::tree_step(&no_sbom, &database(), images::SYFT, images::GRYPE, workspace.path(), None).await;
    assert!(matches!(result, Err(StepError::DidNotRun(reason)) if reason == dependencies::TREE_SBOM_ABSENT));
    assert_eq!(sbom, None);

    let no_match = Fake::answering(|run| {
        let stdout = if run.image == images::SYFT { r#"{"artifacts": [{"name": "a"}]}"# } else { "not json" };
        Ok(ContainerResult { stdout: stdout.into(), stderr: String::new(), exit_code: 0 })
    });
    let (result, sbom) =
        dependencies::tree_step(&no_match, &database(), images::SYFT, images::GRYPE, workspace.path(), None).await;
    assert!(matches!(result, Err(StepError::DidNotRun(reason)) if reason == dependencies::MATCH_ABSENT));
    assert_eq!(
        sbom,
        Some(json!({"artifacts": [{"name": "a"}]})),
        "the SBOM is kept: artifacts.sbom is set before the match"
    );

    let both = Fake::answering(|run| {
        let stdout = if run.image == images::SYFT { r#"{"artifacts": []}"# } else { r#"{"matches": []}"# };
        Ok(ContainerResult { stdout: stdout.into(), stderr: String::new(), exit_code: 0 })
    });
    let (result, _) =
        dependencies::tree_step(&both, &database(), images::SYFT, images::GRYPE, workspace.path(), None).await;
    let step = result.unwrap();
    assert_eq!(step.dependencies, Vec::new(), "analysed, and clean");
    assert_eq!(std::fs::read_to_string(workspace.path().join("sbom.json")).unwrap(), r#"{"artifacts":[]}"#);
}

#[test]
fn severities_read_as_severity_of_reads_them() {
    for (label, severity) in [
        (Some("High"), Severity::High),
        (Some(" CRITICAL "), Severity::Critical),
        (Some("negligible\t"), Severity::Negligible),
        (Some("neg"), Severity::Unknown),
        (Some("\u{a0}low"), Severity::Unknown),
        (None, Severity::Unknown),
    ] {
        assert_eq!(Severity::of(label), severity, "{label:?}");
    }
}
