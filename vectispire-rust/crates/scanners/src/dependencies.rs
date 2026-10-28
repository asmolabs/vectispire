//! Dependency analysis, in two steps — `DependencyScanner`: the cataloguer (Syft) takes the
//! inventory, the matcher (Grype) matches it against known vulnerabilities.
//!
//! **Two tools and not one**, because the SBOM has value of its own: it is exportable, it answers
//! "what is in this application", and it lets the vulnerability analysis be replayed without walking
//! the code again.
//!
//! **Neither tool has the network.** The cataloguer reads dependency files and has nowhere to look;
//! the matcher reads the host's database, which [`crate::vulnerability_database`] fetches and
//! refreshes on its own and which is mounted read-only. A database absent or too old fails the step
//! rather than returning a reassuring result.
//!
//! **A finding here is fingerprint material.** Its identifier, package name and installed version are
//! what an issue is recognised by from one scan to the next; a field read one character differently
//! from the Java parser resolves every dependency issue of a target and recreates it, its triage lost.
//! [`findings`] is held to the Java side's answers by `reference/dependencies/`.

use crate::container_paths;
use crate::failure::ScannerError;
use crate::jackson;
use serde::Serialize;
use serde_json::Value;
use std::future::Future;
use std::path::{Path, PathBuf};
use vectispire_container::{ContainerResult, ContainerRun, ContainerRunner, Mount, RunnerError};

/// Where the vulnerability database is mounted in the matcher's container — `ContainerPaths.DATABASE_CACHE`,
/// which is the runner's `GRYPE_DB_CACHE_DIR` (a test reads the create request to keep the two equal).
pub const DATABASE_CACHE: &str = "/cache";

/// The SBOM's file name, at the root of what the matcher mounts.
pub const SBOM_FILENAME: &str = "sbom.json";

/// The exported image, at the workspace root: not material for the other steps, and an image scan has
/// no source tree anyway.
pub const IMAGE_ARCHIVE_FILENAME: &str = "image.tar";

/// The architecture audited by default. Explicit, because the daemon would otherwise return the host's:
/// an arm64 machine would audit the arm64 variant while production deploys linux/amd64.
pub const DEFAULT_PLATFORM: &str = "linux/amd64";

/// What the directory inventory's container is labelled.
pub const DIRECTORY_SBOM_LABEL: &str = "syft (directory SBOM)";

/// What the match of a workspace's SBOM is labelled.
pub const MATCH_LABEL: &str = "grype (SBOM analysis)";

/// What the match of an image's SBOM is labelled.
pub const STANDALONE_MATCH_LABEL: &str = "grype (image SBOM analysis)";

// ---------------------------------------------------------------------------------- the finding

pub use vectispire_domain::Severity;

/// A vulnerable component, reduced to what Vectispire keeps — the wire form the agent sends, field for
/// field and in this order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyFinding {
    pub identifier: String,
    /// Parsed into the enum rather than kept as text: the matcher says "High", and an unparsed "High"
    /// would match no policy threshold — the finding would be created and enter no gate.
    pub severity: Severity,
    pub package_name: String,
    pub installed_version: String,
    /// The versions that fix it, joined with `", "`; empty when none exists. **A string and not a list**:
    /// it doubles as the gate's "fixable" flag, where empty means "no published fix".
    pub fix_versions: String,
    pub description: Option<String>,
    pub reference_url: Option<String>,
    /// The universal package identifier: what lets two sources be cross-referenced.
    pub purl: Option<String>,
}

/// The findings of the matcher's report — `DependencyScanner.findings`.
///
/// **A report without its `matches` array is not a clean one** (decision 0007): `{}`, an array, a
/// scalar, `"matches": null` or an object each used to read as "analysed, no vulnerabilities", which
/// resolves the target's whole dependency backlog. Grype writes `"matches": []` when nothing matched
/// (measured on the pinned image), so a missing array, or a match that is not an object, fails the
/// step. Pinned by `reference/dependencies/findings/13…18`.
pub fn findings(payload: &Value) -> Result<Vec<DependencyFinding>, ScannerError> {
    let Some(Value::Array(matches)) = jackson::path(payload, "matches") else {
        return Err(ScannerError::of(GRYPE_LABEL, NO_MATCHES));
    };
    matches
        .iter()
        .map(|entry| {
            if entry.is_object() { Ok(finding(entry)) } else { Err(ScannerError::of(GRYPE_LABEL, MATCH_NOT_AN_OBJECT)) }
        })
        .collect()
}

/// What the step says when grype exited 0 with no `matches` array — `DependencyScanner.findings`' words.
pub const NO_MATCHES: &str = "grype exited 0, and its report carries no \"matches\" array; a report of another \
shape is not read as dependencies without vulnerabilities.";

/// What the step says when a match is not an object.
pub const MATCH_NOT_AN_OBJECT: &str = "grype's report holds a match that is not an object; the report is not read.";

/// What the step says when the cataloguer printed JSON that is not its catalogue — `catalogue`'s words.
pub const NOT_A_CATALOGUE: &str = "syft exited 0 and printed JSON that is not its catalogue (no \"artifacts\" \
array); it is not read as a tree without dependencies.";

/// The label the matcher's own failures carry — the Java side's `GRYPE`.
const GRYPE_LABEL: &str = "grype";

/// `Sbom.isCatalogue`: an object with an `artifacts` array, which Syft writes even when it found no
/// package (`"artifacts": []`, measured on the pinned image against an empty tree).
pub fn is_catalogue(document: &Value) -> bool {
    matches!(jackson::path(document, "artifacts"), Some(Value::Array(_)))
}

/// The cataloguer's output, believed only when it is a catalogue. JSON of another shape was handed on
/// as the scan's SBOM: the licence and end-of-life rules read it as an image with no package and
/// resolved both backlogs, and the matcher was given it to match.
fn catalogue(printed: Option<Value>, label: &str) -> Result<Option<Value>, ScannerError> {
    match printed {
        Some(document) if !is_catalogue(&document) => Err(ScannerError::of(label, NOT_A_CATALOGUE)),
        other => Ok(other),
    }
}

fn finding(entry: &Value) -> DependencyFinding {
    let vulnerability = jackson::path(entry, "vulnerability");
    let artifact = jackson::path(entry, "artifact");
    DependencyFinding {
        identifier: jackson::as_text(at(vulnerability, "id"), "unknown"),
        // `asText(null)`: a null or missing severity is no text at all, and so `UNKNOWN`.
        severity: Severity::of(text_or_none(at(vulnerability, "severity")).as_deref()),
        package_name: jackson::as_text(at(artifact, "name"), "unknown"),
        installed_version: jackson::as_text(at(artifact, "version"), ""),
        fix_versions: fix_versions(vulnerability),
        description: textual(at(vulnerability, "description")),
        reference_url: textual(at(vulnerability, "dataSource")),
        purl: textual(at(artifact, "purl")),
    }
}

/// `node.path(field)` on what may itself be missing: a missing node's member is missing.
fn at<'a>(node: Option<&'a Value>, field: &str) -> Option<&'a Value> {
    node.and_then(|node| jackson::path(node, field))
}

/// `asText(null)`: `None` for a null or missing node, a scalar's text, `""` for a container.
fn text_or_none(node: Option<&Value>) -> Option<String> {
    match node {
        None | Some(Value::Null) => None,
        other => Some(jackson::as_text(other, "")),
    }
}

/// The fixing versions, joined — `fixVersions`: each element's `asText()` (so a `null` element is the
/// text `"null"`, as on the Java side), blank ones dropped by `String.isBlank`, `""` when `fix.versions`
/// is not an array.
fn fix_versions(vulnerability: Option<&Value>) -> String {
    let Some(Value::Array(versions)) = at(at(vulnerability, "fix"), "versions") else {
        return String::new();
    };
    versions
        .iter()
        .map(|version| match version {
            // `NullNode.asText()` is "null": no default is passed here, unlike everywhere else.
            Value::Null => "null".to_owned(),
            other => jackson::as_text(Some(other), ""),
        })
        .filter(|version| !java_is_blank(version))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `text(node, field)`: the value when it is a string that is not blank, `None` otherwise — a number
/// where text was expected is no text here, unlike in [`jackson::as_text`].
fn textual(node: Option<&Value>) -> Option<String> {
    match node {
        Some(Value::String(text)) if !java_is_blank(text) => Some(text.clone()),
        _ => None,
    }
}

/// `String.isBlank`: empty or only `Character.isWhitespace` — a no-break space is not blank.
fn java_is_blank(text: &str) -> bool {
    text.chars().all(jackson::is_java_whitespace)
}

/// `ContainerRunner.parseJson`: the exit code checked, then the output stripped — empty, or not JSON, is
/// **absent** (`Ok(None)`): the tool did not produce what it was asked for.
pub fn parse_json(
    result: &ContainerResult,
    label: &str,
    accepted_exit_codes: &[i64],
) -> Result<Option<Value>, ScannerError> {
    if !accepted_exit_codes.contains(&result.exit_code) {
        return Err(ScannerError::exited(label, result.exit_code, &result.stderr));
    }
    let payload = result.stdout.trim_matches(jackson::is_java_whitespace);
    if payload.is_empty() {
        return Ok(None);
    }
    Ok(jackson::read_tree(payload))
}

/// What the matcher's standard output gives, read as the Java side reads it: absent when it is empty or
/// not JSON, a failure for a report of another shape, the findings otherwise — the composition
/// [`match_sbom`] applies, for the reference set.
pub fn read_match_output(stdout: &str) -> Result<Option<Vec<DependencyFinding>>, ScannerError> {
    let result = ContainerResult { stdout: stdout.to_owned(), stderr: String::new(), exit_code: 0 };
    parse_json(&result, MATCH_LABEL, &[0])?.map(|payload| findings(&payload)).transpose()
}

/// What the cataloguer's standard output gives — the SBOM the step keeps and sends, or absent.
pub fn read_sbom_output(stdout: &str) -> Option<Value> {
    let result = ContainerResult { stdout: stdout.to_owned(), stderr: String::new(), exit_code: 0 };
    parse_json(&result, DIRECTORY_SBOM_LABEL, &[0]).ok().flatten()
}

// --------------------------------------------------------------------------- what runs the tools

/// What runs a container — the agent's [`ContainerRunner`], or a test's fake, which is what lets the
/// requests and the database be checked without a daemon.
pub trait RunContainers: Send + Sync {
    fn run(&self, run: &ContainerRun) -> impl Future<Output = Result<ContainerResult, RunnerError>> + Send;
}

impl RunContainers for ContainerRunner {
    fn run(&self, run: &ContainerRun) -> impl Future<Output = Result<ContainerResult, RunnerError>> + Send {
        ContainerRunner::run(self, run)
    }
}

/// Pulls an image for one platform and writes it to an archive — `ContainerRunner.exportImage`.
///
/// **Vectispire pulls it, the container does not**: the cataloguer sees a file, and the socket is never
/// mounted into a scanner. Not implemented for [`ContainerRunner`] yet — it is a pull and a save
/// through the daemon, owned by the container crate's stream.
pub trait ExportImages: Send + Sync {
    fn export_image(
        &self,
        reference: &str,
        platform: &str,
        destination: &Path,
    ) -> impl Future<Output = Result<(), ScannerError>> + Send;
}

/// The generation of the vulnerability database a match mounts — [`crate::vulnerability_database`],
/// or a test's fixed directory.
pub trait MountableDatabase: Send + Sync {
    fn mountable(&self) -> impl Future<Output = Result<PathBuf, ScannerError>> + Send;
}

// ------------------------------------------------------------------------------------- the runs

/// The inventory of the workspace's tree, mounted read-only: the cataloguer has no reason to write
/// into the tree it analyses, and forbidding it removes the question.
pub fn directory_sbom_request(workspace_root: &Path, sub_path: Option<&str>, image: &str) -> ContainerRun {
    ContainerRun::new(
        image,
        vec![format!("dir:{}", container_paths::source(sub_path)), "-o".to_owned(), "json".to_owned()],
        vec![Mount::read_only(workspace_root.display().to_string(), container_paths::MOUNT)],
        DIRECTORY_SBOM_LABEL,
    )
    .running_as_owner_of(workspace_root)
}

/// What an image inventory's container is labelled.
pub fn image_sbom_label(reference: &str) -> String {
    format!("syft (SBOM of image {reference})")
}

/// The inventory of an exported image, at the workspace root. **Neither network nor socket**: the
/// image is already here as an archive.
pub fn image_sbom_request(workspace_root: &Path, reference: &str, image: &str) -> ContainerRun {
    ContainerRun::new(
        image,
        vec![
            format!("docker-archive:{}/{IMAGE_ARCHIVE_FILENAME}", container_paths::MOUNT),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        vec![Mount::read_only(workspace_root.display().to_string(), container_paths::MOUNT)],
        image_sbom_label(reference),
    )
    .running_as_owner_of(workspace_root)
}

/// The match of the SBOM staged in `mounted` against the database `generation`.
///
/// **No network, and nothing writable but the scratch space**: the matcher has nothing left to fetch
/// (`GRYPE_DB_AUTO_UPDATE=false`, set for every container), so the one scanner that ran online no
/// longer does. As the owner of `mounted` rather than root: it reads the 0700 workspace and the 0700
/// generation, both this process's.
pub fn match_request(mounted: &Path, generation: &Path, image: &str, label: &str) -> ContainerRun {
    ContainerRun::new(
        image,
        vec![format!("sbom:{}/{SBOM_FILENAME}", container_paths::MOUNT), "-o".to_owned(), "json".to_owned()],
        vec![
            Mount::read_only(mounted.display().to_string(), container_paths::MOUNT),
            Mount::read_only(generation.display().to_string(), DATABASE_CACHE),
        ],
        label,
    )
    .running_as_owner_of(mounted)
}

/// Takes the inventory of the workspace's tree — `sbomOfDirectory`. `Ok(None)` when the cataloguer
/// printed nothing usable.
pub async fn sbom_of_directory<R: RunContainers>(
    runner: &R,
    image: &str,
    workspace_root: &Path,
    sub_path: Option<&str>,
) -> Result<Option<Value>, ScannerError> {
    let result = runner.run(&directory_sbom_request(workspace_root, sub_path, image)).await?;
    catalogue(parse_json(&result, DIRECTORY_SBOM_LABEL, &[0])?, DIRECTORY_SBOM_LABEL)
}

/// Takes the inventory of a container image — `sbomOfImage`. The platform is applied at the pull, so
/// the archive carries only the variant asked for; the archive goes the moment the SBOM is read,
/// failure included — it routinely runs to hundreds of megabytes, and the matcher does not need it.
pub async fn sbom_of_image<R: RunContainers + ExportImages>(
    runner: &R,
    image: &str,
    workspace_root: &Path,
    reference: &str,
    platform: &str,
) -> Result<Option<Value>, ScannerError> {
    let archive = workspace_root.join(IMAGE_ARCHIVE_FILENAME);
    let outcome = async {
        runner.export_image(reference, platform, &archive).await?;
        let result = runner.run(&image_sbom_request(workspace_root, reference, image)).await?;
        let label = image_sbom_label(reference);
        catalogue(parse_json(&result, &label, &[0])?, &label)
    }
    .await;
    // The workspace removal would get it; this only shortens the window.
    let _ = std::fs::remove_file(&archive);
    outcome
}

/// Matches the workspace's SBOM — `matchSbom`. The SBOM goes through a file at the workspace root,
/// which is what the matcher expects and what leaves the artifact available for export.
///
/// **`Ok(None)` when the analysis did not happen**, never an empty list: an empty list means "analysed,
/// no vulnerabilities" and resolves the target's whole backlog.
pub async fn match_sbom<R: RunContainers, D: MountableDatabase>(
    runner: &R,
    database: &D,
    image: &str,
    workspace_root: &Path,
    sbom_json: &str,
) -> Result<Option<Vec<DependencyFinding>>, ScannerError> {
    write_sbom(workspace_root, sbom_json)?;
    run_match(runner, database, image, workspace_root, MATCH_LABEL).await
}

/// Matches an SBOM that comes from no cloned tree — an image's — `matchStandaloneSbom`: staged in a
/// directory of its own, removed in every case, failure included. An image SBOM weighs several
/// megabytes, and a scan failing hourly would otherwise fill the disk.
pub async fn match_standalone_sbom<R: RunContainers, D: MountableDatabase>(
    runner: &R,
    database: &D,
    image: &str,
    sbom_json: &str,
) -> Result<Option<Vec<DependencyFinding>>, ScannerError> {
    // 0700, as `Files.createTempDirectory` makes it on a POSIX system; removed when dropped.
    let directory = tempfile::Builder::new()
        .prefix("vectispire-sbom-")
        .tempdir()
        .map_err(|_| ScannerError::of("grype", "could not stage the SBOM for matching"))?;
    write_sbom(directory.path(), sbom_json)?;
    let outcome = run_match(runner, database, image, directory.path(), STANDALONE_MATCH_LABEL).await;
    drop(directory);
    outcome
}

async fn run_match<R: RunContainers, D: MountableDatabase>(
    runner: &R,
    database: &D,
    image: &str,
    mounted: &Path,
    label: &str,
) -> Result<Option<Vec<DependencyFinding>>, ScannerError> {
    // **The database is the host's, not the scan's**, resolved here before the container starts:
    // whatever is published afterwards, this scan reads what it mounted. None to be had fails the step.
    let generation = database.mountable().await?;
    let result = runner.run(&match_request(mounted, &generation, image, label)).await?;
    parse_json(&result, label, &[0])?.map(|payload| findings(&payload)).transpose()
}

fn write_sbom(directory: &Path, sbom_json: &str) -> Result<(), ScannerError> {
    std::fs::write(directory.join(SBOM_FILENAME), sbom_json).map_err(|error| {
        ScannerError::of(
            "grype",
            format!("The SBOM could not be staged for matching: {}", java_io_message(&error, directory)),
        )
    })
}

/// What a Java `IOException`'s message would say, as near as it can be told: the path for a missing
/// directory or a refused write, which is what the operator needs either way.
fn java_io_message(error: &std::io::Error, directory: &Path) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            directory.join(SBOM_FILENAME).display().to_string()
        }
        _ => error.to_string(),
    }
}

// ------------------------------------------------------------------------------ the step's result

/// The dependencies step of a tree or image scan, as `ScanRunner` composes it — the SBOM, then its
/// match: the `sbom` and `dependencies` of the scan's `ScanArtifacts`, which the agent's runner fills.
#[derive(Debug, Clone, PartialEq)]
pub struct DependenciesStep {
    pub sbom: Value,
    pub dependencies: Vec<DependencyFinding>,
}

/// Why the step has no result — the sentence `ScanArtifacts.failed("dependencies", …)` records.
#[derive(Debug, thiserror::Error)]
pub enum StepError {
    /// A tool printed nothing usable — `StepDidNotRun`, with `ScanRunner`'s reason.
    #[error("{0}")]
    DidNotRun(&'static str),
    #[error(transparent)]
    Failed(#[from] ScannerError),
}

/// `ScanRunner`'s reason when the tree's inventory is absent.
pub const TREE_SBOM_ABSENT: &str = "the inventory of the tree's dependencies could not be taken.";
/// `ScanRunner`'s reason when an image's inventory is absent.
pub const IMAGE_SBOM_ABSENT: &str = "the image could not be fetched, or its dependencies could not be inventoried.";
/// `ScanRunner`'s reason when the match is absent.
pub const MATCH_ABSENT: &str = "the inventory was taken but could not be matched against known vulnerabilities.";

/// The step over a cloned tree. The SBOM is kept even when the match fails, as `artifacts.sbom` is set
/// before the match runs: the second element is the SBOM taken, if any.
pub async fn tree_step<R: RunContainers, D: MountableDatabase>(
    runner: &R,
    database: &D,
    syft: &str,
    grype: &str,
    workspace_root: &Path,
    sub_path: Option<&str>,
) -> (Result<DependenciesStep, StepError>, Option<Value>) {
    let sbom = match sbom_of_directory(runner, syft, workspace_root, sub_path).await {
        Ok(Some(sbom)) => sbom,
        Ok(None) => return (Err(StepError::DidNotRun(TREE_SBOM_ABSENT)), None),
        Err(error) => return (Err(error.into()), None),
    };
    let matched = match_sbom(runner, database, grype, workspace_root, &sbom.to_string()).await;
    (complete(sbom.clone(), matched), Some(sbom))
}

/// The step over a container image.
pub async fn image_step<R: RunContainers + ExportImages, D: MountableDatabase>(
    runner: &R,
    database: &D,
    syft: &str,
    grype: &str,
    workspace_root: &Path,
    reference: &str,
    platform: &str,
) -> (Result<DependenciesStep, StepError>, Option<Value>) {
    let sbom = match sbom_of_image(runner, syft, workspace_root, reference, platform).await {
        Ok(Some(sbom)) => sbom,
        Ok(None) => return (Err(StepError::DidNotRun(IMAGE_SBOM_ABSENT)), None),
        Err(error) => return (Err(error.into()), None),
    };
    let matched = match_standalone_sbom(runner, database, grype, &sbom.to_string()).await;
    (complete(sbom.clone(), matched), Some(sbom))
}

fn complete(
    sbom: Value,
    matched: Result<Option<Vec<DependencyFinding>>, ScannerError>,
) -> Result<DependenciesStep, StepError> {
    match matched {
        Ok(Some(dependencies)) => Ok(DependenciesStep { sbom, dependencies }),
        Ok(None) => Err(StepError::DidNotRun(MATCH_ABSENT)),
        Err(error) => Err(error.into()),
    }
}
