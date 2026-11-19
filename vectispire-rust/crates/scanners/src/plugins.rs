//! Plugins: a third-party image, confined exactly like the scanners Vectispire ships — `PluginSteps`,
//! `PluginScanner`, `ImageSignatureVerifier` and `PluginProvider`.
//!
//! **Each plugin a task names ends in one of four states** (`PluginStep`): *produced* — its report read, possibly
//! empty, which resolves that plugin's open issues and only those; *not applicable* — none of its languages is in
//! the tree, nothing started; *absent* — it should have run and gave no usable report, a failure of the scan
//! (decision 0007); *refused* — the executor would not start it for want of a verified signer, a failure too, told
//! apart from absent because the fix is the image's provenance, not its code. "Unsigned" read as "crashed" is how a
//! requirement nobody can see gets switched off, so the two are never folded.
//!
//! **No exception to the closed shape.** The run goes through the same runner as Syft or Semgrep: no network, no
//! capability, a read-only root, the scanner limits. Only the analysed tree is mounted, read-only — not the
//! workspace, whose root holds the secrets report in the clear. One writable directory, a bounded tmpfs that
//! cannot hold more than a scanner may hand back. As the workspace's owner, never root, and never at all on a host
//! where that owner is root. The network only when the manifest asks, with the governor's justification.
//!
//! **A declared signer is verified before the image is pulled**, by the pinned cosign image run as a scanner
//! (network on, no file of the target, the public key alone when one is declared, the registry read with the
//! credentials the executor's pulls use). Anything but cosign's exit 0 is a refusal with cosign's own words. An
//! executor requiring a signer — the default — runs no plugin whose manifest declares none, unless the governor
//! waived the requirement for that plugin.
//!
//! Every decision, reason and container request here is held to the Java executor's by `reference/plugins/`.

use crate::failure::ScannerError;
use crate::jackson;
use crate::sarif::{self, Run, SarifFinding};
use serde_json::Value;
use std::collections::BTreeSet;
use std::future::Future;
use std::path::Path;
use std::time::Duration;
use vectispire_container::bounded_output::{BoundedOutput, CollectedOutput, OUTPUT_INODES, OutputFile};
use vectispire_container::{
    ContainerRun, ContainerRunner, ExtendedError, ExtendedResult, Extras, Mount, RegistryAccess, RegistryLogin,
};
use vectispire_domain::bounded_text::Refused;
use vectispire_domain::language::Language;
use vectispire_domain::plugin_image;
use vectispire_domain::plugin_manifest::{OUTPUT, PluginManifest, RawManifest, SOURCE};
use vectispire_domain::plugin_signature::{Form, PluginSignature};
use vectispire_protocol::{Findings, PluginRef, PluginStep, Refusal, Signature};

/// cosign v3.1.3, the version the release workflow signs Vectispire with, by the digest of its multi-architecture
/// index — `ImageSignatureVerifier.COSIGN`, the pin `scripts/release-image.sh` moves with it.
pub const COSIGN: &str =
    "ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8";

/// The holder of a plugin's output directory: busybox 1.37 by the digest of its index — `PluginScanner.OUTPUT_HOLDER`.
pub const OUTPUT_HOLDER: &str = "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e";

/// Where the declared public key is mounted, read-only, alone.
pub const KEY_MOUNT: &str = "/trust/cosign.pub";

/// A registry round trip and a trust root: minutes would be a hang, not a verification.
pub const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(120);

/// A process killed by `SIGXFSZ`: it wrote a file past its `fsize` limit.
pub const FILE_TOO_LARGE_EXIT: i64 = 128 + 25;

/// Where the workspace keeps what the plugin machinery needs — a signer's key — outside the tree.
pub const PLUGINS_SUBDIR: &str = "plugins";

// -------------------------------------------------------------------------------------------------------------
// The manifest, as the agent's mapper reads it.

/// The manifest the control plane answered, read as the Java agent's mapper reads it (`convertValue`, unknown
/// fields ignored, Jackson's scalar coercions) — `None` where that mapper throws.
pub fn manifest_of(value: &Value) -> Option<PluginManifest> {
    let Value::Object(fields) = value else { return None };
    let field = |name: &str| fields.get(name).filter(|value| !value.is_null());
    let raw = RawManifest {
        id: text(field("id"))?,
        name: text(field("name"))?,
        image: text(field("image"))?,
        languages: match field("languages") {
            None => None,
            Some(Value::Array(items)) => Some(items.iter().map(language).collect::<Option<BTreeSet<_>>>()?),
            Some(_) => return None,
        },
        arguments: match field("arguments") {
            None => None,
            Some(Value::Array(items)) => Some(items.iter().map(|item| text(Some(item))).collect::<Option<Vec<_>>>()?),
            Some(_) => return None,
        },
        output: text(field("output"))?,
        exit_codes: match field("exit_codes") {
            None => None,
            Some(Value::Array(items)) => {
                // A null element is a NullPointerException in the record's `TreeSet`.
                Some(items.iter().map(|item| integer(Some(item))?).collect::<Option<BTreeSet<_>>>()?)
            }
            Some(_) => return None,
        },
        network: boolean(field("network"))?,
        network_justification: text(field("network_justification"))?,
        timeout_seconds: integer(field("timeout_seconds"))?,
        signature: match field("signature") {
            None => None,
            Some(Value::Object(signature)) => {
                let part = |name: &str| text(signature.get(name).filter(|value| !value.is_null()));
                Some(PluginSignature::new(part("identity")?, part("issuer")?, part("public_key")?))
            }
            Some(_) => return None,
        },
        schema_version: text(field("schema_version"))?,
    };
    Some(PluginManifest::new(raw))
}

/// A `String` property: text as is, a number or a boolean as its text; `Some(None)` for absent, `None` (unreadable)
/// for a container.
fn text(value: Option<&Value>) -> Option<Option<String>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(text)) => Some(Some(text.clone())),
        Some(scalar @ (Value::Number(_) | Value::Bool(_))) => Some(Some(jackson::as_text(Some(scalar), ""))),
        Some(Value::Array(_) | Value::Object(_)) => None,
    }
}

/// An `Integer` property: an integral number within `int`, a floating one truncated, a text parsed once trimmed (a
/// blank one absent); anything else unreadable.
fn integer(value: Option<&Value>) -> Option<Option<i32>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(Value::Number(number)) => {
            if let Some(integer) = number.as_i64() {
                i32::try_from(integer).ok().map(Some)
            } else {
                let float = number.as_f64()?;
                (f64::from(i32::MIN)..=f64::from(i32::MAX))
                    .contains(&float)
                    .then(|| jackson::as_int(value, 0))
                    .map(Some)
            }
        }
        Some(Value::String(text)) => {
            let trimmed = vectispire_domain::java::trim(text);
            if trimmed.is_empty() {
                return Some(None);
            }
            vectispire_domain::java::read_int(trimmed).ok().map(Some)
        }
        Some(_) => None,
    }
}

/// A `boolean` property: `false` when absent or null, a number true unless zero, `"true"`/`"false"` in any of
/// Java's cases once trimmed (blank is false).
fn boolean(value: Option<&Value>) -> Option<bool> {
    match value {
        None | Some(Value::Null) => Some(false),
        Some(Value::Bool(flag)) => Some(*flag),
        Some(Value::Number(number)) => number.as_i64().map(|integer| integer != 0),
        Some(Value::String(text)) => match vectispire_domain::java::trim(text) {
            "true" | "True" | "TRUE" => Some(true),
            "false" | "False" | "FALSE" | "" => Some(false),
            _ => None,
        },
        Some(_) => None,
    }
}

/// `Language.fromJson`: a known wire name, as text or coerced to it; anything else unreadable.
fn language(value: &Value) -> Option<Language> {
    match text(Some(value))? {
        Some(name) => Language::from_wire_name(&name),
        None => None,
    }
}

/// `PluginScanner.Settings`: the mirror plugin images are pulled from, and whether a signer is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Checked and lowercased; `None` for blank.
    pub registry_mirror: Option<String>,
    /// **On by default** (decision 0017 §9.1): off is the executor operator's explicit choice.
    pub signature_required: bool,
}

impl Default for Settings {
    /// No mirror, and a signer required: the default an executor starts with.
    fn default() -> Settings {
        Settings { registry_mirror: None, signature_required: true }
    }
}

impl Settings {
    pub fn new(registry_mirror: Option<&str>, signature_required: bool) -> Result<Settings, Refused> {
        let registry_mirror = match registry_mirror {
            Some(mirror) if !vectispire_domain::java::is_blank(mirror) => Some(plugin_image::require_mirror(mirror)?),
            _ => None,
        };
        Ok(Settings { registry_mirror, signature_required })
    }

    /// From the Java agent's variables: `VECTISPIRE_PLUGIN_REGISTRY` (blank for none) and
    /// `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` (`true` unless it says `false`, as Spring binds a boolean).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Settings, String> {
        let required =
            match lookup("VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED").map(|value| value.trim().to_ascii_lowercase()) {
                None => true,
                Some(value) if value.is_empty() || value == "true" => true,
                Some(value) if value == "false" => false,
                Some(value) => {
                    return Err(format!("VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED is true or false, not \"{value}\"."));
                }
            };
        Settings::new(lookup("VECTISPIRE_PLUGIN_REGISTRY").as_deref(), required).map_err(|refused| refused.0)
    }

    fn relocate(&self, reference: &str) -> Result<String, Refused> {
        plugin_image::relocate(reference, self.registry_mirror.as_deref())
    }
}

// -------------------------------------------------------------------------------------------------------------
// The executor's half.

/// What a plugin run needs of its executor — the Docker runner here, the Kubernetes one when it comes
/// (`ContainerExecutor`'s plugin half).
pub trait PluginExecutor: Send + Sync {
    /// The ceiling on what a scanner may hand back: its standard output, and a plugin's report.
    fn output_bytes(&self) -> u64;

    /// One run, with its bounded output and its registry login, in the closed shape.
    fn run_with(
        &self,
        run: &ContainerRun,
        extras: &Extras,
    ) -> impl Future<Output = Result<ExtendedResult, ExtendedError>> + Send;

    /// The registry as the pulls key it, and whether credentials are held for it — never them.
    fn registry_access_for(&self, reference: &str) -> RegistryAccess;
}

impl PluginExecutor for ContainerRunner {
    fn output_bytes(&self) -> u64 {
        ContainerRunner::output_bytes(self)
    }

    fn run_with(
        &self,
        run: &ContainerRun,
        extras: &Extras,
    ) -> impl Future<Output = Result<ExtendedResult, ExtendedError>> + Send {
        ContainerRunner::run_with(self, run, extras)
    }

    fn registry_access_for(&self, reference: &str) -> RegistryAccess {
        ContainerRunner::registry_access_for(self, reference)
    }
}

/// Whichever executor the agent chose (decision 0045): Docker runs the plugin; one that does not run plugins yet
/// refuses it, and the step is absent with that sentence.
impl PluginExecutor for vectispire_container::Executor {
    fn output_bytes(&self) -> u64 {
        vectispire_container::Executor::output_bytes(self)
    }

    fn run_with(
        &self,
        run: &ContainerRun,
        extras: &Extras,
    ) -> impl Future<Output = Result<ExtendedResult, ExtendedError>> + Send {
        vectispire_container::Executor::run_with(self, run, extras)
    }

    fn registry_access_for(&self, reference: &str) -> RegistryAccess {
        vectispire_container::Executor::registry_access_for(self, reference)
    }
}

/// A borrowed executor runs the same way — the runner the scan already holds, lent to its plugins.
impl<E: PluginExecutor> PluginExecutor for &E {
    fn output_bytes(&self) -> u64 {
        (**self).output_bytes()
    }

    fn run_with(
        &self,
        run: &ContainerRun,
        extras: &Extras,
    ) -> impl Future<Output = Result<ExtendedResult, ExtendedError>> + Send {
        (**self).run_with(run, extras)
    }

    fn registry_access_for(&self, reference: &str) -> RegistryAccess {
        (**self).registry_access_for(reference)
    }
}

/// Why a plugin did not produce: refused — with why — or failed, with the reason an operator reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PluginFailure {
    /// `PluginRefusedException`: the executor would not start it.
    #[error("{message}")]
    Refused { refusal: Refusal, message: String },
    /// Any other failure of the step — `ScannerFailureException` and the rest.
    #[error("{0}")]
    Failed(String),
}

fn failed(message: impl Into<String>) -> PluginFailure {
    PluginFailure::Failed(message.into())
}

impl From<ScannerError> for PluginFailure {
    fn from(error: ScannerError) -> PluginFailure {
        PluginFailure::Failed(error.to_string())
    }
}

/// What a plugin reported — `PluginScanner.PluginReport`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginReport {
    /// The SARIF driver's name, for provenance.
    pub tool_name: String,
    pub tool_version: Option<String>,
    /// Possibly none — which resolves its issues.
    pub findings: Vec<SarifFinding>,
    /// What was established about the image's signer before it ran.
    pub signature: Option<Signature>,
}

/// `PluginScanner.findings`: the report as findings, or `None` when it says it analysed nothing. Every run must have
/// succeeded and computed results: one failed run among three would otherwise hand back the others' findings as
/// the complete list.
pub fn findings(runs: &[Run], label: &str) -> Result<Option<PluginReport>, ScannerError> {
    let Some(first) = runs.first() else { return Ok(None) };
    let mut all = Vec::new();
    for run in runs {
        if !run.successful {
            return Err(ScannerError::of(
                label,
                format!("The plugin's report says its run \"{}\" did not execute successfully.", run.tool_name),
            ));
        }
        let Some(results) = &run.results else { return Ok(None) };
        all.extend(results.iter().cloned());
    }
    Ok(Some(PluginReport {
        tool_name: first.tool_name.clone(),
        tool_version: first.tool_version.clone(),
        findings: all,
        signature: None,
    }))
}

/// Where a cosign stderr says the registry would not be read: the distribution specification's `UNAUTHORIZED` and
/// `DENIED`, or the status line go-containerregistry prints when the body carries none. Anything else stays
/// `signature_unverified` — refused all the same.
fn registry_refused(said: &str) -> bool {
    use std::sync::LazyLock;
    static PATTERN: LazyLock<Option<regex::Regex>> =
        LazyLock::new(|| regex::Regex::new(r"\b(?:UNAUTHORIZED|DENIED)\b|\b401 Unauthorized\b|\b403 Forbidden\b").ok());
    // A pattern that does not compile reads every refusal as "unverified": still refused, never run.
    PATTERN.as_ref().is_some_and(|pattern| pattern.is_match(said))
}

/// The first 2,000 UTF-16 units of a tool's words, as `substring(0, 2000)` keeps them.
fn first_units(text: &str, limit: usize) -> String {
    let mut units = 0usize;
    text.chars()
        .take_while(|c| {
            units = units.saturating_add(c.len_utf16());
            units <= limit
        })
        .collect()
}

/// `ImageSignatureVerifier.verify`: `cosign verify` of `reference` against `signature`, run as a scanner. `Ok` only
/// on cosign's exit 0.
pub async fn verify<E: PluginExecutor>(
    executor: &E,
    reference: &str,
    signature: &PluginSignature,
    key_directory: &Path,
    owner: &str,
    label: &str,
    cosign: &str,
) -> Result<(), PluginFailure> {
    let mut command = vec!["verify".to_owned()];
    let mut mounts = Vec::new();
    match (signature.form(), &signature.public_key) {
        (Form::Key, Some(key)) => {
            let file = key_directory.join("cosign.pub");
            write_key(key_directory, &file, key)
                .map_err(|error| failed(format!("The signer's key could not be handed to the verifier: {error}")))?;
            mounts.push(Mount::read_only(file.display().to_string(), KEY_MOUNT));
            command.push(format!("--key={KEY_MOUNT}"));
            // The key is the trust root; the log would only publish the internal image's name.
            command.push("--insecure-ignore-tlog=true".to_owned());
        }
        _ => {
            // `--flag=value`, one argv entry each: a value can never be read as another flag.
            command.push(format!("--certificate-identity={}", signature.identity.as_deref().unwrap_or_default()));
            command.push(format!("--certificate-oidc-issuer={}", signature.issuer.as_deref().unwrap_or_default()));
        }
    }
    command.push(reference.to_owned());

    let mut run = ContainerRun::new(cosign, command, mounts, format!("{label} signature"));
    run.network = true;
    run.user = Some(owner.to_owned());
    run.timeout = Some(VERIFICATION_TIMEOUT);
    let extras = Extras {
        output: None,
        login: Some(RegistryLogin { reference: reference.to_owned(), directory: key_directory.to_owned() }),
    };
    let result = match executor.run_with(&run, &extras).await {
        Ok(done) => done.result,
        Err(ExtendedError::Refused(message)) => return Err(failed(message)),
        Err(error) => {
            return Err(failed(format!("Its image's signature could not be checked, so it was not run: {error}")));
        }
    };
    if result.exit_code == 0 {
        return Ok(());
    }
    // A refusal, not a crash: cosign ran and did not vouch for the image.
    let said = vectispire_domain::java::strip(&result.stderr);
    let quoted = first_units(said, 2000);
    if registry_refused(said) {
        let access = executor.registry_access_for(reference);
        let opening = if access.credentials_held {
            format!("The registry {} refused the credentials this executor's pulls use for it", access.registry)
        } else {
            format!(
                "The registry {} requires authentication to be read, and this executor's Docker configuration holds no \
                 credentials for it",
                access.registry
            )
        };
        return Err(PluginFailure::Refused {
            refusal: Refusal::RegistryAuthenticationRequired,
            message: format!(
                "{opening}, so whether its image is signed could not be read and it was not run. cosign: {quoted}"
            ),
        });
    }
    Err(PluginFailure::Refused {
        refusal: Refusal::SignatureUnverified,
        message: format!(
            "Its image's signature was not verified against the signer its manifest declares, so it was not run. \
             cosign: {quoted}"
        ),
    })
}

/// The key as US-ASCII, as Java writes it (`?` for anything else), in a directory of the workspace.
fn write_key(directory: &Path, file: &Path, key: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(directory)?;
    let ascii: String = key.chars().map(|c| if c.is_ascii() { c } else { '?' }).collect();
    std::fs::write(file, ascii)
}

/// `PluginScanner`: runs one plugin over the analysed tree.
#[derive(Debug, Clone)]
pub struct PluginScanner<E> {
    executor: E,
    settings: Settings,
    /// How a directory's `uid:gid` is read — replaceable because the answer is whoever runs the build.
    owner_of: fn(&Path) -> Option<String>,
}

impl<E: PluginExecutor> PluginScanner<E> {
    pub fn new(executor: E, settings: Settings) -> PluginScanner<E> {
        PluginScanner { executor, settings, owner_of: vectispire_container::owner_of }
    }

    pub fn with_owners(executor: E, settings: Settings, owner_of: fn(&Path) -> Option<String>) -> PluginScanner<E> {
        PluginScanner { executor, settings, owner_of }
    }

    /// Whether this executor starts the plugin, and on what footing — before anything else, so an image it refuses
    /// is never fetched. A declared signer is verified whatever the settings or the waiver say.
    fn admit(&self, manifest: &PluginManifest, runs_unsigned: bool) -> Result<Signature, PluginFailure> {
        if manifest.signature.is_some() {
            return Ok(Signature::Verified);
        }
        if !self.settings.signature_required {
            return Ok(Signature::NotRequired);
        }
        if runs_unsigned {
            return Ok(Signature::Waived);
        }
        Err(PluginFailure::Refused {
            refusal: Refusal::Unsigned,
            message:
                "This executor runs only plugins whose image is signed (VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED), and \
                      this plugin's manifest declares no signer nor has the platform governor waived the requirement \
                      for it; it was not run. Declare who signs its image, or record a waiver with its justification \
                      on the plugin."
                    .to_owned(),
        })
    }

    /// `PluginScanner.scan`: `Ok(None)` when the plugin did not analyse — a report with no run, or a run that says
    /// it computed no results — never an empty list.
    ///
    /// `analysed_root`: the directory the scan is limited to, proven inside the clone and present.
    pub async fn scan(
        &self,
        workspace_root: &Path,
        analysed_root: &Path,
        manifest: &PluginManifest,
        runs_unsigned: bool,
    ) -> Result<Option<PluginReport>, PluginFailure> {
        let id = manifest.id.clone().unwrap_or_default();
        let label = format!("plugin {id}");
        let signature = self.admit(manifest, runs_unsigned)?;
        let owner = (self.owner_of)(workspace_root).ok_or_else(|| {
            failed(
                "This host reports no owner for the workspace, so the plugin cannot run as an unprivileged user; it is \
                 not run as root instead.",
            )
        })?;
        if owner.starts_with("0:") {
            return Err(failed(
                "Vectispire runs as root here, so the workspace is root's and the plugin would run as root; it is not \
                 run. Run Vectispire as an unprivileged user, as its images do (1000:1000).",
            ));
        }
        let refused = |refused: Refused| failed(refused.0);
        let image = self.settings.relocate(manifest.image.as_deref().unwrap_or_default()).map_err(refused)?;
        if let Some(declared) = &manifest.signature {
            // Before the run, hence before the pull: an image nobody verified is not even fetched.
            let keys = workspace_root.join(PLUGINS_SUBDIR).join(format!("{id}-signer"));
            let cosign = self.settings.relocate(COSIGN).map_err(refused)?;
            verify(&self.executor, &image, declared, &keys, &owner, &label, &cosign).await?;
        }

        let capacity = self.executor.output_bytes();
        let report_path = format!("{OUTPUT}/{}", manifest.output);
        let mut run = ContainerRun::new(
            image,
            manifest.command(SOURCE, &report_path),
            vec![Mount::read_only(analysed_root.display().to_string(), SOURCE)],
            label.clone(),
        );
        run.user = Some(owner);
        if manifest.network {
            // The governor's declared exception, justified in the manifest and in the audit log.
            run.network = true;
        }
        if let Some(seconds) = manifest.timeout_seconds {
            run.timeout = Some(Duration::from_secs(u64::try_from(seconds).unwrap_or(0)));
        }
        let holder = self.settings.relocate(OUTPUT_HOLDER).map_err(refused)?;
        let bounded = BoundedOutput::new(OUTPUT, capacity, holder, manifest.output.clone())
            .map_err(|invalid| failed(invalid.0))?;
        let extras = Extras { output: Some(bounded), login: None };

        let done = self.executor.run_with(&run, &extras).await.map_err(|error| failed(error.to_string()))?;
        let output = done.output.ok_or_else(|| failed("Its output directory was not read back."))?;
        read_report(manifest, &label, done.result.exit_code, &done.result.stderr, output, capacity)
            .map(|read| read.map(|report| PluginReport { signature: Some(signature), ..report }))
    }
}

/// What the run left, judged in Java's order: a full directory before the exit code — a plugin refused a write
/// usually exits on an error, and the directory being full is the explanation its own words would only hint at.
fn read_report(
    manifest: &PluginManifest,
    label: &str,
    exit_code: i64,
    stderr: &str,
    output: CollectedOutput,
    capacity: u64,
) -> Result<Option<PluginReport>, PluginFailure> {
    if output.full() {
        return Err(failed(format!(
            "It filled its output directory — {capacity} bytes, {OUTPUT_INODES} files — so a write was refused and its \
             report is not believed. {OUTPUT} holds the report and whatever the plugin writes beside it, never more than \
             a scanner may hand back."
        )));
    }
    let declared = |code: i64| i32::try_from(code).is_ok_and(|code| manifest.exit_codes.contains(&code));
    if exit_code == FILE_TOO_LARGE_EXIT && !declared(exit_code) {
        return Err(failed(format!(
            "It was stopped for writing a file larger than {capacity} bytes, the most any file of a plugin may weigh \
             (exit {FILE_TOO_LARGE_EXIT}, SIGXFSZ)."
        )));
    }
    if !declared(exit_code) {
        return Err(ScannerError::exited(label, exit_code, stderr).into());
    }
    let document = match output.file {
        OutputFile::Read(bytes) => bytes,
        OutputFile::Missing => {
            return Err(failed(format!(
                "The plugin exited without writing its report to {OUTPUT}/{}.",
                manifest.output
            )));
        }
        OutputFile::NotRegular => {
            return Err(failed("Its report is not a regular file; a link or a device is not read."));
        }
        OutputFile::TooLarge(_) => {
            return Err(failed(format!("Its report is larger than the {capacity} bytes a scanner may hand back.")));
        }
    };
    let runs = sarif::read(&document, capacity, &[SOURCE])
        .map_err(|refused| failed(format!("The plugin's report was refused: {}", refused.0)))?;
    Ok(findings(&runs, label)?)
}

// -------------------------------------------------------------------------------------------------------------
// The steps.

/// How an executor obtains the manifest a task names — `PluginProvider`. Whatever comes back is checked against the
/// reference by the steps, not by the provider: a provider that answers the wrong manifest fails the step.
pub trait PluginProvider: Send + Sync {
    /// The manifest as the control plane wrote it — `Value::Null` for none — or why it could not be obtained.
    fn manifest<'a>(&'a self, reference: &'a PluginRef) -> impl Future<Output = Result<Value, String>> + Send + 'a;
}

/// The census's verdict on a plugin's languages — `LanguageCensus.Census.applies`: an incomplete census runs every
/// plugin, since "not applicable" is a claim.
pub fn applies(found: &BTreeSet<Language>, complete: bool, declared: &BTreeSet<Language>) -> bool {
    !complete || declared.iter().any(|language| found.contains(language))
}

/// `PluginSteps.run`: the plugins a task names, each turned into one of its states.
///
/// Every manifest is fetched and checked against the task's digest before anything runs; the census decides
/// applicability (`applies`, the runner's census of the whole tree); each plugin's failure is its own.
///
/// `analysed_root`: the directory the scan is limited to; `None` or not a directory and every plugin is absent —
/// nothing was examined, which is not "no language".
pub async fn run_steps<E: PluginExecutor, P: PluginProvider>(
    scanner: &PluginScanner<E>,
    provider: &P,
    references: &[PluginRef],
    workspace_root: &Path,
    analysed_root: Option<&Path>,
    applies: impl Fn(&BTreeSet<Language>) -> bool,
) -> Vec<PluginStep> {
    let mut steps = Vec::with_capacity(references.len());
    let mut resolved: Vec<(&PluginRef, PluginManifest)> = Vec::with_capacity(references.len());
    for reference in references {
        match fetch(provider, reference).await {
            Ok(manifest) => resolved.push((reference, manifest)),
            Err(reason) => steps.push(absent(reference, reason)),
        }
    }
    if resolved.is_empty() {
        return steps;
    }
    let root = analysed_root.filter(|root| std::fs::symlink_metadata(root).is_ok_and(|metadata| metadata.is_dir()));
    let Some(root) = root else {
        for (reference, _) in &resolved {
            steps.push(absent(
                reference,
                "the directory this scan is limited to is absent from the checkout".to_owned(),
            ));
        }
        return steps;
    };
    for (reference, manifest) in resolved {
        if !applies(&manifest.languages) {
            steps.push(PluginStep::NotApplicable {
                plugin_id: reference.id.clone(),
                manifest_digest: reference.digest.clone(),
                languages: manifest.languages.iter().map(|language| language.wire_name().to_owned()).collect(),
            });
            continue;
        }
        let step = match scanner.scan(workspace_root, root, &manifest, reference.runs_unsigned).await {
            Ok(Some(report)) => match Findings::of(&report.findings) {
                Ok(findings) => PluginStep::Produced {
                    plugin_id: reference.id.clone(),
                    manifest_digest: reference.digest.clone(),
                    tool_name: Some(report.tool_name),
                    tool_version: report.tool_version,
                    findings,
                    signature: report.signature,
                },
                Err(error) => absent(reference, error.to_string()),
            },
            Ok(None) => {
                absent(reference, "the plugin's report says it computed no results, or carries no run".to_owned())
            }
            Err(PluginFailure::Refused { refusal, message }) => PluginStep::Refused {
                plugin_id: reference.id.clone(),
                manifest_digest: reference.digest.clone(),
                refusal,
                reason: message,
            },
            Err(PluginFailure::Failed(reason)) => absent(reference, reason),
        };
        steps.push(step);
    }
    steps
}

/// A manifest believed, or the reason it was not.
async fn fetch<P: PluginProvider>(provider: &P, reference: &PluginRef) -> Result<PluginManifest, String> {
    let answered =
        provider.manifest(reference).await.map_err(|why| format!("its definition could not be obtained: {why}"))?;
    if answered.is_null() {
        return Err("no definition was returned for it".to_owned());
    }
    // Java's mapper throws here, in the provider, with Jackson's words; this port's are its own.
    let manifest = manifest_of(&answered).ok_or_else(|| {
        "its definition could not be obtained: the manifest the control plane answered could not be read".to_owned()
    })?;
    if manifest.id.as_deref() != Some(reference.id.as_str()) || manifest.digest() != reference.digest {
        return Err(format!(
            "the definition received is not the one the task names (digest {}); it is not run",
            reference.digest
        ));
    }
    manifest.validated().map_err(|refused| format!("its definition could not be obtained: {}", refused.0))?;
    Ok(manifest)
}

fn absent(reference: &PluginRef, reason: String) -> PluginStep {
    PluginStep::Absent { plugin_id: reference.id.clone(), manifest_digest: reference.digest.clone(), reason }
}

/// The digest of a manifest the control plane answered — what `AgentClient::plugin` caches by.
pub fn digest_of(value: &Value) -> Option<String> {
    manifest_of(value).map(|manifest| manifest.digest())
}
