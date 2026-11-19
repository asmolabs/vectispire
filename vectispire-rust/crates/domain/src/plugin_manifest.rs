//! What a plugin manifest's rules say of a value another module names a plugin by.

use crate::bounded_text::Refused;
use crate::java;

/// `ManifestRules.MAX_ID`.
pub const MAX_ID: usize = 40;

/// `PluginManifest.requireId`: lowercase letters, digits and inner hyphens, 2 to [`MAX_ID`] characters — the id
/// enters every issue's fingerprint and is never renamed.
pub fn require_id(id: Option<&str>) -> Result<&str, Refused> {
    let id = id.unwrap_or("");
    let length = java::utf16_len(id);
    if !(2..=MAX_ID).contains(&length) {
        return Err(Refused(format!("A plugin id is 2 to {MAX_ID} characters.")));
    }
    let last = id.chars().count().saturating_sub(1);
    for (index, c) in id.chars().enumerate() {
        let alphanumeric = c.is_ascii_lowercase() || c.is_ascii_digit();
        let edge = index == 0 || index == last;
        if !alphanumeric && (edge || c != '-') {
            return Err(Refused(
                "A plugin id is lowercase letters, digits and inner hyphens: it enters every issue's fingerprint and is \
                 never renamed."
                    .to_owned(),
            ));
        }
    }
    Ok(id)
}

// -------------------------------------------------------------------------------------------------------------
// The manifest — `PluginManifest`.

use crate::fingerprint::sha256_fields;
use crate::language::Language;
use crate::plugin_signature::PluginSignature;
use std::collections::BTreeSet;

/// The newest format this build reads — `PluginManifest.SCHEMA_VERSION`.
pub const SCHEMA_VERSION: &str = "1.0";
/// What a manifest stating no version is read as — pinned, not [`SCHEMA_VERSION`].
pub const UNVERSIONED: &str = "1.0";
const SCHEMA_MAJOR: u32 = 1;
/// Where the analysed tree is mounted, read-only.
pub const SOURCE: &str = "/repo/source";
/// The one writable directory, empty at start.
pub const OUTPUT: &str = "/repo/output";
pub const SOURCE_PLACEHOLDER: &str = "{source}";
pub const OUTPUT_PLACEHOLDER: &str = "{output}";
pub const DEFAULT_OUTPUT: &str = "results.sarif";
/// The scanner limits' timeout: a plugin may ask for less, never for more.
pub const MAX_TIMEOUT_SECONDS: i32 = 900;
const MIN_TIMEOUT_SECONDS: i32 = 10;
/// `ManifestRules.MAX_NAME`.
pub const MAX_NAME: usize = 100;
/// `ManifestRules.MAX_ARGUMENTS`.
pub const MAX_ARGUMENTS: usize = 32;
/// `ManifestRules.MAX_ARGUMENT`.
pub const MAX_ARGUMENT: usize = 4_096;
const MAX_EXIT_CODES: usize = 8;
const MIN_JUSTIFICATION: usize = 20;
const MAX_JUSTIFICATION: usize = 500;

/// The fields as they were read, before the record's constructor normalises them.
#[derive(Debug, Clone, Default)]
pub struct RawManifest {
    pub id: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub languages: Option<BTreeSet<Language>>,
    /// An element may be absent (`null` in the JSON): refused by [`PluginManifest::validated`], as Java refuses it.
    pub arguments: Option<Vec<Option<String>>>,
    pub output: Option<String>,
    pub exit_codes: Option<BTreeSet<i32>>,
    pub network: bool,
    pub network_justification: Option<String>,
    pub timeout_seconds: Option<i32>,
    pub signature: Option<PluginSignature>,
    pub schema_version: Option<String>,
}

/// What a plugin is: an image pinned by digest, the languages it reads, how it is called, and what it is allowed
/// beyond the closed shape every scanner runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManifest {
    pub id: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    /// In the enum's order, as an `EnumSet`.
    pub languages: BTreeSet<Language>,
    pub arguments: Vec<Option<String>>,
    pub output: String,
    pub exit_codes: BTreeSet<i32>,
    pub network: bool,
    pub network_justification: Option<String>,
    pub timeout_seconds: Option<i32>,
    pub signature: Option<PluginSignature>,
    pub schema_version: String,
}

fn stripped(value: Option<String>) -> Option<String> {
    value.map(|value| crate::java::strip(&value).to_owned())
}

fn has_control(value: &str) -> bool {
    value.chars().any(crate::java::is_iso_control)
}

/// `MAJOR.MINOR`, each `0` or up to four digits without a leading zero — `PluginManifest.VERSION`.
fn version(text: &str) -> Option<(u32, u32)> {
    let (major, minor) = text.split_once('.')?;
    let part = |part: &str| -> Option<u32> {
        let well_formed = !part.is_empty()
            && part.len() <= 4
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'));
        well_formed.then(|| part.parse().ok()).flatten()
    };
    Some((part(major)?, part(minor)?))
}

impl PluginManifest {
    /// The canonical constructor: absent collections empty, absent exit codes `[0]`, a blank output the default,
    /// an absent version [`UNVERSIONED`], text stripped.
    pub fn new(raw: RawManifest) -> PluginManifest {
        let blank = |value: &Option<String>| value.as_deref().is_none_or(crate::java::is_blank);
        PluginManifest {
            output: if blank(&raw.output) {
                DEFAULT_OUTPUT.to_owned()
            } else {
                stripped(raw.output).unwrap_or_default()
            },
            network_justification: if blank(&raw.network_justification) {
                None
            } else {
                stripped(raw.network_justification)
            },
            schema_version: if blank(&raw.schema_version) {
                UNVERSIONED.to_owned()
            } else {
                stripped(raw.schema_version).unwrap_or_default()
            },
            id: stripped(raw.id),
            name: stripped(raw.name),
            image: stripped(raw.image),
            languages: raw.languages.unwrap_or_default(),
            arguments: raw.arguments.unwrap_or_default(),
            exit_codes: raw.exit_codes.filter(|codes| !codes.is_empty()).unwrap_or_else(|| BTreeSet::from([0])),
            network: raw.network,
            timeout_seconds: raw.timeout_seconds,
            signature: raw.signature,
        }
    }

    /// `validated`: this manifest, or a refusal naming the first thing wrong with it — meant for the governor.
    pub fn validated(&self) -> Result<&PluginManifest, Refused> {
        // First: under another major the fields below may not mean what they are checked for.
        let (major, _) = self.parsed_version()?;
        if major != SCHEMA_MAJOR {
            return Err(Refused(format!(
                "The manifest is schema_version {}; this Vectispire reads major {SCHEMA_MAJOR} only, and a manifest \
                 of another major may mean something else by the same field.",
                self.schema_version
            )));
        }
        require_id(self.id.as_deref())?;
        require_text(self.name.as_deref(), MAX_NAME, "The plugin's name")?;
        crate::plugin_image::parse(self.image.as_deref())?;
        if self.languages.is_empty() {
            let names: Vec<&str> = Language::all().map(Language::wire_name).collect();
            return Err(Refused(format!(
                "A plugin declares the languages it reads, from [{}]: it runs only on a repository where one of them \
                 is present.",
                names.join(", ")
            )));
        }
        require_arguments(&self.arguments)?;
        require_output_name(&self.output, OUTPUT)?;
        if self.exit_codes.len() > MAX_EXIT_CODES {
            return Err(Refused(format!("A plugin declares at most {MAX_EXIT_CODES} exit codes.")));
        }
        if self.exit_codes.iter().any(|code| !(0..=255).contains(code)) {
            return Err(Refused("An exit code is between 0 and 255.".to_owned()));
        }
        if self.network {
            let justified = self.network_justification.as_deref().is_some_and(|text| {
                let length = crate::java::utf16_len(text);
                (MIN_JUSTIFICATION..=MAX_JUSTIFICATION).contains(&length) && !has_control(text)
            });
            if !justified {
                return Err(Refused(format!(
                    "A plugin that needs the network says why, in {MIN_JUSTIFICATION} to {MAX_JUSTIFICATION} \
                     characters: every plugin runs with the network cut, and an exception is a decision somebody has \
                     to be able to read."
                )));
            }
        } else if self.network_justification.is_some() {
            return Err(Refused("A justification is given for a network the plugin does not ask for.".to_owned()));
        }
        if self.timeout_seconds.is_some_and(|seconds| !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&seconds)) {
            return Err(Refused(format!(
                "The timeout is between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS} seconds: a plugin may ask for \
                 less time than a scanner, never more."
            )));
        }
        if let Some(signature) = &self.signature {
            signature.validated()?;
        }
        Ok(self)
    }

    fn parsed_version(&self) -> Result<(u32, u32), Refused> {
        version(&self.schema_version).ok_or_else(|| {
            Refused(format!(
                "A manifest's schema_version is MAJOR.MINOR, such as {SCHEMA_VERSION}, or absent for {UNVERSIONED}."
            ))
        })
    }

    /// `digest`: every field in a fixed order — sets sorted by value, lists joined by a separator no field may
    /// contain — the signer only when there is one and the version only outside major 1, so a manifest without
    /// them hashes as it did before those fields existed.
    pub fn digest(&self) -> String {
        let mut languages: Vec<&str> = self.languages.iter().map(|language| language.wire_name()).collect();
        languages.sort_unstable();
        let arguments: Vec<&str> = self.arguments.iter().map(|argument| argument.as_deref().unwrap_or("null")).collect();
        let exit_codes: Vec<String> = self.exit_codes.iter().map(i32::to_string).collect();
        let timeout = self.timeout_seconds.map(|seconds| seconds.to_string()).unwrap_or_default();
        let mut fields: Vec<Option<String>> = vec![
            Some("vectispire-plugin-manifest/1".to_owned()),
            self.id.clone(),
            self.name.clone(),
            self.image.clone(),
            Some(languages.join(",")),
            Some(arguments.join("\u{1f}")),
            Some(self.output.clone()),
            Some(exit_codes.join(",")),
            Some(if self.network { "network" } else { "no-network" }.to_owned()),
            self.network_justification.clone(),
            Some(timeout),
        ];
        if let Some(signature) = &self.signature {
            fields.extend(signature.digest_fields().into_iter().map(Some));
        }
        if version(&self.schema_version).is_none_or(|(major, _)| major != SCHEMA_MAJOR) {
            fields.push(Some(format!("schema_version {}", self.schema_version)));
        }
        let borrowed: Vec<Option<&str>> = fields.iter().map(Option::as_deref).collect();
        sha256_fields(&borrowed)
    }

    /// The arguments with the two placeholders replaced by the paths the container sees. Only called on a
    /// validated manifest, whose arguments are all present.
    pub fn command(&self, source: &str, output: &str) -> Vec<String> {
        self.arguments
            .iter()
            .map(|argument| {
                argument.as_deref().unwrap_or("null").replace(SOURCE_PLACEHOLDER, source).replace(OUTPUT_PLACEHOLDER, output)
            })
            .collect()
    }
}

/// `ManifestRules.requireText`: required, bounded, free of control characters.
fn require_text(value: Option<&str>, max: usize, what: &str) -> Result<(), Refused> {
    let value = value.filter(|value| !value.is_empty()).ok_or_else(|| Refused(format!("{what} is required.")))?;
    if crate::java::utf16_len(value) > max || has_control(value) {
        return Err(Refused(format!("{what} is at most {max} characters, with no control character.")));
    }
    Ok(())
}

/// `ManifestRules.requireArguments`: each one argv entry, no shell on this side; a newline or a tab is an ordinary
/// character of one, every other control character refused — the digest's separator among them.
fn require_arguments(arguments: &[Option<String>]) -> Result<(), Refused> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(Refused(format!("A plugin takes at most {MAX_ARGUMENTS} arguments.")));
    }
    let refused = |argument: &Option<String>| match argument {
        None => true,
        Some(argument) => {
            crate::java::utf16_len(argument) > MAX_ARGUMENT
                || argument.chars().any(|c| c != '\n' && c != '\t' && crate::java::is_iso_control(c))
        }
    };
    if arguments.iter().any(refused) {
        return Err(Refused(format!(
            "Each argument is a string of at most {MAX_ARGUMENT} characters with no control character but a newline \
             or a tab."
        )));
    }
    Ok(())
}

/// `ManifestRules.requireOutputName`: a bare file name in `directory`, read back as a regular file.
fn require_output_name(output: &str, directory: &str) -> Result<(), Refused> {
    if crate::java::utf16_len(output) > MAX_NAME || output.starts_with('.') {
        return Err(Refused(format!(
            "The output is a file name of at most {MAX_NAME} characters, not starting with a dot."
        )));
    }
    if !output.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
        return Err(Refused(format!(
            "The output is a file name in {directory} — letters, digits, dots, hyphens and underscores, no directory."
        )));
    }
    Ok(())
}
