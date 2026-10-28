//! `ImageReference`: a container image as a registry, a name and a tag — validated where it is entered, because a
//! reference reaching a `docker pull` unchecked is whatever the operator's daemon will fetch.

use regex::Regex;
use std::sync::LazyLock;

// `\d` is written `[0-9]`: Java's is ASCII by default, the `regex` crate's is any Unicode digit.
#[allow(clippy::expect_used)] // Literal patterns: a typo fails every test, not a request.
static REGISTRY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$").expect("registry"));
#[allow(clippy::expect_used)]
static IMAGE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$").expect("image name"));
#[allow(clippy::expect_used)]
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$").expect("tag"));
#[allow(clippy::expect_used)]
static DIGEST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^sha256:[a-f0-9]{64}$").expect("digest"));

const DIGEST_PREFIX: &str = "sha256:";

/// A registry (absent for Docker Hub), an image name and a tag or a `sha256:` digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    pub registry: Option<String>,
    pub image_name: Option<String>,
    pub tag: Option<String>,
}

impl ImageReference {
    pub fn new(registry: Option<&str>, image_name: Option<&str>, tag: Option<&str>) -> ImageReference {
        ImageReference {
            registry: registry.map(str::to_owned),
            image_name: image_name.map(str::to_owned),
            tag: tag.map(str::to_owned),
        }
    }

    /// `validate`: `None` when the reference is usable, otherwise the sentence the form shows.
    pub fn validate(&self) -> Option<String> {
        if let Some(registry) = self.registry.as_deref().filter(|registry| !registry.is_empty())
            && !REGISTRY.is_match(registry)
        {
            return Some(format!(
                "Invalid registry \"{registry}\". Expected a host, optionally followed by \":port\"."
            ));
        }
        let Some(name) = self.image_name.as_deref().filter(|name| !name.is_empty()) else {
            return Some("The image name is required.".to_owned());
        };
        if !IMAGE_NAME.is_match(name) {
            // Upper case is refused by the registry itself: better said at entry than at the first scan.
            return Some(format!("Invalid image name \"{name}\". Lower case, digits, \". _ -\" and \"/\"."));
        }
        let Some(tag) = self.tag.as_deref().filter(|tag| !tag.is_empty()) else {
            return Some("The tag is required (\"latest\" if nothing else).".to_owned());
        };
        if !TAG.is_match(tag) && !DIGEST.is_match(tag) {
            return Some(format!("Invalid tag \"{tag}\". Expected a tag or a \"sha256:…\" digest."));
        }
        None
    }

    /// `format`: what `docker pull` is handed — a digest joined with `@`, a tag with `:`; joined wrongly, the
    /// registry refuses it at pull time, on the agent, far from here. Java throws on an absent tag; the routes
    /// never hold one, and `null` is written here as Java's string concatenation would.
    pub fn format(&self) -> String {
        let name = self.image_name.as_deref().unwrap_or("null");
        let base = match self.registry.as_deref().filter(|registry| !registry.is_empty()) {
            Some(registry) => format!("{registry}/{name}"),
            None => name.to_owned(),
        };
        let tag = self.tag.as_deref().unwrap_or("null");
        if tag.starts_with(DIGEST_PREFIX) { format!("{base}@{tag}") } else { format!("{base}:{tag}") }
    }

    /// `displayName`: `name:tag`, as every screen names an image — `null` written as Java's concatenation writes it.
    pub fn display_name(&self) -> String {
        format!("{}:{}", self.image_name.as_deref().unwrap_or("null"), self.tag.as_deref().unwrap_or("null"))
    }
}
