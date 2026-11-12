//! What the deployment says about itself — `BrandingProperties`, `ExportProperties` and `ProductVersion`, from the
//! values the runtime read under their Java names (`vectispire-cp-runtime`'s `Settings`, which reads them raw: the
//! module owns what they mean, as the records' compact constructors did).

use crate::types::is_blank;

/// The brand name when none is configured, and the repository the footer links to.
pub const DEFAULT_BRAND_NAME: &str = "Vectispire";
pub const DEFAULT_REPOSITORY_URL: &str = "https://github.com/asmolabs/vectispire";

/// `BrandingProperties`: the name displayed in headers, reports and exported documents, and the upstream repository
/// URL in the footer — `gitlab_url` by the name the public branding response has always carried, GitHub since the
/// 2026-08-27 move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branding {
    pub name: String,
    pub gitlab_url: String,
}

impl Branding {
    /// Blank is the default and anything else is trimmed: a variable set to spaces must not put an empty brand on a
    /// signed document.
    pub fn configured(name: Option<&str>, gitlab_url: Option<&str>) -> Branding {
        Branding {
            name: or_default(name, DEFAULT_BRAND_NAME),
            gitlab_url: or_default(gitlab_url, DEFAULT_REPOSITORY_URL),
        }
    }
}

fn or_default(value: Option<&str>, default: &str) -> String {
    match value.filter(|value| !is_blank(value)) {
        Some(value) => java_trim(value).to_owned(),
        None => default.to_owned(),
    }
}

/// `ExportProperties.publicUrl`: where this deployment is reachable, for SARIF's information URI and a VEX
/// document's identifier — absent when blank, so no document names an empty origin.
pub fn public_url(configured: Option<&str>) -> Option<String> {
    configured.filter(|value| !is_blank(value)).map(str::to_owned)
}

/// `ProductVersion`: the version every document Vectispire produces states about itself, from one place —
/// `vectispire.exports.tool-version`, trimmed, for a vendor rebuild shipped under its own version, or else the
/// build's. Neither is `None`, and every format then leaves the field out rather than stating a guess: the literal
/// it replaced defaulted to `1.0.0`, a release that does not exist.
pub fn product_version(tool_version: Option<&str>, build_version: Option<&str>) -> Option<String> {
    match tool_version.filter(|value| !is_blank(value)) {
        Some(configured) => Some(java_trim(configured).to_owned()),
        None => build_version.map(str::to_owned),
    }
}

/// `String.trim`: every leading and trailing character up to U+0020.
fn java_trim(value: &str) -> &str {
    value.trim_matches(|c: char| c <= ' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blank_brand_is_the_default_and_a_set_one_is_trimmed() {
        assert_eq!(
            Branding::configured(None, Some(" \t")),
            Branding { name: "Vectispire".to_owned(), gitlab_url: "https://github.com/asmolabs/vectispire".to_owned() }
        );
        assert_eq!(
            Branding::configured(Some("  Acme Sec "), Some(" https://git.example/acme ")),
            Branding { name: "Acme Sec".to_owned(), gitlab_url: "https://git.example/acme".to_owned() }
        );
        // A no-break space is not blank to Java, and not trimmed either: it is the brand.
        assert_eq!(Branding::configured(Some("\u{a0}"), None).name, "\u{a0}");
    }

    #[test]
    fn the_version_is_the_configured_one_or_the_build_s_or_none() {
        assert_eq!(product_version(Some(" 2.0.0-acme "), Some("0.12.0")), Some("2.0.0-acme".to_owned()));
        assert_eq!(product_version(Some("  "), Some("0.12.0")), Some("0.12.0".to_owned()));
        assert_eq!(product_version(None, Some("0.12.0")), Some("0.12.0".to_owned()));
        assert_eq!(product_version(None, None), None);
    }

    #[test]
    fn a_blank_public_url_is_none() {
        assert_eq!(public_url(Some("  ")), None);
        assert_eq!(public_url(Some("https://vs.example")), Some("https://vs.example".to_owned()));
        assert_eq!(public_url(None), None);
    }
}
