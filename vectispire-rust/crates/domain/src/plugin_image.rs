//! A plugin's image, pinned by its content — `ImageDigest`: `repository@sha256:<64 hex>` and nothing else.
//!
//! **No tag, not even beside the digest**: the tag would read as the version on every screen while saying nothing
//! true about it. **Relocated, never replaced**: a mirror swaps the registry host and keeps the path and the
//! digest, so it can serve the image and cannot substitute another. Held to `reference/plugins/images/`.

use crate::bounded_text::Refused;

const SHA256: &str = "sha256:";

/// A parsed reference: the registry host (if any) and path, and the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDigest {
    pub repository: String,
    pub digest: String,
}

fn refused(message: impl Into<String>) -> Refused {
    Refused(message.into())
}

/// `ImageDigest.parse`.
pub fn parse(reference: Option<&str>) -> Result<ImageDigest, Refused> {
    let reference = match reference {
        Some(reference) if !crate::java::is_blank(reference) => reference,
        _ => return Err(refused("A plugin's image is required, pinned by digest: repository@sha256:….")),
    };
    let (repository, digest) = match reference.split_once('@') {
        Some((repository, digest)) if !repository.is_empty() && !digest.contains('@') => (repository, digest),
        _ => {
            return Err(refused(format!(
                "A plugin's image is pinned by digest — repository@sha256:… — never by a tag, which moves: \
                 \"{reference}\"."
            )));
        }
    };
    let hex = digest.strip_prefix(SHA256).filter(|hex| hex.len() == 64 && hex.bytes().all(is_lowercase_hex));
    if hex.is_none() {
        return Err(refused("The image digest is sha256: and 64 lowercase hexadecimal digits."));
    }
    if crate::java::utf16_len(repository) > 255 {
        return Err(refused("The image repository is at most 255 characters."));
    }
    let last_segment = repository.rsplit('/').next().unwrap_or(repository);
    if last_segment.contains(':') {
        return Err(refused("The image names a tag beside its digest; the digest alone says what runs."));
    }
    if !repository.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-/:".contains(&b)) {
        return Err(refused("The image repository is lowercase letters, digits and . - _ / : only."));
    }
    if repository.starts_with('/') || repository.ends_with('/') || repository.contains("//") {
        return Err(refused("The image repository has an empty path segment."));
    }
    Ok(ImageDigest { repository: repository.to_owned(), digest: digest.to_owned() })
}

fn is_lowercase_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// `ImageDigest.relocate`: the same image pulled from `mirror`, or `reference` unchanged when there is no mirror.
/// The reference is checked either way.
///
/// The first path segment is a registry host when it holds a dot or a colon or is `localhost`, as Docker reads it;
/// otherwise the image is Docker Hub's, and a single-segment name is Hub's `library/`.
pub fn relocate(reference: &str, mirror: Option<&str>) -> Result<String, Refused> {
    let image = parse(Some(reference))?;
    let mirror = match mirror {
        Some(mirror) if !crate::java::is_blank(mirror) => mirror,
        _ => return Ok(reference.to_owned()),
    };
    let host = require_mirror(mirror)?;
    let path = match image.repository.split_once('/') {
        Some((first, rest)) if !first.is_empty() => {
            if first.contains('.') || first.contains(':') || first == "localhost" {
                rest.to_owned()
            } else {
                image.repository.clone()
            }
        }
        // A leading slash is refused by `parse`; what is left has no slash at all.
        _ => format!("library/{}", image.repository),
    };
    Ok(format!("{host}/{path}@{}", image.digest))
}

/// `ImageDigest.requireMirror`: a registry host, a port and a path prefix at most — no scheme, no credential —
/// lowercased, trailing slashes dropped.
pub fn require_mirror(mirror: &str) -> Result<String, Refused> {
    let trimmed = crate::java::strip(mirror).trim_end_matches('/');
    if trimmed.is_empty() || trimmed.contains("://") || trimmed.contains('@') || trimmed.starts_with('/') {
        return Err(refused(
            "The plugin registry mirror is a host, optionally with a port and a path \
             (registry.example.internal:5000/mirror) — no scheme and no credential.",
        ));
    }
    if !trimmed.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-/:".contains(&b)) {
        return Err(refused("The plugin registry mirror carries a character a registry host cannot."));
    }
    Ok(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn a_mirror_swaps_the_host_and_keeps_the_path_and_digest() {
        let at = |reference: &str| format!("{reference}@{D}");
        assert_eq!(relocate(&at("lint"), Some("m.internal")).unwrap(), format!("m.internal/library/lint@{D}"));
        assert_eq!(relocate(&at("acme/lint"), Some("m.internal")).unwrap(), format!("m.internal/acme/lint@{D}"));
        assert_eq!(relocate(&at("r.io/acme/lint"), Some("M.internal/")).unwrap(), format!("m.internal/acme/lint@{D}"));
        assert_eq!(relocate(&at("localhost/lint"), Some("m")).unwrap(), format!("m/lint@{D}"));
        assert_eq!(relocate(&at("acme/lint"), None).unwrap(), at("acme/lint"));
        assert!(relocate("acme/lint:1", None).is_err(), "checked without a mirror too");
    }
}
