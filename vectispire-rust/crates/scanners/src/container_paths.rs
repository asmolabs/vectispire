//! Paths as the scanner containers see them — `ContainerPaths`.
//!
//! Built as POSIX strings: the target is a path inside a Linux container whatever machine launched
//! the scan.

/// Where the workspace root is mounted in every scanner container.
pub const MOUNT: &str = "/repo";

/// The workspace's subdirectory the clone goes into — `Workspace.SOURCE_SUBDIR`.
pub const SOURCE_SUBDIR: &str = "source";

/// The workspace's subdirectory Vectispire's rules are copied into — `Workspace.RULES_SUBDIR`.
pub const RULES_SUBDIR: &str = "rules";

/// The scanned tree, or a subdirectory of it.
pub fn source(sub_path: Option<&str>) -> String {
    let base = format!("{MOUNT}/{SOURCE_SUBDIR}");
    match sub_path {
        Some(sub) if !sub.trim().is_empty() => format!("{base}/{}", sub.trim_start_matches('/').trim_end_matches('/')),
        _ => base,
    }
}

/// A file in the rule tree Vectispire copied into the workspace.
pub fn rules(segments: &[&str]) -> String {
    format!("{MOUNT}/{RULES_SUBDIR}/{}", segments.join("/"))
}

/// A container path turned back into one relative to the scanned tree.
///
/// **Exactly as the Java side does it, quirks included**: the prefix is matched as a string, so
/// `/repo/sourcefoo/a` becomes `foo/a`, and only leading slashes are removed — `a//b` stays. Either
/// "fix" would change the path of an existing finding, hence its fingerprint.
pub fn relative_to_source(container_path: &str, sub_path: Option<&str>) -> String {
    let prefix = source(sub_path);
    let relative = container_path.strip_prefix(prefix.as_str()).unwrap_or(container_path);
    relative.trim_start_matches('/').to_owned()
}
