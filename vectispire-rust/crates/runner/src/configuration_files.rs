//! The scanners' own configuration files, taken out of the clone before any of them runs — Java's
//! `ScannerConfigurationFiles`, which the port had not carried over (Phase 2 security review, 2026-11).
//!
//! **The target does not configure its own audit.** checkov reads a `.checkov.yaml` or `.checkov.yml` from the
//! directory it is pointed at (skipped checks, and an external checks directory whose Python it runs), gitleaks a
//! `.gitleaksignore` from its source beside the configuration Vectispire forces, semgrep every `.semgrepignore` of the
//! tree despite `--no-git-ignore`. A silenced scanner exits 0 with a clean report, and a clean report is an empty
//! list, which resolves the target's backlog of that type and passes the gate (decision 0007): whoever can push to
//! the audited repository closed its findings. None of the three has a switch that turns the file off, so the files
//! leave Vectispire's own copy of the tree, which is made for this scan and deleted with it.
//!
//! **The whole clone, not the scanned directory**: semgrep reads the file at any depth, and a sub-path decides only
//! where the others look. **No link is followed, and a link is removed as a link**: one named `.semgrepignore` is as
//! much the target's configuration as a file, and following it could reach outside the clone. A directory bearing
//! one of the names goes too. A directory that cannot be read **fails the scan**: it may hold one of the files, and
//! a scanner that can read it would be configured by it.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

/// The names the pinned scanners read from the analysed tree.
pub const NAMES: [&str; 4] = [".checkov.yaml", ".checkov.yml", ".gitleaksignore", ".semgrepignore"];

fn is_configuration(name: &OsStr) -> bool {
    NAMES.iter().any(|candidate| OsStr::new(candidate) == name)
}

/// Removes every file, link or directory bearing one of [`NAMES`] under `clone`, and answers what it removed, relative
/// to the clone and sorted. An error when the tree cannot be walked or an entry cannot be removed.
pub fn remove_from(clone: &Path) -> io::Result<Vec<String>> {
    let mut removed = Vec::new();
    // A stack rather than recursion: a repository decides how deep its tree goes.
    let mut pending: Vec<PathBuf> = vec![clone.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            // `DirEntry::file_type` does not follow a link: a link to a directory is not a directory here.
            let kind = entry.file_type()?;
            let named = is_configuration(&entry.file_name());
            if kind.is_dir() && !kind.is_symlink() {
                if named {
                    // `remove_dir_all` removes the links inside as links, never what they point to.
                    std::fs::remove_dir_all(&path)?;
                } else {
                    pending.push(path);
                    continue;
                }
            } else if named {
                std::fs::remove_file(&path)?;
            } else {
                continue;
            }
            removed.push(path.strip_prefix(clone).unwrap_or(&path).to_string_lossy().into_owned());
        }
    }
    removed.sort();
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plant(root: &Path, names: &[&str]) {
        for name in names {
            let file = root.join(name);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, "planted\n").unwrap();
        }
    }

    /// `ScannerConfigurationFilesTest`'s three scanners at once: every name, at the root, in a sub-path and deeper.
    #[test]
    fn every_scanner_s_file_leaves_the_tree_at_any_depth_and_nothing_else_does() {
        let clone = tempfile::tempdir().unwrap();
        plant(
            clone.path(),
            &[
                "main.tf",
                ".checkov.yaml",
                "infra/.checkov.yaml",
                "infra/.checkov.yml",
                "infra/modules/.checkov.yml",
                ".gitleaksignore",
                "infra/.gitleaksignore",
                ".semgrepignore",
                "infra/.semgrepignore",
                "infra/modules/.semgrepignore",
                "infra/modules/main.tf",
            ],
        );
        let removed = remove_from(clone.path()).unwrap();
        assert_eq!(
            removed,
            [
                ".checkov.yaml",
                ".gitleaksignore",
                ".semgrepignore",
                "infra/.checkov.yaml",
                "infra/.checkov.yml",
                "infra/.gitleaksignore",
                "infra/.semgrepignore",
                "infra/modules/.checkov.yml",
                "infra/modules/.semgrepignore",
            ]
        );
        for name in NAMES {
            assert!(!clone.path().join(name).exists(), "{name}");
        }
        assert!(clone.path().join("main.tf").is_file(), "the tree's other files stay");
        assert!(clone.path().join("infra/modules/main.tf").is_file(), "at any depth");
    }

    /// A link is removed as a link — what it points to, outside the clone, stays — and never entered.
    #[test]
    fn a_link_is_removed_as_a_link_and_never_followed() {
        let clone = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        plant(outside.path(), &[".semgrepignore", "kept/.gitleaksignore"]);
        std::os::unix::fs::symlink(outside.path().join(".semgrepignore"), clone.path().join(".semgrepignore")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("kept"), clone.path().join("elsewhere")).unwrap();

        let removed = remove_from(clone.path()).unwrap();
        assert_eq!(removed, [".semgrepignore"]);
        assert!(clone.path().join(".semgrepignore").symlink_metadata().is_err(), "the link is gone");
        assert!(outside.path().join(".semgrepignore").is_file(), "its target is not");
        assert!(outside.path().join("kept/.gitleaksignore").is_file(), "a linked directory is not entered");
    }

    /// A directory bearing one of the names goes with what it holds: read as configuration it would fail the scanner.
    #[test]
    fn a_directory_bearing_a_name_goes_with_its_content() {
        let clone = tempfile::tempdir().unwrap();
        plant(clone.path(), &["a/.checkov.yaml/inner.yaml", "a/.checkov.yaml/deeper/x"]);
        assert_eq!(remove_from(clone.path()).unwrap(), ["a/.checkov.yaml"]);
        assert!(!clone.path().join("a/.checkov.yaml").exists());
        assert!(clone.path().join("a").is_dir());
    }

    /// A tree that cannot be walked is an error, never an empty answer.
    #[test]
    fn a_tree_that_cannot_be_walked_is_an_error() {
        let clone = tempfile::tempdir().unwrap();
        assert!(remove_from(&clone.path().join("absent")).is_err());
    }
}
