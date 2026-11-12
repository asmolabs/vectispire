//! Reading a package's Rust files.

use std::path::{Path, PathBuf};

use crate::facts::{self, Facts};

#[derive(Debug)]
pub struct SourceFile {
    pub path: PathBuf,
    /// Relative to the package directory, with forward slashes: `src/web/routes.rs`.
    pub rel: String,
    pub facts: Facts,
}

/// Every `.rs` file under `dir`'s `roots` (relative directories or files), parsed. A file that does not parse is
/// an error, not a silent skip: a rule that cannot read a file has not checked it.
pub fn read_package(dir: &Path, roots: &[&str]) -> (Vec<SourceFile>, Vec<String>) {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for root in roots {
        let mut pending = vec![dir.join(root)];
        if !pending[0].exists() {
            continue;
        }
        while let Some(path) = pending.pop() {
            if path.is_dir() {
                match std::fs::read_dir(&path) {
                    Ok(entries) => {
                        let mut children: Vec<PathBuf> =
                            entries.filter_map(|entry| entry.ok().map(|e| e.path())).collect();
                        children.sort();
                        pending.extend(children.into_iter().rev());
                    }
                    Err(error) => errors.push(format!("{}: {error}", path.display())),
                }
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let rel = path.strip_prefix(dir).unwrap_or(&path).to_string_lossy().replace('\\', "/");
                match std::fs::read_to_string(&path)
                    .map_err(|error| error.to_string())
                    .and_then(|text| facts::read(&text))
                {
                    Ok(facts) => files.push(SourceFile { path: path.clone(), rel, facts }),
                    Err(error) => errors.push(format!("{rel}: {error}")),
                }
            }
        }
    }
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    (files, errors)
}

/// The text of every `.rs` file under `roots`, for the rules that look for a word and not for a path.
pub fn read_text(dir: &Path, roots: &[&str]) -> Vec<(String, String)> {
    let mut texts = Vec::new();
    for root in roots {
        let mut pending = vec![dir.join(root)];
        while let Some(path) = pending.pop() {
            if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&path) {
                    pending.extend(entries.filter_map(|entry| entry.ok().map(|e| e.path())));
                }
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                texts.push((path.strip_prefix(dir).unwrap_or(&path).to_string_lossy().replace('\\', "/"), text));
            }
        }
    }
    texts.sort();
    texts
}
