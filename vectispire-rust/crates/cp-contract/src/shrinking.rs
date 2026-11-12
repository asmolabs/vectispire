//! The lists that only shrink, **one file per module**: `reference/not-yet-ported/` (the routes not served yet) and
//! `golden/deferred/` (the recordings not replayed yet).
//!
//! A single file every module port edited was a merge conflict between any two ports running at once — the same
//! ceiling line lowered by both, neighbouring lines removed by both. So each list is a directory: `<module>.txt` for
//! what that module's port removes, `_<name>.txt` for what no module's port ends (the binary's composition, the
//! recorder's limits), and a `README.md` saying what the list is. Each file carries its own ceiling:
//!
//! ```text
//! # a comment
//! ceiling 3
//! GET /api/v1/teams
//! ```
//!
//! `ceiling N` appears once, and N is the number of entries in the file: above it the file grew, below it the
//! ceiling was not lowered in the commit that removed lines — each a failure, so the slack of a port cannot be spent
//! on another route. A file that lists nothing is deleted, not kept at `ceiling 0`. The totals are what the old single
//! files held; the per-file ceilings say which module owes them.
//!
//! The files are read from the source tree when a check runs, not embedded: the set of files is the set of modules
//! with something left, which a `include_str!` per file would have turned back into a list every port edits.

use std::path::{Path, PathBuf};

/// The workspace's `golden/deferred/`.
#[must_use]
pub fn deferred_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../golden/deferred")
}

/// This crate's `reference/not-yet-ported/`.
#[must_use]
pub fn not_yet_ported_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("reference/not-yet-ported")
}

/// One file of a list: what its name says (the module, or `_name`), as `<list>/<name>.txt` for a message, and its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListFile {
    /// The file's stem: a module, or `_` and what no module ends.
    pub name: String,
    /// `<directory>/<name>.txt`, for messages.
    pub label: String,
    pub text: String,
}

impl ListFile {
    /// A file given whole — a test's.
    #[must_use]
    pub fn new(list: &str, name: &str, text: &str) -> ListFile {
        ListFile { name: name.to_owned(), label: format!("{list}/{name}.txt"), text: text.to_owned() }
    }
}

/// Every `*.txt` of `dir`, by name. Anything else there (its `README.md`) is not a list. A directory that cannot be
/// read, or that holds no list at all, is an error: an empty set of files would read as "nothing left to port".
pub fn read_dir(dir: &Path) -> Result<Vec<ListFile>, String> {
    let list = dir.file_name().map_or_else(|| dir.display().to_string(), |name| name.to_string_lossy().into_owned());
    let entries = std::fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.map_err(|error| format!("{}: {error}", dir.display()))?.path();
        if path.extension().is_none_or(|extension| extension != "txt") {
            continue;
        }
        let Some(name) = path.file_stem().map(|stem| stem.to_string_lossy().into_owned()) else {
            continue;
        };
        let text = std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        files.push(ListFile { label: format!("{list}/{name}.txt"), name, text });
    }
    if files.is_empty() {
        return Err(format!("{}: no list file in it", dir.display()));
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(files)
}

/// A file's entries and ceiling, its comments and blank lines left out.
#[derive(Debug)]
pub struct Counted<'a> {
    /// Its `ceiling N`, or what is wrong with it.
    pub ceiling: Result<usize, String>,
    /// `(line number, trimmed text)` of every entry.
    pub lines: Vec<(usize, &'a str)>,
}

/// Splits a file into its ceiling and its entries.
#[must_use]
pub fn count(file: &ListFile) -> Counted<'_> {
    let mut ceilings: Vec<(usize, &str)> = Vec::new();
    let mut lines = Vec::new();
    for (index, line) in file.text.lines().enumerate() {
        let line = line.trim();
        let at = index.saturating_add(1);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.strip_prefix("ceiling ") {
            Some(value) => ceilings.push((at, value.trim())),
            None => lines.push((at, line)),
        }
    }
    let ceiling = match ceilings.as_slice() {
        [] => Err(format!("{}: no `ceiling N` line", file.label)),
        [(at, value)] => {
            value.parse::<usize>().map_err(|_| format!("{}:{at}: `ceiling {value}` is not a number", file.label))
        }
        [_, (at, _), ..] => Err(format!("{}:{at}: a second `ceiling` line", file.label)),
    };
    Counted { ceiling, lines }
}

/// The file against its own ceiling: the problem, if any, in a sentence.
#[must_use]
pub fn against_ceiling(label: &str, entries: usize, ceiling: usize) -> Option<String> {
    if entries == 0 {
        Some(format!("{label} lists nothing: delete the file"))
    } else if entries > ceiling {
        Some(format!("{label} holds {entries} lines, above its ceiling {ceiling}: the list only shrinks"))
    } else if entries < ceiling {
        Some(format!("{label} holds {entries} lines and its ceiling says {ceiling}: lower it to {entries}"))
    } else {
        None
    }
}
