//! Which languages a checked-out tree is written in — `LanguageCensus`, enough to say whether a plugin applies.
//!
//! **The answer has a third value.** A plugin that reads Java has nothing to say about a Python repository, and
//! running it would return an empty result: "analysed, found nothing", which resolves its issues on the target
//! (decision 0007). Not running it is right, and it is reported as *not applicable* — and this census is what
//! decides it. So it must never under-report: a walk that hits its bounds says so ([`Census::complete`] false),
//! and the caller runs every plugin rather than trusting a partial count, and records no languages at all.
//!
//! **Bounded like every read of the tree in this process.** No file is opened: names only, through
//! [`Language::of_file_name`]. Links are not followed and not counted — a `src -> /` must not walk the host. The
//! walk stops at [`MAX_ENTRIES`] entries or at its deadline, and early once every language asked about is seen.
//! Pinned by `reference/workspace/`.

use std::collections::BTreeSet;
use std::fs::Metadata;
use std::path::Path;
use std::time::{Duration, Instant};

use vectispire_domain::java;
use vectispire_domain::language::Language;

use crate::walk::{self, Visit, Visitor};

/// More than any real repository's source files; less than a tree built to exhaust the walk.
pub const MAX_ENTRIES: u32 = 200_000;

pub const DEADLINE: Duration = Duration::from_secs(60);

/// A clone's own metadata, and the one dependency tree that routinely outnumbers the code — whose
/// `package.json` names JavaScript on its own.
const SKIPPED: [&str; 2] = [".git", "node_modules"];

/// What the census saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Census {
    /// The languages seen, as far as the walk went.
    pub found: BTreeSet<Language>,
    /// False when the walk stopped before the end of the tree — its bound, its deadline, an unreadable
    /// directory — so an absent language proves nothing.
    pub complete: bool,
}

impl Census {
    /// Whether a plugin declaring these languages should run. An incomplete census runs it: it cannot prove the
    /// plugin's languages absent, and "not applicable" is a claim.
    pub fn applies(&self, declared: &BTreeSet<Language>) -> bool {
        !self.complete || declared.iter().any(|language| self.found.contains(language))
    }

    /// What the scan records — `ScanRunner.census`: the wire names when the census is complete, and nothing when it
    /// is not. A walk stopped at its bound has not seen the rest of the tree, and a screen comparing the partial set
    /// with a plugin's languages would say a Java repository holds no Java; absent reads as unknown, the truth.
    pub fn recorded(&self) -> Option<BTreeSet<String>> {
        self.complete.then(|| self.found.iter().map(|language| language.wire_name().to_owned()).collect())
    }
}

/// The whole census, stopping early once every language in `wanted` has been seen.
pub fn of(root: &Path, wanted: &BTreeSet<Language>) -> Census {
    of_bounded(root, wanted, MAX_ENTRIES, DEADLINE, &mut Instant::now)
}

/// [`of`] with its bounds and its clock named — for the tests that reach them.
pub fn of_bounded(
    root: &Path,
    wanted: &BTreeSet<Language>,
    max_entries: u32,
    deadline: Duration,
    clock: &mut dyn FnMut() -> Instant,
) -> Census {
    let is_directory = std::fs::symlink_metadata(root).is_ok_and(|metadata| metadata.file_type().is_dir());
    if !is_directory {
        // Nothing to count is not "no language": the caller decides what a missing tree means, and it is not the
        // census's to turn into "not applicable".
        return Census { found: BTreeSet::new(), complete: false };
    }
    let give_up_at = clock().checked_add(deadline);
    let mut count =
        Count { root, wanted, max_entries, give_up_at, clock, entries: 0, found: BTreeSet::new(), complete: true };
    match walk::walk(root, &mut count) {
        Ok(()) => Census { found: count.found, complete: count.complete },
        // A listing that broke off: what it did not list is not seen.
        Err(Unwalkable) => Census { found: count.found, complete: false },
    }
}

struct Unwalkable;

struct Count<'a> {
    root: &'a Path,
    wanted: &'a BTreeSet<Language>,
    max_entries: u32,
    give_up_at: Option<Instant>,
    clock: &'a mut dyn FnMut() -> Instant,
    entries: u32,
    found: BTreeSet<Language>,
    complete: bool,
}

impl Count<'_> {
    /// Every directory and file counts, a skipped directory included; past the bound or the deadline the census
    /// is incomplete.
    fn budget(&mut self) -> Visit {
        self.entries = self.entries.saturating_add(1);
        let late = self.give_up_at.is_some_and(|give_up_at| (self.clock)() > give_up_at);
        if self.entries > self.max_entries || late {
            self.complete = false;
            return Visit::Terminate;
        }
        Visit::Continue
    }
}

impl Visitor for Count<'_> {
    type Error = Unwalkable;

    fn pre_visit_directory(&mut self, dir: &Path, _: &Metadata) -> Result<Visit, Unwalkable> {
        let spent = self.budget();
        if spent != Visit::Continue {
            return Ok(spent);
        }
        let name = dir.file_name().map(|name| java::to_lower_root(&name.to_string_lossy()));
        if dir != self.root && name.is_some_and(|name| SKIPPED.contains(&name.as_str())) {
            return Ok(Visit::SkipSubtree);
        }
        Ok(Visit::Continue)
    }

    fn visit_file(&mut self, file: &Path, metadata: &Metadata) -> Result<Visit, Unwalkable> {
        let spent = self.budget();
        if spent != Visit::Continue {
            return Ok(spent);
        }
        if metadata.file_type().is_file()
            && let Some(name) = file.file_name()
        {
            self.found.extend(Language::of_file_name(&name.to_string_lossy()));
        }
        if !self.wanted.is_empty() && self.wanted.is_subset(&self.found) {
            // Everything anybody asked about is here: the rest of the tree cannot change an answer.
            return Ok(Visit::Terminate);
        }
        Ok(Visit::Continue)
    }

    fn visit_file_failed(&mut self, _: &Path, _: std::io::Error) -> Result<Visit, Unwalkable> {
        // An unreadable directory hides what is under it: the count no longer proves an absence. The walk goes on
        // for whatever else it can see.
        self.complete = false;
        Ok(Visit::Continue)
    }

    fn post_visit_directory(&mut self, _: &Path, error: Option<std::io::Error>) -> Result<Visit, Unwalkable> {
        match error {
            Some(_) => Err(Unwalkable),
            None => Ok(Visit::Continue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn languages(names: &[&str]) -> BTreeSet<Language> {
        names.iter().filter_map(|name| Language::from_wire_name(name)).collect()
    }

    fn tree(files: &[&str]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for file in files {
            let path = root.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "").unwrap();
        }
        root
    }

    #[test]
    fn an_exhausted_walk_proves_nothing() {
        let root = tree(&["a.java", "b.py", "c/d.go", "c/e.rs"]);
        let census = of_bounded(root.path(), &BTreeSet::new(), 3, DEADLINE, &mut Instant::now);
        assert!(!census.complete);
        assert_eq!(census.recorded(), None, "an incomplete census records nothing");
        assert!(census.applies(&languages(&["ruby"])), "and runs every plugin");
        let whole = of_bounded(root.path(), &BTreeSet::new(), 6, DEADLINE, &mut Instant::now);
        assert!(whole.complete, "six entries: the root, three files, one directory and its file");
        assert!(!whole.applies(&languages(&["ruby"])));
        assert!(whole.applies(&languages(&["ruby", "go"])));
        let recorded = whole.recorded().unwrap();
        assert_eq!(recorded.into_iter().collect::<Vec<_>>(), ["go", "java", "python", "rust"]);
    }

    #[test]
    fn it_stops_once_everything_wanted_is_seen() {
        let root = tree(&["a.java", "b.java", "c.java", "d.java", "e.java"]);
        let wanted = languages(&["java"]);
        // Two entries — the root and the first file — and the rest of the tree can change nothing.
        assert!(of_bounded(root.path(), &wanted, 2, DEADLINE, &mut Instant::now).complete);
        assert!(!of_bounded(root.path(), &BTreeSet::new(), 2, DEADLINE, &mut Instant::now).complete);
    }

    #[test]
    fn the_deadline_stops_it() {
        let root = tree(&["a.java", "b.py"]);
        let start = Instant::now();
        let mut readings = 0u32;
        let mut clock = || {
            readings += 1;
            // The first reading sets the deadline; the third is past it.
            if readings >= 3 { start + Duration::from_secs(61) } else { start }
        };
        let census = of_bounded(root.path(), &BTreeSet::new(), MAX_ENTRIES, DEADLINE, &mut clock);
        assert!(!census.complete);
        // Reading the clock at the deadline itself is still in time.
        let mut at_the_deadline = {
            let mut first = true;
            move || {
                if std::mem::take(&mut first) { start } else { start + DEADLINE }
            }
        };
        assert!(of_bounded(root.path(), &BTreeSet::new(), MAX_ENTRIES, DEADLINE, &mut at_the_deadline).complete);
    }

    #[test]
    fn an_unreadable_directory_makes_it_incomplete() {
        use std::os::unix::fs::PermissionsExt;
        let root = tree(&["a.java", "closed/b.py"]);
        let closed = root.path().join("closed");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let census = of(root.path(), &BTreeSet::new());
        let readable = std::fs::read_dir(&closed).is_ok();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Running as root, the directory is still read: then the census saw everything, and says so.
        assert_eq!(census.complete, readable);
        assert_eq!(census.found.contains(&Language::from_wire_name("python").unwrap()), readable);
    }
}
