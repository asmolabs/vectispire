//! `Files.walkFileTree(root, visitor)` without `FOLLOW_LINKS`, for the readers of the tree that run in process.
//!
//! **The same events in the same order**, because the census and the API discovery decide on them: an entry is
//! looked at through its own metadata (`lstat`: a link is a file, never what it points at); a directory is opened
//! before anything is said about it, so one that cannot be opened is a *failed visit* and never a directory to
//! enter or skip; its entries come in the order the directory lists them, each subtree walked as soon as it is
//! met; and a listing that breaks off ends its directory with the error. What the visitor answers — go on, skip
//! the subtree, stop — is applied as the JDK's walker applies it.
//!
//! **Iterative**, where a recursion would put one frame per level of a tree the repository's author chose; what
//! a deep tree costs is one open directory per level, as on the Java side.

use std::fs::{Metadata, ReadDir};
use std::path::{Path, PathBuf};

/// `FileVisitResult`, less the one the readers never answer (`SKIP_SIBLINGS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visit {
    Continue,
    SkipSubtree,
    Terminate,
}

/// `FileVisitor`.
pub trait Visitor {
    type Error;

    fn pre_visit_directory(&mut self, dir: &Path, metadata: &Metadata) -> Result<Visit, Self::Error>;

    fn visit_file(&mut self, file: &Path, metadata: &Metadata) -> Result<Visit, Self::Error>;

    /// An entry whose metadata could not be read, or a directory that could not be opened.
    fn visit_file_failed(&mut self, file: &Path, error: std::io::Error) -> Result<Visit, Self::Error>;

    /// `SimpleFileVisitor`'s rethrows a listing's error; each reader decides what it does with it.
    fn post_visit_directory(&mut self, dir: &Path, error: Option<std::io::Error>) -> Result<Visit, Self::Error>;
}

enum Entry {
    Failed(std::io::Error),
    File(Metadata),
    Directory(Metadata, ReadDir),
}

fn open(path: &Path, metadata: std::io::Result<Metadata>) -> Entry {
    match metadata {
        Err(error) => Entry::Failed(error),
        Ok(metadata) if metadata.file_type().is_dir() => match std::fs::read_dir(path) {
            Ok(listing) => Entry::Directory(metadata, listing),
            Err(error) => Entry::Failed(error),
        },
        Ok(metadata) => Entry::File(metadata),
    }
}

/// Walks `root` depth first, stopping where the visitor says so; a visitor's error ends the walk with it.
pub fn walk<V: Visitor>(root: &Path, visitor: &mut V) -> Result<(), V::Error> {
    let mut stack: Vec<(PathBuf, ReadDir)> = Vec::new();
    // The root is visited as any entry is: a link given as the root is a file.
    let mut next = Some((root.to_path_buf(), open(root, std::fs::symlink_metadata(root))));
    loop {
        if let Some((path, entry)) = next.take() {
            let visit = match entry {
                Entry::Failed(error) => visitor.visit_file_failed(&path, error)?,
                Entry::File(metadata) => visitor.visit_file(&path, &metadata)?,
                Entry::Directory(metadata, listing) => {
                    let visit = visitor.pre_visit_directory(&path, &metadata)?;
                    if visit == Visit::Continue {
                        stack.push((path, listing));
                    }
                    visit
                }
            };
            if visit == Visit::Terminate {
                return Ok(());
            }
        }
        let Some((_, listing)) = stack.last_mut() else {
            return Ok(());
        };
        match listing.next() {
            Some(Ok(entry)) => {
                let path = entry.path();
                let metadata = entry.metadata();
                next = Some((path.clone(), open(&path, metadata)));
            }
            ended => {
                let error = ended.and_then(Result::err);
                if let Some((dir, _)) = stack.pop()
                    && visitor.post_visit_directory(&dir, error)? == Visit::Terminate
                {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Record {
        events: Vec<String>,
        skip: Option<&'static str>,
        stop: Option<&'static str>,
    }

    impl Record {
        fn name(path: &Path) -> String {
            path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
        }
    }

    impl Visitor for Record {
        type Error = String;

        fn pre_visit_directory(&mut self, dir: &Path, _: &Metadata) -> Result<Visit, String> {
            self.events.push(format!("pre {}", Record::name(dir)));
            Ok(if self.skip == Some(Record::name(dir).as_str()) { Visit::SkipSubtree } else { Visit::Continue })
        }

        fn visit_file(&mut self, file: &Path, metadata: &Metadata) -> Result<Visit, String> {
            let kind = if metadata.file_type().is_symlink() { "link" } else { "file" };
            self.events.push(format!("{kind} {}", Record::name(file)));
            Ok(if self.stop == Some(Record::name(file).as_str()) { Visit::Terminate } else { Visit::Continue })
        }

        fn visit_file_failed(&mut self, file: &Path, _: std::io::Error) -> Result<Visit, String> {
            self.events.push(format!("failed {}", Record::name(file)));
            Ok(Visit::Continue)
        }

        fn post_visit_directory(&mut self, dir: &Path, error: Option<std::io::Error>) -> Result<Visit, String> {
            self.events.push(format!("post {} {}", Record::name(dir), error.is_some()));
            Ok(Visit::Continue)
        }
    }

    #[test]
    fn subtrees_are_walked_where_they_are_met_and_links_are_files() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("only")).unwrap();
        std::fs::write(root.path().join("only/a"), "").unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("only/l")).unwrap();
        let mut record = Record::default();
        walk(&root.path().join("only"), &mut record).unwrap();
        let mut middle = record.events.get(1..3).unwrap().to_vec();
        middle.sort();
        assert_eq!(record.events.first().map(String::as_str), Some("pre only"));
        assert_eq!(middle, ["file a", "link l"], "the link is a file, never entered");
        assert_eq!(record.events.get(3).map(String::as_str), Some("post only false"));
    }

    #[test]
    fn a_skipped_subtree_is_neither_listed_nor_closed() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("t/skip/deeper")).unwrap();
        let mut record = Record { skip: Some("skip"), ..Record::default() };
        walk(&root.path().join("t"), &mut record).unwrap();
        assert_eq!(record.events, ["pre t", "pre skip", "post t false"]);
    }

    #[test]
    fn terminate_stops_everything() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("t/d")).unwrap();
        std::fs::write(root.path().join("t/d/stop"), "").unwrap();
        let mut record = Record { stop: Some("stop"), ..Record::default() };
        walk(&root.path().join("t"), &mut record).unwrap();
        assert_eq!(record.events, ["pre t", "pre d", "file stop"]);
    }

    #[test]
    fn a_root_that_is_a_file_or_missing_is_one_event() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("f"), "").unwrap();
        let mut record = Record::default();
        walk(&root.path().join("f"), &mut record).unwrap();
        walk(&root.path().join("missing"), &mut record).unwrap();
        assert_eq!(record.events, ["file f", "failed missing"]);
    }

    #[test]
    fn a_deep_tree_does_not_recurse() {
        let root = tempfile::tempdir().unwrap();
        let mut deep = root.path().join("t");
        for _ in 0..200 {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        let mut record = Record::default();
        walk(&root.path().join("t"), &mut record).unwrap();
        assert_eq!(record.events.len(), 402);
    }
}
