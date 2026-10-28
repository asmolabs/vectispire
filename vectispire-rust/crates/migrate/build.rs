//! Embeds the control plane's migration directory, byte for byte, as the Java jar carries it.
//!
//! **The files are read from `vectispire-java`, never copied here.** One set of files with two
//! readers is the point of the crate: a copy would be a second set that the next migration updates in
//! one place only, and Flyway would refuse every installation the other one migrated.
//!
//! Every file under `db/migration` is embedded, not only the `V*.sql` ones: the layout rules
//! (`layout.rs`) are about what a commit put in the directories, a misnamed file or a stray directory
//! included, and an embedder that skipped those would let the rules pass having looked at nothing.

// A build script reports a failure by panicking: there is no caller to hand an error to.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let root = manifest.join("../../../vectispire-java/vectispire-core/src/main/resources/db/migration");
    let root = root.canonicalize().unwrap_or_else(|missing| {
        panic!("the migrations are read from {}: {missing}", root.display());
    });
    println!("cargo:rerun-if-changed={}", root.display());

    let mut entries: Vec<(String, String, PathBuf)> = Vec::new();
    for entry in sorted(&root) {
        let name = file_name(&entry);
        if entry.is_dir() {
            println!("cargo:rerun-if-changed={}", entry.display());
            for file in sorted(&entry) {
                if file.is_file() {
                    entries.push((name.clone(), file_name(&file), file));
                }
            }
        } else if entry.is_file() {
            // A file directly under db/migration is on no location Flyway reads; it is embedded with
            // an empty directory so that the layout rules can name it.
            entries.push((String::new(), name, entry));
        }
    }

    let mut generated = String::from("/// Every file under `db/migration`, as `(directory, file name, bytes)`.\n");
    generated.push_str("pub(crate) static EMBEDDED: &[(&str, &str, &[u8])] = &[\n");
    for (directory, file, path) in &entries {
        let path = path.display().to_string();
        writeln!(generated, "    ({directory:?}, {file:?}, include_bytes!({path:?})),").expect("writing to a String");
    }
    generated.push_str("];\n");

    let out = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR")).join("embedded.rs");
    fs::write(&out, generated).expect("OUT_DIR is writable");
}

fn sorted(directory: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(directory)
        .unwrap_or_else(|unreadable| panic!("{}: {unreadable}", directory.display()))
        .map(|entry| entry.expect("a readable directory entry").path())
        .collect();
    entries.sort();
    entries
}

fn file_name(path: &Path) -> String {
    path.file_name().expect("an entry has a name").to_string_lossy().into_owned()
}
