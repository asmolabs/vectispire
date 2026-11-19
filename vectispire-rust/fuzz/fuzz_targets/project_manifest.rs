//! A manifest at the root of the audited tree — `pom.xml`, `gradle.properties`, `package.json`, `pyproject.toml` —
//! read in the agent's own process: whatever it holds, each reader answers, never panics, and never loops. The first
//! byte picks the reader; the rest is the file.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_scanners::{jackson_tree, manifest, pom, properties, source_files};

fuzz_target!(|data: &[u8]| {
    let Some((&reader, file)) = data.split_first() else { return };
    match reader % 4 {
        0 => {
            let _ = pom::version(file);
        }
        1 => {
            let _ = properties::value_of(file, "version");
        }
        2 => {
            let _ = jackson_tree::read_bytes(file);
        }
        _ => {
            let _ = manifest::python_version(&source_files::java_utf8(file));
        }
    }
});
