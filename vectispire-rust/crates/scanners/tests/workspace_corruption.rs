//! Every file of the workspace reference set, corrupted a few thousand ways, through every reader that runs in the
//! agent's process — the manifest readers and the API discovery's: each must answer, never panic. The nightly fuzzing
//! (`fuzz/fuzz_targets/project_manifest.rs`, `api_discovery.rs`) goes further from the same seeds; this keeps a
//! floor in the gate, deterministic, so a regression is red the day it is written.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine;
use vectispire_scanners::{api_discovery, jackson_tree, manifest, pom, properties, source_files};

/// xorshift64*: the same corruptions on every run.
struct Corruptions(u64);

impl Corruptions {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap()).unwrap()
    }

    /// One corruption: a byte changed, a run cut out, a run repeated, the file cut short, a special byte inserted.
    fn corrupt(&mut self, original: &[u8]) -> Vec<u8> {
        let mut data = original.to_vec();
        const SPECIAL: [u8; 14] =
            [b'<', b'>', b'&', b'"', b'\'', b'\\', b'{', b'[', b'\n', b'\r', 0x00, 0xED, 0xF4, 0xC0];
        for _ in 0..=self.below(3) {
            let at = self.below(data.len());
            match self.below(5) {
                0 if !data.is_empty() => data[at] = u8::try_from(self.next() & 0xFF).unwrap(),
                1 if !data.is_empty() => {
                    let end = (at + self.below(16)).min(data.len());
                    data.drain(at..end);
                }
                2 if !data.is_empty() => {
                    let end = (at + 1 + self.below(8)).min(data.len());
                    let run: Vec<u8> = data[at..end].to_vec();
                    for _ in 0..self.below(64) {
                        data.splice(at..at, run.iter().copied());
                    }
                }
                3 => data.truncate(at),
                _ => data.insert(at.min(data.len()), SPECIAL[self.below(SPECIAL.len())]),
            }
        }
        data
    }
}

fn files() -> Vec<(String, Vec<u8>)> {
    let cases = vectispire_testkit::reference_root().join("workspace/cases");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(cases).unwrap() {
        let specs: serde_json::Value = serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap();
        for case in specs["cases"].as_array().unwrap() {
            for file in case["entries"].as_array().unwrap() {
                let data = if let Some(encoded) = file["base64"].as_str() {
                    base64::engine::general_purpose::STANDARD.decode(encoded).unwrap()
                } else if file.get("text").is_some() || file.get("head").is_some() {
                    // A repeated run capped: the corruptions are the point, not the size.
                    let repeat = usize::try_from(file["repeat"].as_u64().unwrap_or(1).min(512)).unwrap();
                    let text = file["text"].as_str().unwrap_or("").repeat(repeat);
                    format!("{}{text}{}", file["head"].as_str().unwrap_or(""), file["tail"].as_str().unwrap_or(""))
                        .into_bytes()
                } else {
                    continue;
                };
                let name = file["path"].as_str().unwrap().rsplit('/').next().unwrap().to_owned();
                files.push((name, data));
            }
        }
    }
    files
}

#[test]
fn no_corruption_of_a_reference_file_makes_a_reader_panic() {
    let files = files();
    assert!(files.len() >= 200, "{} files", files.len());
    let mut corruptions = Corruptions(0x5EED_CAFE_F00D_0001);
    let mut read = 0usize;
    for (name, original) in &files {
        for _ in 0..12 {
            let data = corruptions.corrupt(original);
            let _ = pom::version(&data);
            let _ = properties::value_of(&data, "version");
            let _ = jackson_tree::read_bytes(&data);
            let text = source_files::java_utf8(&data);
            let _ = manifest::python_version(&text);
            let _ = jackson_tree::read_text(&text);
            let _ = api_discovery::read_one(name, &text);
            for other in ["openapi.json", "openapi.yaml", "A.java", "a.ts", "a.py", "a.go"] {
                let _ = api_discovery::read_one(other, &text);
            }
            read += 1;
        }
    }
    assert!(read >= 2400, "{read} corrupted files read");
}
