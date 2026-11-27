//! What the save of an image asks for and what the check of its archive answers, against the Java side's answers —
//! `reference/container/image-platform/`, written by `ImagePlatformReferenceSetTest`.
//!
//! The archives are Java's bytes, base64, built there by its `TarBuilder`: the reader here must find the same
//! entries, refuse the same damage, and the check word the same refusal.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use vectispire_container::image_archive;

#[test]
fn every_archive_is_asked_for_and_checked_as_the_java_side_does() {
    let inputs = vectispire_testkit::read_json("container/image-platform/inputs.json");
    let answers = vectispire_testkit::read_json("container/image-platform/java-answers.json");
    let (inputs, answers) = (inputs.as_array().unwrap(), answers.as_array().unwrap());
    assert!(inputs.len() >= 80, "the reference set is there");
    assert_eq!(inputs.len(), answers.len(), "one answer per input");
    let directory = tempfile::tempdir().unwrap();
    let mut differences = Vec::new();
    for (input, answer) in inputs.iter().zip(answers) {
        let name = input["name"].as_str().unwrap();
        assert_eq!(answer["name"], name);
        let reference = input["reference"].as_str().unwrap();
        // Java's `null` is the Rust agent's empty platform: what the wire carries for a task that names none.
        let platform = input["platform"].as_str().unwrap_or_default();
        let file = directory.path().join(format!("{name}.tar"));
        std::fs::write(&file, STANDARD.decode(answer["archive"].as_str().unwrap()).unwrap()).unwrap();

        let (query, refusal) = match image_archive::requested(platform) {
            Err(malformed) => (None, Some(malformed)),
            Ok(None) => (None, None),
            Ok(Some(asked)) => (
                Some(asked.save_query()),
                image_archive::refusal(reference, platform, &asked, |entry, limit| {
                    image_archive::entry(&file, entry, limit)
                }),
            ),
        };
        let rust = (query.map(Value::from).unwrap_or(Value::Null), refusal.map(Value::from).unwrap_or(Value::Null));
        if rust != (answer["query"].clone(), answer["refusal"].clone()) {
            differences.push(format!(
                "{name}:\n  java: {} | {}\n  rust: {} | {}",
                answer["query"], answer["refusal"], rust.0, rust.1
            ));
        }
    }
    assert!(differences.is_empty(), "{} difference(s) with Java:\n{}", differences.len(), differences.join("\n"));
}

/// The defect, read off the set: an arm64 image is refused where amd64 was asked, never handed to the cataloguer.
#[test]
fn another_architecture_is_refused_not_scanned() {
    let answers = vectispire_testkit::read_json("container/image-platform/java-answers.json");
    let defect = answers.as_array().unwrap().iter().find(|answer| answer["name"] == "amd64-asked-arm64-found").unwrap();
    let refusal = defect["refusal"].as_str().unwrap();
    assert!(refusal.contains("as linux/arm64 where linux/amd64 was asked"), "{refusal}");
    assert!(refusal.contains("another architecture is not scanned"), "{refusal}");
}

/// A few thousand corruptions of the set's archives — a byte changed in every header field, the archive cut at
/// every block — each answered without a panic. The nightly fuzzes the same reader
/// (`fuzz/fuzz_targets/image_archive.rs`) from these archives.
#[test]
fn corrupted_archives_are_answered_never_a_panic() {
    let answers = vectispire_testkit::read_json("container/image-platform/java-answers.json");
    let asked = image_archive::Platform::of("linux", "amd64", "");
    let check = |bytes: &[u8]| {
        image_archive::refusal("image", "linux/amd64", &asked, |name, limit| {
            image_archive::entry_of(std::io::Cursor::new(bytes), name, limit)
        })
    };
    let mut runs = 0;
    for answer in answers.as_array().unwrap() {
        let archive = STANDARD.decode(answer["archive"].as_str().unwrap()).unwrap();
        for at in (0..archive.len()).step_by(37) {
            for value in [0x00, 0x30, 0x37, 0x80, 0xff] {
                let mut damaged = archive.clone();
                damaged[at] = value;
                let _ = check(&damaged);
                runs += 1;
            }
        }
        for cut in (0..archive.len()).step_by(100) {
            let _ = check(&archive[..cut]);
            runs += 1;
        }
    }
    assert!(runs > 2_000, "{runs} corruptions only");
}

#[test]
fn an_entry_larger_than_its_limit_is_refused_on_its_header() {
    // One header announcing two megabytes, and nothing after it: the size is read before a byte of content.
    let mut header = [0u8; 512];
    header[..13].copy_from_slice(b"manifest.json");
    header[124..136].copy_from_slice(b"00010000000\0");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let error =
        image_archive::entry_of(std::io::Cursor::new(header.to_vec()), "manifest.json", image_archive::MANIFEST_LIMIT)
            .unwrap_err();
    assert_eq!(error, "manifest.json is larger than 1048576 bytes");
}

#[test]
fn a_base_256_size_is_read_and_a_negative_one_is_not_a_size() {
    let mut field = [0u8; 12];
    field[0] = 0x80;
    field[10] = 0x02;
    field[11] = 0x01;
    assert_eq!(image_archive::number(&field), Ok(513));
    field[0] = 0xff;
    assert!(image_archive::number(&field).is_err());
    assert_eq!(image_archive::number(b" 0000755\0"), Ok(0o755));
    assert_eq!(image_archive::entry_of(std::io::Cursor::new(Vec::new()), "x", 1), Ok(None));
}
