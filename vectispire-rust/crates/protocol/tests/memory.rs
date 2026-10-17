//! What reading a result costs in memory, measured on bodies near the route's 256 MB limit.
//!
//! **The risk is a tree.** A `serde_json::Value` of a 250 MB SBOM costs several times the body, and the
//! body itself is kept for its signature: two such results at once and the control plane is out of
//! memory. So the reader keeps the SBOM as the bytes that came and reads each step into typed findings —
//! and this test holds it to that, on the process's peak resident set rather than on a reading of the
//! code: each scenario runs in a child process twice, once only building the body (the baseline) and once
//! reading it too, and the difference is what reading cost.
//!
//! The peak is the kernel's: `VmHWM` from `/proc/self/status` on Linux, `/usr/bin/time -l`'s maximum
//! resident set on macOS. Anywhere else the test fails rather than skips: a bound nobody measured is not
//! one.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// The child reports its peak to the parent on its standard output, and the parent prints what it measured.
#![allow(clippy::print_stdout)]

use std::process::Command;
use vectispire_protocol::ScanArtifacts;

const MIB: u64 = 1024 * 1024;
const SCENARIO: &str = "VECTISPIRE_MEMORY_SCENARIO";

/// A body of `size` bytes, built in one allocation so that the baseline is the body and nothing else.
fn body(scenario: &str, size: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(size + 4096);
    match scenario {
        // A CycloneDX document's shape: one long list of components.
        "sbom" | "sbom-rewritten" => {
            body.extend_from_slice(br#"{"sbom":{"bomFormat":"CycloneDX","specVersion":"1.6","components":["#);
            if scenario == "sbom-rewritten" {
                // One unpaired surrogate, and the whole body has to be rewritten.
                body.extend_from_slice(br#"{"name":"\uD800"},"#);
            }
            let mut index = 0u64;
            while body.len() < size {
                if index > 0 {
                    body.push(b',');
                }
                body.extend_from_slice(
                    format!(r#"{{"type":"library","name":"component-{index}","version":"1.0.{index}","purl":"pkg:npm/component-{index}@1.0.{index}"}}"#)
                        .as_bytes(),
                );
                index += 1;
            }
            body.extend_from_slice(br#"]},"secrets":[],"duration":"PT1S"}"#);
        }
        // As many findings as fit: the typed records are the cost.
        "findings" => {
            body.extend_from_slice(br#"{"secrets":["#);
            let mut index = 0u64;
            while body.len() < size {
                if index > 0 {
                    body.push(b',');
                }
                body.extend_from_slice(
                    format!(r#"{{"rule":"generic-api-key","description":"Generic API Key","file":"src/f{index}.yaml","line":{index},"fingerprint":"src/f{index}.yaml:generic-api-key:{index}"}}"#)
                        .as_bytes(),
                );
                index += 1;
            }
            body.extend_from_slice(b"]}");
        }
        other => panic!("no scenario {other}"),
    }
    body
}

/// The child's side: build the body, read it unless this is the baseline, and report the peak.
#[test]
fn child() {
    let Ok(scenario) = std::env::var(SCENARIO) else { return };
    let (name, size, read) = {
        let mut parts = scenario.split(':');
        (
            parts.next().unwrap().to_owned(),
            parts.next().unwrap().parse::<usize>().unwrap(),
            parts.next() == Some("read"),
        )
    };
    let body = body(&name, size);
    if read {
        let received = ScanArtifacts::read(&body).unwrap();
        // Held until the peak is read, as ingestion would hold it.
        assert!(received.sbom.is_some() || received.secrets.is_some());
        report_peak();
        drop(received);
    } else {
        assert!(body.len() >= size);
        report_peak();
    }
}

#[cfg(target_os = "linux")]
fn report_peak() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).expect("VmHWM in /proc/self/status");
    let kib: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    println!("PEAK_BYTES={}", kib * 1024);
}

#[cfg(not(target_os = "linux"))]
fn report_peak() {}

/// The child's peak resident set, in bytes.
fn peak(scenario: &str) -> u64 {
    let test = std::env::current_exe().unwrap();
    let args = ["child", "--exact", "--nocapture", "--test-threads=1"];
    let output = if cfg!(target_os = "linux") {
        Command::new(&test).args(args).env(SCENARIO, scenario).output().unwrap()
    } else if cfg!(target_os = "macos") {
        Command::new("/usr/bin/time").arg("-l").arg(&test).args(args).env(SCENARIO, scenario).output().unwrap()
    } else {
        panic!("no way to read a child's peak resident set on this platform: measure it before relying on the bound");
    };
    assert!(output.status.success(), "{scenario}: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("PEAK_BYTES="))
        .or_else(|| {
            stderr
                .lines()
                .find(|line| line.contains("maximum resident set size"))
                .and_then(|line| line.split_whitespace().next())
        })
        .and_then(|bytes| bytes.parse().ok())
        .unwrap_or_else(|| panic!("{scenario}: no peak reported\n{stdout}\n{stderr}"))
}

fn cost(name: &str, size: usize) -> u64 {
    let baseline = peak(&format!("{name}:{size}:baseline"));
    let reading = peak(&format!("{name}:{size}:read"));
    let cost = reading.saturating_sub(baseline);
    println!(
        "{name}, {} MiB body: baseline {} MiB, reading {} MiB, cost {} MiB",
        size as u64 / MIB,
        baseline / MIB,
        reading / MIB,
        cost / MIB
    );
    cost
}

#[test]
fn an_sbom_near_the_limit_is_read_without_a_copy_or_a_tree() {
    if std::env::var(SCENARIO).is_ok() {
        return;
    }
    // 250 MB of SBOM: the route takes 256. A tree would cost several hundred more; a copy, 250.
    // Measured on macOS: nothing — 252 MiB at the peak with or without reading.
    assert!(cost("sbom", 250 * MIB as usize) < 32 * MIB);
}

#[test]
fn a_rewritten_sbom_costs_one_more_body_and_no_more() {
    if std::env::var(SCENARIO).is_ok() {
        return;
    }
    // The rewritten document is a copy; the SBOM is then cut out of it in place, not copied again.
    let size = 250 * MIB as usize;
    assert!(cost("sbom-rewritten", size) < size as u64 + 32 * MIB);
}

#[test]
fn findings_are_read_into_records_at_a_bounded_multiple_of_the_body() {
    if std::env::var(SCENARIO).is_ok() {
        return;
    }
    let size = 64 * MIB as usize;
    // Each finding becomes a record of owned texts; the list of their places in the body is the rest.
    // Measured on macOS: 92 MiB for this 64 MiB body, about 640,000 findings.
    assert!(cost("findings", size) < 2 * size as u64);
}
