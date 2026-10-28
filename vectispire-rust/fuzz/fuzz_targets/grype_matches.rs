//! Grype's matches, from the matcher's standard output: whatever it holds, reading it must answer
//! (findings, absent or a failure), never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(output) = std::str::from_utf8(data) else { return };
    let _ = vectispire_scanners::dependencies::read_match_output(output);
});
