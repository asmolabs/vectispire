//! Syft's SBOM, from the cataloguer's standard output — kept and sent on, so what it holds reaches the
//! control plane: reading it, and asking whether it is a catalogue, must answer, never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(output) = std::str::from_utf8(data) else { return };
    if let Some(document) = vectispire_scanners::dependencies::read_sbom_output(output) {
        let _ = vectispire_scanners::dependencies::is_catalogue(&document);
    }
});
