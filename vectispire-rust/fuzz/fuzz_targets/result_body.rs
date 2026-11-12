//! A result body is the largest input the control plane takes from an agent — up to 256 MB, read before
//! anything in it is believed beyond its signature — and the reader in front of `serde_json` is a lexer
//! of its own (`jackson::prepare`). On any bytes it must answer, never panic, and what it hands on must be
//! what it promised: an SBOM that is one JSON value. The other two bodies read from an agent's bytes, the
//! failure report and the hello, go through the same lexer and are fuzzed with it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_protocol::ScanArtifacts;
use vectispire_protocol::server::{FailureReport, HelloRequest, SealingKeyRequest};

fuzz_target!(|data: &[u8]| {
    if let Ok(read) = ScanArtifacts::read(data) {
        if let Some(sbom) = &read.sbom {
            let mut deserializer = serde_json::Deserializer::from_str(sbom.get());
            deserializer.disable_recursion_limit();
            let value = <serde::de::IgnoredAny as serde::Deserialize>::deserialize(&mut deserializer);
            assert!(value.is_ok() && deserializer.end().is_ok(), "the SBOM handed on is not one JSON value");
        }
        let _ = read.observed_nothing();
    }
    let _ = FailureReport::read(data);
    let _ = HelloRequest::read(data);
    let _ = SealingKeyRequest::read(data);
});
