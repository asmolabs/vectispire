//! The verification side of the agent's signatures, on keys, bodies and signatures it did not make:
//! never a panic, never a forged acceptance.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let mut parts = text.splitn(3, '\n');
    let (Some(key), Some(body), Some(signature)) = (parts.next(), parts.next(), parts.next()) else { return };
    let accepted = vectispire_crypto::verify_result(key, 42, body.as_bytes(), signature);
    let failure = vectispire_crypto::verify_failure(key, 42, body.as_bytes(), signature);
    // The same bytes cannot be both a result's and a failure's signature: the two are domain-separated.
    assert!(!(accepted && failure), "one signature verified as a result and as a failure");
    let _ = vectispire_crypto::is_usable_sealing_key(key);
});
