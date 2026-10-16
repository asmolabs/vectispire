//! A sealed credential arrives in a claimed task: an envelope that is not ours must not open, and
//! must not panic on the way to saying so.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_crypto::{SealContext, SealingKeyPair};

fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = std::str::from_utf8(data) else { return };
    let keys = SealingKeyPair::from_secret_bytes([7; 32]);
    assert!(keys.open(envelope, &SealContext::deployment_key()).is_none(), "an envelope nobody sealed opened");
    let _ = keys.open(envelope, &SealContext::https_token(Some("gitlab.example.org"), None));
});
