//! What padding a key may carry, as Java reads it — found by the agents' administration reference set
//! (`reference/agents/administration.json`, `pin-a-key-padded-with-a-no-break-space`): `str::trim` took a no-break
//! space off a pinned key that `ResultAttestation.decode` refuses.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vectispire_crypto::{
    SealingKeyPair, generate_signing_key_pair, is_usable_sealing_key, is_valid_signing_public_key,
};

#[test]
fn a_signing_key_is_trimmed_as_string_trim_does() {
    let (public, _) = generate_signing_key_pair();
    assert!(is_valid_signing_public_key(&public));
    assert!(is_valid_signing_public_key(&format!("  {public}\n")), "spaces and controls come off");
    assert!(is_valid_signing_public_key(&format!("\u{1}{public}\u{0}")), "controls are below U+0020");
    assert!(!is_valid_signing_public_key(&format!("\u{a0}{public}")), "a no-break space stays, and is not base64");
    assert!(!is_valid_signing_public_key(&format!("{public}\u{2003}")), "an em space is beyond U+0020");
    assert!(!is_valid_signing_public_key("   "));
    assert!(!is_valid_signing_public_key(""));
}

#[test]
fn a_sealing_key_is_read_untrimmed() {
    let public = SealingKeyPair::generate().public_key();
    assert!(is_usable_sealing_key(&public));
    assert!(!is_usable_sealing_key(&format!(" {public}")), "SealedEnvelope.parsePublicKey trims nothing");
    assert!(!is_usable_sealing_key(&format!("{public}\n")));
    assert!(!is_usable_sealing_key(""));
}
