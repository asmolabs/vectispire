//! `WebhookSignature`: proof that a webhook message came from this Vectispire.
//!
//! The signed string is `<unix seconds>.<body>` — the timestamp **inside** the MAC, so a receiver can reject a replay
//! weeks later and nobody can rewrite the window — over the **encoded** body, the bytes actually sent: signing one
//! serialisation and sending another verifies nowhere. A contract with receivers outside this repository, so the
//! functions a receiver reproduces are public.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// `sha256=<hex>`, prefixed so a second algorithm can be added without ambiguity.
pub const SIGNATURE_HEADER: &str = "X-Vectispire-Signature";
/// Unix seconds, covered by the signature.
pub const TIMESTAMP_HEADER: &str = "X-Vectispire-Timestamp";
const ALGORITHM_PREFIX: &str = "sha256=";

/// The headers to add, in Java's order — **none at all** without a secret: a signature over an empty key is one any
/// receiver could compute, which looks like authentication and is not.
pub fn headers(secret: &str, epoch_second: i64, encoded_body: &str) -> Vec<(String, String)> {
    if crate::java::is_blank(secret) {
        return Vec::new();
    }
    let timestamp = epoch_second.to_string();
    let signature = format!("{ALGORITHM_PREFIX}{}", hex(secret, &timestamp, encoded_body));
    vec![(TIMESTAMP_HEADER.to_owned(), timestamp), (SIGNATURE_HEADER.to_owned(), signature)]
}

/// The signature's lower-case hex.
pub fn hex(secret: &str, timestamp: &str, encoded_body: &str) -> String {
    hmac_sha256_hex(secret, &signed_string(timestamp, encoded_body))
}

/// What is run through the MAC: the timestamp, a full stop, the body.
pub fn signed_string(timestamp: &str, encoded_body: &str) -> String {
    format!("{timestamp}.{encoded_body}")
}

/// HMAC-SHA256 of `message` under `secret`, both as UTF-8, in lower-case hex — `Digests.hmacSha256Hex` and
/// `WebhookAuthenticity.hmacSha256Hex` alike.
pub fn hmac_sha256_hex(secret: &str, message: &str) -> String {
    // HMAC takes a key of any length; `new_from_slice` refuses none.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else { return String::new() };
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `MessageDigest.isEqual` on two strings' UTF-8 bytes: the time does not depend on where they differ.
pub fn constant_time_equals(expected: &str, presented: Option<&str>) -> bool {
    let Some(presented) = presented else { return false };
    let (a, b) = (expected.as_bytes(), presented.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |difference, (x, y)| difference | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scheme_is_rfc_hmac_over_timestamp_dot_body() {
        // RFC 4231 test case 2's key and message, the message split at its first character as "W.hat…" cannot be:
        // checked on the raw function instead.
        assert_eq!(
            hmac_sha256_hex("Jefe", "what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert!(headers("  ", 1, "{}").is_empty());
        let signed = headers("s", 1_700_000_000, "{}");
        assert_eq!(signed[0], (TIMESTAMP_HEADER.to_owned(), "1700000000".to_owned()));
        assert_eq!(signed[1].1, format!("sha256={}", hmac_sha256_hex("s", "1700000000.{}")));
        assert!(constant_time_equals("abc", Some("abc")));
        assert!(!constant_time_equals("abc", Some("abd")));
        assert!(!constant_time_equals("abc", None));
    }
}
