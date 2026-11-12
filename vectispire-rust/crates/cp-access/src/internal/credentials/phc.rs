//! Argon2id in the PHC string `common.domain.crypto.PasswordHasher` writes — `$argon2id$v=19$m=…,t=…,p=…$salt$hash`.
//!
//! An API key's stored hash is one (`AgentKeys.issue`, `ApiKeyAdministrationService.issue`), and so is a password's;
//! the accounts task (1.1) will own the password side and should take this module rather than write a second reader.
//!
//! **The string is read as Java reads it, not as the PHC specification would.** A stored hash that one control plane
//! verifies and the other refuses is a key that stops working on the day of the switch, so the parsing follows
//! `PasswordHasher.verify` piece by piece: `split("\\$")` (trailing empty pieces dropped), the algorithm name and the
//! piece count checked, the `v=` piece not read at all (BouncyCastle is always given version 0x13), `m=`, `t=`, `p=`
//! found by prefix in any order, base64 decoded leniently about padding, and a 32-byte derivation compared in constant
//! time with whatever the hash piece decodes to.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

use super::text::{java_is_blank, java_split};

/// 19 MiB, two passes, one lane — OWASP's minimum for Argon2id, and `PasswordHasher`'s.
pub const MEMORY_KIB: u32 = 19 * 1024;
pub const ITERATIONS: u32 = 2;
pub const PARALLELISM: u32 = 1;
const SALT_BYTES: usize = 16;
const HASH_BYTES: usize = 32;

/// `Base64.getEncoder().withoutPadding()` to write; `Base64.getDecoder()` to read, which takes the padding or not
/// and does not object to non-zero trailing bits.
const WRITE: GeneralPurpose =
    GeneralPurpose::new(&base64::alphabet::STANDARD, GeneralPurposeConfig::new().with_encode_padding(false));
const READ: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// `PasswordHasher.hash(secret)`: a fresh 16-byte salt, today's parameters.
pub fn hash(secret: &str) -> String {
    hash_with(secret, MEMORY_KIB, ITERATIONS, PARALLELISM).unwrap_or_default()
}

/// `PasswordHasher.hash(secret, m, t, p)`; `None` for parameters Argon2 refuses.
pub fn hash_with(secret: &str, memory_kib: u32, iterations: u32, parallelism: u32) -> Option<String> {
    let mut salt = [0u8; SALT_BYTES];
    OsRng.fill_bytes(&mut salt);
    let digest = derive(secret, &salt, memory_kib, iterations, parallelism)?;
    Some(format!(
        "$argon2id$v=19$m={memory_kib},t={iterations},p={parallelism}${}${}",
        WRITE.encode(salt),
        WRITE.encode(digest)
    ))
}

/// `PasswordHasher.verify`: whether `secret` is what `encoded` was made from. Every malformed string is `false`.
pub fn verify(secret: &str, encoded: &str) -> bool {
    if java_is_blank(encoded) {
        return false;
    }
    let parts = java_split(encoded, '$');
    // ["", "argon2id", "v=19", "m=…,t=…,p=…", salt, hash]
    let [_, algorithm, _version, parameters, salt, expected] = parts.as_slice() else {
        return false;
    };
    if *algorithm != "argon2id" {
        return false;
    }
    let (Some(memory), Some(iterations), Some(parallelism)) =
        (parameter(parameters, "m="), parameter(parameters, "t="), parameter(parameters, "p="))
    else {
        return false;
    };
    let (Ok(salt), Ok(expected)) = (READ.decode(salt), READ.decode(expected)) else {
        return false;
    };
    let Some(actual) = derive(secret, &salt, memory, iterations, parallelism) else {
        return false;
    };
    // Constant time, and a length that differs is simply unequal: an ordinary comparison stops at the first
    // differing byte, and its duration measures how much of the hash was right.
    actual.as_slice().ct_eq(expected.as_slice()).into()
}

/// `PasswordHasher.needsRehash`: not Argon2id, not six pieces, unreadable, or below today's memory or passes.
pub fn needs_rehash(encoded: Option<&str>) -> bool {
    let Some(encoded) = encoded.filter(|value| value.starts_with("$argon2id$")) else {
        return true;
    };
    let parts = java_split(encoded, '$');
    let [_, _, _, parameters, _, _] = parts.as_slice() else {
        return true;
    };
    match (parameter(parameters, "m="), parameter(parameters, "t=")) {
        (Some(memory), Some(iterations)) => memory < MEMORY_KIB || iterations < ITERATIONS,
        _ => true,
    }
}

/// The first of the comma-separated parameters starting with `name`, read as `Integer.parseInt` reads it. A
/// negative or zero value is refused here; BouncyCastle would fail on it too, one way or another.
fn parameter(parameters: &str, name: &str) -> Option<u32> {
    let value = parameters.split(',').find_map(|piece| piece.strip_prefix(name))?;
    let digits = value.strip_prefix('+').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok().filter(|parsed| *parsed > 0)
}

fn derive(secret: &str, salt: &[u8], memory_kib: u32, iterations: u32, parallelism: u32) -> Option<[u8; HASH_BYTES]> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(HASH_BYTES)).ok()?;
    let mut digest = [0u8; HASH_BYTES];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret.as_bytes(), salt, &mut digest)
        .ok()?;
    Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_verifies_its_secret_and_nothing_else() {
        let encoded = hash_with("zsk_invented", 1024, 1, 1).unwrap();
        assert!(encoded.starts_with("$argon2id$v=19$m=1024,t=1,p=1$"));
        assert!(verify("zsk_invented", &encoded));
        assert!(!verify("zsk_invente", &encoded));
        assert!(!verify("zsk_invented", &encoded.replacen("argon2id", "argon2i", 1)));
        assert!(!verify("zsk_invented", ""));
    }

    #[test]
    fn parameters_are_found_by_prefix_and_a_trailing_separator_is_ignored() {
        let encoded = hash_with("s", 1024, 1, 1).unwrap();
        let reordered = encoded.replacen("m=1024,t=1,p=1", "p=1,t=1,m=1024", 1);
        assert!(verify("s", &reordered));
        assert!(verify("s", &format!("{encoded}$")));
        assert!(!verify("s", &format!("{encoded}$x")));
    }

    #[test]
    fn rehash_is_owed_below_todays_cost() {
        assert!(needs_rehash(None));
        assert!(needs_rehash(Some("$2a$10$bcrypt")));
        assert!(needs_rehash(Some("$argon2id$v=19$m=4096,t=2,p=1$a$b")));
        assert!(!needs_rehash(Some("$argon2id$v=19$m=19456,t=2,p=1$a$b")));
    }
}
