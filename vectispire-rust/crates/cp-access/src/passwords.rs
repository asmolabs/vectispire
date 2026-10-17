//! Password hashing: Argon2id, written and read the way `PasswordHasher` writes and reads it.
//!
//! **The stored string is the contract, not the library.** A hash written by the Java control plane has to
//! verify here and one written here has to verify there — an account must survive the switch, and during the
//! transition either program may be the one that last rewrote it. So the PHC string is built and parsed by hand,
//! with `PasswordHasher`'s exact grammar, and only the derivation is RustCrypto's. `tests/passwords.rs` holds
//! both directions against `vectispire-rust/reference/accounts/`, which the Java side writes and checks.
//!
//! The form is `$argon2id$v=19$m=19456,t=2,p=1$salt$hash`: standard base64 without padding, a 16-byte salt and
//! a 32-byte digest, m = 19 MiB, t = 2, p = 1 (OWASP's recommendation, as the Java javadoc says). The parameters
//! travel with the hash, so an old hash verifies under its own cost and [`needs_rehash`] says when the next
//! successful sign-in should rewrite it.
//!
//! **No bcrypt.** The port plan says older bcrypt hashes are recognised; the Java code does not recognise them
//! (`verify` answers false for anything but `argon2id`), and neither does this. Nothing has ever been stored as
//! bcrypt by this implementation — the javadoc's history is the NestJS predecessor's.
//!
//! What differs from Java, on purpose, and only for a hash nobody wrote through `hash` (a row edited by hand):
//! a parameter Java's `Integer.parseInt` reads as a non-ASCII digit is refused here; a memory cost above
//! [`MAX_MEMORY_KIB`] is refused here rather than allocated; a parameter set BouncyCastle throws on (a memory
//! below 8 × lanes, no lanes, no pass) answers false here where Java's `verify` lets the exception reach the
//! sign-in. The reference set lists each such case with what Java does.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::alphabet::STANDARD;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD_NO_PAD};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// 19 MiB, in kibibytes.
pub const MEMORY_KIB: u32 = 19 * 1024;
pub const ITERATIONS: u32 = 2;
pub const PARALLELISM: u32 = 1;
pub const SALT_BYTES: usize = 16;
pub const HASH_BYTES: usize = 32;
/// BouncyCastle's `Argon2Parameters.ARGON2_VERSION_13`, which `hash` writes after `v=`.
const VERSION_13: u32 = 0x13;

/// A ceiling Java does not have: a stored memory cost above it is refused rather than allocated. A row whose
/// `m=` was edited to two billion would otherwise make one sign-in attempt allocate two terabytes — Java throws
/// `OutOfMemoryError` into that request; a Rust allocation failure ends the process.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// `Base64.getEncoder().withoutPadding()`.
const ENCODER: GeneralPurpose = STANDARD_NO_PAD;

/// `Base64.getDecoder()`: the standard alphabet, padding accepted when right and not required, and the unused
/// bits of the last character not checked — Java's decoder ignores them.
const DECODER: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HashError {
    /// Parameters the derivation refuses — BouncyCastle throws for the same ones.
    #[error("Argon2 refused the parameters m={memory_kib}, t={iterations}, p={parallelism}")]
    Parameters { memory_kib: u32, iterations: u32, parallelism: u32 },
}

/// Hashes under today's parameters. Takes the password as the bytes Java's `getBytes(UTF_8)` gives: a Rust
/// `str` is already valid UTF-8, so the two agree for every password a request can carry.
pub fn hash(password: &str) -> String {
    match hash_with(password, MEMORY_KIB, ITERATIONS, PARALLELISM) {
        Ok(encoded) => encoded,
        // The constants are valid parameters; `tests/passwords.rs` proves it on every run.
        Err(error) => unreachable_parameters(error),
    }
}

#[cold]
fn unreachable_parameters(error: HashError) -> String {
    tracing::error!(%error, "today's Argon2 parameters were refused");
    String::new()
}

/// Hashes under stated parameters — `PasswordHasher.hash(password, memoryKib, iterations, parallelism)`: what a
/// migration rehearsal or a test needs to produce a hash at a past cost.
pub fn hash_with(password: &str, memory_kib: u32, iterations: u32, parallelism: u32) -> Result<String, HashError> {
    let mut salt = [0u8; SALT_BYTES];
    OsRng.fill_bytes(&mut salt);
    hash_with_salt(password, &salt, memory_kib, iterations, parallelism)
}

/// The same with the salt given: deterministic, for the reference set and nothing else.
pub fn hash_with_salt(
    password: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<String, HashError> {
    let digest = derive(password.as_bytes(), salt, memory_kib, iterations, parallelism)
        .ok_or(HashError::Parameters { memory_kib, iterations, parallelism })?;
    Ok(format!(
        "$argon2id$v={VERSION_13_DECIMAL}$m={memory_kib},t={iterations},p={parallelism}${}${}",
        ENCODER.encode(salt),
        ENCODER.encode(digest.as_slice()),
        VERSION_13_DECIMAL = VERSION_13
    ))
}

/// Whether `password` is the one `encoded` was made from.
///
/// False for an absent password, an absent or blank hash, and a malformed one, as Java's `verify`: a row with a
/// corrupt hash fails authentication rather than the endpoint, and an attacker cannot tell the two apart. The
/// comparison is constant-time — an ordinary one stops at the first differing byte, and its duration measures how
/// much of the hash was right.
pub fn verify(password: Option<&str>, encoded: Option<&str>) -> bool {
    let (Some(password), Some(encoded)) = (password, encoded) else {
        return false;
    };
    if java_is_blank(encoded) {
        return false;
    }
    let parts = java_split(encoded, '$');
    // ["", "argon2id", "v=19", "m=…,t=…,p=…", salt, hash] — `v=` is not read, as Java does not read it.
    let [_, algorithm, _, parameters, salt, expected] = parts.as_slice() else {
        return false;
    };
    if *algorithm != "argon2id" {
        return false;
    }
    let (Some(memory), Some(iterations), Some(parallelism)) =
        (int_parameter(parameters, "m="), int_parameter(parameters, "t="), int_parameter(parameters, "p="))
    else {
        return false;
    };
    let (Ok(salt), Ok(expected)) = (DECODER.decode(salt), DECODER.decode(expected)) else {
        return false;
    };
    let (Ok(memory), Ok(iterations), Ok(parallelism)) =
        (u32::try_from(memory), u32::try_from(iterations), u32::try_from(parallelism))
    else {
        return false;
    };
    let Some(actual) = derive(password.as_bytes(), &salt, memory, iterations, parallelism) else {
        return false;
    };
    actual.as_slice().ct_eq(expected.as_slice()).into()
}

/// Whether a stored hash was made under weaker parameters than today's — `PasswordHasher.needsRehash`, which
/// reads `m` and `t` only: a hash with more lanes is not weaker.
pub fn needs_rehash(encoded: Option<&str>) -> bool {
    let Some(encoded) = encoded else {
        return true;
    };
    if !encoded.starts_with("$argon2id$") {
        return true;
    }
    let parts = java_split(encoded, '$');
    let [_, _, _, parameters, _, _] = parts.as_slice() else {
        return true;
    };
    match (int_parameter(parameters, "m="), int_parameter(parameters, "t=")) {
        (Some(memory), Some(iterations)) => memory < i64::from(MEMORY_KIB) || iterations < i64::from(ITERATIONS),
        _ => true,
    }
}

/// A well-formed hash of a password nobody knows — what Java builds from `UUID.randomUUID()` for the sign-in's
/// unknown-name path and for a lifted password-change requirement. 122 random bits, never shown.
pub fn hash_of_nothing_anybody_knows() -> String {
    hash(&uuid::Uuid::new_v4().to_string())
}

fn derive(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Option<Zeroizing<[u8; HASH_BYTES]>> {
    if memory_kib > MAX_MEMORY_KIB {
        return None;
    }
    let params = Params::new(memory_kib, iterations, parallelism, Some(HASH_BYTES)).ok()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut digest = Zeroizing::new([0u8; HASH_BYTES]);
    argon2.hash_password_into(password, salt, digest.as_mut_slice()).ok()?;
    Some(digest)
}

/// `Integer.parseInt` of what follows `name` in the first comma-separated parameter that starts with it, as
/// `PasswordHasher.intParameter`: an optional sign, then ASCII digits, within `int`'s range.
fn int_parameter(parameters: &str, name: &str) -> Option<i64> {
    let value = java_split(parameters, ',').into_iter().find(|parameter| parameter.starts_with(name))?;
    java_parse_int(value.get(name.len()..)?)
}

fn java_parse_int(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value: i64 = text.parse().ok()?;
    (i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&value).then_some(value)
}

/// `String.split` with a one-character literal: trailing empty strings removed, a leading one kept — and, when the
/// separator does not occur at all, the text itself, even empty.
pub(crate) fn java_split(text: &str, separator: char) -> Vec<&str> {
    if !text.contains(separator) {
        return vec![text];
    }
    let mut parts: Vec<&str> = text.split(separator).collect();
    while parts.last().is_some_and(|part| part.is_empty()) {
        parts.pop();
    }
    parts
}

/// `String.isBlank`: empty or only `Character.isWhitespace` characters.
fn java_is_blank(text: &str) -> bool {
    text.chars().all(java_is_whitespace)
}

/// `Character.isWhitespace`: the Unicode space separators except the non-breaking ones, plus the ASCII and
/// information-separator controls.
fn java_is_whitespace(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | '\u{1C}'..='\u{1F}')
        || (matches!(
            character,
            ' ' | '\u{1680}'
                | '\u{2000}'..='\u{2006}'
                | '\u{2008}'..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{205F}'
                | '\u{3000}'
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn todays_parameters_are_accepted_and_the_form_is_javas() {
        let encoded = hash_with_salt("an invented passphrase", &[7u8; SALT_BYTES], MEMORY_KIB, ITERATIONS, PARALLELISM);
        let Ok(encoded) = encoded else { panic!("today's parameters refused") };
        assert!(encoded.starts_with("$argon2id$v=19$m=19456,t=2,p=1$BwcHBwcHBwcHBwcHBwcHBw$"), "{encoded}");
        assert!(verify(Some("an invented passphrase"), Some(&encoded)));
        assert!(!verify(Some("an invented passphrasf"), Some(&encoded)));
        assert!(!needs_rehash(Some(&encoded)));
    }

    #[test]
    fn split_is_javas() {
        assert_eq!(java_split("$a$b$$", '$'), vec!["", "a", "b"]);
        assert_eq!(java_split("$", '$'), Vec::<&str>::new());
        assert_eq!(java_split("a", '$'), vec!["a"]);
        assert_eq!(java_split("", '$'), vec![""]);
    }

    #[test]
    fn parse_int_is_javas() {
        assert_eq!(java_parse_int("+12"), Some(12));
        assert_eq!(java_parse_int("-1"), Some(-1));
        assert_eq!(java_parse_int("2147483648"), None);
        assert_eq!(java_parse_int("-2147483648"), Some(-2_147_483_648));
        assert_eq!(java_parse_int(""), None);
        assert_eq!(java_parse_int("+"), None);
        assert_eq!(java_parse_int("1 "), None);
    }
}
