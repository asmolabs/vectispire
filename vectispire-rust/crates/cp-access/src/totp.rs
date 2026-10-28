//! `Totp`: RFC 6238 time-based one-time passwords over HMAC-SHA1, and RFC 4648 Base32 as Java reads and writes it.
//!
//! **An enrolled authenticator must survive the switch.** The secret is stored as Base32 (encrypted, under
//! `user:totp_secret:<id>`) and decoded on every sign-in, so the decoder keeps Java's leniency letter for letter:
//! upper-cased by `toUpperCase(ROOT)` — `ß` reads as `SS` — then everything outside `A–Z2–7` dropped, padding
//! included. Held to `reference/sign-in/`, which `SignInReferenceSetTest` writes, RFC 6238's own vectors among them.

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use time::OffsetDateTime;
use vectispire_domain::java;

const TIME_STEP_SECONDS: i64 = 30;
const CODE_DIGITS: usize = 6;
const DIGIT_MODULO: u32 = 1_000_000;
const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BACKUP_ALPHABET: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

/// `Totp.generateSecret`: 160 random bits, Base32.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    encode_base32(&bytes)
}

/// `Totp.qrCodeUri`: the `otpauth://` enrolment URI, the issuer and the username encoded as `URLEncoder.encode`
/// encodes them — a space is `+`, `*` is kept, `~` is not.
pub fn qr_code_uri(username: &str, secret: &str, issuer: &str) -> String {
    let issuer = form_encode(issuer);
    format!(
        "otpauth://totp/{issuer}:{}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        form_encode(username)
    )
}

/// `Totp.generateBackupCodes`: `count` codes of eight lower-case letters or digits, a hyphen after the fourth.
pub fn generate_backup_codes(count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let mut code = String::with_capacity(9);
            for position in 0..8 {
                if position == 4 {
                    code.push('-');
                }
                code.extend(BACKUP_ALPHABET.chars().nth(uniform_below_36()));
            }
            code
        })
        .collect()
}

/// `Totp.generateCode`: the code of the step `instant` falls in. `None` where Java throws — a secret that decodes to
/// no key, which no secret this side generates does.
pub fn generate_code(secret: &str, instant: OffsetDateTime) -> Option<String> {
    let key = decode_base32(secret);
    (!key.is_empty()).then(|| code_for_step(&key, step_of(instant)))
}

/// `Totp.matchingStep`: the step a submitted code belongs to, within one step either side of `now`, or `None`.
///
/// The step rather than a yes: a code is valid for up to ninety seconds, and only a caller that knows which step it
/// matched can refuse to accept that step twice. The code is trimmed as `String.trim` trims and measured in UTF-16
/// units; a secret with no key matches nothing (Java answered 500 until it was fixed to do the same).
pub fn matching_step(secret: Option<&str>, submitted: Option<&str>, now: OffsetDateTime) -> Option<i64> {
    let (secret, submitted) = (secret?, submitted?);
    let cleaned = java::trim(submitted);
    if java::utf16_len(cleaned) != CODE_DIGITS {
        return None;
    }
    let key = decode_base32(secret);
    if key.is_empty() {
        return None;
    }
    let current = step_of(now);
    [current.saturating_sub(1), current, current.saturating_add(1)]
        .into_iter()
        .find(|&step| cleaned == code_for_step(&key, step))
}

/// `Instant.getEpochSecond() / 30`: the whole seconds floored, then divided toward zero — so the half second before
/// the epoch is step 0, as is the first half minute after it.
fn step_of(instant: OffsetDateTime) -> i64 {
    instant.unix_timestamp().wrapping_div(TIME_STEP_SECONDS)
}

fn code_for_step(key: &[u8], step: i64) -> String {
    #[allow(clippy::expect_used)] // HMAC takes a key of any length; an empty one is refused by the callers.
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&step.to_be_bytes());
    let hash: [u8; 20] = mac.finalize().into_bytes().into();
    // Dynamic truncation, RFC 4226 §5.4: the last nibble is an offset of at most 15 into a 20-byte digest, so the
    // four bytes it names are always there.
    let [.., last] = hash;
    let mut window = hash.iter().skip(usize::from(last & 0x0f)).copied();
    let mut next = || window.next().unwrap_or(0);
    let binary = u32::from_be_bytes([next() & 0x7f, next(), next(), next()]);
    format!("{:06}", binary.wrapping_rem(DIGIT_MODULO))
}

/// `Totp.encodeBase32`: unpadded, the last group's bits shifted up.
pub fn encode_base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(8).div_ceil(5));
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in data {
        buffer = (buffer.wrapping_shl(8) | u32::from(byte)) & 0xffff;
        bits = bits.wrapping_add(8);
        while bits >= 5 {
            bits = bits.wrapping_sub(5);
            out.push(letter(buffer.wrapping_shr(bits)));
        }
    }
    if bits > 0 {
        out.push(letter(buffer.wrapping_shl(5u32.wrapping_sub(bits))));
    }
    out
}

/// `Totp.decodeBase32`: upper-cased in the root locale, everything outside the alphabet dropped, a trailing partial
/// byte discarded.
pub fn decode_base32(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for value in text.to_uppercase().chars().filter_map(|c| ALPHABET.find(c)) {
        buffer = (buffer.wrapping_shl(5) | u32::try_from(value).unwrap_or(0)) & 0xffff;
        bits = bits.wrapping_add(5);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            let [low, ..] = buffer.wrapping_shr(bits).to_le_bytes();
            out.push(low);
        }
    }
    out
}

/// The letter of the low five bits.
fn letter(bits: u32) -> char {
    ALPHABET.chars().nth(usize::try_from(bits & 0x1f).unwrap_or(0)).unwrap_or('A')
}

/// `URLEncoder.encode(text, UTF_8)`: the form encoding, upper-case hex.
fn form_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(char::from(byte)),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// `SecureRandom.nextInt(36)`, uniform: a byte past the last whole multiple of 36 is drawn again.
fn uniform_below_36() -> usize {
    loop {
        let [byte, ..] = OsRng.next_u32().to_le_bytes();
        if byte < 252 {
            return usize::from(byte.wrapping_rem(36));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_code_is_four_and_four() {
        let codes = generate_backup_codes(8);
        assert_eq!(codes.len(), 8);
        for code in &codes {
            let (left, right) = code.split_once('-').unwrap_or_else(|| panic!("{code}"));
            for half in [left, right] {
                assert_eq!(half.len(), 4, "{code}");
                assert!(half.bytes().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()), "{code}");
            }
        }
    }

    #[test]
    fn a_generated_secret_is_160_bits_and_verifies() {
        let secret = generate_secret();
        assert_eq!(secret.len(), 32);
        assert_eq!(decode_base32(&secret).len(), 20);
        let now = OffsetDateTime::now_utc();
        let code = generate_code(&secret, now);
        assert_eq!(matching_step(Some(&secret), code.as_deref(), now), Some(step_of(now)));
    }

    #[test]
    fn no_key_no_code() {
        assert_eq!(generate_code("!!!", OffsetDateTime::UNIX_EPOCH), None);
    }

    /// HMAC takes an empty key where `SecretKeySpec` throws, so the code an empty key would give is a real code here:
    /// only the refusal keeps a secret of no letters from opening with it.
    #[test]
    fn a_secret_of_no_letters_matches_not_even_its_own_code() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let code = code_for_step(&[], step_of(now));
        assert_eq!(matching_step(Some("!!!"), Some(&code), now), None);
    }
}
