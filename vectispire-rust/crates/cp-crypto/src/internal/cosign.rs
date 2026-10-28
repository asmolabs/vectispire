//! ECDSA P-256 as `CosignSigner` reads, writes, signs and verifies — what `SigningKeyService` needs of it.
//!
//! **Read as BouncyCastle reads.** A key is PEM — PKCS#8 (`PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`) — or the
//! bare base64 of a PKCS#8 DER; anything else, or a PEM that is neither, falls through to the base64 reading
//! with the PEM markers and the white space removed, as Java's does. A P-384 or P-521 key is *a* key, refused
//! for its curve with Java's sentence; any other content is "not a key".

use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::der::Decode;
use p256::pkcs8::der::asn1::ObjectIdentifier;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding, PrivateKeyInfo};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::cipher::BASIC;

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// The other curves the JDK's EC provider reads: a key on one of them parses in Java, and is then refused for
/// its curve rather than for its format.
const OTHER_JDK_CURVES: [ObjectIdentifier; 2] = [
    ObjectIdentifier::new_unwrap("1.3.132.0.34"), // secp384r1
    ObjectIdentifier::new_unwrap("1.3.132.0.35"), // secp521r1
];

/// Why a private key was not taken — both are `IllegalArgumentException` in Java, refused at start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRefusal {
    /// "Invalid ECDSA private key format"
    Unreadable,
    /// "The signing key must be an ECDSA P-256 private key."
    NotP256,
}

/// `CosignSigner.parsePrivateKey`, then `derivePublicKey`'s curve check.
pub fn parse_private_key(pem_or_base64: &str) -> Result<SigningKey, KeyRefusal> {
    if pem_or_base64.contains("-----")
        && let Some((label, der)) = first_pem(pem_or_base64)
    {
        match label.as_str() {
            "PRIVATE KEY" => return from_pkcs8(&der),
            "EC PRIVATE KEY" => return from_sec1(&der),
            // Another PEM object — a public key, an encrypted PKCS#8: Java's parser hands back something that is
            // not a key info, and the base64 reading below is tried, and fails.
            _ => {}
        }
    }
    let der = Zeroizing::new(BASIC.decode(bare_base64(pem_or_base64)).map_err(|_| KeyRefusal::Unreadable)?);
    from_pkcs8(&der)
}

/// `replaceAll("-----[^-]+-----", "").replaceAll("\\s+", "")`: the PEM markers and Java's `\s` removed.
fn bare_base64(text: &str) -> String {
    let mut stripped = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once("-----") {
        stripped.push_str(before);
        match after.split_once('-') {
            // At least one character that is not a dash, then exactly the closing five (one taken by the split).
            Some((marker, tail)) if !marker.is_empty() && tail.starts_with("----") => {
                rest = tail.strip_prefix("----").unwrap_or(tail);
            }
            // No marker starts at this dash: it stays, and the search goes on from the next character.
            _ => {
                stripped.push('-');
                rest = rest.strip_prefix(before).and_then(|from| from.strip_prefix('-')).unwrap_or_default();
            }
        }
    }
    stripped.push_str(rest);
    stripped.retain(|c| !matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r'));
    stripped
}

fn from_pkcs8(der: &[u8]) -> Result<SigningKey, KeyRefusal> {
    let info = PrivateKeyInfo::from_der(der).map_err(|_| KeyRefusal::Unreadable)?;
    if info.algorithm.oid != EC_PUBLIC_KEY {
        return Err(KeyRefusal::Unreadable);
    }
    let curve = info.algorithm.parameters_oid().map_err(|_| KeyRefusal::Unreadable)?;
    if OTHER_JDK_CURVES.contains(&curve) {
        return Err(KeyRefusal::NotP256);
    }
    if curve != P256 {
        return Err(KeyRefusal::Unreadable);
    }
    SigningKey::from_pkcs8_der(der).map_err(|_| KeyRefusal::Unreadable)
}

/// SEC1, as BouncyCastle's `PEMKeyPair` reads it: the curve is the key's own named-curve parameter, and a key
/// without one is refused — Java's key factory cannot place it on a curve.
fn from_sec1(der: &[u8]) -> Result<SigningKey, KeyRefusal> {
    let key = sec1::EcPrivateKey::from_der(der).map_err(|_| KeyRefusal::Unreadable)?;
    match key.parameters.and_then(|parameters| parameters.named_curve()) {
        Some(curve) if curve == P256 => {
            p256::SecretKey::from_sec1_der(der).map(SigningKey::from).map_err(|_| KeyRefusal::Unreadable)
        }
        Some(curve) if OTHER_JDK_CURVES.contains(&curve) => Err(KeyRefusal::NotP256),
        _ => Err(KeyRefusal::Unreadable),
    }
}

/// The first PEM object of the text, as `PEMParser.readObject` finds it: its label and its decoded body.
fn first_pem(text: &str) -> Option<(String, Zeroizing<Vec<u8>>)> {
    let (_, after) = text.split_once("-----BEGIN ")?;
    let (label, from_body) = after.split_once("-----")?;
    let (body, _) = from_body.split_once(format!("-----END {label}-----").as_str())?;
    let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = BASIC.decode(compact).ok()?;
    Some((label.to_owned(), Zeroizing::new(der)))
}

/// `CosignSigner.parsePublicKey`, for P-256: the key a reviewer pasted, PEM or bare base64 of its SPKI.
pub fn parse_public_key(pem_or_base64: &str) -> Option<VerifyingKey> {
    if pem_or_base64.contains("-----")
        && let Some((label, der)) = first_pem(pem_or_base64)
        && label == "PUBLIC KEY"
    {
        return VerifyingKey::from_public_key_der(&der).ok();
    }
    VerifyingKey::from_public_key_der(&BASIC.decode(bare_base64(pem_or_base64)).ok()?).ok()
}

/// `toPem(PublicKey)`: `PUBLIC KEY`, 64 columns, `\n` — BouncyCastle's writer on the platforms Vectispire runs on.
pub fn public_pem(key: &VerifyingKey) -> String {
    // A valid point always encodes: the conversion fails only for an allocation the size of a key.
    key.to_public_key_pem(LineEnding::LF).unwrap_or_default()
}

/// `toPem(PrivateKey)`: PKCS#8, `PRIVATE KEY`. Wiped when dropped.
pub fn private_pem(key: &SigningKey) -> Option<Zeroizing<String>> {
    key.to_pkcs8_pem(LineEnding::LF).ok().map(|pem| Zeroizing::new(pem.to_string()))
}

/// `computeKeyId`: the hex SHA-256 of the public key's `SubjectPublicKeyInfo`.
pub fn key_id(key: &VerifyingKey) -> String {
    let der = key.to_public_key_der().map(|der| der.into_vec()).unwrap_or_default();
    Sha256::digest(der).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `SHA256withECDSA`, DER, base64. Deterministic (RFC 6979) where Java draws `k` at random: either verifies.
pub fn sign(payload: &[u8], key: &SigningKey) -> String {
    let signature: DerSignature = key.sign(payload);
    BASIC.encode(signature.as_bytes())
}

/// `CosignSigner.verify`: the signature `trim`med and base64-decoded, any failure a `false`.
pub fn verify(payload: &[u8], signature: &str, key: &VerifyingKey) -> bool {
    let Ok(der) = BASIC.decode(vectispire_domain::java::trim(signature)) else {
        return false;
    };
    let Ok(signature) = Signature::from_der(&der) else {
        return false;
    };
    key.verify(payload, &signature).is_ok()
}

/// DSSE's pre-authentication encoding: `DSSEv1 <len(type)> <type> <len(payload)> <payload>`, lengths in bytes.
pub fn pre_authentication_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut encoded = format!("DSSEv1 {} {payload_type} {} ", payload_type.len(), payload.len()).into_bytes();
    encoded.extend_from_slice(payload);
    encoded
}
