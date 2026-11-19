//! Who a plugin's image must be signed by — `PluginSignature`, the governor's answer to "who built this?", which
//! the digest does not give.
//!
//! **Two forms, exactly one of them.** Keyless — the Fulcio certificate's identity and the OIDC issuer that
//! vouched for it, both matched exactly — or a PEM public key (ECDSA P-256/384/521, Ed25519, RSA ≥ 2048), which is
//! then the trust root and the transparency log is not consulted. **Part of the manifest's digest**: changing the
//! signer is a new manifest.
//!
//! The key is read as BouncyCastle reads it for the Java side (the PEM reader `pinned_ca` already holds to Java,
//! the DER reader of `x509`), and each refusal is held to `reference/plugins/manifests/`.

use crate::bounded_text::Refused;
use crate::java;
use crate::x509;

/// `PluginSignature.MAX_IDENTITY`.
pub const MAX_IDENTITY: usize = 500;
/// `PluginSignature.MAX_KEY`, in UTF-16 units of PEM.
pub const MAX_KEY: usize = 8_192;
const MIN_RSA_BITS: usize = 2048;

const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const ED25519: &str = "1.3.101.112";
/// P-256, P-384, P-521 — `secp256r1`, `secp384r1`, `secp521r1`.
const CURVES: [&str; 3] = ["1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35"];

/// The form declared, which decides what `cosign verify` is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    Keyless,
    Key,
}

impl Form {
    /// `form().name().toLowerCase()`.
    pub fn name(self) -> &'static str {
        match self {
            Form::Keyless => "keyless",
            Form::Key => "key",
        }
    }
}

/// A declared signer, normalised as the Java record's constructor normalises it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSignature {
    pub identity: Option<String>,
    pub issuer: Option<String>,
    pub public_key: Option<String>,
}

fn refused(message: impl Into<String>) -> Refused {
    Refused(message.into())
}

/// `Texts.strippedOrNull`.
fn stripped_or_none(value: Option<String>) -> Option<String> {
    value.filter(|value| !java::is_blank(value)).map(|value| java::strip(&value).to_owned())
}

impl PluginSignature {
    /// The canonical constructor: blank fields absent; a key's line endings `\n`, stripped, one `\n` after it — so
    /// a paste hashes as typed.
    pub fn new(identity: Option<String>, issuer: Option<String>, public_key: Option<String>) -> PluginSignature {
        let public_key = public_key
            .filter(|key| !java::is_blank(key))
            .map(|key| format!("{}\n", java::strip(&key.replace("\r\n", "\n").replace('\r', "\n"))));
        PluginSignature { identity: stripped_or_none(identity), issuer: stripped_or_none(issuer), public_key }
    }

    pub fn form(&self) -> Form {
        if self.public_key.is_some() { Form::Key } else { Form::Keyless }
    }

    /// `digestFields`: what a manifest's digest covers, in a fixed order.
    pub fn digest_fields(&self) -> [String; 4] {
        [
            format!("signature/{}", self.form().name()),
            self.identity.clone().unwrap_or_default(),
            self.issuer.clone().unwrap_or_default(),
            self.public_key.clone().unwrap_or_default(),
        ]
    }

    /// `validated`: this declaration, or a refusal naming the first thing wrong with it.
    pub fn validated(&self) -> Result<&PluginSignature, Refused> {
        let keyless = self.identity.is_some() || self.issuer.is_some();
        if keyless == self.public_key.is_some() {
            return Err(refused(
                "A plugin's signature is declared either keyless — an identity and its OIDC issuer — or by a public \
                 key, not both and not neither.",
            ));
        }
        match (&self.identity, &self.issuer, &self.public_key) {
            (_, _, Some(key)) => require_key(key)?,
            (Some(identity), Some(issuer), None) => {
                require_exact(identity, "The signer's identity")?;
                require_exact(issuer, "The signer's OIDC issuer")?;
                if !issuer.starts_with("https://") {
                    return Err(refused(
                        "The signer's OIDC issuer is an https URL, such as https://token.actions.githubusercontent.com.",
                    ));
                }
            }
            _ => {
                return Err(refused(
                    "A keyless signature names both the certificate's identity and the OIDC issuer that vouched for \
                     it: either alone admits anybody the other one does.",
                ));
            }
        }
        Ok(self)
    }
}

/// No whitespace, no control character: each value is one `--flag=value` argument, and an exact match is only
/// exact if what is compared is what was shown.
fn require_exact(value: &str, what: &str) -> Result<(), Refused> {
    if java::utf16_len(value) > MAX_IDENTITY {
        return Err(refused(format!("{what} is at most {MAX_IDENTITY} characters.")));
    }
    if value.chars().any(|c| java::is_whitespace(c) || java::is_iso_control(c)) {
        return Err(refused(format!("{what} is matched exactly, and carries no space or control character.")));
    }
    Ok(())
}

const UNREADABLE: &str = "The signer's public key is not a readable PEM public key.";

fn require_key(pem: &str) -> Result<(), Refused> {
    if java::utf16_len(pem) > MAX_KEY {
        return Err(refused(format!("The signer's public key is at most {MAX_KEY} characters of PEM.")));
    }
    if pem.chars().any(|c| c != '\n' && java::is_iso_control(c)) {
        return Err(refused("The signer's public key is PEM text, with no control character but newlines."));
    }
    // `readPemObject` twice: the first object, then whether another follows. An object that cannot be read — no
    // end marker, Base64 that does not decode — is BouncyCastle's exception, caught as "not readable".
    let mut lines = crate::pinned_ca::java_lines(pem).into_iter();
    let object = match crate::pinned_ca::next_object(&mut lines) {
        None => None,
        Some(None) => return Err(refused(UNREADABLE)),
        Some(Some(object)) => Some(object),
    };
    let more = match object {
        None => false,
        Some(_) => match crate::pinned_ca::next_object(&mut lines) {
            None => false,
            Some(None) => return Err(refused(UNREADABLE)),
            Some(Some(_)) => true,
        },
    };
    let der = match object {
        Some((kind, der)) if kind == "PUBLIC KEY" && !more => der,
        _ => {
            return Err(refused(
                "The signer's public key is one PEM block, BEGIN PUBLIC KEY — as `cosign generate-key-pair` writes \
                 cosign.pub.",
            ));
        }
    };
    let (algorithm, parameters, key) = subject_public_key_info(&der).ok_or_else(|| refused(UNREADABLE))?;
    match algorithm.as_str() {
        EC_PUBLIC_KEY => {
            let curve = parameters.filter(|parameters| parameters.tag == x509::OID).and_then(|oid| x509::oid(&oid));
            if !curve.is_some_and(|curve| CURVES.contains(&curve.as_str())) {
                return Err(refused("An ECDSA signer's key is on P-256, P-384 or P-521."));
            }
        }
        RSA_ENCRYPTION => {
            let bits = rsa_modulus_bits(key).ok_or_else(|| refused("The signer's RSA key is not readable."))?;
            if bits < MIN_RSA_BITS {
                return Err(refused(format!("An RSA signer's key has at least {MIN_RSA_BITS} bits.")));
            }
        }
        ED25519 => {}
        _ => return Err(refused("The signer's key is ECDSA, Ed25519 or RSA — the kinds cosign verifies.")),
    }
    Ok(())
}

/// `SubjectPublicKeyInfo.getInstance`: a sequence of an `AlgorithmIdentifier` (an identifier and perhaps its
/// parameters) and a bit string — the identifier, the parameters, and the key's bits.
fn subject_public_key_info(der: &[u8]) -> Option<(String, Option<x509::Tlv<'_>>, &[u8])> {
    let outer = x509::read_whole(der).filter(|outer| outer.tag == x509::SEQUENCE)?;
    let items = x509::elements(outer.value)?;
    let [algorithm, key] = items.as_slice() else { return None };
    if algorithm.tag != x509::SEQUENCE {
        return None;
    }
    let algorithm_items = x509::elements(algorithm.value)?;
    let (identifier, parameters) = match algorithm_items.as_slice() {
        [identifier] => (identifier, None),
        [identifier, parameters] => (identifier, Some(*parameters)),
        _ => return None,
    };
    let (_, bits) = x509::bit_string(key)?;
    Some((x509::oid(identifier)?, parameters, bits))
}

/// `RSAPublicKey.getInstance(key.parsePublicKey()).getModulus().bitLength()`: a sequence of two integers, the
/// first read as a positive magnitude (`getPositiveValue`), its significant bits counted.
fn rsa_modulus_bits(key: &[u8]) -> Option<usize> {
    let sequence = x509::read_whole(key).filter(|sequence| sequence.tag == x509::SEQUENCE)?;
    let items = x509::elements(sequence.value)?;
    let [modulus, exponent] = items.as_slice() else { return None };
    x509::integer(Some(modulus))?;
    x509::integer(Some(exponent))?;
    let mut octets = modulus.value.iter().skip_while(|octet| **octet == 0);
    let Some(first) = octets.next() else { return Some(0) };
    let rest = octets.count();
    let leading = usize::try_from(u8::BITS.checked_sub(first.leading_zeros())?).ok()?;
    rest.checked_mul(8)?.checked_add(leading)
}
