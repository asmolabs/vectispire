//! The key every Vectispire signature is made with — `SigningKeyService`: evidence bundles, VEX, CSAF,
//! CycloneDX, DSSE.
//!
//! **Where it comes from**, as in Java: `vectispire.signing.key` (PEM PKCS#8, P-256), its public half derived
//! from it; otherwise the key generated on first use and kept in an internal settings row, encrypted under `ENCRYPTION_KEY`
//! and bound to its row. Java had published the half of another, random pair, and before that generated a key
//! at every start: a signature nobody can check against the published key is not a signature.
//!
//! **Refused rather than improvised**: without a configured key and without `ENCRYPTION_KEY`, nothing is
//! signed; a stored key no configured key reads is an error, **never replaced** — a new key would make every
//! document already handed out unverifiable without a word.

use std::future::Future;
use std::sync::Arc;

use base64::Engine;
use p256::ecdsa::{SigningKey, VerifyingKey};
use tokio::sync::OnceCell;
use vectispire_cp_settings::{Settings, SettingsError};
use vectispire_domain::java;

use crate::internal::cipher::BASIC;
use crate::internal::cosign::{self, KeyRefusal};
use crate::{Encryption, EncryptionError, MISSING_KEY, SecretState};

/// The internal row — named with a dot so it can never collide with a catalog key, and so the settings routes
/// refuse it.
pub const STORED_KEY: &str = "internal.document_signing_key";

/// The row's context: a ciphertext copied into another row does not decrypt there.
const CONTEXT: &str = "internal:document_signing_key";

/// Why nothing was signed, or the key not taken.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// No configured key, and no `ENCRYPTION_KEY` to keep a generated one under: 412, as `MissingEncryptionKeyException`.
    #[error("{}", MISSING_KEY)]
    MissingKey,
    /// A stored key no configured `ENCRYPTION_KEY` reads.
    #[error(
        "The stored document signing key cannot be decrypted by any configured ENCRYPTION_KEY. It is not replaced: a \
         new key would make every document already signed unverifiable. Restore the key it was encrypted with, or \
         set vectispire.signing.key."
    )]
    Unreadable,
    /// The configured or stored key is not a key — refused at start for a configured one.
    #[error("Invalid ECDSA private key format")]
    InvalidPrivateKey,
    /// The key is ECDSA on another curve.
    #[error("The signing key must be an ECDSA P-256 private key.")]
    NotP256,
    /// The key a reviewer supplied is not one — `InvalidInputException`, theirs to correct.
    #[error("Invalid ECDSA public key format")]
    InvalidPublicKey,
    /// The row was stored, and is not there when read back.
    #[error("No value present")]
    Vanished,
    /// Vault refused to encrypt the generated key.
    #[error(transparent)]
    Encryption(EncryptionError),
    #[error(transparent)]
    Settings(#[from] SettingsError),
}

impl From<KeyRefusal> for SigningError {
    fn from(refusal: KeyRefusal) -> SigningError {
        match refusal {
            KeyRefusal::Unreadable => SigningError::InvalidPrivateKey,
            KeyRefusal::NotP256 => SigningError::NotP256,
        }
    }
}

/// Where the stored key lives — `SettingsService`'s two internal doors. A trait so that a test can stand between
/// two instances starting together; [`Settings`] is the one the product uses.
pub trait KeyStore: Send + Sync {
    fn internal_value(&self, key: &str) -> impl Future<Output = Result<Option<String>, SettingsError>> + Send;
    fn store_internal_if_absent(
        &self,
        key: &str,
        value: &str,
    ) -> impl Future<Output = Result<bool, SettingsError>> + Send;
}

impl KeyStore for Settings {
    fn internal_value(&self, key: &str) -> impl Future<Output = Result<Option<String>, SettingsError>> + Send {
        Settings::internal_value(self, key)
    }

    fn store_internal_if_absent(
        &self,
        key: &str,
        value: &str,
    ) -> impl Future<Output = Result<bool, SettingsError>> + Send {
        Settings::store_internal_if_absent(self, key, value)
    }
}

/// The verdict on a signature, **naming the key it was checked against**: it once answered "valid and authentic"
/// with Vectispire's key id for a signature checked against the caller's key, so anybody could obtain a response
/// saying Vectispire had signed their forgery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    pub valid: bool,
    pub key_id: String,
    pub vectispire_key: bool,
    pub message: String,
}

/// A DSSE envelope — `DsseEnvelope`: the payload in base64 and one signature over its pre-authentication encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsseEnvelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

struct KeyMaterial {
    signing: SigningKey,
    verifying: VerifyingKey,
    public_pem: String,
    key_id: String,
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The private half never: the id is what a log may say.
        formatter.debug_struct("KeyMaterial").field("key_id", &self.key_id).finish_non_exhaustive()
    }
}

impl KeyMaterial {
    fn of(signing: SigningKey) -> KeyMaterial {
        let verifying = *signing.verifying_key();
        KeyMaterial {
            public_pem: cosign::public_pem(&verifying),
            key_id: cosign::key_id(&verifying),
            signing,
            verifying,
        }
    }
}

/// The document signing key — `SigningKeyService`.
#[derive(Debug)]
pub struct SigningKeys<S: KeyStore = Settings> {
    store: S,
    encryption: Arc<Encryption>,
    material: OnceCell<KeyMaterial>,
}

impl<S: KeyStore> SigningKeys<S> {
    /// With `configured` — `vectispire.signing.key`, empty when unset — **checked now**: a malformed or non-P-256
    /// key is a deployment error, and finding it on the first evidence export is finding it too late.
    pub fn new(configured: &str, store: S, encryption: Arc<Encryption>) -> Result<SigningKeys<S>, SigningError> {
        let configured = java::trim(configured);
        let material = OnceCell::new();
        if !configured.is_empty() {
            // A fresh cell cannot be full: the result is always `Ok`.
            let _ = material.set(KeyMaterial::of(cosign::parse_private_key(configured)?));
        }
        Ok(SigningKeys { store, encryption, material })
    }

    /// The public half, PEM.
    pub async fn public_key_pem(&self) -> Result<String, SigningError> {
        Ok(self.material().await?.public_pem.clone())
    }

    /// The public half.
    pub async fn public_key(&self) -> Result<VerifyingKey, SigningError> {
        Ok(self.material().await?.verifying)
    }

    /// The hex SHA-256 of the public half's `SubjectPublicKeyInfo`.
    pub async fn key_id(&self) -> Result<String, SigningError> {
        Ok(self.material().await?.key_id.clone())
    }

    /// `SHA256withECDSA` over `payload`, DER, base64.
    pub async fn sign(&self, payload: &[u8]) -> Result<String, SigningError> {
        Ok(cosign::sign(payload, &self.material().await?.signing))
    }

    /// `payload` wrapped in DSSE and signed under this key's id.
    pub async fn wrap_and_sign_dsse(&self, payload_type: &str, payload: &[u8]) -> Result<DsseEnvelope, SigningError> {
        let key = self.material().await?;
        let signature = cosign::sign(&cosign::pre_authentication_encoding(payload_type, payload), &key.signing);
        Ok(DsseEnvelope {
            payload_type: payload_type.to_owned(),
            payload: BASIC.encode(payload),
            signatures: vec![DsseSignature { keyid: key.key_id.clone(), sig: signature }],
        })
    }

    /// Whether `signature` is Vectispire's over `payload`.
    pub async fn verify(&self, payload: &[u8], signature: &str) -> Result<bool, SigningError> {
        Ok(cosign::verify(payload, signature, &self.material().await?.verifying))
    }

    /// A signature checked against Vectispire's key, or against the one `supplied` names (PEM, or the bare base64
    /// of its `SubjectPublicKeyInfo`) — and the answer says whose key that is.
    pub async fn verify_with(
        &self,
        payload: &[u8],
        signature: &str,
        supplied: Option<&str>,
    ) -> Result<Verification, SigningError> {
        let ours = self.material().await?;
        let Some(supplied) = supplied.filter(|key| !java::is_blank(key)) else {
            let valid = cosign::verify(payload, signature, &ours.verifying);
            return Ok(Verification {
                valid,
                key_id: ours.key_id.clone(),
                vectispire_key: true,
                message: if valid {
                    "Signature valid: signed with Vectispire's signing key."
                } else {
                    "Signature does not match Vectispire's signing key for this payload."
                }
                .to_owned(),
            });
        };
        let key = cosign::parse_public_key(supplied).ok_or(SigningError::InvalidPublicKey)?;
        let key_id = cosign::key_id(&key);
        let is_ours = key_id == ours.key_id;
        let valid = cosign::verify(payload, signature, &key);
        let message = if !valid {
            "Signature does not match the supplied key for this payload."
        } else if is_ours {
            "Signature valid: signed with Vectispire's signing key."
        } else {
            "Signature valid for the key you supplied, which is not Vectispire's signing key: this does not show that \
             Vectispire signed the document."
        };
        Ok(Verification { valid, key_id, vectispire_key: is_ours, message: message.to_owned() })
    }

    /// Loaded once and kept; a failure is not kept, so the next call tries again — as Java's lazy field.
    async fn material(&self) -> Result<&KeyMaterial, SigningError> {
        self.material.get_or_try_init(|| self.load_or_create()).await
    }

    async fn load_or_create(&self) -> Result<KeyMaterial, SigningError> {
        let stored = self.store.internal_value(STORED_KEY).await?.unwrap_or_default();
        let stored = java::trim(&stored);
        if !stored.is_empty() {
            return self.decrypt(stored).await;
        }

        let generated = SigningKey::random(&mut rand_core::OsRng);
        let pem = cosign::private_pem(&generated).ok_or(SigningError::InvalidPrivateKey)?;
        // Refused without ENCRYPTION_KEY: a key that cannot be kept is a key whose signatures die with the process.
        let encrypted = self.encryption.encrypt(&pem, CONTEXT).await.map_err(|refused| match refused {
            EncryptionError::MissingKey => SigningError::MissingKey,
            other => SigningError::Encryption(other),
        })?;
        let inserted = self.store.store_internal_if_absent(STORED_KEY, &encrypted).await?;

        // **Read back, and use what is stored.** Two instances starting together can each generate a key; the
        // first insert wins, the second is refused and never overwrites it, and both sign with the row that won.
        let kept = self.store.internal_value(STORED_KEY).await?.ok_or(SigningError::Vanished)?;
        let key = self.decrypt(java::trim(&kept)).await?;
        if inserted {
            tracing::info!(
                key_id = %key.key_id,
                "Generated the document signing key and stored it encrypted. Keep ENCRYPTION_KEY: without it, this key \
                 cannot be read back and nothing can be signed."
            );
        } else {
            tracing::info!(key_id = %key.key_id, "Another instance stored the document signing key first; signing with it.");
        }
        Ok(key)
    }

    async fn decrypt(&self, stored: &str) -> Result<KeyMaterial, SigningError> {
        let secret = self.encryption.inspect(stored, CONTEXT).await;
        if secret.state() == SecretState::Unreadable {
            return Err(SigningError::Unreadable);
        }
        Ok(KeyMaterial::of(cosign::parse_private_key(secret.plain_text())?))
    }
}
