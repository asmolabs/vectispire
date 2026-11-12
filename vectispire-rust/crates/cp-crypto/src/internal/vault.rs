//! HashiCorp Vault's Transit engine — `VaultKmsProvider`, reached through the outbound door and nothing else.
//!
//! The exchanges — the URL, the headers, the body, the timeout and the label of each request, and what each of
//! Vault's answers becomes — are held to the ones Java makes by the reference set (`encryption/`, `vault`).

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use serde_json::Value;
use vectispire_cp_outbound::{Destination, Method, OutboundPolicy};
use vectispire_domain::java;
use vectispire_domain::secret::Secret;

use super::cipher::{BASIC, LocalKms};
use crate::{Decrypted, EncryptionError, SecretState, VaultDoor as Door};

const TIMEOUT: Duration = Duration::from_secs(5);
/// What every Transit ciphertext starts with — and so what marks a stored value as encrypted.
pub const CIPHERTEXT_PREFIX: &str = "vault:";
const LABEL: &str = "Vault KMS";

#[derive(Debug)]
pub struct VaultKms {
    endpoint: String,
    token: Secret,
    key_name: String,
    mount_path: String,
    door: Door,
    fallback: LocalKms,
    /// `None` until Vault has answered; only a definite answer is kept.
    derived: Mutex<Option<bool>>,
    unbound_reported: AtomicBool,
}

impl VaultKms {
    pub fn new(
        endpoint: &str,
        token: Secret,
        key_name: Option<&str>,
        mount_path: Option<&str>,
        door: Door,
        fallback: LocalKms,
    ) -> VaultKms {
        let named = |value: Option<&str>, default: &str| match value {
            Some(value) if !java::is_blank(value) => value.to_owned(),
            _ => default.to_owned(),
        };
        VaultKms {
            // `replaceAll("/+$", "")`: the paths are appended with their own slash.
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            token,
            key_name: named(key_name, "vectispire"),
            mount_path: named(mount_path, "transit"),
            door,
            fallback,
            derived: Mutex::new(None),
            unbound_reported: AtomicBool::new(false),
        }
    }

    pub fn is_configured(&self) -> bool {
        !java::is_blank(&self.endpoint) && !java::is_blank(self.token.expose())
    }

    fn url(&self, operation: &str) -> String {
        format!("{}/v1/{}/{operation}/{}", self.endpoint, self.mount_path, self.key_name)
    }

    fn destination(&self, operation: &str) -> Result<Destination, EncryptionError> {
        self.door
            .guard
            .validate_and_resolve(&self.url(operation), OutboundPolicy::InternalAllowed, LABEL)
            .map_err(|refused| EncryptionError::UnsafeUrl(refused.0))
    }

    pub async fn encrypt(&self, plain: &str, context: &str) -> Result<String, EncryptionError> {
        if plain.is_empty() {
            return Ok(String::new());
        }
        if !self.is_configured() {
            return Err(EncryptionError::Kms(
                "Vault KMS is not fully configured (missing endpoint or token).".to_owned(),
            ));
        }
        // **The context binds a ciphertext to its row only on a derived key.** Vault uses it for key derivation
        // and ignores it otherwise, silently: on an ordinary Transit key a ciphertext moved to another row would
        // decrypt there. So nothing is written under a key that would drop it.
        if !context.is_empty() && !self.key_is_derived().await? {
            return Err(EncryptionError::Kms(format!(
                "Vault Transit key \"{key}\" is not a derived key, so Vault would ignore the context that binds each \
                 secret to its row. Create the key with derived=true (vault write -f {mount}/keys/{key} derived=true) \
                 and point Vectispire at it.",
                key = self.key_name,
                mount = self.mount_path
            )));
        }
        // Outside the wrapping below, as in Java: a refused URL is the operator's to correct, said as such.
        let destination = self.destination("encrypt")?;
        self.send_encrypt(&destination, plain, context).await.map_err(|failure| {
            tracing::error!(failure = %failure, "Error communicating with Vault KMS encrypt endpoint");
            EncryptionError::Kms(format!("Vault KMS encryption failed: {failure}"))
        })
    }

    async fn send_encrypt(&self, destination: &Destination, plain: &str, context: &str) -> Result<String, String> {
        let mut body = serde_json::Map::new();
        body.insert("plaintext".to_owned(), Value::String(BASIC.encode(plain.as_bytes())));
        if !context.is_empty() {
            body.insert("context".to_owned(), Value::String(BASIC.encode(context.as_bytes())));
        }
        let body = Value::Object(body).to_string();
        let response = self
            .door
            .sender
            .send(
                Method::Post,
                destination,
                &[("X-Vault-Token", self.token.expose()), ("Content-Type", "application/json")],
                Some(&body),
                TIMEOUT,
                "Vault KMS encrypt",
            )
            .await
            .map_err(|failure| failure.message().to_owned())?;
        if response.status != 200 {
            tracing::error!(status = response.status, body = %response.body, "Vault encryption request refused");
            return Err(format!("Vault KMS encrypt failed with status {}", response.status));
        }
        let root = read_tree(&response.body)?;
        // `path("data").path("ciphertext")`: missing, or blank as `asText()` reads it — a JSON null reads "null".
        let ciphertext = java::path(java::path(root.as_ref(), "data"), "ciphertext");
        match ciphertext.and_then(|node| java::as_text(Some(node), Some("null"))) {
            Some(text) if !java::is_blank(&text) => Ok(text),
            _ => Err("Vault KMS response missing data.ciphertext".to_owned()),
        }
    }

    /// The value Vault holds under `encrypted`, a `vault:` ciphertext: `None` when it does not answer one.
    async fn decrypt(&self, encrypted: &str, context: &str) -> Option<Secret> {
        if self.is_configured() {
            // Reading stays possible under a key that is not derived: refusing would lock every existing
            // deployment out of its own secrets, and Vault cannot convert a key. Said once, loudly.
            if !context.is_empty()
                && self.derived_if_known().await == Some(false)
                && !self.unbound_reported.swap(true, Ordering::SeqCst)
            {
                tracing::error!(
                    key = %self.key_name,
                    "Vault Transit key is not derived: the ciphertexts it holds are not bound to their rows, and one \
                     moved to another row would still decrypt. Nothing new is encrypted under it; re-save the secrets \
                     after switching to a key created with derived=true."
                );
            }
            match self.send_decrypt(encrypted, context).await {
                Ok(Some(plain)) => return Some(plain),
                Ok(None) => {}
                Err(failure) => tracing::warn!(failure = %failure, "Vault KMS decryption failed"),
            }
        }
        // Java falls back to the local keys here, for a value Vault did not write. Only `inspect` asks, and it hands
        // such a value to the local keys itself: what reaches this line starts with `vault:`, which no local key
        // reads.
        None
    }

    async fn send_decrypt(&self, encrypted: &str, context: &str) -> Result<Option<Secret>, String> {
        let destination = self.destination("decrypt").map_err(|refused| refused.to_string())?;
        let mut body = serde_json::Map::new();
        body.insert("ciphertext".to_owned(), Value::String(encrypted.to_owned()));
        if !context.is_empty() {
            body.insert("context".to_owned(), Value::String(BASIC.encode(context.as_bytes())));
        }
        let body = Value::Object(body).to_string();
        let response = self
            .door
            .sender
            .send(
                Method::Post,
                &destination,
                &[("X-Vault-Token", self.token.expose()), ("Content-Type", "application/json")],
                Some(&body),
                TIMEOUT,
                "Vault KMS decrypt",
            )
            .await
            .map_err(|failure| failure.message().to_owned())?;
        if response.status == 200 {
            let root = read_tree(&response.body)?;
            let plaintext = java::path(java::path(root.as_ref(), "data"), "plaintext");
            if let Some(text) = plaintext.and_then(|node| java::as_text(Some(node), Some("null")))
                && !java::is_blank(&text)
            {
                let decoded = BASIC.decode(&text).map_err(|error| format!("Illegal base64 character: {error}"))?;
                return Ok(Some(Secret::new(String::from_utf8_lossy(&decoded).into_owned())));
            }
            // A 200 without a plaintext: the body is not logged, it is Vault's answer to a decryption.
            tracing::warn!(status = response.status, "Vault decrypt returned no plaintext");
        } else {
            tracing::warn!(status = response.status, body = %response.body, "Vault decrypt refused");
        }
        Ok(None)
    }

    /// Whether the Transit key derives per context, asked of Vault until it answers.
    async fn key_is_derived(&self) -> Result<bool, EncryptionError> {
        self.derived_if_known().await.ok_or_else(|| {
            EncryptionError::Kms(format!(
                "Vault KMS: could not read the Transit key \"{}\" to check that it is derived.",
                self.key_name
            ))
        })
    }

    async fn derived_if_known(&self) -> Option<bool> {
        let known = *self.derived.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if known.is_some() || !self.is_configured() {
            return known;
        }
        match self.read_key().await {
            Ok(Some(derived)) => {
                *self.derived.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(derived);
                Some(derived)
            }
            Ok(None) => None,
            Err(failure) => {
                tracing::warn!(key = %self.key_name, failure = %failure, "Vault KMS: could not read the Transit key");
                None
            }
        }
    }

    async fn read_key(&self) -> Result<Option<bool>, String> {
        let destination = self.destination("keys").map_err(|refused| refused.to_string())?;
        let response = self
            .door
            .sender
            .send(Method::Get, &destination, &[("X-Vault-Token", self.token.expose())], None, TIMEOUT, "Vault KMS key")
            .await
            .map_err(|failure| failure.message().to_owned())?;
        if response.status != 200 {
            tracing::warn!(key = %self.key_name, status = response.status, "Vault KMS: reading the Transit key refused");
            return Ok(None);
        }
        let root = read_tree(&response.body)?;
        // `isBoolean()`: the string "true" is not an answer.
        Ok(java::path(java::path(root.as_ref(), "data"), "derived").and_then(Value::as_bool))
    }

    pub async fn inspect(&self, encrypted: &str, context: &str) -> Decrypted {
        if java::is_blank(encrypted) {
            return Decrypted::unreadable();
        }
        if encrypted.starts_with(CIPHERTEXT_PREFIX) {
            // Vault keeps its own key versions: what it reads is current as far as this side can tell.
            return match self.decrypt(encrypted, context).await {
                Some(plain) => Decrypted::new(plain, SecretState::Current),
                None => Decrypted::unreadable(),
            };
        }
        self.fallback.inspect(encrypted, context)
    }
}

/// `ObjectMapper.readTree`: the first value of the body, `None` for an empty one — Jackson answers a missing
/// node there, and reads past nothing after the first value.
fn read_tree(body: &str) -> Result<Option<Value>, String> {
    serde_json::Deserializer::from_str(body).into_iter::<Value>().next().transpose().map_err(|error| error.to_string())
}
