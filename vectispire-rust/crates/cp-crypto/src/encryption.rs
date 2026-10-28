//! Encryption at rest, as the configuration asks for it — `EncryptionService`.

use rand_core::RngCore;
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_domain::java;
use vectispire_domain::secret::Secret;

use crate::internal::cipher::{EncryptionKey, FORMAT_PREFIX, LocalKms, SecretCipher};
use crate::internal::vault::{CIPHERTEXT_PREFIX, VaultKms};

/// `MissingEncryptionKeyException`'s sentence — answered 412, not 500: a deployment with no key is misconfigured,
/// not broken, and the difference is an operator fixing a variable rather than reading a stack trace.
pub const MISSING_KEY: &str = "No encryption key is configured: a new value cannot be encrypted. Generate one with \
`openssl rand -base64 32` and set ENCRYPTION_KEY before saving a secret.";

/// The key material and the KMS, as the environment resolved them — `EncryptionProperties` after `resolved()`.
///
/// Filled by the composition from `vectispire-cp-runtime`'s reading (`ENCRYPTION_KEY` or its file, the previous
/// keys split and trimmed, `vectispire.encryption.*`), and read here as the record's constructor reads it: the
/// previous keys trimmed with empty ones dropped, the plain settings trimmed with blank ones absent.
#[derive(Clone, Debug, Default)]
pub struct EncryptionConfig {
    pub key: Option<Secret>,
    pub previous_keys: Vec<Secret>,
    pub kms_type: Option<String>,
    pub vault_endpoint: Option<String>,
    pub vault_token: Option<Secret>,
    pub vault_key_name: Option<String>,
    pub vault_mount_path: Option<String>,
}

/// The way out to Vault: the guard decides what may be reached, the sender connects to what was decided.
#[derive(Clone, Debug)]
pub struct VaultDoor {
    pub sender: PinnedHttpSender,
    pub guard: OutboundUrlGuard,
}

/// A configuration this refuses to start with — `IllegalStateException` at construction in Java.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct StartupRefusal(pub String);

/// Why a value was not encrypted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncryptionError {
    /// No current key: [`MISSING_KEY`], answered 412.
    #[error("{}", MISSING_KEY)]
    MissingKey,
    /// Vault refused, could not be reached, or holds a key that would drop the context — Java's sentence.
    #[error("{0}")]
    Kms(String),
    /// The guard refused Vault's address — `UnsafeUrlException`.
    #[error("{0}")]
    UnsafeUrl(String),
}

/// A ciphertext's state with respect to the configured keys — `SecretCipher.SecretState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretState {
    /// Read by the current key — or by Vault, which keeps its own versions.
    Current,
    /// Read by a previous key: rotation is not finished until nothing reports this.
    PreviousKey,
    /// Read by no configured key: written under a lost key, relocated, altered, or never encrypted.
    Unreadable,
}

impl SecretState {
    /// Java's constant.
    pub fn name(self) -> &'static str {
        match self {
            SecretState::Current => "CURRENT",
            SecretState::PreviousKey => "PREVIOUS_KEY",
            SecretState::Unreadable => "UNREADABLE",
        }
    }
}

/// What a stored value reads as — `SecretCipher.Decrypted`. Unreadable is `""` and says so in its state, rather
/// than passing for an empty secret.
#[derive(Clone, Debug)]
pub struct Decrypted {
    plain: Secret,
    state: SecretState,
}

impl Decrypted {
    pub(crate) fn new(plain: Secret, state: SecretState) -> Decrypted {
        Decrypted { plain, state }
    }

    pub(crate) fn unreadable() -> Decrypted {
        Decrypted { plain: Secret::new(""), state: SecretState::Unreadable }
    }

    /// The clear value — `""` when unreadable.
    pub fn plain_text(&self) -> &str {
        self.plain.expose()
    }

    pub fn into_plain(self) -> Secret {
        self.plain
    }

    pub fn state(&self) -> SecretState {
        self.state
    }
}

/// `pathOrEmpty`: a plain setting trimmed, a blank one absent.
fn setting(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(java::trim).filter(|value| !value.is_empty())
}

#[derive(Debug)]
enum Kms {
    Local(LocalKms),
    Vault(Box<VaultKms>),
}

/// Encryption at rest — `EncryptionService`.
#[derive(Debug)]
pub struct Encryption {
    kms: Kms,
}

impl Encryption {
    /// From the resolved configuration, nonces from the operating system. Passphrase keys are stretched here,
    /// once: call it at start and keep the result.
    pub fn new(config: &EncryptionConfig, door: VaultDoor) -> Result<Encryption, StartupRefusal> {
        Encryption::with_random(config, door, Box::new(rand_core::OsRng))
    }

    /// The same, the nonces drawn from `random` — `new SecretCipher(SecureRandom)`. Only a reference set has a
    /// reason to pass anything but the operating system's generator: a nonce that repeats under one key gives
    /// away GCM's authentication key.
    pub fn with_random(
        config: &EncryptionConfig,
        door: VaultDoor,
        random: Box<dyn RngCore + Send>,
    ) -> Result<Encryption, StartupRefusal> {
        let primary = config
            .key
            .as_ref()
            .filter(|key| !java::is_blank(key.expose()))
            .map(|key| EncryptionKey::derive(key.expose()));
        let current = primary.is_some();
        let mut keys: Vec<EncryptionKey> = primary.into_iter().collect();
        for secret in config.previous_keys.iter().map(|key| java::trim(key.expose())).filter(|key| !key.is_empty()) {
            let derived = EncryptionKey::derive(secret);
            if !keys.contains(&derived) {
                keys.push(derived);
            }
        }
        let local = LocalKms::new(current, keys, SecretCipher::new(random));

        let kms_type = java::to_lower_root(setting(&config.kms_type).unwrap_or("local"));
        let endpoint = setting(&config.vault_endpoint);
        // Any `kms-type` but `vault` is local — `aws` included, silently, as in Java.
        let kms = match (kms_type == "vault", endpoint, &config.vault_token) {
            (true, Some(endpoint), Some(token)) => {
                tracing::info!(endpoint, "Configuring HashiCorp Vault Transit KMS");
                Kms::Vault(Box::new(VaultKms::new(
                    endpoint,
                    token.clone(),
                    setting(&config.vault_key_name),
                    setting(&config.vault_mount_path),
                    door,
                    local,
                )))
            }
            (true, endpoint, _) => {
                // **Asking for Vault and silently not getting it is the failure this refuses.** A fallback to a
                // local key moved every later write out of Transit's custody, and the two are not interchangeable
                // afterwards: what was written locally is not in Vault, and a later boot that reaches Transit
                // cannot read it. `kms-type` is not a default: somebody set it to `vault` on purpose.
                return Err(StartupRefusal(format!(
                    "Vault KMS is configured (vectispire.encryption.kms-type=vault) but {}. Refusing to start rather \
                     than falling back to local encryption: secrets written under a local key are not in Vault and a \
                     later boot that reaches Transit cannot read them. Set vectispire.encryption.vault-endpoint and \
                     vault-token, or set kms-type=local deliberately.",
                    if endpoint.is_none() { "no endpoint was provided" } else { "no token was provided" }
                )));
            }
            _ => {
                if !current {
                    tracing::warn!(
                        "No encryption key configured — stored secrets stay readable, but no new one can be encrypted. \
                         Generate one with `openssl rand -base64 32`."
                    );
                }
                Kms::Local(local)
            }
        };
        Ok(Encryption { kms })
    }

    /// Whether a new value can be encrypted — so a screen can say so before asking for a secret.
    pub fn is_configured(&self) -> bool {
        match &self.kms {
            Kms::Local(local) => local.is_configured(),
            Kms::Vault(vault) => vault.is_configured(),
        }
    }

    /// Whether key custody is external: "encrypted" and "encrypted with a key on the same host as the ciphertext"
    /// are not the same claim, and an assessor asks which one it is.
    pub fn is_externally_managed(&self) -> bool {
        matches!(self.kms, Kms::Vault(_))
    }

    /// `plain` bound to `context`. An empty value is written as it is, key or no key: a repository without a
    /// deployment key must stay saveable on a deployment that has not configured encryption yet.
    pub async fn encrypt(&self, plain: &str, context: &str) -> Result<String, EncryptionError> {
        if plain.is_empty() {
            return Ok(String::new());
        }
        if !self.is_configured() {
            return Err(EncryptionError::MissingKey);
        }
        match &self.kms {
            Kms::Local(local) => local.encrypt(plain, context).ok_or(EncryptionError::MissingKey),
            Kms::Vault(vault) => vault.encrypt(plain, context).await,
        }
    }

    /// What a stored value reads as under `context`, and which key read it.
    pub async fn inspect(&self, encrypted: &str, context: &str) -> Decrypted {
        match &self.kms {
            Kms::Local(local) => local.inspect(encrypted, context),
            Kms::Vault(vault) => vault.inspect(encrypted, context).await,
        }
    }

    /// Whether a stored value is a ciphertext of either kind this writes. Only `v2:` was recognised once, and with
    /// Vault every `vault:v1:…` read as a legacy clear value — a tracker was sent the ciphertext as its token.
    pub fn is_ciphertext(stored: &str) -> bool {
        stored.starts_with(FORMAT_PREFIX) || stored.starts_with(CIPHERTEXT_PREFIX)
    }

    /// A stored credential, tolerating one written before it was encrypted — `readSecret`.
    ///
    /// **Tolerated, and said on every read.** Rows stored in the clear by an older route still carry a working
    /// credential; reading them strictly would disable the integration on upgrade, without a message. So a legacy
    /// value is used and reported at warn, naming the setting, and not re-encrypted here: a read that writes is a
    /// surprise inside every caller. Empty when nothing is stored or nothing reads it.
    pub async fn read_secret(&self, stored: &str, context: &str, label: &str) -> Secret {
        let value = java::trim(stored);
        if value.is_empty() {
            return Secret::new("");
        }
        if !Encryption::is_ciphertext(value) {
            tracing::warn!(
                "{label} is stored in the clear — it predates encryption, or was written through a route that did not \
                 encrypt it. It still works. Save it again from the settings screen to encrypt it."
            );
            return Secret::new(value);
        }
        let secret = self.inspect(value, context).await;
        if secret.state() == SecretState::Unreadable {
            tracing::error!(
                "{label} cannot be decrypted by any configured key — the feature that uses it is disabled until it is \
                 set again."
            );
            return Secret::new("");
        }
        secret.into_plain()
    }
}
