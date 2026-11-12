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
//!
//! **Rotation keeps the past verifiable** (`docs/en/KEY_ROTATION.md`). Every public half this deployment has signed
//! with is kept in a second internal row, [`SEALED_KNOWN_KEYS`], sealed under `ENCRYPTION_KEY` for that row — for its
//! authenticity, not its secrecy: which keys are Vectispire's is not something a row anybody can write may decide —
//! and published beside the active one. The record is written before the first signature. A key listed in
//! `vectispire.signing.revoked-keys` stays published, marked revoked, and nothing signed with it verifies.

use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use p256::ecdsa::{SigningKey, VerifyingKey};
use tokio::sync::OnceCell;
use vectispire_cp_settings::{Settings, SettingsError};
use vectispire_domain::instant::Instant;
use vectispire_domain::java;

use crate::internal::cipher::BASIC;
use crate::internal::cosign::{self, KeyRefusal};
use crate::{Encryption, EncryptionError, MISSING_KEY, SecretState};

/// The internal row — named with a dot so it can never collide with a catalog key, and so the settings routes
/// refuse it.
pub const STORED_KEY: &str = "internal.document_signing_key";

/// Every public half signed with, one line per key: `keyId;activeFrom;retiredAt;base64 DER`, `-` for a time not
/// known — sealed under `ENCRYPTION_KEY` with [`KNOWN_KEYS_CONTEXT`] as its associated data.
///
/// **Sealed for its authenticity, not its secrecy.** Kept in the clear, every key in it verified as Vectispire's, so
/// whoever could write the database could have a key of their own published among Vectispire's. Only a value this
/// installation sealed, bound to this row, is read; anything else publishes nothing and verifies nothing.
pub const SEALED_KNOWN_KEYS: &str = "internal.document_signing_keys.sealed";

/// The same list in the clear, as builds of `develop` before 1.0.0-rc.1 kept it. **Never trusted**: a key in it is
/// published only once the operator names it in `vectispire.signing.adopt-unsealed-keys`, at a start, which seals it
/// into [`SEALED_KNOWN_KEYS`]. Read, never written nor deleted.
pub const KNOWN_KEYS: &str = "internal.document_signing_keys";

/// The private key row's context: a ciphertext copied into another row does not decrypt there.
const CONTEXT: &str = "internal:document_signing_key";

/// The record's context: a value sealed for another row — the private key's, a token's — is not a list.
pub const KNOWN_KEYS_CONTEXT: &str = "internal:document_signing_keys";

/// How many times the record is re-read when another instance moved it under this one.
const REGISTER_ATTEMPTS: usize = 5;

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
    /// The key that would sign is listed in `vectispire.signing.revoked-keys` — refused at start, for a configured
    /// key and for a readable generated one.
    #[error(
        "The document signing key {0} is listed in vectispire.signing.revoked-keys and cannot sign. Configure a new \
         key in vectispire.signing.key."
    )]
    Revoked(String),
    /// Five instances in a row moved the record under this one.
    #[error(
        "Could not record the document signing key {0} among the published keys: the row kept changing under five \
         attempts."
    )]
    RecordContended(String),
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

impl From<EncryptionError> for SigningError {
    fn from(refused: EncryptionError) -> SigningError {
        match refused {
            EncryptionError::MissingKey => SigningError::MissingKey,
            other => SigningError::Encryption(other),
        }
    }
}

/// Where the stored key lives — `SettingsService`'s internal doors. A trait so that a test can stand between two
/// instances starting together; [`Settings`] is the one the product uses.
pub trait KeyStore: Send + Sync {
    fn internal_value(&self, key: &str) -> impl Future<Output = Result<Option<String>, SettingsError>> + Send;
    fn store_internal_if_absent(
        &self,
        key: &str,
        value: &str,
    ) -> impl Future<Output = Result<bool, SettingsError>> + Send;
    /// `resealInternal`: the row moved from `expected` to `value` in a transaction of its own, and whether it was.
    fn reseal_internal(
        &self,
        key: &str,
        expected: &str,
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

    fn reseal_internal(
        &self,
        key: &str,
        expected: &str,
        value: &str,
    ) -> impl Future<Output = Result<bool, SettingsError>> + Send {
        Settings::reseal_internal(self, key, expected, value)
    }
}

/// Where a known key stands — `SigningKeyService.KeyStatus`: the one signing now, one that signed before, or one not
/// to trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

impl KeyStatus {
    /// Java's constant, as the routes write it.
    pub fn name(self) -> &'static str {
        match self {
            KeyStatus::Active => "ACTIVE",
            KeyStatus::Retired => "RETIRED",
            KeyStatus::Revoked => "REVOKED",
        }
    }
}

/// A public half this deployment has signed with — `PublishedKey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedKey {
    pub key_id: String,
    pub status: KeyStatus,
    pub public_key_pem: String,
    /// When this deployment first signed with it; `None` for a key recorded only as the stored key a configured one
    /// replaced, whose first use predates the record.
    pub active_from: Option<Instant>,
    /// When another key replaced it; `None` while it is the active one.
    pub retired_at: Option<Instant>,
    verifying: VerifyingKey,
}

/// The verdict on a signature, **naming the key it was checked against**: it once answered "valid and authentic"
/// with Vectispire's key id for a signature checked against the caller's key, so anybody could obtain a response
/// saying Vectispire had signed their forgery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    pub valid: bool,
    /// The caller's key when one was supplied; without one, the published key the signature matched, and `None`
    /// when it matched none — never the active key's id for a signature it did not make.
    pub key_id: Option<String>,
    /// Whether that key is one of Vectispire's, active or not; without a supplied key, `true`.
    pub vectispire_key: bool,
    /// Where that key stands when it is one of Vectispire's; `None` otherwise and when nothing matched.
    pub key_status: Option<KeyStatus>,
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

/// Where the time a key is recorded comes from — `java.time.Clock`.
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> Instant + Send + Sync>);

impl std::fmt::Debug for Clock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Clock")
    }
}

impl Clock {
    /// `Clock.systemUTC()`.
    pub fn system() -> Clock {
        Clock(Arc::new(|| {
            let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            Instant { epoch_second: i64::try_from(since.as_secs()).unwrap_or(i64::MAX), nano: since.subsec_nanos() }
        }))
    }

    /// `Clock.fixed(at, UTC)`.
    pub fn fixed(at: Instant) -> Clock {
        Clock(Arc::new(move || at))
    }

    fn now(&self) -> Instant {
        (self.0)()
    }
}

/// What the deployment configured — `vectispire.signing.*`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SigningConfig<'a> {
    /// `vectispire.signing.key`, empty when unset.
    pub key: &'a str,
    /// `vectispire.signing.revoked-keys`: key ids, comma-separated, any case.
    pub revoked_keys: &'a str,
    /// `vectispire.signing.adopt-unsealed-keys`: the ids of the unsealed record the operator vouches for.
    pub adopted_keys: &'a str,
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

/// A line of the record — `Known`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Known {
    key_id: String,
    active_from: Option<Instant>,
    retired_at: Option<Instant>,
    der: String,
}

impl Known {
    /// The line, or `None` when it cannot be taken as written. **The id is recomputed from the key, never read**:
    /// everything finds a key by its id — the revocation list, the route serving one id, the verification naming the
    /// key it matched — and whoever could write the row could otherwise publish a key under another key's id.
    fn parse(line: &str) -> Option<Known> {
        let fields: Vec<&str> = line.split(';').collect();
        let [claimed, active_from, retired_at, der] = fields.as_slice() else {
            return None;
        };
        let key = cosign::parse_public_key(der)?;
        if cosign::key_id(&key) != *claimed {
            return None;
        }
        Some(Known {
            key_id: (*claimed).to_owned(),
            active_from: time(active_from)?,
            retired_at: time(retired_at)?,
            der: (*der).to_owned(),
        })
    }

    fn of(key: &VerifyingKey, active_from: Option<Instant>, retired_at: Option<Instant>) -> Known {
        Known { key_id: cosign::key_id(key), active_from, retired_at, der: cosign::public_der_base64(key) }
    }

    fn line(&self) -> String {
        let spell = |at: Option<Instant>| at.and_then(Instant::to_java_string).unwrap_or_else(|| "-".to_owned());
        format!("{};{};{};{}", self.key_id, spell(self.active_from), spell(self.retired_at), self.der)
    }
}

/// `-` for a time not known, an `Instant.toString` otherwise; `None` for anything else — the line is refused.
fn time(field: &str) -> Option<Option<Instant>> {
    if field == "-" { Some(None) } else { Instant::parse_java(field).map(Some) }
}

/// The record as read: the lines taken, and the ones refused, kept verbatim so a rewrite carries them on.
#[derive(Clone, Debug, Default)]
struct Read {
    keys: Vec<Known>,
    refused: Vec<String>,
}

/// `ids`: comma-separated, trimmed, the empty ones dropped, lower-cased as the ids are written.
fn ids(list: &str) -> BTreeSet<String> {
    list.split(',').map(java::trim).filter(|id| !id.is_empty()).map(str::to_lowercase).collect()
}

/// The document signing key — `SigningKeyService`.
#[derive(Debug)]
pub struct SigningKeys<S: KeyStore = Settings> {
    store: S,
    encryption: Arc<Encryption>,
    configured: bool,
    revoked: BTreeSet<String>,
    adopted: BTreeSet<String>,
    clock: Clock,
    /// When this instance started: a key retired after it was retired under this instance, not before it.
    started_at: Instant,
    material: OnceCell<KeyMaterial>,
    /// Whether this instance has recorded its key as the active one; nothing is signed before it has.
    registered: AtomicBool,
    registering: tokio::sync::Mutex<()>,
    /// Set once the published list has said why it is published without this instance's key.
    warned_unavailable: AtomicBool,
    /// The refused lines already warned about, so that an anonymous caller cannot fill the log with them.
    warned_lines: Mutex<HashSet<String>>,
    /// The stored record last refused whole and warned about; warned again only when it changes.
    warned_record: Mutex<Option<String>>,
    /// Whether the start's work on the stored rows is still owed ([`SigningKeys::start_lazily`]): done once, before the
    /// first key is loaded or the record read, and tried again after a failure.
    deferred: bool,
    started: tokio::sync::OnceCell<()>,
    /// The record last opened, by the stored value it was opened from: the list is served to anyone, and opening it
    /// at every request would be a decryption — a call to Vault, with Transit — whose rate an anonymous caller chooses.
    opened: Mutex<Option<(String, Option<Read>)>>,
}

impl<S: KeyStore> SigningKeys<S> {
    /// With `configured` — `vectispire.signing.key`, empty when unset — **checked now**: a malformed or non-P-256
    /// key is a deployment error, and finding it on the first evidence export is finding it too late. No revocation
    /// list, no adoption, and none of the start's work on the stored rows: [`SigningKeys::start`] is the start.
    pub fn new(configured: &str, store: S, encryption: Arc<Encryption>) -> Result<SigningKeys<S>, SigningError> {
        SigningKeys::configured(
            SigningConfig { key: configured, ..SigningConfig::default() },
            store,
            encryption,
            Clock::system(),
        )
    }

    /// The service as a start builds it — Java's constructor: the configured key checked and refused when revoked,
    /// the generated one refused when revoked and readable, the record re-sealed under the current `ENCRYPTION_KEY`
    /// when a previous one opened it, and the keys the operator vouched for adopted from the unsealed record.
    pub async fn start(
        config: SigningConfig<'_>,
        store: S,
        encryption: Arc<Encryption>,
        clock: Clock,
    ) -> Result<SigningKeys<S>, SigningError> {
        let keys = SigningKeys::configured(config, store, encryption, clock)?;
        keys.start_work().await?;
        Ok(keys)
    }

    /// The start as the binary runs it, **which needs no database**: the configured key checked and refused when
    /// revoked now, as Java's constructor does — a deployment error is found at start — and the work on the stored
    /// rows (the generated key refused when revoked, the record re-sealed, the vouched-for keys adopted) done once,
    /// before the first key is loaded or the record read, and tried again after a failure.
    ///
    /// Java does that work in its constructor and cannot start without a database. The Rust control plane starts
    /// without one (its pool connects lazily, and a database that does not answer must not hold a stop), so the work
    /// waits for the first use instead: nothing is signed, verified or published before it has run. The cost is when a
    /// revoked *stored* key is found — at the first signature or the first read of the published keys, refused there
    /// with the same sentence, rather than at start.
    pub fn start_lazily(
        config: SigningConfig<'_>,
        store: S,
        encryption: Arc<Encryption>,
        clock: Clock,
    ) -> Result<SigningKeys<S>, SigningError> {
        let mut keys = SigningKeys::configured(config, store, encryption, clock)?;
        keys.deferred = true;
        Ok(keys)
    }

    /// The start's work on the stored rows, in Java's order.
    async fn start_work(&self) -> Result<(), SigningError> {
        if !self.configured && !self.revoked.is_empty() {
            self.refuse_revoked_stored_key().await?;
        }
        self.reseal_record().await?;
        self.adopt_vouched_keys().await
    }

    /// Runs [`SigningKeys::start_work`] once when it was deferred; a failure is not kept, so the next use tries again.
    async fn started(&self) -> Result<(), SigningError> {
        if !self.deferred {
            return Ok(());
        }
        self.started.get_or_try_init(|| self.start_work()).await.map(|_| ())
    }

    fn configured(
        config: SigningConfig<'_>,
        store: S,
        encryption: Arc<Encryption>,
        clock: Clock,
    ) -> Result<SigningKeys<S>, SigningError> {
        let configured = java::trim(config.key);
        let revoked = ids(config.revoked_keys);
        let material = OnceCell::new();
        if !configured.is_empty() {
            let key = KeyMaterial::of(cosign::parse_private_key(configured)?);
            refuse_revoked(&revoked, &key)?;
            // A fresh cell cannot be full: the result is always `Ok`.
            let _ = material.set(key);
        }
        let started_at = clock.now();
        Ok(SigningKeys {
            store,
            encryption,
            configured: !configured.is_empty(),
            revoked,
            adopted: ids(config.adopted_keys),
            clock,
            started_at,
            material,
            registered: AtomicBool::new(false),
            registering: tokio::sync::Mutex::new(()),
            warned_unavailable: AtomicBool::new(false),
            warned_lines: Mutex::new(HashSet::new()),
            warned_record: Mutex::new(None),
            deferred: false,
            started: tokio::sync::OnceCell::new(),
            opened: Mutex::new(None),
        })
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

    /// Whether `signature` is Vectispire's over `payload`, by the active key or one it replaced; never by a revoked
    /// one.
    pub async fn verify(&self, payload: &[u8], signature: &str) -> Result<bool, SigningError> {
        Ok(self.verify_with(payload, signature, None).await?.valid)
    }

    /// The active key first, then the ones it replaced, most recent first.
    ///
    /// **The status is the record's, not this instance's**: through a rolling restart, instances deciding it by
    /// their own key published contradictory lists behind one load balancer. **Readable without the signing key**:
    /// an instance whose own key cannot be loaded still publishes what it recorded — the revocations among it.
    pub async fn published_keys(&self) -> Result<Vec<PublishedKey>, SigningError> {
        // Before the read: loading the key records it, and the list must show what was recorded.
        let active = self.signing_if_available().await;
        let mut known = self.known().await?;
        // The key that signs is always published, whatever the row says: a restore of an older dump can take it
        // away under a running instance.
        if let Some(key) = active
            && !known.iter().any(|k| k.key_id == key.key_id)
        {
            known.push(Known::of(&key.verifying, None, None));
        }
        let mut published: Vec<PublishedKey> = known
            .into_iter()
            .filter_map(|k| {
                let verifying = cosign::parse_public_key(&k.der)?;
                Some(PublishedKey {
                    status: self.status_of(&k),
                    public_key_pem: cosign::public_pem(&verifying),
                    key_id: k.key_id,
                    active_from: k.active_from,
                    retired_at: k.retired_at,
                    verifying,
                })
            })
            .collect();
        published.sort_by(|a, b| {
            (a.status != KeyStatus::Active).cmp(&(b.status != KeyStatus::Active)).then_with(|| {
                match (a.retired_at, b.retired_at) {
                    (None, None) => std::cmp::Ordering::Equal,
                    (None, Some(_)) => std::cmp::Ordering::Less,
                    (Some(_), None) => std::cmp::Ordering::Greater,
                    (Some(a), Some(b)) => b.cmp(&a),
                }
            })
        });
        Ok(published)
    }

    /// The PEM `public-key.pub` serves: the key the list calls active, so that it agrees with the list on every
    /// instance. Only when the record names none — nothing signed yet — this instance's key, loaded (or generated)
    /// as for a signature.
    pub async fn active_public_key_pem(&self) -> Result<String, SigningError> {
        match self.published_keys().await?.into_iter().find(|k| k.status == KeyStatus::Active) {
            Some(active) => Ok(active.public_key_pem),
            None => self.public_key_pem().await,
        }
    }

    /// One published key by its id, in any case.
    pub async fn published_key(&self, key_id: &str) -> Result<Option<PublishedKey>, SigningError> {
        Ok(self.published_keys().await?.into_iter().find(|k| k.key_id.eq_ignore_ascii_case(key_id)))
    }

    /// A signature checked against Vectispire's keys, or against the one `supplied` names (PEM, or the bare base64
    /// of its `SubjectPublicKeyInfo`) — and the answer says whose key that is.
    pub async fn verify_with(
        &self,
        payload: &[u8],
        signature: &str,
        supplied: Option<&str>,
    ) -> Result<Verification, SigningError> {
        let Some(supplied) = supplied.filter(|key| !java::is_blank(key)) else {
            // **Every published key, the active one first.** A document signed before a rotation was reported as
            // not matching "Vectispire's signing key", which an auditor reads as forged.
            for key in self.published_keys().await? {
                if cosign::verify(payload, signature, &key.verifying) {
                    return Ok(answer(key.key_id, key.status, key.retired_at));
                }
            }
            // No key named and no status: the active key's id and "ACTIVE" read as the key that signed.
            return Ok(Verification {
                valid: false,
                key_id: None,
                vectispire_key: true,
                key_status: None,
                message: "Signature does not match any of Vectispire's signing keys for this payload.".to_owned(),
            });
        };
        let key = cosign::parse_public_key(supplied).ok_or(SigningError::InvalidPublicKey)?;
        let key_id = cosign::key_id(&key);
        let valid = cosign::verify(payload, signature, &key);
        let known = self.published_key(&key_id).await?;
        if !valid {
            return Ok(Verification {
                valid: false,
                vectispire_key: known.is_some(),
                key_status: known.map(|k| k.status),
                key_id: Some(key_id),
                message: "Signature does not match the supplied key for this payload.".to_owned(),
            });
        }
        Ok(match known {
            None => Verification {
                valid: true,
                key_id: Some(key_id),
                vectispire_key: false,
                key_status: None,
                message: "Signature valid for the key you supplied, which is not Vectispire's signing key nor one it \
                          signed with before: this does not show that Vectispire signed the document."
                    .to_owned(),
            },
            Some(known) => answer(key_id, known.status, known.retired_at),
        })
    }

    /// Loaded once and kept, then recorded as the active key before anything is signed with it; a failure is not
    /// kept, so the next call tries again — as Java's lazy field.
    async fn material(&self) -> Result<&KeyMaterial, SigningError> {
        self.started().await?;
        let key = self
            .material
            .get_or_try_init(|| async {
                let key = self.load_or_create().await?;
                refuse_revoked(&self.revoked, &key)?;
                Ok::<_, SigningError>(key)
            })
            .await?;
        if !self.registered.load(Ordering::Acquire) {
            let _one_at_a_time = self.registering.lock().await;
            if !self.registered.load(Ordering::Acquire) {
                self.register(key).await?;
                self.registered.store(true, Ordering::Release);
            }
        }
        Ok(key)
    }

    fn status_of(&self, key: &Known) -> KeyStatus {
        if self.revoked.contains(&key.key_id) {
            KeyStatus::Revoked
        } else if key.retired_at.is_none() {
            KeyStatus::Active
        } else {
            KeyStatus::Retired
        }
    }

    /// This instance's key, when it can be loaded. A key that cannot be is still refused to every signature, with
    /// its reason; the published list goes on without it, and says why once.
    async fn signing_if_available(&self) -> Option<&KeyMaterial> {
        match self.material().await {
            Ok(key) => Some(key),
            Err(unavailable) => {
                if !self.warned_unavailable.swap(true, Ordering::AcqRel) {
                    tracing::warn!(
                        "The document signing key cannot be loaded ({unavailable}); the published keys are served \
                         from the record alone."
                    );
                }
                None
            }
        }
    }

    async fn sealed_record(&self) -> Result<Option<String>, SigningError> {
        let stored = self.store.internal_value(SEALED_KNOWN_KEYS).await?;
        Ok(stored.map(|value| java::trim(&value).to_owned()).filter(|value| !value.is_empty()))
    }

    async fn known(&self) -> Result<Vec<Known>, SigningError> {
        self.started().await?;
        let stored = self.sealed_record().await?;
        Ok(self.open_record(stored.as_deref()).await.map(|read| read.keys).unwrap_or_default())
    }

    /// The sealed record, opened: empty when there is none, and `None` when what is stored is not a value this
    /// installation sealed for this row — in the clear, sealed for another row, under a key no longer configured.
    ///
    /// **Absent is not empty, and the record is refused whole**: what authenticates a line is the seal around all
    /// of them. Refused, it publishes nothing and verifies nothing — only the active key, from the instance itself —
    /// and it is never overwritten, since restoring the key it was sealed under brings it back.
    async fn open_record(&self, stored: Option<&str>) -> Option<Read> {
        let Some(stored) = stored else {
            return Some(Read::default());
        };
        if let Ok(opened) = self.opened.lock()
            && let Some((last, read)) = opened.as_ref()
            && last == stored
        {
            return read.clone();
        }
        let read = if Encryption::is_ciphertext(stored) {
            let record = self.encryption.inspect(stored, KNOWN_KEYS_CONTEXT).await;
            (record.state() != SecretState::Unreadable).then(|| self.read(Some(record.plain_text())))
        } else {
            None
        };
        if read.is_none()
            && let Ok(mut warned) = self.warned_record.lock()
            && warned.as_deref() != Some(stored)
        {
            *warned = Some(stored.to_owned());
            tracing::warn!(
                "The record of published document signing keys ({SEALED_KNOWN_KEYS}) is refused: it is not a value \
                 sealed for it under a configured ENCRYPTION_KEY. Nothing in it is published or used to verify, and it \
                 is not overwritten. Restore the ENCRYPTION_KEY it was sealed under, or the row from a backup."
            );
        }
        // Vault answers an unreachable Transit as an unreadable value: not remembered, since it may answer at the
        // next request — Java's `RuntimeException` there is not cached either.
        if (read.is_some() || !self.encryption.is_externally_managed())
            && let Ok(mut opened) = self.opened.lock()
        {
            *opened = Some((stored.to_owned(), read.clone()));
        }
        read
    }

    /// The record, a line refused when it does not hold together — **a line, not the record**: refusing the whole
    /// row would take the revocation list down with one bad line. A refused line stays in the row, for whoever
    /// investigates, and is warned about once per line and instance.
    fn read(&self, row: Option<&str>) -> Read {
        let mut read = Read::default();
        let row = row.map(java::trim).unwrap_or_default();
        for line in row.lines().filter(|line| !java::is_blank(line)) {
            match Known::parse(line) {
                Some(known) => read.keys.push(known),
                None => {
                    read.refused.push(line.to_owned());
                    let first =
                        self.warned_lines.lock().map(|mut warned| warned.insert(line.to_owned())).unwrap_or(false);
                    if first {
                        let claimed: String = line.split(';').next().unwrap_or_default().chars().take(64).collect();
                        tracing::warn!(
                            "A line of {KNOWN_KEYS} is refused: its key cannot be read, or {claimed} is not the key's \
                             own id. It is neither published nor used to verify."
                        );
                    }
                }
            }
        }
        read
    }

    /// Seals `lines` into the record, conditionally on `read` still being what is stored.
    async fn write(&self, read: Option<&str>, lines: &str) -> Result<bool, SigningError> {
        let sealed = self.encryption.encrypt(lines, KNOWN_KEYS_CONTEXT).await?;
        Ok(match read {
            None => self.store.store_internal_if_absent(SEALED_KNOWN_KEYS, &sealed).await?,
            // In a transaction of its own: the first signature may be made inside a read-only transaction.
            Some(read) => self.store.reseal_internal(SEALED_KNOWN_KEYS, read, &sealed).await?,
        })
    }

    /// The record re-sealed under the current `ENCRYPTION_KEY` when a previous one opened it — at start, as the
    /// private key is: it is rewritten only when a key is added or retired, so nothing else would move it before
    /// the previous key is removed, and the list would then be refused.
    async fn reseal_record(&self) -> Result<(), SigningError> {
        let Some(stored) = self.sealed_record().await? else {
            return Ok(());
        };
        let record = self.encryption.inspect(&stored, KNOWN_KEYS_CONTEXT).await;
        if record.state() != SecretState::PreviousKey {
            return Ok(());
        }
        let resealed = match self.encryption.encrypt(record.plain_text(), KNOWN_KEYS_CONTEXT).await {
            Ok(sealed) => {
                self.store.reseal_internal(SEALED_KNOWN_KEYS, &stored, &sealed).await.map_err(SigningError::from)
            }
            Err(refused) => Err(refused.into()),
        };
        match resealed {
            Ok(true) => {
                tracing::info!(
                    "Re-sealed the record of published document signing keys under the current ENCRYPTION_KEY."
                )
            }
            Ok(false) => {}
            Err(refused) => tracing::warn!(
                "The record of published document signing keys could not be re-sealed now ({refused}); the next start \
                 tries again."
            ),
        }
        Ok(())
    }

    /// Seals into the record the keys of the unsealed record the operator named, and says which of its keys stay
    /// unpublished. **At start only, and only on the operator's word**: the unsealed row is anybody's who can write
    /// the database. A key named but not in the row is said too, so a mistyped id does not read as an adoption.
    async fn adopt_vouched_keys(&self) -> Result<(), SigningError> {
        let unsealed_row = self.store.internal_value(KNOWN_KEYS).await?;
        let unsealed = self.read(unsealed_row.as_deref());
        if unsealed.keys.is_empty() && self.adopted.is_empty() {
            return Ok(());
        }
        let stored = self.sealed_record().await?;
        let Some(sealed) = self.open_record(stored.as_deref()).await else {
            tracing::warn!(
                "The unsealed record of published document signing keys ({KNOWN_KEYS}) is not adopted: the sealed \
                 record cannot be opened, and is not overwritten."
            );
            return Ok(());
        };
        let present: HashSet<&str> = sealed.keys.iter().map(|k| k.key_id.as_str()).collect();
        let adopted: Vec<&Known> = unsealed
            .keys
            .iter()
            .filter(|k| self.adopted.contains(&k.key_id) && !present.contains(k.key_id.as_str()))
            .collect();
        let ignored: Vec<&str> = unsealed
            .keys
            .iter()
            .map(|k| k.key_id.as_str())
            .filter(|id| !self.adopted.contains(*id) && !present.contains(id))
            .collect();
        // The configured ids, sorted (a `BTreeSet`), as Java sorts them.
        let missing: Vec<&str> = self
            .adopted
            .iter()
            .map(String::as_str)
            .filter(|id| !present.contains(id) && !unsealed.keys.iter().any(|k| k.key_id == *id))
            .collect();
        if !ignored.is_empty() {
            tracing::warn!(
                "The unsealed record of published document signing keys ({KNOWN_KEYS}) lists {} key(s) that are \
                 neither published nor used to verify, since nothing authenticates that record: {}. If this \
                 installation signed with them, list their ids in vectispire.signing.adopt-unsealed-keys and restart.",
                ignored.len(),
                ignored.join(", ")
            );
        }
        if !missing.is_empty() {
            tracing::warn!(
                "vectispire.signing.adopt-unsealed-keys names {} key(s) the unsealed record does not hold: {}.",
                missing.len(),
                missing.join(", ")
            );
        }
        if adopted.is_empty() {
            return Ok(());
        }
        if !self.encryption.is_configured() {
            tracing::warn!(
                "The document signing keys named in vectispire.signing.adopt-unsealed-keys are not adopted: without \
                 ENCRYPTION_KEY the record cannot be sealed."
            );
            return Ok(());
        }
        let lines: Vec<String> = sealed
            .keys
            .iter()
            .chain(adopted.iter().copied())
            .map(Known::line)
            .chain(sealed.refused.iter().cloned())
            .collect();
        if self.write(stored.as_deref(), &lines.join("\n")).await? {
            let names: Vec<&str> = adopted.iter().map(|k| k.key_id.as_str()).collect();
            tracing::info!(
                "Adopted {} document signing key(s) from the unsealed record, as vectispire.signing.adopt-unsealed-keys \
                 names them: {}. They are published, and verify, from now on.",
                adopted.len(),
                names.join(", ")
            );
        } else {
            tracing::warn!(
                "The record of published document signing keys changed while the named keys were adopted; the next \
                 start adopts them."
            );
        }
        Ok(())
    }

    /// The generated key, revoked, refused at start as a configured one is — it was refused at its first use, and
    /// a revocation read as an outage. Only a key that can be read is refused here; one that cannot signs nothing
    /// either way, and its refusal stays the first use's.
    async fn refuse_revoked_stored_key(&self) -> Result<(), SigningError> {
        let stored = self.store.internal_value(STORED_KEY).await?.unwrap_or_default();
        let stored = java::trim(&stored);
        if stored.is_empty() {
            return Ok(());
        }
        let Ok(key) = self.decrypt(stored).await else {
            return Ok(());
        };
        refuse_revoked(&self.revoked, &key)
    }

    /// Records the key this instance signs with as the active one, before it signs anything.
    ///
    /// The key it replaces is marked retired, not removed: a document signed before the rotation is verified against
    /// it. Conditional on what was read, so two instances starting together each re-read and agree; two instances on
    /// two different keys — a rolling restart — do not take the record from each other.
    async fn register(&self, active: &KeyMaterial) -> Result<(), SigningError> {
        for _ in 0..REGISTER_ATTEMPTS {
            let read = self.sealed_record().await?;
            let Some(record) = self.open_record(read.as_deref()).await else {
                // Never overwritten: the key it was sealed under may come back.
                tracing::warn!(
                    "The document signing key {} is not recorded among the published keys: the record cannot be \
                     opened. It signs, and is published as the active key while it does.",
                    active.key_id
                );
                return Ok(());
            };
            let after = self.reconcile(&record.keys, active).await?;
            if after == record.keys {
                return Ok(());
            }
            if !self.encryption.is_configured() {
                // A record nobody can authenticate is a record anybody can write: none is kept.
                tracing::warn!(
                    "The document signing key {} is not recorded among the published keys: without ENCRYPTION_KEY the \
                     record cannot be sealed. Set ENCRYPTION_KEY before rotating the signing key, or what this one \
                     signed stops verifying.",
                    active.key_id
                );
                return Ok(());
            }
            let value: Vec<String> = after.iter().map(Known::line).chain(record.refused.iter().cloned()).collect();
            if self.write(read.as_deref(), &value.join("\n")).await? {
                if let Some(retired) = record.keys.iter().find(|k| k.retired_at.is_none() && k.key_id != active.key_id)
                {
                    tracing::info!(
                        "The document signing key is now {}; {} is retired and stays published for verification.",
                        active.key_id,
                        retired.key_id
                    );
                }
                return Ok(());
            }
        }
        Err(SigningError::RecordContended(active.key_id.clone()))
    }

    async fn reconcile(&self, before: &[Known], active: &KeyMaterial) -> Result<Vec<Known>, SigningError> {
        let now = self.clock.now();
        let mut after = Vec::with_capacity(before.len().saturating_add(2));
        let mut present = false;
        for k in before {
            if k.key_id == active.key_id {
                present = true;
                if let Some(retired_at) = k.retired_at
                    && retired_at > self.started_at
                {
                    // **Retired under this instance, not before it**: a rolling restart, and this is an instance not
                    // yet restarted signing for the first time. Taking the record back would publish the old key as
                    // active once the restart is over. It signs, as a retired key.
                    tracing::warn!(
                        "The document signing key {} was replaced on {}, after this instance started; it signs with it \
                         until it restarts, and the record keeps it retired.",
                        k.key_id,
                        retired_at.to_java_string().unwrap_or_default()
                    );
                    return Ok(before.to_vec());
                }
                // A key brought back — a rotation rolled back — is active again from now.
                after.push(if k.retired_at.is_none() {
                    k.clone()
                } else {
                    Known { active_from: Some(now), retired_at: None, ..k.clone() }
                });
            } else {
                after.push(if k.retired_at.is_none() {
                    Known { retired_at: Some(now), ..k.clone() }
                } else {
                    k.clone()
                });
            }
        }
        if !present {
            after.push(Known::of(&active.verifying, Some(now), None));
        }
        if self.configured
            && let Some(stored) = self.stored_public_key().await?
        {
            let id = cosign::key_id(&stored);
            if !after.iter().any(|k| k.key_id == id) {
                after.push(Known::of(&stored, None, Some(now)));
            }
        }
        Ok(after)
    }

    /// The public half of the generated key a configured key replaced, when there is one and it can be read.
    /// Unreadable is not fatal here: the configured key signs either way, and the warning says what will not verify.
    async fn stored_public_key(&self) -> Result<Option<VerifyingKey>, SigningError> {
        let stored = self.store.internal_value(STORED_KEY).await?.unwrap_or_default();
        let stored = java::trim(&stored);
        if stored.is_empty() {
            return Ok(None);
        }
        Ok(match self.decrypt(stored).await {
            Ok(key) => Some(key.verifying),
            Err(unreadable) => {
                tracing::warn!(
                    "The stored document signing key cannot be read ({unreadable}): documents it signed will not be \
                     verifiable against the published keys."
                );
                None
            }
        })
    }

    async fn load_or_create(&self) -> Result<KeyMaterial, SigningError> {
        let stored = self.store.internal_value(STORED_KEY).await?.unwrap_or_default();
        let stored = java::trim(&stored);
        if !stored.is_empty() {
            return self.decrypt_resealing(stored).await;
        }

        let generated = SigningKey::random(&mut rand_core::OsRng);
        let pem = cosign::private_pem(&generated).ok_or(SigningError::InvalidPrivateKey)?;
        // Refused without ENCRYPTION_KEY: a key that cannot be kept is a key whose signatures die with the process.
        let encrypted = self.encryption.encrypt(&pem, CONTEXT).await?;
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

    /// The key, re-sealed under the current `ENCRYPTION_KEY` when a previous one opened it. Written once and read
    /// once per start, nothing else would ever move it: after a rotation it stayed under the old key, and removing
    /// that key stopped every signature. A failed re-seal is not a failed load: the next start tries again.
    async fn decrypt_resealing(&self, stored: &str) -> Result<KeyMaterial, SigningError> {
        let secret = self.encryption.inspect(stored, CONTEXT).await;
        if secret.state() == SecretState::Unreadable {
            return Err(SigningError::Unreadable);
        }
        let key = KeyMaterial::of(cosign::parse_private_key(secret.plain_text())?);
        if secret.state() == SecretState::PreviousKey {
            let resealed = match self.encryption.encrypt(secret.plain_text(), CONTEXT).await {
                Ok(sealed) => self.store.reseal_internal(STORED_KEY, stored, &sealed).await.map_err(SigningError::from),
                Err(refused) => Err(refused.into()),
            };
            match resealed {
                Ok(true) => tracing::info!("Re-sealed the document signing key under the current ENCRYPTION_KEY."),
                Ok(false) => {}
                Err(refused) => tracing::warn!(
                    "The document signing key is still sealed under a previous ENCRYPTION_KEY and could not be \
                     re-sealed now ({refused}); the next start tries again."
                ),
            }
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

fn refuse_revoked(revoked: &BTreeSet<String>, key: &KeyMaterial) -> Result<(), SigningError> {
    if revoked.contains(&key.key_id) { Err(SigningError::Revoked(key.key_id.clone())) } else { Ok(()) }
}

/// A signature that matches one of Vectispire's keys, said for the key's status.
fn answer(key_id: String, status: KeyStatus, retired_at: Option<Instant>) -> Verification {
    let (valid, message) = match status {
        KeyStatus::Active => (true, "Signature valid: signed with Vectispire's signing key.".to_owned()),
        // No claim on when the document was signed: through a rolling restart an instance not yet restarted signs
        // with the key after the record has retired it. Retired is not revoked.
        KeyStatus::Retired => (
            true,
            format!(
                "Signature valid: signed with a previous Vectispire signing key, replaced on {}. The key was retired, \
                 not revoked: what it signed remains authentic.",
                retired_at.and_then(Instant::to_java_string).unwrap_or_else(|| "null".to_owned())
            ),
        ),
        // Not valid, though the arithmetic matches: whoever holds a revoked key can sign anything with it.
        KeyStatus::Revoked => (
            false,
            "The signature matches a Vectispire signing key that has been revoked: do not trust this document."
                .to_owned(),
        ),
    };
    Verification { valid, key_id: Some(key_id), vectispire_key: true, key_status: Some(status), message }
}
