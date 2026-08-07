"""Encryption at rest for the secrets Zanshin stores.

**The application no longer ships a key to its own secrets.** An earlier implementation
had a constant, used whenever no key was configured, and published in this repository
along with the rest of the source. Anyone holding a copy of the database file could
read every stored SSH private key with nothing else. A previous change
stopped *encrypting* with it; this one stops the source code from being able to
*decrypt* with it. That is the half that mattered: a key an attacker can read is not a
key, and keeping it "just for compatibility" meant the compromise stayed live for as
long as one unrotated row existed.

**What replaces the compatibility argument.** Old ciphertexts are not stranded — they
are readable by an operator who deliberately provides the old key through
`ZANSHIN_PREVIOUS_ENCRYPTION_KEYS`. The difference is not cryptographic, it is who
decides: reading a legacy secret now takes an explicit act by someone with access to
the environment, instead of happening by default for anyone with the file.

That variable is a rotation mechanism, not a special case for the published key. There
was none before: changing `ENCRYPTION_KEY` made every stored secret unreadable, so the
documented procedure was to re-enter each key by hand. Now the old key stays available
for decryption while values migrate to the new one as they are re-saved.

**A secret still readable only under a previous key has not been rotated.** That is a
state worth seeing rather than a log line, so `state_of` reports it and the SSH keys
page shows it — and for a value that was under the published key, rotation means
generating a new key pair at the provider, not re-encrypting: the plaintext is already
public. See `docs/ROTATION_ET_PURGE.md`.
"""
import base64
import enum
import logging
import os
from typing import List, Optional, Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

ENCRYPTION_KEY_ENV_VAR = "ENCRYPTION_KEY"

# Keys to try when the current one fails, most recent first. Comma-separated, because
# a rotation can be interrupted and a deployment can legitimately be carrying two
# generations of secrets at once.
PREVIOUS_KEYS_ENV_VAR = "ZANSHIN_PREVIOUS_ENCRYPTION_KEYS"

KEY_LENGTH_BYTES = 32


class SecretState(enum.Enum):
    """How a stored ciphertext stands relative to the configured key."""

    CURRENT = "current"
    #: Readable, but only under a previous key — i.e. not yet rotated.
    PREVIOUS_KEY = "previous_key"
    UNREADABLE = "unreadable"


class MissingEncryptionKeyError(RuntimeError):
    """No `ENCRYPTION_KEY` is configured, so there is nothing to encrypt with.

    Raised at encryption time rather than at startup so that an existing deployment can
    still *read* what it already stored (and so the Settings/SSH pages still render)
    while refusing to write a new secret it could not protect.
    """

    def __init__(self):
        super().__init__(
            f"{ENCRYPTION_KEY_ENV_VAR} n'est pas définie : impossible de chiffrer "
            "une nouvelle valeur. Définissez une clé de 32 octets dans "
            "l'environnement de Zanshin avant d'enregistrer une clé SSH."
        )


class UndecryptableSecretError(RuntimeError):
    """No configured key reads this value.

    Its own class, and its own message, because the likely cause is now something an
    operator can act on: an upgrade removed the key the value was encrypted with. The
    previous version raised a bare `RuntimeError("Error decrypting value")`, which is
    what someone would see after upgrading — accurate and useless.
    """

    def __init__(self):
        super().__init__(
            "Valeur illisible avec la clé de chiffrement configurée. Si ce secret a "
            f"été enregistré avec une clé précédente, ajoutez-la à "
            f"{PREVIOUS_KEYS_ENV_VAR} (valeurs séparées par des virgules) le temps de "
            "le réenregistrer. S'il datait de la clé par défaut publiée dans ce dépôt, "
            "il est à considérer comme compromis : voir docs/ROTATION_ET_PURGE.md."
        )


def _aad(context: Optional[str]) -> Optional[bytes]:
    """Associated data for AES-GCM: authenticated, not encrypted."""
    return context.encode("utf-8") if context else None


def _derive(secret: str) -> bytes:
    """Coerce a configured secret to AES-256's 32 bytes.

    Kept byte-identical to the original implementation (truncate, or pad with NUL)
    rather than switched to a KDF: changing it would make every value already encrypted
    by this application undecryptable. A short passphrase is therefore no stronger than
    the entropy it contains — pass 32 random bytes.
    """
    key = secret.encode("utf-8")
    if len(key) < KEY_LENGTH_BYTES:
        return key.ljust(KEY_LENGTH_BYTES, b"\0")[:KEY_LENGTH_BYTES]
    return key[:KEY_LENGTH_BYTES]


def _previous_keys_from_environment() -> List[str]:
    raw = os.getenv(PREVIOUS_KEYS_ENV_VAR) or ""
    return [part for part in (piece.strip() for piece in raw.split(",")) if part]


class EncryptionService:
    """AES-GCM encryption for the secrets Zanshin stores (SSH private keys, tokens).

    Fails closed in both directions: with no `ENCRYPTION_KEY` in the environment,
    encryption raises rather than writing something it cannot protect, and decryption
    only tries keys an operator actually supplied.

    **Associated data.** `encrypt(value, context=...)` binds a ciphertext to where it
    lives, through AES-GCM's associated-data channel. Without it a ciphertext is valid
    *anywhere*: someone able to write to the database could copy the encrypted private
    key of one `ssh_key` row into another, and it would decrypt cleanly — so repository
    A would be cloned with repository B's deploy key, silently. The binding costs one
    string and makes that swap fail loudly.

    Values written before that existed carry no associated data, so decryption falls
    back to trying without it. Unlike the published key, that fallback weakens nothing:
    it accepts a ciphertext that is *already* under the right key, whereas the old
    fallback accepted one under a key everybody has.
    """

    def __init__(self, key: Optional[str] = None, previous_keys: Optional[Sequence[str]] = None):
        # `key` is for tests and for callers that manage the secret themselves; normal
        # operation reads the environment.
        configured = key if key is not None else os.getenv(ENCRYPTION_KEY_ENV_VAR)
        self._encryption_key: Optional[bytes] = _derive(configured) if configured else None
        if self._encryption_key is None:
            logger.warning(
                "%s is not set — stored secrets can be read but no new secret can be encrypted",
                ENCRYPTION_KEY_ENV_VAR,
            )

        previous = (
            list(previous_keys)
            if previous_keys is not None
            else _previous_keys_from_environment()
        )
        # Tried in order, current key first, so a rotated value never reports itself as
        # legacy. Duplicates are dropped rather than tried twice.
        self._decryption_keys: List[bytes] = []
        if self._encryption_key is not None:
            self._decryption_keys.append(self._encryption_key)
        for secret in previous:
            derived = _derive(secret)
            if derived not in self._decryption_keys:
                self._decryption_keys.append(derived)

    def is_configured(self) -> bool:
        """Whether a real key is available, i.e. whether `encrypt()` will work.
        Lets callers report the misconfiguration before collecting a secret."""
        return self._encryption_key is not None

    def _require_encryption_key(self) -> bytes:
        if self._encryption_key is None:
            raise MissingEncryptionKeyError()
        return self._encryption_key

    def encrypt(self, plain_text: str, context: Optional[str] = None) -> str:
        """Encrypt, optionally bound to `context`.

        `context` should identify *where* the value belongs — e.g.
        `"ssh_key:<uuid>:private_key"`. Anything decrypting it must pass the same
        string, so moving the ciphertext elsewhere makes it undecryptable.
        """
        if not plain_text:
            return plain_text
        key = self._require_encryption_key()
        try:
            aesgcm = AESGCM(key)
            iv = os.urandom(12)
            ciphertext = aesgcm.encrypt(iv, plain_text.encode("utf-8"), _aad(context))
            # Prepend IV to ciphertext
            combined = iv + ciphertext
            return base64.b64encode(combined).decode("utf-8")
        except Exception as e:
            raise RuntimeError("Error encrypting value") from e

    def decrypt(self, encrypted_text: str, context: Optional[str] = None) -> str:
        """Decrypt a value, trying the expected associated data first.

        Falls back to no associated data for rows written before contexts existed —
        logged, so an operator can see there is legacy data to re-save. The fallback
        deliberately does *not* try a different context: that would defeat the binding
        entirely.
        """
        plain_text, state = self._decrypt(encrypted_text, context)
        if state is SecretState.UNREADABLE:
            raise UndecryptableSecretError()
        if state is SecretState.PREVIOUS_KEY:
            logger.warning(
                "A stored secret is still encrypted with a previous key — re-save it to "
                "move it under the current %s",
                ENCRYPTION_KEY_ENV_VAR,
            )
        return plain_text

    def state_of(self, encrypted_text: str, context: Optional[str] = None) -> SecretState:
        """Whether this value is under the current key, an older one, or unreadable.

        Exists so a secret needing rotation can be *shown* rather than logged: the SSH
        keys page reads it. Costs one decryption, which is why it is called per row on
        a page, not per scan.
        """
        return self._decrypt(encrypted_text, context)[1]

    def _decrypt(self, encrypted_text: str, context: Optional[str]):
        if not encrypted_text:
            return encrypted_text, SecretState.CURRENT
        try:
            combined = base64.b64decode(encrypted_text.encode("utf-8"))
            iv = combined[:12]
            ciphertext = combined[12:]
        except Exception:
            return "", SecretState.UNREADABLE

        # (associated data, is_legacy_shape) in the order they are tried.
        aad_candidates = [(_aad(context), False)]
        if context is not None:
            aad_candidates.append((None, True))

        for index, key in enumerate(self._decryption_keys):
            for aad, legacy_aad in aad_candidates:
                try:
                    decrypted = AESGCM(key).decrypt(iv, ciphertext, aad)
                except Exception:
                    continue
                if legacy_aad:
                    logger.info(
                        "A stored secret predates context binding — re-save it to bind it "
                        "to its row"
                    )
                # Index 0 is the current key only when there *is* one: with no
                # `ENCRYPTION_KEY` configured, every key in the list is a previous
                # one, and reporting those as current would hide exactly the
                # deployment that most needs to be told.
                is_current = index == 0 and self._encryption_key is not None
                state = SecretState.CURRENT if is_current else SecretState.PREVIOUS_KEY
                return decrypted.decode("utf-8"), state

        # Authentication failure under every candidate key: wrong key, or
        # tampered/corrupt ciphertext. Indistinguishable by design.
        return "", SecretState.UNREADABLE
