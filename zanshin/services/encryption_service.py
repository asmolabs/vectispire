import base64
import logging
import os
from typing import List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

ENCRYPTION_KEY_ENV_VAR = "ENCRYPTION_KEY"

# The key an earlier implementation of this application used when none was
# configured. It is published in this repository, so it protects nothing — but
# rows encrypted with it still exist, so it stays usable for *decryption* to
# avoid stranding them. New values are never encrypted with it: `encrypt()`
# refuses to run without a real key (see `_require_encryption_key`).
LEGACY_DEFAULT_KEY = "my-secret-encryption-key-32bytes"

KEY_LENGTH_BYTES = 32


class MissingEncryptionKeyError(RuntimeError):
    """No `ENCRYPTION_KEY` is configured, so there is nothing to encrypt with.

    Raised at encryption time rather than at startup so that an existing
    deployment can still *read* what it already stored (and so the Settings/SSH
    pages still render) while refusing to write new secrets under a key that is
    public knowledge.
    """

    def __init__(self):
        super().__init__(
            f"{ENCRYPTION_KEY_ENV_VAR} n'est pas définie : impossible de chiffrer "
            "une nouvelle valeur. Définissez une clé de 32 octets dans "
            "l'environnement de Zanshin avant d'enregistrer une clé SSH."
        )


def _derive(secret: str) -> bytes:
    """Coerce a configured secret to AES-256's 32 bytes.

    Kept byte-identical to the original implementation (truncate, or pad with
    NUL) rather than switched to a KDF: changing it would make every value
    already encrypted by this application undecryptable. A short passphrase is
    therefore no stronger than the entropy it contains — pass 32 random bytes.
    """
    key = secret.encode("utf-8")
    if len(key) < KEY_LENGTH_BYTES:
        return key.ljust(KEY_LENGTH_BYTES, b"\0")[:KEY_LENGTH_BYTES]
    return key[:KEY_LENGTH_BYTES]


class EncryptionService:
    """AES-GCM encryption for the secrets Zanshin stores (SSH private keys).

    Fails closed: with no `ENCRYPTION_KEY` in the environment, encryption
    raises instead of silently falling back to the well-known legacy key that
    ships with this repository — which would have meant that anyone holding a
    copy of the database file could read every stored SSH private key.

    Decryption accepts the legacy key as a fallback, so enabling a real key on
    an existing deployment doesn't strand data: values re-encrypt to the new
    key the next time they're saved.
    """

    def __init__(self, key: Optional[str] = None):
        # `key` is for tests and for callers that manage the secret
        # themselves; normal operation reads the environment.
        configured = key if key is not None else os.getenv(ENCRYPTION_KEY_ENV_VAR)
        self._encryption_key: Optional[bytes] = _derive(configured) if configured else None
        if self._encryption_key is None:
            logger.warning(
                "%s is not set — stored secrets can be read but no new secret can be encrypted",
                ENCRYPTION_KEY_ENV_VAR,
            )

        # Tried in order. The legacy key comes last so a configured key always
        # wins, and it is skipped entirely when it *is* the configured key.
        self._decryption_keys: List[bytes] = []
        if self._encryption_key is not None:
            self._decryption_keys.append(self._encryption_key)
        legacy = _derive(LEGACY_DEFAULT_KEY)
        if legacy not in self._decryption_keys:
            self._decryption_keys.append(legacy)

    def is_configured(self) -> bool:
        """Whether a real key is available, i.e. whether `encrypt()` will work.
        Lets callers report the misconfiguration before collecting a secret."""
        return self._encryption_key is not None

    def _require_encryption_key(self) -> bytes:
        if self._encryption_key is None:
            raise MissingEncryptionKeyError()
        return self._encryption_key

    def encrypt(self, plain_text: str) -> str:
        if not plain_text:
            return plain_text
        key = self._require_encryption_key()
        try:
            aesgcm = AESGCM(key)
            iv = os.urandom(12)
            ciphertext = aesgcm.encrypt(iv, plain_text.encode("utf-8"), None)
            # Prepend IV to ciphertext
            combined = iv + ciphertext
            return base64.b64encode(combined).decode("utf-8")
        except Exception as e:
            raise RuntimeError("Error encrypting value") from e

    def decrypt(self, encrypted_text: str) -> str:
        if not encrypted_text:
            return encrypted_text
        try:
            combined = base64.b64decode(encrypted_text.encode("utf-8"))
            iv = combined[:12]
            ciphertext = combined[12:]
        except Exception as e:
            raise RuntimeError("Error decrypting value") from e

        for index, key in enumerate(self._decryption_keys):
            try:
                decrypted = AESGCM(key).decrypt(iv, ciphertext, None)
            except Exception:
                continue
            if index > 0:
                logger.warning(
                    "A stored secret is still encrypted with the legacy default key — "
                    "re-save it to move it under %s",
                    ENCRYPTION_KEY_ENV_VAR,
                )
            return decrypted.decode("utf-8")

        # Authentication failure under every candidate key: wrong key, or
        # tampered/corrupt ciphertext. Indistinguishable by design, and
        # reported the same way the single-key implementation did.
        raise RuntimeError("Error decrypting value")
