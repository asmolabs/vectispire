"""Storage and retrieval of the SSH deploy keys used to clone private repositories.

The private half is the most sensitive thing this application holds: it grants read
access to somebody's source. It is encrypted at rest by `EncryptionService`, and —
since this service is the only place that reads it back — this is where the
ciphertext is bound to the row it belongs to.
"""
import uuid

from zanshin.models.ssh_key import SSHKey
from zanshin.repositories.ssh_key_repository import SSHKeyRepository
from zanshin.services.encryption_service import EncryptionService, SecretState


def private_key_context(key_id) -> str:
    """Associated data binding an encrypted private key to its row.

    Without it, a ciphertext is valid anywhere: an attacker able to write to the
    database could move repository B's encrypted deploy key into repository A's row
    and A would then be cloned with B's key, silently and successfully. With it, the
    swap fails to decrypt.

    Deliberately includes the column as well as the row: the same value must not be
    replayable into another field that happens to be encrypted.
    """
    return f"ssh_key:{key_id}:private_key"


class SSHKeyService:
    def __init__(self, ssh_key_repository: SSHKeyRepository, encryption_service: EncryptionService):
        self.ssh_key_repository = ssh_key_repository
        self.encryption_service = encryption_service

    def create_key(self, name: str, private_key: str, public_key: str = "") -> SSHKey:
        """Persist a key, encrypting the private half bound to its own row.

        Saved twice on purpose: the row id is part of the associated data, and it
        does not exist until the row does. The first save stores a placeholder, the
        second the bound ciphertext — so a crash in between leaves an unusable key
        rather than one encrypted without its binding.
        """
        key = self.ssh_key_repository.save(
            SSHKey(name=name, private_key="", public_key=public_key or None)
        )
        key.private_key = self.encryption_service.encrypt(
            private_key, context=private_key_context(key.id)
        )
        return self.ssh_key_repository.save(key)

    def get_decrypted_key(self, key_id: uuid.UUID) -> str:
        key = self.ssh_key_repository.find_by_id(key_id)
        if not key:
            raise RuntimeError("SSH Key not found")
        return self.encryption_service.decrypt(
            key.private_key, context=private_key_context(key.id)
        )

    def state_of(self, key: SSHKey) -> SecretState:
        """Whether this key is under the current encryption key, an older one, or none.

        Shown on the SSH keys page. A key readable only under a previous key has not
        been rotated, and the reason to surface it is concrete: the deployment that
        this application was written against had a deploy key encrypted with the
        default key published in this repository, so its private half was public. The
        only signal was a line in a log nobody reads — the failure mode this makes
        visible is finding out months later.
        """
        return self.encryption_service.state_of(
            key.private_key, context=private_key_context(key.id)
        )
