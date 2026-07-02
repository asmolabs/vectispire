import uuid
from zanshin.repositories.ssh_key_repository import SSHKeyRepository
from zanshin.services.encryption_service import EncryptionService

class SSHKeyService:
    def __init__(self, ssh_key_repository: SSHKeyRepository, encryption_service: EncryptionService):
        self.ssh_key_repository = ssh_key_repository
        self.encryption_service = encryption_service

    def get_decrypted_key(self, key_id: uuid.UUID) -> str:
        key = self.ssh_key_repository.find_by_id(key_id)
        if not key:
            raise RuntimeError("SSH Key not found")
        return self.encryption_service.decrypt(key.private_key)
