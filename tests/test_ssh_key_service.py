import uuid

import pytest

from zanshin.models.ssh_key import SSHKey
from zanshin.services.encryption_service import EncryptionService
from zanshin.services.ssh_key_service import SSHKeyService
from zanshin.repositories.ssh_key_repository import SSHKeyRepository


@pytest.fixture()
def encryption_service():
    return EncryptionService()


@pytest.fixture()
def ssh_key_service(ssh_key_repository, encryption_service):
    return SSHKeyService(ssh_key_repository, encryption_service)


def test_get_decrypted_key_round_trip(db_session, ssh_key_service, encryption_service):
    raw_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"
    key = SSHKey(
        name="deploy-key",
        private_key=encryption_service.encrypt(raw_private_key),
        public_key="ssh-rsa AAAA...",
    )
    db_session.add(key)
    db_session.commit()
    db_session.refresh(key)

    decrypted = ssh_key_service.get_decrypted_key(key.id)

    assert decrypted == raw_private_key


def test_get_decrypted_key_not_found_raises(ssh_key_service):
    with pytest.raises(RuntimeError):
        ssh_key_service.get_decrypted_key(uuid.uuid4())
