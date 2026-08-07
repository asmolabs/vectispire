import uuid

import pytest

from zanshin.models.ssh_key import SSHKey
from zanshin.services.encryption_service import EncryptionService, SecretState
from zanshin.services.ssh_key_service import SSHKeyService
from zanshin.repositories.ssh_key_repository import SSHKeyRepository


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


# --- Which encryption key a stored key is under --------------------------------
#
# Surfaced on the SSH keys page. The deployment this was written against had a deploy
# key encrypted with the default key that used to ship in this repository — so its
# private half was public — and the only signal was a log line. The failure mode being
# closed here is finding out months later.

def test_a_freshly_saved_key_is_under_the_current_key(ssh_key_service):
    key = ssh_key_service.create_key("deploy-key", "-----BEGIN-----\nfake\n-----END-----")

    assert ssh_key_service.state_of(key) is SecretState.CURRENT


def test_a_key_readable_only_under_a_previous_key_is_reported_as_such(
    db_session, ssh_key_repository
):
    """The "à faire tourner" state: readable, but only because the old key is still
    listed in the environment."""
    old = EncryptionService(key="the-old-key-of-exactly-32-bytes!!", previous_keys=[])
    saved = SSHKeyService(ssh_key_repository, old).create_key("deploy-key", "secret")

    rotated = SSHKeyService(
        ssh_key_repository,
        EncryptionService(
            key="brand-new-rotated-key-32-bytes!!",
            previous_keys=["the-old-key-of-exactly-32-bytes!!"],
        ),
    )

    assert rotated.state_of(saved) is SecretState.PREVIOUS_KEY
    # Still usable in the meantime — rotation must not take scanning down with it.
    assert rotated.get_decrypted_key(saved.id) == "secret"


def test_a_key_no_configured_key_reads_is_reported_rather_than_raising(
    db_session, ssh_key_repository
):
    """One unreadable key must not take the page down: the whole point is to show it."""
    old = EncryptionService(key="the-old-key-of-exactly-32-bytes!!", previous_keys=[])
    saved = SSHKeyService(ssh_key_repository, old).create_key("deploy-key", "secret")

    stranded = SSHKeyService(
        ssh_key_repository,
        EncryptionService(key="brand-new-rotated-key-32-bytes!!", previous_keys=[]),
    )

    assert stranded.state_of(saved) is SecretState.UNREADABLE
    with pytest.raises(RuntimeError):
        stranded.get_decrypted_key(saved.id)
