"""Basic CRUD round-trip coverage for the simple SQLAlchemy repository
wrappers. These have little branching logic, but a wrong column/attribute
name would break the app at runtime with no warning until someone hits that
code path — cheap tests here catch that class of regression early."""
import uuid

from zanshin.models.setting import Setting
from zanshin.models.ssh_key import SSHKey
from zanshin.models.api_key import ApiKey


# --- UserRepository ---

def test_user_repository_find_by_username_and_email(user_repository, make_user):
    make_user(username="alice")

    assert user_repository.find_by_username("alice") is not None
    assert user_repository.find_by_username("nobody") is None


def test_user_repository_delete(db_session, user_repository, make_user):
    user = make_user(username="bob")
    user_repository.delete(user)
    assert user_repository.find_by_id(user.id) is None


# --- RepositoryRepository ---

def test_repository_repository_crud(repository_repository, make_repository):
    repo = make_repository(url="git@example.com:org/repo.git")

    assert repository_repository.find_by_id(repo.id).url == "git@example.com:org/repo.git"
    assert len(repository_repository.find_all()) == 1

    assert repository_repository.delete_by_id(repo.id) is True
    assert repository_repository.find_by_id(repo.id) is None
    assert repository_repository.delete_by_id(repo.id) is False


# --- ContainerRepository ---

def test_container_repository_crud(container_repository, make_container):
    c = make_container(image_name="nginx", tag="1.25", registry="docker.io")

    found = container_repository.find_by_registry_and_image_name_and_tag("docker.io", "nginx", "1.25")
    assert found is not None
    assert found.id == c.id

    assert container_repository.delete_by_id(c.id) is True
    assert container_repository.find_by_id(c.id) is None


# --- ScanRepository ---

def test_scan_repository_find_all_by_repository_and_container(scan_repository, make_scan, make_repository, make_container):
    repo = make_repository()
    container = make_container()
    make_scan(repo_id=repo.id)
    make_scan(repo_id=repo.id)
    make_scan(container_id=container.id)

    assert len(scan_repository.find_all_by_repository_id(repo.id)) == 2
    assert len(scan_repository.find_all_by_container_id(container.id)) == 1
    assert len(scan_repository.find_all()) == 3


def test_scan_repository_delete(db_session, scan_repository, make_scan):
    scan = make_scan()
    scan_repository.delete(scan)
    assert scan_repository.find_by_id(scan.id) is None


# --- SSHKeyRepository ---

def test_ssh_key_repository_crud(db_session, ssh_key_repository):
    key = SSHKey(name="deploy", private_key="encrypted-blob", public_key="ssh-rsa AAA")
    ssh_key_repository.save(key)

    assert ssh_key_repository.find_by_name("deploy").id == key.id
    assert ssh_key_repository.find_by_id(key.id) is not None

    assert ssh_key_repository.delete_by_id(key.id) is True
    assert ssh_key_repository.find_by_id(key.id) is None
    assert ssh_key_repository.delete_by_id(uuid.uuid4()) is False


# --- ApiKeyRepository ---

def test_api_key_repository_crud(db_session, api_key_repository):
    key = ApiKey(name="CI key", key_hash="hashed", prefix="zsk_ab12")
    api_key_repository.save(key)

    assert len(api_key_repository.find_all()) == 1
    assert api_key_repository.find_by_id(key.id) is not None

    assert api_key_repository.delete_by_id(key.id) is True
    assert api_key_repository.find_by_id(key.id) is None


# --- SettingRepository ---

def test_setting_repository_crud(db_session, setting_repository):
    setting_repository.save(Setting(key="scan_backend", value="docker"))

    assert setting_repository.find_by_key("scan_backend").value == "docker"
    assert setting_repository.find_by_key("missing") is None

    assert setting_repository.delete_by_key("scan_backend") is True
    assert setting_repository.find_by_key("scan_backend") is None


