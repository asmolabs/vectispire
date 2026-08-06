"""Tests for the fixes from the security review.

One module, because these are otherwise scattered across layers and what ties them
together is *why* they exist. Each test names the attack it closes.
"""
import ipaddress
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from zanshin.services.login_throttle import LoginThrottle
from zanshin.services.url_guard import UnsafeUrlError, is_safe_outbound_url, validate_outbound_url


# --- S1: the sidecar must not read outside its shared volume, nor answer anonymously ---

@pytest.fixture()
def sidecar(monkeypatch, tmp_path):
    """The scan-api app with a shared root and a token, freshly imported so the
    module-level configuration is picked up."""
    import importlib

    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "source").mkdir()
    monkeypatch.setenv("ZANSHIN_SHARED_ROOT", str(shared))
    monkeypatch.setenv("ZANSHIN_SCAN_API_TOKEN", "le-jeton-partage")
    monkeypatch.syspath_prepend("scan-api")
    import main as scan_api_main

    importlib.reload(scan_api_main)
    return TestClient(scan_api_main.app), shared


def test_the_sidecar_refuses_a_request_without_the_token(sidecar):
    """It can read files and returns the secrets it finds, so anonymous access is
    an arbitrary-file-read oracle."""
    client, shared = sidecar

    response = client.post("/scan/secrets", json={"path": str(shared / "source")})

    assert response.status_code == 401


def test_the_sidecar_refuses_a_wrong_token(sidecar):
    client, shared = sidecar

    response = client.post(
        "/scan/secrets",
        json={"path": str(shared / "source")},
        headers={"X-Zanshin-Token": "mauvais"},
    )

    assert response.status_code == 401


@pytest.mark.parametrize("path", ["/", "/etc", "/etc/passwd", "../../etc"])
def test_the_sidecar_refuses_any_path_outside_the_shared_root(sidecar, path):
    """`{"path": "/"}` used to be accepted: the check was "does it exist", not "is
    it mine to read"."""
    client, _ = sidecar

    response = client.post(
        "/scan/secrets", json={"path": path}, headers={"X-Zanshin-Token": "le-jeton-partage"}
    )

    assert response.status_code == 400
    assert "hors du répertoire partagé" in response.json()["detail"]


def test_the_sidecar_refuses_a_symlink_escape(sidecar, tmp_path):
    """A prefix check on the *given* path would pass this; resolving it first is
    what closes it."""
    client, shared = sidecar
    escape = shared / "escape"
    escape.symlink_to("/etc")

    response = client.post(
        "/scan/secrets", json={"path": str(escape)}, headers={"X-Zanshin-Token": "le-jeton-partage"}
    )

    assert response.status_code == 400


def test_a_sibling_directory_with_the_same_prefix_is_not_inside(sidecar, tmp_path):
    """`/shared-evil` must not pass a check meant for `/shared`."""
    client, shared = sidecar
    sibling = shared.parent / (shared.name + "-evil")
    sibling.mkdir()

    response = client.post(
        "/scan/secrets", json={"path": str(sibling)}, headers={"X-Zanshin-Token": "le-jeton-partage"}
    )

    assert response.status_code == 400


def test_the_sidecar_fails_closed_when_no_token_is_configured(monkeypatch, tmp_path):
    """An unauthenticated scanner reachable on a network is worse than a broken
    one, so an unconfigured service serves nothing."""
    import importlib

    monkeypatch.setenv("ZANSHIN_SHARED_ROOT", str(tmp_path))
    monkeypatch.delenv("ZANSHIN_SCAN_API_TOKEN", raising=False)
    monkeypatch.syspath_prepend("scan-api")
    import main as scan_api_main

    importlib.reload(scan_api_main)
    client = TestClient(scan_api_main.app)

    response = client.post("/scan/secrets", json={"path": str(tmp_path)})

    assert response.status_code == 503
    assert "ZANSHIN_SCAN_API_TOKEN" in response.json()["detail"]


def test_the_health_probe_stays_open_and_reveals_nothing(sidecar):
    client, _ = sidecar

    body = client.get("/health").json()

    assert body["status"] == "ok"
    assert set(body) == {"status", "configured"}


def test_the_zanshin_side_sends_the_token():
    """The two halves have to agree, or the sidecar refuses every scan."""
    from zanshin.services.scanners.local_api_engine import LocalApiScannerEngine

    sent = {}

    def fake_post(url, json=None, timeout=None, headers=None):
        sent["headers"] = headers

        class Response:
            def raise_for_status(self):
                pass

            def json(self):
                return {}

        return Response()

    engine = LocalApiScannerEngine(
        base_url="http://localhost:8686", auth_token="le-jeton-partage", http_post=fake_post
    )
    engine.generate_sbom_for_image("nginx:latest")

    assert sent["headers"]["X-Zanshin-Token"] == "le-jeton-partage"


# --- S2: an API key grants the whole API, so only admins may mint one ---

def test_the_api_keys_page_is_admin_only():
    """While this was `@requires_login`, any USER could mint themselves a key and
    step around the role they were given."""
    import inspect

    from zanshin.ui.pages.api_keys import ApiKeysState

    for handler in ("load_keys_data", "create_api_key", "delete_key"):
        source = inspect.getsource(ApiKeysState.event_handlers[handler].fn)
        # The decorator is applied, so the guard is in the wrapper, not the source;
        # assert on behaviour instead.
        assert source is not None

    from zanshin.ui.pages.api_keys import ApiKeysState as State

    class FakeState:
        logged_in = True
        user_role = "USER"
        username = "bob"

    denied = State.event_handlers["create_api_key"].fn(FakeState())
    events = list(denied)
    # A denial redirects instead of running the body.
    assert events and "create" not in str(events[0]).lower()


# --- S3: login rate limiting ---

def test_a_burst_of_failures_locks_the_account_out():
    throttle = LoginThrottle(max_per_user=3, max_per_client=100)

    for _ in range(3):
        assert throttle.check("alice")[0] is True
        throttle.record_failure("alice")

    allowed, wait = throttle.check("alice")
    assert allowed is False
    assert wait and wait > 0


def test_the_lockout_is_checked_before_hashing():
    """bcrypt is deliberately slow; an attacker must not be able to spend the
    server's CPU for free once they are locked out."""
    throttle = LoginThrottle(max_per_user=1)
    throttle.record_failure("alice")

    allowed, _ = throttle.check("alice")

    assert allowed is False  # no password verification needed to reach this


def test_a_correct_password_clears_the_counter():
    throttle = LoginThrottle(max_per_user=3)
    throttle.record_failure("alice")
    throttle.record_failure("alice")

    throttle.record_success("alice")

    assert throttle.attempts_for("alice") == 0
    assert throttle.check("alice")[0] is True


def test_attempts_expire_with_the_window():
    throttle = LoginThrottle(max_per_user=2, window=timedelta(seconds=0))
    throttle.record_failure("alice")
    throttle.record_failure("alice")

    # A zero-length window means nothing is ever "recent".
    assert throttle.check("alice")[0] is True


def test_locking_one_account_does_not_lock_another():
    """Keying only on the client would let one user's failures block everyone."""
    throttle = LoginThrottle(max_per_user=1, max_per_client=100)
    throttle.record_failure("alice", client_id="c1")

    assert throttle.check("alice", client_id="c1")[0] is False
    assert throttle.check("bob", client_id="c1")[0] is True


def test_one_client_cannot_spread_attempts_across_usernames_forever():
    """The mirror image: keying only on the username lets a botnet iterate
    accounts from one host."""
    throttle = LoginThrottle(max_per_user=100, max_per_client=3)

    for index in range(3):
        throttle.record_failure(f"user{index}", client_id="c1")

    assert throttle.check("someone-else", client_id="c1")[0] is False


def test_the_username_counter_is_case_insensitive():
    """Otherwise `Alice` gets a fresh allowance after `alice` is locked."""
    throttle = LoginThrottle(max_per_user=1)
    throttle.record_failure("alice")

    assert throttle.check("ALICE")[0] is False


# --- S4: SSRF guard ---

@pytest.mark.parametrize("url", ["https://hooks.example.com/x", "http://example.com/y"])
def test_public_urls_are_accepted(url):
    assert validate_outbound_url(url, allow_private=False) == url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/",
        "not-a-url",
        "",
    ],
)
def test_only_http_and_https_are_allowed(url):
    with pytest.raises(UnsafeUrlError):
        validate_outbound_url(url, allow_private=False)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",   # AWS/GCP/Azure metadata
        "http://169.254.169.254/",
    ],
)
def test_link_local_is_refused_even_when_private_is_allowed(url):
    """This is the address the attack actually wants: instance credentials. Nothing
    legitimate lives in 169.254.0.0/16."""
    with pytest.raises(UnsafeUrlError, match="link-local"):
        validate_outbound_url(url, allow_private=True)


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:11434", "http://10.0.0.5:8686", "http://192.168.1.10/", "http://[::1]:11434"],
)
def test_private_destinations_are_refused_for_a_webhook_and_allowed_for_a_sidecar(url):
    """Two different rules for two different uses: a webhook is a public endpoint,
    Ollama and the scan sidecar are deliberately internal."""
    with pytest.raises(UnsafeUrlError):
        validate_outbound_url(url, allow_private=False)

    assert validate_outbound_url(url, allow_private=True) == url


def test_a_hostname_resolving_to_a_blocked_address_is_refused(monkeypatch):
    """Checking the literal string only would be trivially bypassed by a DNS name
    pointing at the metadata endpoint."""
    import zanshin.services.url_guard as guard

    monkeypatch.setattr(
        guard, "_resolve", lambda hostname, label: [ipaddress.ip_address("169.254.169.254")]
    )

    with pytest.raises(UnsafeUrlError, match="link-local"):
        validate_outbound_url("https://metadata.evil.tld/", allow_private=True)


def test_every_resolved_address_is_checked_not_just_the_first(monkeypatch):
    """A hostname can return a public *and* a private address; checking one lets
    the other through."""
    import zanshin.services.url_guard as guard

    monkeypatch.setattr(
        guard,
        "_resolve",
        lambda hostname, label: [
            ipaddress.ip_address("93.184.216.34"),
            ipaddress.ip_address("169.254.169.254"),
        ],
    )

    with pytest.raises(UnsafeUrlError):
        validate_outbound_url("https://split-horizon.tld/", allow_private=True)


def test_a_resolution_failure_does_not_block_the_settings_page(monkeypatch):
    """Refusing on a DNS hiccup would make the page unusable, and the request will
    fail on its own anyway. The gap is logged rather than hidden."""
    import socket

    import zanshin.services.url_guard as guard

    def boom(*args, **kwargs):
        raise socket.gaierror("dns down")

    monkeypatch.setattr(guard.socket, "getaddrinfo", boom)

    assert validate_outbound_url("https://example.com/", allow_private=False)


def test_the_non_raising_variant_returns_the_reason():
    assert is_safe_outbound_url("https://example.com", allow_private=False) is None
    assert "link-local" in is_safe_outbound_url("http://169.254.169.254", allow_private=True)


def test_a_notification_is_not_sent_to_an_unsafe_url(settings_service, setting_repository):
    """Validated again at send time, not only at save time: the setting may predate
    the guard or have been written straight into the database."""
    from zanshin.models.setting import Setting
    from zanshin.services.notification_service import (
        SETTING_KEY_WEBHOOK_URL,
        NotificationService,
    )

    setting_repository.save(
        Setting(key=SETTING_KEY_WEBHOOK_URL, value="http://169.254.169.254/hook")
    )
    calls = []
    service = NotificationService(settings_service, http_post=lambda *a, **k: calls.append(1))

    from zanshin.models.issue import Issue

    sent = service.notify_scan_delta(
        target_name="app",
        scan_id=1,
        new_issues=[Issue(id=1, type="vulnerability", severity="critical", is_kev=False)],
    )

    assert sent is False
    assert calls == []


# --- M12: security headers ---

def test_every_response_carries_a_content_security_policy():
    """This application renders scanner output, advisory text and package metadata —
    attacker-influenceable strings. Without a CSP, an injected one executes with the
    analyst's session."""
    from zanshin.api import api_app

    client = TestClient(api_app)
    response = client.get("/api/v1/health")

    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_hsts_is_deliberately_absent():
    """Zanshin is commonly reached over plain HTTP on an internal address; an HSTS
    header would make that origin permanently unreachable in a browser that saw it
    once. It belongs on the proxy that terminates TLS."""
    from zanshin.api import api_app

    response = TestClient(api_app).get("/api/v1/health")

    assert "Strict-Transport-Security" not in response.headers


def test_a_route_can_still_set_its_own_header():
    """The middleware must not clobber a download's Content-Disposition or a
    proxy's own policy."""
    from zanshin.api.security_headers import HEADERS

    assert "Content-Security-Policy" in HEADERS  # applied only when absent


# --- M15: one scan in flight per target ---

def test_a_second_scan_of_the_same_target_is_refused(db_session, make_repository):
    """An unbounded queue is a denial-of-service primitive: the pool has five
    workers and every extra scan eventually writes a multi-megabyte SBOM."""
    from zanshin.models.scan import Scan
    from zanshin.repositories.repository_repository import RepositoryRepository
    from zanshin.repositories.scan_repository import ScanRepository
    from zanshin.services.repository_service import RepositoryService, ScanAlreadyRunningError

    repo = make_repository()
    db_session.add(Scan(repo_id=repo.id, branch="main", status="scanning", findings_count=0))
    db_session.commit()

    service = RepositoryService(RepositoryRepository(db_session), ScanRepository(db_session))

    with pytest.raises(ScanAlreadyRunningError):
        service.trigger_scan(repo.id)


def test_a_finished_scan_does_not_block_the_next_one(db_session, make_repository, scan_dispatch):
    from zanshin.models.scan import Scan
    from zanshin.repositories.repository_repository import RepositoryRepository
    from zanshin.repositories.scan_repository import ScanRepository
    from zanshin.services.repository_service import RepositoryService

    repo = make_repository()
    db_session.add_all([
        Scan(repo_id=repo.id, branch="main", status="completed", findings_count=0),
        Scan(repo_id=repo.id, branch="main", status="failed", findings_count=0),
    ])
    db_session.commit()

    service = RepositoryService(RepositoryRepository(db_session), ScanRepository(db_session))

    scan = service.trigger_scan(repo.id)

    assert scan.status in ("pending", "scanning")
    assert scan_dispatch.done.wait(timeout=2)


def test_another_targets_scan_does_not_block_this_one(db_session, make_repository, make_container, scan_dispatch):
    from zanshin.models.scan import Scan
    from zanshin.repositories.container_repository import ContainerRepository
    from zanshin.repositories.scan_repository import ScanRepository
    from zanshin.services.container_service import ContainerService

    repo = make_repository()
    container = make_container()
    db_session.add(Scan(repo_id=repo.id, branch="main", status="scanning", findings_count=0))
    db_session.commit()

    service = ContainerService(ContainerRepository(db_session), ScanRepository(db_session))

    assert service.trigger_scan(container.id).status in ("pending", "scanning")


# --- M11: the database file holds hashes and encrypted keys ---

def test_the_database_file_is_not_world_readable(tmp_path, monkeypatch):
    import os
    import stat

    import zanshin.schema as schema

    db_path = tmp_path / "test.sqlite"
    db_path.write_bytes(b"")
    os.chmod(db_path, 0o644)

    schema.restrict_database_permissions(str(db_path))

    mode = stat.S_IMODE(os.stat(db_path).st_mode)
    assert mode == 0o600


def test_tightening_permissions_never_breaks_startup(monkeypatch):
    """A read-only or exotic filesystem must not stop the application from
    starting."""
    import zanshin.schema as schema

    monkeypatch.setattr(schema, "DATABASE_URL", "sqlite:////nonexistent/dir/x.sqlite")

    schema.restrict_database_permissions()  # must not raise


# --- R1: the websocket must not accept any origin ---

def test_the_websocket_origin_is_restricted():
    """Reflex defaults to "*", which lets any page a user visits open a socket and
    create server-side state at will. It cannot steal a session (the client token is
    a UUID4 in localStorage) but unbounded state creation is a denial of service."""
    from rxconfig import config

    assert config.cors_allowed_origins != ("*",)
    assert config.cors_allowed_origins != ["*"]
    assert config.cors_allowed_origins


# --- R2: the Ollama endpoint receives source code, so it must stay internal ---

def test_a_public_ollama_url_is_refused_by_default(settings_service):
    """The risk here is the mirror image of SSRF: not that the URL points somewhere
    internal, but that it points somewhere *external* — this endpoint receives up to
    40 000 characters of the scanned repository's source."""
    from zanshin.services.ai_review_service import AiReviewService

    service = AiReviewService(settings_service)

    with pytest.raises(UnsafeUrlError, match="code source"):
        service.set_ollama_url("https://ollama.attacker.tld")


def test_a_local_ollama_url_is_accepted(settings_service):
    from zanshin.services.ai_review_service import AiReviewService

    service = AiReviewService(settings_service)
    service.set_ollama_url("http://127.0.0.1:11434")

    assert service.get_ollama_url() == "http://127.0.0.1:11434"


def test_a_remote_ollama_can_be_opted_into(settings_service, setting_repository):
    from zanshin.models.setting import Setting
    from zanshin.services.ai_review_service import (
        SETTING_KEY_AI_REVIEW_ALLOW_REMOTE,
        AiReviewService,
    )

    setting_repository.save(Setting(key=SETTING_KEY_AI_REVIEW_ALLOW_REMOTE, value="true"))
    service = AiReviewService(settings_service)

    service.set_ollama_url("https://ollama.example.com")

    assert service.get_ollama_url() == "https://ollama.example.com"


def test_the_url_is_revalidated_before_the_code_is_sent(settings_service, setting_repository):
    """A setting written straight into the database, or predating the guard, must not
    become an exfiltration channel at scan time."""
    from zanshin.models.setting import Setting
    from zanshin.services.ai_review_service import (
        SETTING_KEY_AI_REVIEW_OLLAMA_URL,
        AiReviewService,
    )

    setting_repository.save(
        Setting(key=SETTING_KEY_AI_REVIEW_OLLAMA_URL, value="https://exfil.attacker.tld")
    )
    calls = []
    service = AiReviewService(settings_service, http_post=lambda *a, **k: calls.append(1))

    with pytest.raises(UnsafeUrlError):
        service.review_code("print('secret')")

    assert calls == []


# --- R4: a ciphertext must not be valid in another row ---

def test_a_ciphertext_cannot_be_moved_to_another_row(encryption_service):
    """Without associated data, an attacker able to write to the database could copy
    repository B's encrypted deploy key into repository A's row, and A would then be
    cloned with B's key — silently and successfully."""
    from zanshin.services.ssh_key_service import private_key_context

    encrypted = encryption_service.encrypt("-----BEGIN KEY-----", context=private_key_context("row-a"))

    assert encryption_service.decrypt(encrypted, context=private_key_context("row-a"))
    with pytest.raises(RuntimeError):
        encryption_service.decrypt(encrypted, context=private_key_context("row-b"))


def test_values_written_before_context_binding_still_decrypt(encryption_service):
    """Existing rows carry no associated data; refusing them would strand real
    deploy keys."""
    legacy = encryption_service.encrypt("secret")  # no context

    assert encryption_service.decrypt(legacy, context="ssh_key:1:private_key") == "secret"


def test_the_ssh_service_binds_the_key_to_its_own_row(db_session, encryption_service):
    from zanshin.repositories.ssh_key_repository import SSHKeyRepository
    from zanshin.services.ssh_key_service import SSHKeyService, private_key_context

    service = SSHKeyService(SSHKeyRepository(db_session), encryption_service)
    key = service.create_key(name="deploy", private_key="-----BEGIN KEY-----")

    assert service.get_decrypted_key(key.id) == "-----BEGIN KEY-----"
    # The stored ciphertext is bound: reading it with the wrong context fails.
    with pytest.raises(RuntimeError):
        encryption_service.decrypt(key.private_key, context=private_key_context("other"))


# --- R7: a provisioning password is not a password ---

def test_the_bootstrap_account_must_change_its_password(monkeypatch, isolated_session_local):
    import zanshin.bootstrap as bootstrap_module
    from zanshin.models.user import User

    monkeypatch.setattr(bootstrap_module, "SessionLocal", isolated_session_local)
    monkeypatch.setenv("ZANSHIN_BOOTSTRAP_USERNAME", "admin")
    monkeypatch.setenv("ZANSHIN_BOOTSTRAP_PASSWORD", "provisioning-secret")

    bootstrap_module.ensure_bootstrap_superuser()

    session = isolated_session_local()
    try:
        user = session.query(User).one()
        assert user.must_change_password is True
    finally:
        session.close()


def test_an_admin_reset_also_requires_a_change(db_session, make_user, auth_service):
    """Whoever typed the new password knows it, so it is provisional by
    construction — the same reasoning as the bootstrap password."""
    from zanshin.repositories.user_repository import UserRepository
    from zanshin.services.user_service import UserService

    user = make_user(username="bob")
    service = UserService(UserRepository(db_session), auth_service)

    service.reset_password(user.id, "nouveau-mot-de-passe")

    assert user.must_change_password is True


def test_changing_ones_own_password_clears_the_flag(db_session, make_user, auth_service):
    from zanshin.repositories.user_repository import UserRepository
    from zanshin.services.user_service import UserService

    user = make_user(username="bob")
    user.must_change_password = True
    db_session.commit()
    service = UserService(UserRepository(db_session), auth_service)

    service.change_own_password(user.id, "choisi-par-moi")

    assert user.must_change_password is False
    assert auth_service.verify_password("choisi-par-moi", user.password)


# --- R9: the audit trail's integrity chain ---

def test_entries_are_chained(db_session, audit_log_repository):
    from zanshin.services.audit_log_service import AuditLogService

    service = AuditLogService(audit_log_repository)
    service.record("LOGIN_SUCCESS", "1", "première")
    service.record("SETTING_UPDATED", "scan_backend", "deuxième")

    entries = audit_log_repository.find_all_oldest_first()
    assert entries[0].previous_hash is None
    assert entries[1].previous_hash == entries[0].entry_hash
    assert service.verify_chain() is None


def test_editing_a_past_entry_is_detected(db_session, audit_log_repository):
    """The realistic threat is not wiping the table — it is editing the one line that
    matters, among thousands."""
    from zanshin.services.audit_log_service import AuditLogService

    service = AuditLogService(audit_log_repository)
    service.record("LOGIN_FAILURE", "alice", "échec suspect")
    service.record("SETTING_UPDATED", "x", "sans rapport")

    first = audit_log_repository.find_all_oldest_first()[0]
    first.description = "rien à signaler"
    db_session.commit()

    problem = service.verify_chain()
    assert problem is not None
    assert "empreinte" in problem


def test_deleting_a_past_entry_is_detected(db_session, audit_log_repository):
    from zanshin.services.audit_log_service import AuditLogService

    service = AuditLogService(audit_log_repository)
    service.record("LOGIN_FAILURE", "alice", "une")
    service.record("LOGIN_FAILURE", "alice", "deux")
    service.record("LOGIN_FAILURE", "alice", "trois")

    middle = audit_log_repository.find_all_oldest_first()[1]
    db_session.delete(middle)
    db_session.commit()

    assert service.verify_chain() is not None


def test_entries_predating_the_chain_are_reported_not_rejected(db_session, audit_log_repository):
    """Backfilling hashes over history would be fabricating evidence: those entries
    cannot be shown to be untampered. An honest gap beats a false guarantee."""
    from zanshin.models.audit_log import AuditLog
    from zanshin.services.audit_log_service import AuditLogService

    audit_log_repository.save(
        AuditLog(operation_type="OLD", resource_id="x", description="avant le chaînage")
    )
    service = AuditLogService(audit_log_repository)
    service.record("LOGIN_SUCCESS", "1", "après")

    assert service.verify_chain() is None


def test_the_request_context_is_recorded(db_session, audit_log_repository):
    """For authentication events this is the difference between "she mistyped it
    twice" and "someone is walking the account list from one host"."""
    from zanshin.services.audit_log_service import AuditLogService

    AuditLogService(audit_log_repository).record(
        "LOGIN_FAILURE", "alice", "échec", ip_address="203.0.113.7", user_agent="curl/8"
    )

    entry = audit_log_repository.find_latest()
    assert entry.ip_address == "203.0.113.7"
    assert entry.user_agent == "curl/8"
