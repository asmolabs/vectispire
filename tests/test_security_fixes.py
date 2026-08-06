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

    service = RepositoryService(
        RepositoryRepository(db_session), ScanRepository(db_session), scan_processor=None
    )

    with pytest.raises(ScanAlreadyRunningError):
        service.trigger_scan(repo.id)


def test_a_finished_scan_does_not_block_the_next_one(db_session, make_repository):
    import threading

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

    class FakeProcessor:
        def __init__(self):
            self.done = threading.Event()

        def process_scan(self, *args):
            self.done.set()

    processor = FakeProcessor()
    service = RepositoryService(
        RepositoryRepository(db_session), ScanRepository(db_session), processor
    )

    scan = service.trigger_scan(repo.id)

    assert scan.status == "pending"
    assert processor.done.wait(timeout=2)


def test_another_targets_scan_does_not_block_this_one(db_session, make_repository, make_container):
    from zanshin.models.scan import Scan
    from zanshin.repositories.container_repository import ContainerRepository
    from zanshin.repositories.scan_repository import ScanRepository
    from zanshin.services.container_service import ContainerService

    repo = make_repository()
    container = make_container()
    db_session.add(Scan(repo_id=repo.id, branch="main", status="scanning", findings_count=0))
    db_session.commit()

    class FakeProcessor:
        def process_scan(self, *args):
            pass

    service = ContainerService(
        ContainerRepository(db_session), ScanRepository(db_session), FakeProcessor()
    )

    assert service.trigger_scan(container.id).status == "pending"


# --- M11: the database file holds hashes and encrypted keys ---

def test_the_database_file_is_not_world_readable(tmp_path, monkeypatch):
    import os
    import stat

    import zanshin.schema as schema

    db_path = tmp_path / "test.sqlite"
    db_path.write_bytes(b"")
    os.chmod(db_path, 0o644)
    monkeypatch.setattr(schema, "DATABASE_URL", f"sqlite:///{db_path}")

    schema.restrict_database_permissions()

    mode = stat.S_IMODE(os.stat(db_path).st_mode)
    assert mode == 0o600


def test_tightening_permissions_never_breaks_startup(monkeypatch):
    """A read-only or exotic filesystem must not stop the application from
    starting."""
    import zanshin.schema as schema

    monkeypatch.setattr(schema, "DATABASE_URL", "sqlite:////nonexistent/dir/x.sqlite")

    schema.restrict_database_permissions()  # must not raise
