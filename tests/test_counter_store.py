"""Tests for the shared security counters.

Every case runs against **both** implementations, and that is the point rather than
thoroughness for its own sake: the in-memory store is what a single install uses and
the Redis one is what a fleet uses, so a behaviour that differs between them is a
security guard that changes when somebody scales out.

The Redis cases need a real server (testcontainers) and skip themselves without
Docker — mocking a Redis would test the mock's idea of `ZREMRANGEBYSCORE`, which is
exactly the assumption worth checking.
"""
import time

import pytest

from zanshin.services.counter_store import (
    MemoryCounterStore,
    RedisCounterStore,
    build_store,
    get_store,
    reset_store,
)


def _docker_available() -> bool:
    import shutil
    import subprocess

    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except Exception:
        return False


@pytest.fixture(scope="module")
def redis_container():
    if not _docker_available():
        pytest.skip("Docker is not available")
    testcontainers = pytest.importorskip("testcontainers.community.redis")

    with testcontainers.RedisContainer("redis:7-alpine") as container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(container.port)
        yield f"redis://{host}:{port}/0"


@pytest.fixture(
    params=[
        pytest.param("memory", id="memory"),
        # Marked, so the Redis half runs in the job that has Docker (`pytest -m
        # backends`) instead of silently skipping in the default one. Marking the
        # *parameter* rather than the test keeps every case written once, for both
        # implementations.
        pytest.param("redis", id="redis", marks=pytest.mark.backends),
    ]
)
def store(request, redis_container_or_skip):
    """One store per implementation, empty.

    Parametrised rather than duplicated so a case cannot be written for one
    implementation and quietly forgotten for the other.
    """
    if request.param == "memory":
        return MemoryCounterStore()
    built = RedisCounterStore(redis_container_or_skip, prefix="zanshin:test:")
    built.clear()
    return built


@pytest.fixture()
def redis_container_or_skip(request):
    """Resolves the container only for the Redis parameter, so the in-memory cases
    still run on a machine without Docker."""
    if request.node.callspec.params.get("store") == "redis":
        return request.getfixturevalue("redis_container")
    return ""


# --- The fixed window (API quota) -----------------------------------------------

def test_increment_counts_up(store):
    assert store.increment("k", 60)[0] == 1
    assert store.increment("k", 60)[0] == 2
    assert store.increment("k", 60)[0] == 3


def test_two_keys_are_counted_apart(store):
    store.increment("a", 60)
    store.increment("a", 60)

    assert store.increment("b", 60)[0] == 1


def test_the_retry_delay_is_within_the_window(store):
    """A caller refused by the quota is told when it may retry; a number outside the
    window would send it away for the wrong length of time."""
    _, retry_after = store.increment("k", 60)

    assert 0 < retry_after <= 61


def test_the_window_expires(store):
    """Checked with a real one-second window rather than by mocking the clock: on Redis
    the expiry is the server's, and mocking `utcnow` here would prove nothing about it."""
    store.increment("k", 1)
    store.increment("k", 1)
    time.sleep(1.2)

    assert store.increment("k", 1)[0] == 1


# --- The sliding window (login throttle) ----------------------------------------

def test_record_counts_events_in_the_window(store):
    assert store.record("k", 60) == 1
    assert store.record("k", 60) == 2
    assert store.count("k", 60) == 2


def test_count_does_not_add_an_event(store):
    store.record("k", 60)

    assert store.count("k", 60) == 1
    assert store.count("k", 60) == 1


def test_events_leave_the_window_as_it_slides(store):
    """A lockout must not become forgiving at a boundary, which is why this is a
    sliding window and not a fixed one."""
    store.record("k", 1)
    time.sleep(1.2)

    assert store.count("k", 1) == 0


def test_earliest_reports_the_oldest_event_still_counted(store):
    """It is what turns a refusal into "try again in N seconds"."""
    store.record("k", 60)
    time.sleep(0.05)
    store.record("k", 60)

    oldest = store.earliest("k", 60)

    assert oldest is not None
    assert oldest <= min(time.time(), oldest + 1)


def test_earliest_is_none_when_nothing_is_counted(store):
    assert store.earliest("unknown", 60) is None


def test_clearing_one_key_leaves_the_others(store):
    store.record("a", 60)
    store.record("b", 60)

    store.clear("a")

    assert store.count("a", 60) == 0
    assert store.count("b", 60) == 1


def test_clearing_everything_empties_both_shapes(store):
    store.increment("a", 60)
    store.record("b", 60)

    store.clear()

    assert store.increment("a", 60)[0] == 1
    assert store.count("b", 60) == 0


# --- What a fleet actually needs ------------------------------------------------

@pytest.mark.backends
def test_two_instances_share_one_redis_counter(redis_container):
    """The defect this closes (ADR-002 §2.5): two instances counting separately means
    the quota doubles and the anti-stuffing guard is bypassed by alternating between
    them."""
    first = RedisCounterStore(redis_container, prefix="zanshin:shared-test:")
    second = RedisCounterStore(redis_container, prefix="zanshin:shared-test:")
    first.clear()

    assert first.increment("key", 60)[0] == 1
    assert second.increment("key", 60)[0] == 2, "the second instance started its own count"

    first.record("login", 60)
    assert second.count("login", 60) == 1


def test_two_memory_stores_do_not_share_anything(redis_container_or_skip=None):
    """Stated as a test because it is the property that made the fleet unsafe, and
    because somebody reading the fallback should not assume otherwise."""
    first, second = MemoryCounterStore(), MemoryCounterStore()

    first.increment("key", 60)

    assert second.increment("key", 60)[0] == 1


# --- Choosing an implementation --------------------------------------------------

def test_no_redis_url_means_the_in_memory_store(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)

    assert isinstance(build_store(), MemoryCounterStore)


@pytest.mark.backends
def test_a_redis_url_is_used_when_it_is_set(redis_container, monkeypatch):
    monkeypatch.setenv("REDIS_URL", redis_container)

    assert isinstance(build_store(), RedisCounterStore)


def test_a_broken_redis_falls_back_instead_of_stopping_the_application(monkeypatch):
    """A configured-but-unreachable Redis must not be fatal: the counters go back to
    what they were before, which is what a single instance uses anyway."""
    monkeypatch.setattr(
        RedisCounterStore, "_connect",
        staticmethod(lambda url: (_ for _ in ()).throw(RuntimeError("no route to host"))),
    )

    assert isinstance(build_store("redis://nowhere:6379/0"), MemoryCounterStore)


def test_an_unreachable_redis_allows_rather_than_refuses(monkeypatch):
    """Deliberate: these guards protect against abuse, and a Redis outage turning every
    login and every API call into a refusal would convert a dependency failure into a
    total one."""
    class DeadClient:
        def pipeline(self):
            raise ConnectionError("connection lost")

    store = RedisCounterStore("redis://unused", client=DeadClient())

    count, retry_after = store.increment("k", 60)
    assert count == 0  # below any ceiling, so the caller is allowed through
    assert retry_after == 60
    assert store.record("k", 60) == 0
    assert store.count("k", 60) == 0
    assert store.earliest("k", 60) is None


def test_the_process_store_is_built_once(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    reset_store(None)

    assert get_store() is get_store()

    reset_store(None)
