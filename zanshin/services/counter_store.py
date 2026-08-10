"""Where the security counters live: shared when there is somewhere to share them.

Two guards count things per unit of time — the API quota (`zanshin/api/rate_limit.py`)
and the login throttle (`zanshin/services/login_throttle.py`). Both counted in the
process's own memory, which is correct for one instance and quietly wrong for two: the
quota doubles, and the anti-stuffing guard is bypassed by alternating between instances
(docs/architecture/04). Neither failure raises anything or shows up in a test — the numbers are
simply larger than the operator asked for.

**Why Redis and not a table** (docs/architecture/04): these are counters written on *every* request,
including the ones being refused. A table would mean a write per request, so the
counter would amplify exactly the traffic it exists to limit — and losing them on
restart is acceptable, which is the profile Redis serves well and a relational database
serves badly.

**Why the in-memory fallback stays.** It is not a degraded mode, it is the correct
implementation for the deployment most installations run: one process, no Redis to
operate. It is used whenever no Redis URL is configured, and it is exactly the code
that was there before.

The two operations exist because the two callers count differently, and neither should
have to change its semantics to share a store: a **fixed window** (the quota tells a
caller when it may retry, which a sliding window cannot state simply) and a **sliding
window** (a lockout must not become forgiving at a window boundary).
"""
import logging
import os
import threading
from typing import Dict, List, Optional, Protocol, Tuple

from zanshin.clock import utcnow

logger = logging.getLogger(__name__)


def redis_url() -> str:
    """The Redis to share counters through, or empty.

    Read from `REDIS_URL` — the same variable Reflex uses for its own state manager,
    deliberately: an operator running a fleet has to set it anyway (§2.4), and asking
    for a second URL to the same server would be a way to get them out of step.
    """
    return (os.getenv("REDIS_URL") or "").strip()


class CounterStore(Protocol):
    def increment(self, key: str, window_seconds: int) -> Tuple[int, int]:
        """Count one event in a fixed window. Returns `(count, seconds_remaining)`."""

    def record(self, key: str, window_seconds: int) -> int:
        """Count one event in a sliding window. Returns the number in the window."""

    def count(self, key: str, window_seconds: int) -> int:
        """How many events are in the sliding window, without adding one."""

    def earliest(self, key: str, window_seconds: int) -> Optional[float]:
        """Timestamp of the oldest event still in the window, or `None`.

        Needed by the login throttle to say *when* a lockout ends, which is the
        difference between a usable refusal and a dead end.
        """

    def clear(self, key: Optional[str] = None) -> None:
        """Forget one key, or everything. For tests and for an operator unlocking an
        account by hand."""


class MemoryCounterStore:
    """Per-process counters — the single-instance implementation.

    Deliberately keeps the two shapes separate rather than emulating one with the
    other: a fixed window that pretended to be sliding would drift from what Redis
    does, and the difference would only appear under load.
    """

    def __init__(self):
        self._windows: Dict[str, Tuple[float, int]] = {}
        self._events: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def increment(self, key: str, window_seconds: int) -> Tuple[int, int]:
        now = utcnow().timestamp()
        with self._lock:
            start, count = self._windows.get(key, (now, 0))
            if now - start >= window_seconds:
                start, count = now, 0
            count += 1
            self._windows[key] = (start, count)
            return count, int(window_seconds - (now - start)) + 1

    def record(self, key: str, window_seconds: int) -> int:
        now = utcnow().timestamp()
        with self._lock:
            events = [t for t in self._events.get(key, []) if t > now - window_seconds]
            events.append(now)
            self._events[key] = events
            return len(events)

    def count(self, key: str, window_seconds: int) -> int:
        now = utcnow().timestamp()
        with self._lock:
            events = [t for t in self._events.get(key, []) if t > now - window_seconds]
            self._events[key] = events
            return len(events)

    def earliest(self, key: str, window_seconds: int) -> Optional[float]:
        now = utcnow().timestamp()
        with self._lock:
            events = [t for t in self._events.get(key, []) if t > now - window_seconds]
            self._events[key] = events
            return min(events) if events else None

    def clear(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._windows.clear()
                self._events.clear()
            else:
                self._windows.pop(key, None)
                self._events.pop(key, None)


class RedisCounterStore:
    """Counters shared by every instance.

    Both operations are a single round trip, in a pipeline, because a read-then-write
    would be a race between instances — which is the very thing this class exists to
    fix. The fixed window uses `INCR` + `EXPIRE` on a first write; the sliding window
    uses a sorted set scored by timestamp, trimmed on each write.

    Every method degrades to *allowing* the request if Redis is unreachable. That is a
    deliberate choice and not an oversight: these guards protect against abuse, and a
    Redis outage turning every login and every API call into a refusal would convert a
    dependency failure into a total one. The unavailability is logged; the alternative
    is worse.
    """

    def __init__(self, url: str, client=None, prefix: str = "zanshin:counter:"):
        self.prefix = prefix
        self._client = client or self._connect(url)

    @staticmethod
    def _connect(url: str):
        import redis  # Imported here: an installation with no Redis never needs it.

        return redis.Redis.from_url(url, decode_responses=True, socket_timeout=2)

    def _key(self, key: str) -> str:
        return f"{self.prefix}{key}"

    def increment(self, key: str, window_seconds: int) -> Tuple[int, int]:
        redis_key = self._key(f"w:{key}")
        try:
            pipeline = self._client.pipeline()
            pipeline.incr(redis_key)
            pipeline.ttl(redis_key)
            count, ttl = pipeline.execute()
            if ttl is None or ttl < 0:
                # First write of this window (or a key that somehow lost its expiry):
                # set it, and report the full window as the retry delay.
                self._client.expire(redis_key, window_seconds)
                ttl = window_seconds
            return int(count), int(ttl) + 1
        except Exception:
            logger.warning("Redis unavailable for the rate counter — allowing the request")
            return 0, window_seconds

    def record(self, key: str, window_seconds: int) -> int:
        redis_key = self._key(f"s:{key}")
        now = utcnow().timestamp()
        try:
            pipeline = self._client.pipeline()
            pipeline.zremrangebyscore(redis_key, 0, now - window_seconds)
            # Member and score are both the timestamp: two events in the same
            # microsecond collapsing into one is a rounding error, not a hole — and it
            # errs towards counting fewer, i.e. towards not locking somebody out.
            pipeline.zadd(redis_key, {str(now): now})
            pipeline.zcard(redis_key)
            pipeline.expire(redis_key, window_seconds)
            _, _, size, _ = pipeline.execute()
            return int(size)
        except Exception:
            logger.warning("Redis unavailable for the login throttle — allowing the attempt")
            return 0

    def count(self, key: str, window_seconds: int) -> int:
        redis_key = self._key(f"s:{key}")
        now = utcnow().timestamp()
        try:
            pipeline = self._client.pipeline()
            pipeline.zremrangebyscore(redis_key, 0, now - window_seconds)
            pipeline.zcard(redis_key)
            _, size = pipeline.execute()
            return int(size)
        except Exception:
            logger.warning("Redis unavailable for the login throttle — reporting no attempts")
            return 0

    def earliest(self, key: str, window_seconds: int) -> Optional[float]:
        redis_key = self._key(f"s:{key}")
        now = utcnow().timestamp()
        try:
            pipeline = self._client.pipeline()
            pipeline.zremrangebyscore(redis_key, 0, now - window_seconds)
            pipeline.zrange(redis_key, 0, 0, withscores=True)
            _, oldest = pipeline.execute()
            return float(oldest[0][1]) if oldest else None
        except Exception:
            logger.warning("Redis unavailable for the login throttle — no lockout deadline")
            return None

    def clear(self, key: Optional[str] = None) -> None:
        try:
            if key is None:
                for found in self._client.scan_iter(f"{self.prefix}*"):
                    self._client.delete(found)
            else:
                self._client.delete(self._key(f"w:{key}"), self._key(f"s:{key}"))
        except Exception:
            logger.warning("Redis unavailable — could not clear counters")


_store: Optional[CounterStore] = None
_store_lock = threading.Lock()


def get_store() -> CounterStore:
    """The process's counter store, built once.

    Built lazily rather than at import so that `REDIS_URL` can be set by a test, and so
    that an installation without Redis never constructs a client it will not use.
    """
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = build_store()
    return _store


def build_store(url: Optional[str] = None) -> CounterStore:
    url = redis_url() if url is None else url
    if not url:
        return MemoryCounterStore()
    try:
        store = RedisCounterStore(url)
        logger.info("Security counters are shared through Redis")
        return store
    except Exception:
        # A configured-but-broken Redis must not stop the application: the counters
        # fall back to per-process, which is what they were before.
        logger.exception("Could not reach Redis for the security counters — using memory")
        return MemoryCounterStore()


def reset_store(store: Optional[CounterStore] = None) -> None:
    """Replace the process store. For tests, and for the fixture that has to run each
    case against both implementations."""
    global _store
    with _store_lock:
        _store = store
