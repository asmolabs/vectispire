"""Per-key request quota for the API.

Every route was unbounded. The "one scan in flight per target" guard bounds scans,
which was the expensive path, but `/issues`, `/gate` and the exports can be called
in a loop — and `/gate` loads a target's whole open backlog into memory each time.

In memory, per process, for the same reasons as `LoginThrottle`: this is a single
process, and counting requests in SQLite would mean a write per request, so the
counter would amplify exactly the traffic it is meant to limit.

A fixed window rather than a token bucket: a caller that exceeds it learns *when* it
may retry (`Retry-After`), which a bucket's continuous refill cannot state as
simply. The imprecision at a window boundary is irrelevant at this scale.
"""
import logging
import os
import threading
from typing import Dict, Optional, Tuple

from fastapi import Depends, HTTPException, status

from zanshin.api.deps import require_api_key
from zanshin.models.api_key import ApiKey
from zanshin.services.counter_store import get_store

logger = logging.getLogger(__name__)

# Generous: a CI pipeline polls a scan every few seconds and is nowhere near this.
# The point is to stop a loop, not to shape traffic.
MAX_REQUESTS_PER_WINDOW = int(os.getenv("ZANSHIN_API_RATE_LIMIT", "300"))
WINDOW_SECONDS = int(os.getenv("ZANSHIN_API_RATE_WINDOW_SECONDS", "60"))


class FixedWindowLimiter:
    """The quota itself. Where it *counts* is `counter_store`'s business.

    That indirection is the whole change: the counters used to be a dictionary in this
    object, which is correct for one process and doubles the quota for two (ADR-002
    §2.5). The behaviour — a fixed window, and a `Retry-After` a caller can act on — is
    unchanged.
    """

    def __init__(
        self,
        max_requests: int = MAX_REQUESTS_PER_WINDOW,
        window_seconds: int = WINDOW_SECONDS,
        store=None,
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Resolved per call rather than captured here: `get_store()` builds the store
        # lazily, and a limiter constructed at import time would otherwise freeze the
        # in-memory one before `REDIS_URL` had been read.
        self._store = store

    @property
    def store(self):
        return self._store or get_store()

    def check(self, identity: str) -> Tuple[bool, Optional[int]]:
        """`(allowed, seconds_until_reset)`."""
        count, retry_after = self.store.increment(f"api:{identity}", self.window_seconds)
        if count > self.max_requests:
            return False, retry_after
        return True, None

    def reset(self) -> None:
        self.store.clear()


limiter = FixedWindowLimiter()


def rate_limited(api_key: ApiKey = Depends(require_api_key)) -> ApiKey:
    """Dependency that enforces the quota and passes the key through.

    Keyed on the key's id, not on the client address: the API is authenticated, so
    the credential is the accountable identity — and it is the thing an operator can
    actually revoke.
    """
    allowed, retry_after = limiter.check(str(api_key.id))
    if not allowed:
        logger.warning("Rate limit reached for API key '%s'", api_key.name)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Quota dépassé. Réessayez dans {retry_after} seconde(s).",
            headers={"Retry-After": str(retry_after)},
        )
    return api_key
