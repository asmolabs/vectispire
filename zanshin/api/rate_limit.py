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
from zanshin.clock import utcnow
from zanshin.models.api_key import ApiKey

logger = logging.getLogger(__name__)

# Generous: a CI pipeline polls a scan every few seconds and is nowhere near this.
# The point is to stop a loop, not to shape traffic.
MAX_REQUESTS_PER_WINDOW = int(os.getenv("ZANSHIN_API_RATE_LIMIT", "300"))
WINDOW_SECONDS = int(os.getenv("ZANSHIN_API_RATE_WINDOW_SECONDS", "60"))


class FixedWindowLimiter:
    def __init__(self, max_requests: int = MAX_REQUESTS_PER_WINDOW, window_seconds: int = WINDOW_SECONDS):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # key -> (window start, count)
        self._windows: Dict[str, Tuple[float, int]] = {}
        self._lock = threading.Lock()

    def check(self, identity: str) -> Tuple[bool, Optional[int]]:
        """`(allowed, seconds_until_reset)`."""
        now = utcnow().timestamp()
        with self._lock:
            start, count = self._windows.get(identity, (now, 0))
            if now - start >= self.window_seconds:
                start, count = now, 0
            count += 1
            self._windows[identity] = (start, count)
            if count > self.max_requests:
                return False, int(self.window_seconds - (now - start)) + 1
        return True, None

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()


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
