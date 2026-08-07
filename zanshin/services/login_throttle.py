"""Rate limiting for authentication attempts.

Nothing slowed a login attempt down. bcrypt at cost 12 takes ~100 ms, which stops
a naive script and not a patient one — and the password policy only asks for eight
characters. The audit log already recorded `LOGIN_FAILURE`; this is what finally
reads it.

**Where the state lives.** In `counter_store`: per process when Zanshin runs alone,
shared through Redis when `REDIS_URL` is set. It was per-process only, which is correct
for one instance and a hole for two — an attacker alternating between instances gets
the ceiling twice over, silently (ADR-002 §2.5). Counters are still never written to
the database: one write per failed attempt would make an attacker's own traffic cheap
to send and expensive to absorb.

The consequence to know: with no Redis, counters reset when the process restarts. An
attacker who can force restarts can reset the lockout — but they would need an existing
vulnerability to do that, and the audit trail still records every attempt.

**What is keyed.** The username *and* the client identifier separately. Keying only
the username lets anyone lock out a known account by failing on purpose (a denial
of service dressed as a security control); keying only the client lets a botnet
spread attempts across addresses. Both counters must stay under their ceiling.
"""
import logging
from datetime import timedelta
from typing import Optional, Tuple

from zanshin.clock import utcnow
from zanshin.services.counter_store import get_store

logger = logging.getLogger(__name__)

# Five wrong passwords in a row is already unusual for a human.
MAX_ATTEMPTS_PER_USER = 5
# Higher for a client: several people can legitimately share an office address.
MAX_ATTEMPTS_PER_CLIENT = 20
# How far back attempts are counted, and how long a lockout lasts.
WINDOW = timedelta(minutes=15)


class LoginThrottle:
    """Counts recent failures and refuses once they pass a ceiling.

    Concurrency is the store's problem, not this class's: Reflex handles events on a
    worker pool, so two attempts can be in flight at once, and with Redis they can be
    in flight on two *instances*.
    """

    def __init__(
        self,
        max_per_user: int = MAX_ATTEMPTS_PER_USER,
        max_per_client: int = MAX_ATTEMPTS_PER_CLIENT,
        window: timedelta = WINDOW,
        store=None,
    ):
        self.max_per_user = max_per_user
        self.max_per_client = max_per_client
        self.window = window
        # Resolved per call: see `FixedWindowLimiter` for why a store captured at
        # construction would freeze the wrong one.
        self._store = store

    @property
    def store(self):
        return self._store or get_store()

    @property
    def _window_seconds(self) -> int:
        return int(self.window.total_seconds())

    def _keys(self, username: str, client_id: str):
        """The two counters, and their ceilings.

        Namespaced apart so a username can never collide with a client identifier —
        with a shared store, keys from different callers live in one keyspace.
        """
        return (
            (f"login:user:{self._normalize(username)}", self.max_per_user)
            if self._normalize(username) else None,
            (f"login:client:{client_id}", self.max_per_client) if client_id else None,
        )

    def check(self, username: str, client_id: str = "") -> Tuple[bool, Optional[int]]:
        """`(allowed, seconds_to_wait)`.

        Called *before* verifying the password, so a locked-out account costs no
        bcrypt round at all — which is the other half of the point: hashing is
        expensive on purpose, and an attacker should not be able to spend the
        server's CPU for free.
        """
        now = utcnow()
        for entry in self._keys(username, client_id):
            if entry is None:
                continue
            key, ceiling = entry
            if self.store.count(key, self._window_seconds) < ceiling:
                continue
            oldest = self.store.earliest(key, self._window_seconds)
            if oldest is None:
                continue
            wait = int(oldest + self._window_seconds - now.timestamp()) + 1
            return False, max(wait, 1)
        return True, None

    def record_failure(self, username: str, client_id: str = "") -> None:
        for entry in self._keys(username, client_id):
            if entry is None:
                continue
            self.store.record(entry[0], self._window_seconds)
        logger.warning(
            "Failed login for '%s' (client %s): %d recent attempt(s)",
            username, client_id or "unknown", self.attempts_for(username),
        )

    def record_success(self, username: str, client_id: str = "") -> None:
        """Clear the counters: a correct password proves the earlier failures were
        someone forgetting theirs, not an attack in progress."""
        for entry in self._keys(username, client_id):
            if entry is not None:
                self.store.clear(entry[0])

    def attempts_for(self, username: str) -> int:
        if not self._normalize(username):
            return 0
        return self.store.count(f"login:user:{self._normalize(username)}", self._window_seconds)

    def reset(self) -> None:
        """Drop every counter. For tests, and for an operator unlocking an account
        by restarting — which is what happens implicitly today anyway."""
        self.store.clear()

    @staticmethod
    def _normalize(username: str) -> str:
        # Case-insensitive: usernames are compared exactly at login, but an
        # attacker must not get a fresh allowance by changing the capitalisation.
        return (username or "").strip().lower()


# Module-level instance: every login attempt in the process goes through the same
# object, and the UI layer builds a fresh container per event. What it *counts* through
# may be shared with the other instances too — see `counter_store`.
login_throttle = LoginThrottle()
