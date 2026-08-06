"""Rate limiting for authentication attempts.

Nothing slowed a login attempt down. bcrypt at cost 12 takes ~100 ms, which stops
a naive script and not a patient one — and the password policy only asks for eight
characters. The audit log already recorded `LOGIN_FAILURE`; this is what finally
reads it.

**Where the state lives.** In memory, per process. That is a real limitation and it
is deliberate:

- Zanshin runs as a single process (one Reflex app, one scan pool, one SQLite
  file). A shared store would buy nothing today and add an operational dependency.
- Putting counters in SQLite would mean a write per failed attempt, which is a
  denial-of-service amplifier: an attacker's own traffic would make them cheap to
  send and expensive to absorb.

The consequence to know: counters reset when the process restarts. An attacker who
can force restarts can reset the lockout — but they would need an existing
vulnerability to do that, and the audit trail still records every attempt.

**What is keyed.** The username *and* the client identifier separately. Keying only
the username lets anyone lock out a known account by failing on purpose (a denial
of service dressed as a security control); keying only the client lets a botnet
spread attempts across addresses. Both counters must stay under their ceiling.
"""
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from zanshin.clock import utcnow

logger = logging.getLogger(__name__)

# Five wrong passwords in a row is already unusual for a human.
MAX_ATTEMPTS_PER_USER = 5
# Higher for a client: several people can legitimately share an office address.
MAX_ATTEMPTS_PER_CLIENT = 20
# How far back attempts are counted, and how long a lockout lasts.
WINDOW = timedelta(minutes=15)


@dataclass
class _Bucket:
    attempts: List[datetime] = field(default_factory=list)

    def prune(self, now: datetime, window: timedelta) -> None:
        """Drop attempts older than the window.

        The window is passed in rather than read from the module constant: a
        `LoginThrottle` built with a different window would otherwise be pruned
        against the default, so its configuration would silently not apply.
        """
        cutoff = now - window
        self.attempts = [moment for moment in self.attempts if moment > cutoff]


class LoginThrottle:
    """Counts recent failures and refuses once they pass a ceiling.

    Thread-safe: Reflex handles events on a worker pool, so two attempts can be in
    flight at once and a plain dict would lose one of them.
    """

    def __init__(
        self,
        max_per_user: int = MAX_ATTEMPTS_PER_USER,
        max_per_client: int = MAX_ATTEMPTS_PER_CLIENT,
        window: timedelta = WINDOW,
    ):
        self.max_per_user = max_per_user
        self.max_per_client = max_per_client
        self.window = window
        self._users: Dict[str, _Bucket] = {}
        self._clients: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, username: str, client_id: str = "") -> Tuple[bool, Optional[int]]:
        """`(allowed, seconds_to_wait)`.

        Called *before* verifying the password, so a locked-out account costs no
        bcrypt round at all — which is the other half of the point: hashing is
        expensive on purpose, and an attacker should not be able to spend the
        server's CPU for free.
        """
        now = utcnow()
        with self._lock:
            for key, buckets, ceiling in (
                (self._normalize(username), self._users, self.max_per_user),
                (client_id, self._clients, self.max_per_client),
            ):
                if not key:
                    continue
                bucket = buckets.get(key)
                if bucket is None:
                    continue
                bucket.prune(now, self.window)
                if len(bucket.attempts) >= ceiling:
                    oldest = min(bucket.attempts)
                    wait = int((oldest + self.window - now).total_seconds()) + 1
                    return False, max(wait, 1)
        return True, None

    def record_failure(self, username: str, client_id: str = "") -> None:
        now = utcnow()
        with self._lock:
            for key, buckets in (
                (self._normalize(username), self._users),
                (client_id, self._clients),
            ):
                if not key:
                    continue
                bucket = buckets.setdefault(key, _Bucket())
                bucket.prune(now, self.window)
                bucket.attempts.append(now)
        logger.warning(
            "Failed login for '%s' (client %s): %d recent attempt(s)",
            username, client_id or "unknown", self.attempts_for(username),
        )

    def record_success(self, username: str, client_id: str = "") -> None:
        """Clear the counters: a correct password proves the earlier failures were
        someone forgetting theirs, not an attack in progress."""
        with self._lock:
            self._users.pop(self._normalize(username), None)
            if client_id:
                self._clients.pop(client_id, None)

    def attempts_for(self, username: str) -> int:
        with self._lock:
            bucket = self._users.get(self._normalize(username))
            if not bucket:
                return 0
            bucket.prune(utcnow(), self.window)
            return len(bucket.attempts)

    def reset(self) -> None:
        """Drop every counter. For tests, and for an operator unlocking an account
        by restarting — which is what happens implicitly today anyway."""
        with self._lock:
            self._users.clear()
            self._clients.clear()

    @staticmethod
    def _normalize(username: str) -> str:
        # Case-insensitive: usernames are compared exactly at login, but an
        # attacker must not get a fresh allowance by changing the capitalisation.
        return (username or "").strip().lower()


# Module-level instance: the counters have to be shared by every login attempt in
# the process, and the UI layer builds a fresh container per event.
login_throttle = LoginThrottle()
