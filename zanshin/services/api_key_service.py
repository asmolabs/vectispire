import hmac
import secrets
from typing import Optional, Tuple

import bcrypt

from zanshin.clock import utcnow
from zanshin.models.api_key import ApiKey
from zanshin.repositories.api_key_repository import ApiKeyRepository

KEY_PREFIX = "zsk"
# Characters of the full key kept in cleartext for identification. Long enough
# to be selective as a lookup key, short enough to be useless on its own: the
# secret is 43 url-safe characters of entropy after it.
PREFIX_LENGTH = len(KEY_PREFIX) + 9


class ApiKeyService:
    """Issues and verifies Zanshin's own API keys (for CI/CD or scripted
    callers to trigger scans and fetch results programmatically).

    The raw secret is never stored: only its bcrypt hash is persisted, and
    the raw value is returned exactly once, at creation time, so the caller
    can copy it. This replaces the previous implementation, which used the
    row's own database id as the "secret" and then displayed that same
    value permanently in the key listing — i.e. it was never actually
    secret.
    """

    def __init__(self, api_key_repository: ApiKeyRepository):
        self.api_key_repository = api_key_repository

    def create_key(self, name: str) -> Tuple[ApiKey, str]:
        raw_secret = secrets.token_urlsafe(32)
        full_key = f"{KEY_PREFIX}_{raw_secret}"
        hashed = bcrypt.hashpw(full_key.encode("utf-8")[:72], bcrypt.gensalt())

        api_key = ApiKey(
            name=name,
            key_hash=hashed.decode("utf-8"),
            prefix=full_key[:PREFIX_LENGTH],
        )
        saved = self.api_key_repository.save(api_key)
        return saved, full_key

    def verify_key(self, raw_key: str, record_use: bool = False) -> Optional[ApiKey]:
        """Return the matching key, or `None`.

        Looks the candidate up by its cleartext prefix instead of bcrypt-comparing
        against every stored key in turn — which is what the previous
        implementation did, at one bcrypt round (deliberately ~100ms) per key on
        every single request. That cost is the point of bcrypt for passwords, but
        here it turned each API call into O(number of keys) of CPU, and the whole
        purpose of storing a `prefix` was to avoid it.

        `record_use` stamps `last_used_at`, which nothing could write before this
        method had a caller — the column existed and was always "Jamais" in the UI.
        """
        if not raw_key:
            return None
        raw_key = raw_key.strip()
        if len(raw_key) <= PREFIX_LENGTH:
            return None

        candidate_bytes = raw_key.encode("utf-8")[:72]
        for api_key in self.api_key_repository.find_all_by_prefix(raw_key[:PREFIX_LENGTH]):
            try:
                if bcrypt.checkpw(candidate_bytes, api_key.key_hash.encode("utf-8")):
                    if record_use:
                        self._record_use(api_key)
                    return api_key
            except ValueError:
                # Malformed stored hash: skip rather than fail the whole request,
                # so one bad row can't lock out every caller.
                continue
        return None

    def _record_use(self, api_key: ApiKey) -> None:
        api_key.last_used_at = utcnow()
        self.api_key_repository.save(api_key)

    @staticmethod
    def looks_like_a_key(raw_key: str) -> bool:
        """Cheap shape check, before any database work.

        `hmac.compare_digest` on the prefix rather than `==`: not because the
        prefix is secret, but because it keeps the comparison time independent of
        how many leading characters matched, which is free to do here.
        """
        if not raw_key or "_" not in raw_key:
            return False
        head = raw_key.split("_", 1)[0]
        return hmac.compare_digest(head, KEY_PREFIX)
