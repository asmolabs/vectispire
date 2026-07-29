import secrets
from typing import Optional, Tuple

import bcrypt

from zanshin.models.api_key import ApiKey
from zanshin.repositories.api_key_repository import ApiKeyRepository

KEY_PREFIX = "zsk"

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
            prefix=full_key[: len(KEY_PREFIX) + 9],
        )
        saved = self.api_key_repository.save(api_key)
        return saved, full_key

    def verify_key(self, raw_key: str) -> Optional[ApiKey]:
        if not raw_key:
            return None
        candidate_bytes = raw_key.encode("utf-8")[:72]
        for api_key in self.api_key_repository.find_all():
            try:
                if bcrypt.checkpw(candidate_bytes, api_key.key_hash.encode("utf-8")):
                    return api_key
            except ValueError:
                continue
        return None
