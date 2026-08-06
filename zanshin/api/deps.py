"""Request-scoped dependencies: a database session, and the calling API key.

Authentication is a bearer token — the `zsk_…` value shown once when the key was
created. Until now `ApiKeyService.verify_key` had no caller at all: keys could be
issued from the UI and there was nothing to present them to, which is also why
`last_used_at` was permanently "Jamais".
"""
import logging
from typing import Iterator

from fastapi import Depends, Header, HTTPException, status

from zanshin.container import IoCContainer
from zanshin.database import SessionLocal
from zanshin.models.api_key import ApiKey


logger = logging.getLogger(__name__)

UNAUTHORIZED_HEADERS = {"WWW-Authenticate": "Bearer"}


def get_container() -> Iterator[IoCContainer]:
    """One session per request, closed on the way out.

    Deliberately not `zanshin.container.get_container()`: that helper hands back a
    container whose session the caller must remember to close, which is fine
    inside a UI event handler that owns a `finally`, but a dependency can
    guarantee it instead.
    """
    db = SessionLocal()
    try:
        yield IoCContainer(db)
    finally:
        db.close()


def require_api_key(
    authorization: str = Header(default=""),
    container: IoCContainer = Depends(get_container),
) -> ApiKey:
    """Resolve the caller's key, or refuse the request.

    Failures are deliberately indistinguishable to the caller (missing, malformed
    and wrong all yield the same 401): telling an unauthenticated client *why*
    would confirm which prefixes exist.
    """
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Clé API requise : en-tête 'Authorization: Bearer zsk_...'.",
            headers=UNAUTHORIZED_HEADERS,
        )

    api_key = container.api_key_service.verify_key(token.strip(), record_use=True)
    if not api_key:
        logger.warning("Rejected API request with an invalid key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Clé API invalide.",
            headers=UNAUTHORIZED_HEADERS,
        )
    return api_key


def require_scope(scope: str):
    """Dependency factory: the calling key must hold `scope`.

    Enforced per route rather than checked once, because "what a key may do" is a
    property of the route, not of the request: a key with only `read` must be able to
    poll a scan and be refused when it tries to queue one.
    """

    from zanshin.api.rate_limit import rate_limited

    def dependency(api_key: ApiKey = Depends(rate_limited)) -> ApiKey:
        if not api_key.has_scope(scope):
            logger.warning(
                "API key '%s' lacks scope '%s' (has: %s)",
                api_key.name, scope, ",".join(api_key.scope_list) or "none",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cette clé n'a pas la portée '{scope}'.",
            )
        return api_key

    return dependency


def require_target_access(api_key: ApiKey, kind: str, target_id) -> None:
    """Refuse a key that is restricted to another target.

    403 and not 404: hiding the target's existence would be a nicer story, but the
    caller already knows the id it asked for, and a distinct status is what lets a
    pipeline tell "my key is scoped elsewhere" from "this target is gone".
    """
    if not api_key.covers(kind, target_id):
        logger.warning(
            "API key '%s' is restricted to %s:%s and asked for %s:%s",
            api_key.name, api_key.target_kind, api_key.target_id, kind, target_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cette clé est restreinte à une autre cible.",
        )
