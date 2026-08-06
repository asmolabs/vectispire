"""Zanshin's programmatic HTTP API.

Kept in its own package, mounted on the Reflex app via `api_transformer` (see
zanshin/zanshin.py). It shares the services and repositories with the UI and adds
no business logic of its own — a scan triggered from CI and one triggered from a
button are the same code path, which is the only way the two stay consistent.
"""
from zanshin.api.app import api_app
from zanshin.api.security_headers import SecurityHeadersMiddleware

# Applied to the whole ASGI app, UI included: `api_transformer` mounts this
# FastAPI instance as the app Reflex serves, so middleware here covers every
# response. Without a CSP, any injected markup executes with the analyst's session
# — and this application renders scanner output, i.e. attacker-influenced strings.
api_app.add_middleware(SecurityHeadersMiddleware)

__all__ = ["api_app", "SecurityHeadersMiddleware"]
