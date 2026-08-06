"""Security response headers for every response, UI and API alike.

None were set. The consequence is not theoretical for this application: it renders
strings that come from scanner output, advisory feeds and package metadata — data an
attacker can influence — so the difference between "an injected string is inert" and
"it executes with the analyst's session" is exactly what a Content-Security-Policy
decides.

The policy is deliberately narrow but not aspirational: it describes what Reflex
actually needs, so it can be enabled rather than admired.

- `'unsafe-inline'` for styles and `'unsafe-eval'` for scripts are required by the
  Next.js bundle Reflex generates. Removing them means changing how the frontend is
  built, not changing this header, so pretending otherwise would just mean shipping
  a policy someone has to disable on first contact.
- `connect-src 'self'` covers the websocket the UI runs on (`ws:`/`wss:` to the
  same origin), which is how every event reaches the server.
- `frame-ancestors 'none'` and `X-Frame-Options: DENY` say the same thing to old and
  new browsers; both are cheap.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        # See the module docstring for why these two relaxations are honest.
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self' data:",
        # Same-origin XHR and the Reflex event websocket.
        "connect-src 'self' ws: wss:",
        # Nothing in Zanshin embeds a plugin, a frame, or another origin's page.
        "object-src 'none'",
        "frame-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]
)

HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    # Referrers can carry a scan id or a target name; no reason to leak them.
    "Referrer-Policy": "no-referrer",
    # This application has no use for any of these.
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    # Deliberately *not* HSTS: Zanshin is commonly reached over plain HTTP on an
    # internal address, and a Strict-Transport-Security header would make that
    # origin permanently unreachable in the browser that saw it once. It belongs on
    # the reverse proxy that terminates TLS, which knows it has TLS.
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        for name, value in HEADERS.items():
            # `setdefault` semantics: never override a header a route set on
            # purpose (a download's Content-Disposition, a proxy's own CSP).
            if name not in response.headers:
                response.headers[name] = value
        return response
