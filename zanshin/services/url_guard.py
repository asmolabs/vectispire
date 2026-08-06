"""Validation of the URLs Zanshin will make outbound requests to.

Three settings become server-side requests: the notification webhook, the Ollama
server, and the local scan API. Each is an admin-settable string that the server
then fetches, which is a server-side request forgery primitive — the classic target
being the cloud metadata endpoint (`169.254.169.254`), which hands out instance
credentials to anything that asks.

"Only an admin can set it" is a mitigation, not an answer: an admin of Zanshin is
not necessarily someone entitled to read the host's IAM credentials, and this is
exactly the pivot an attacker who has phished one account wants.

**The private-address problem.** Blocking private addresses outright would break
two of the three settings by design — Ollama and the scan sidecar are *supposed* to
be on localhost or the internal network. So the rule is per-use:

- `allow_private=False` (the webhook): public destinations only.
- `allow_private=True` (the sidecar): private and loopback are fine, but link-local
  — the metadata range — never is. Nothing legitimate lives at 169.254.0.0/16, and
  that is the address the attack actually wants.
- `require_private=True` (Ollama): the mirror image, and the one that is easy to
  miss. Ollama receives the scanned repository's *source code*, so the risk is not
  that the URL points somewhere internal — it is that it points somewhere
  **external**. A public, well-formed URL is exactly what an exfiltration channel
  looks like, and no amount of SSRF checking would flag it.

DNS is resolved here so that a hostname pointing at a blocked address is refused
too. That leaves a rebinding window between this check and the request itself,
which this cannot close: doing so would mean pinning the resolved address into the
HTTP client. Recorded as a known limitation rather than papered over.
"""
import ipaddress
import logging
import socket
from typing import List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = ("https", "http")

# Instance metadata (AWS/GCP/Azure and friends). Never a legitimate destination.
LINK_LOCAL_V4 = ipaddress.ip_network("169.254.0.0/16")
LINK_LOCAL_V6 = ipaddress.ip_network("fe80::/10")


class UnsafeUrlError(ValueError):
    """The URL is not one Zanshin will call. A `ValueError` so the UI's existing
    `str(e)` handling surfaces the reason unchanged."""


def validate_outbound_url(
    url: str,
    *,
    allow_private: bool,
    require_private: bool = False,
    label: str = "URL",
) -> str:
    """Return the cleaned URL, or raise `UnsafeUrlError`."""
    candidate = (url or "").strip()
    if not candidate:
        raise UnsafeUrlError(f"{label} : valeur vide.")

    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeUrlError(
            f"{label} : schéma '{parsed.scheme or '(aucun)'}' non autorisé "
            f"(attendu : {', '.join(ALLOWED_SCHEMES)})."
        )
    if not parsed.hostname:
        raise UnsafeUrlError(f"{label} : hôte manquant.")

    addresses = _resolve(parsed.hostname, label)
    if require_private and not addresses:
        # Failing open is defensible for "is this private?" — the request would fail
        # anyway. It is not defensible for "this MUST be private": an unresolvable
        # name proves nothing, and this check is what stands between the scanned
        # source code and an external host. So an unverifiable name is refused.
        raise UnsafeUrlError(
            f"{label} : l'hôte n'a pas pu être résolu, donc son caractère interne ne "
            "peut pas être vérifié — et ce point de terminaison reçoit du code source."
        )

    for address in addresses:
        if address in LINK_LOCAL_V4 or address in LINK_LOCAL_V6:
            raise UnsafeUrlError(
                f"{label} : l'hôte résout vers une adresse link-local ({address}), "
                "utilisée par les services de métadonnées d'instance."
            )
        if not allow_private and not address.is_global:
            raise UnsafeUrlError(
                f"{label} : l'hôte résout vers une adresse privée ou locale ({address}). "
                "Une destination publique est attendue ici."
            )
        if require_private and address.is_global:
            raise UnsafeUrlError(
                f"{label} : l'hôte résout vers une adresse publique ({address}). "
                "Une destination locale ou interne est attendue ici — ce point de "
                "terminaison reçoit du code source."
            )
    return candidate


def _resolve(hostname: str, label: str) -> List[ipaddress._BaseAddress]:
    """Every address a hostname resolves to.

    All of them, not just the first: a hostname can return a public and a private
    address, and checking one would let the other through.
    """
    try:
        literal = ipaddress.ip_address(hostname)
        return [literal]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        # Refusing on a resolution failure would make the settings page unusable
        # whenever DNS hiccups, and the request itself will fail anyway. Logged so
        # the gap is visible.
        logger.warning("%s: could not resolve %r (%s) — address checks skipped", label, hostname, e)
        return []

    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return addresses


def is_safe_outbound_url(url: str, *, allow_private: bool) -> Optional[str]:
    """Non-raising variant: the reason, or `None` when the URL is acceptable."""
    try:
        validate_outbound_url(url, allow_private=allow_private)
    except UnsafeUrlError as e:
        return str(e)
    return None
