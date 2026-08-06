"""Zanshin's programmatic HTTP API.

Kept in its own package, mounted on the Reflex app via `api_transformer` (see
zanshin/zanshin.py). It shares the services and repositories with the UI and adds
no business logic of its own — a scan triggered from CI and one triggered from a
button are the same code path, which is the only way the two stay consistent.
"""
from zanshin.api.app import api_app

__all__ = ["api_app"]
