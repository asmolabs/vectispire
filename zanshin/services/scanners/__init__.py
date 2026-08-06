"""Scanner backends: the `ScannerEngine` contract and its implementations.

**Why the imports below are lazy.** This package used to import every engine and
the factory at module load. The factory reads a setting, so it imports
`SettingsService`, which imports the repositories, which import the models and
SQLAlchemy — meaning that `from zanshin.services.scanners.base import
ScannerEngine`, an import of one abstract class with no dependencies, pulled in
the entire persistence layer as a side effect of running this file.

That was merely wasteful until scans became runnable on a remote agent: an agent
holds engines but has no database and no `ENCRYPTION_KEY`, and that absence is a
security property, not an optimisation (ADR-002 D3). A test asserts it
(`tests/test_scan_runner.py`), and it is this module that would have broken it.

PEP 562 module-level `__getattr__` keeps every existing call site working —
`from zanshin.services.scanners import get_scanner_engine` still resolves — while
importing nothing until a name is actually asked for.
"""
from typing import Any

# name → module that defines it. Kept explicit rather than derived so that the
# public surface of this package is still readable in one glance.
_EXPORTS = {
    "ScannerEngine": "zanshin.services.scanners.base",
    "DockerScannerEngine": "zanshin.services.scanners.docker_engine",
    "DEFAULT_IMAGE_SCAN_PLATFORM": "zanshin.services.scanners.docker_engine",
    "OsvScannerEngine": "zanshin.services.scanners.osv_engine",
    "LocalApiScannerEngine": "zanshin.services.scanners.local_api_engine",
    "get_scanner_engine": "zanshin.services.scanners.factory",
    "SETTING_KEY_SCAN_BACKEND": "zanshin.services.scanners.factory",
    "SETTING_KEY_LOCAL_API_URL": "zanshin.services.scanners.factory",
    "SETTING_KEY_LOCAL_API_SHARED_DIR": "zanshin.services.scanners.factory",
    "SETTING_KEY_IMAGE_SCAN_PLATFORM": "zanshin.services.scanners.factory",
    "DEFAULT_LOCAL_API_URL": "zanshin.services.scanners.factory",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    module_path = _EXPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    value = import_module(module_path).__dict__[name]
    # Cached on the package so repeated access costs nothing after the first.
    globals()[name] = value
    return value


def __dir__() -> list:
    return sorted(__all__)
