"""How an agent is configured: environment first, command line on top.

Environment variables because that is how a container is configured, and command
line flags because that is how a first run is debugged. Nothing is read from a
file and nothing is read from the database — an agent has neither.
"""
import os
from dataclasses import dataclass, field
from typing import Optional

# Chunk size for a result too large to post in one request. 4 MiB of serialized
# JSON: comfortably under the body limits of the proxies typically put in front of
# an application, and large enough that even a substantial SBOM takes a handful of
# requests rather than hundreds.
DEFAULT_CHUNK_BYTES = 4 * 1024 * 1024

# Local safety net for the poll loop, in case the controller's answer is missing or
# nonsensical. The real values come from `hello` — see `AgentIdentity`.
DEFAULT_POLL_WAIT_SECONDS = 30
DEFAULT_HEARTBEAT_SECONDS = 60
# After a network failure. Short enough that a controller restart is picked up
# quickly, long enough not to hammer a service that is down.
DEFAULT_RETRY_SECONDS = 10


@dataclass
class AgentConfig:
    url: str
    token: str
    # Which ScannerEngine to use locally. `docker` is the only one that makes sense
    # on a bare agent; `local_api` is there for an agent that already runs the
    # `scan-api` sidecar, which is the migration path away from that sidecar.
    scanner_engine: str = "docker"
    local_api_url: str = "http://localhost:8686"
    local_api_shared_dir: str = ""
    name: Optional[str] = None
    poll_wait_seconds: int = DEFAULT_POLL_WAIT_SECONDS
    heartbeat_seconds: int = DEFAULT_HEARTBEAT_SECONDS
    retry_seconds: int = DEFAULT_RETRY_SECONDS
    chunk_bytes: int = DEFAULT_CHUNK_BYTES
    # Stop after this many jobs. `None` means "run forever"; a number is what makes
    # the agent usable as a one-shot CI step, and what the tests use to bound a loop
    # that is otherwise infinite by design.
    max_jobs: Optional[int] = None
    verify_tls: bool = True

    def __post_init__(self):
        self.url = (self.url or "").rstrip("/")
        if not self.url:
            raise ValueError(
                "L'URL du contrôleur Zanshin est obligatoire (--url ou ZANSHIN_URL)."
            )
        if not self.token:
            raise ValueError(
                "Une clé API à portée « agent » est obligatoire "
                "(--token ou ZANSHIN_AGENT_TOKEN). Créez-la depuis la page Agents."
            )

    @property
    def is_secure(self) -> bool:
        return self.url.startswith("https://")


def from_environment(**overrides) -> AgentConfig:
    """Build a config from `ZANSHIN_*` variables, with explicit overrides winning.

    `None` overrides are dropped rather than applied, so an unset command line flag
    does not erase an environment variable.
    """
    values = {
        "url": os.getenv("ZANSHIN_URL", ""),
        "token": os.getenv("ZANSHIN_AGENT_TOKEN", ""),
        "scanner_engine": os.getenv("ZANSHIN_AGENT_SCANNER_ENGINE", "docker"),
        "local_api_url": os.getenv("ZANSHIN_AGENT_LOCAL_API_URL", "http://localhost:8686"),
        "local_api_shared_dir": os.getenv("ZANSHIN_AGENT_LOCAL_API_SHARED_DIR", ""),
        "name": os.getenv("ZANSHIN_AGENT_NAME") or None,
        "retry_seconds": int(os.getenv("ZANSHIN_AGENT_RETRY_SECONDS", DEFAULT_RETRY_SECONDS)),
        "chunk_bytes": int(os.getenv("ZANSHIN_AGENT_CHUNK_BYTES", DEFAULT_CHUNK_BYTES)),
        "verify_tls": os.getenv("ZANSHIN_AGENT_VERIFY_TLS", "true").lower() != "false",
    }
    values.update({k: v for k, v in overrides.items() if v is not None})
    return AgentConfig(**values)
