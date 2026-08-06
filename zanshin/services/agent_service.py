"""The agent registry: who may run scans, and how much they may run at once.

Answers three questions the application could not answer before: what workers
exist, which of them are alive, and how much capacity each one has left. The
queue asks the third one on every dispatch; the agents screen shows all three.

The built-in agent is created here rather than by a migration, because it
describes a *host*, not a schema: a data migration would have invented a row for
whichever machine happened to run `alembic upgrade`.
"""
import logging
import platform
import socket
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from zanshin.clock import utcnow
from zanshin.models.agent import (
    CREDENTIALS_DELEGATED,
    CREDENTIALS_LOCAL,
    KIND_BUILTIN,
    KIND_REMOTE,
    ONLINE_TTL_SECONDS,
    STATUS_DISABLED,
    STATUS_OFFLINE,
    STATUS_ONLINE,
    Agent,
)
from zanshin.models.api_key import SCOPE_AGENT
from zanshin.repositories.agent_repository import AgentRepository
from zanshin.scan_contract import CONTRACT_VERSION
from zanshin.services.api_key_service import ApiKeyService

logger = logging.getLogger(__name__)

BUILTIN_AGENT_NAME_PREFIX = "Agent intégré"

class AgentService:
    def __init__(
        self,
        agent_repository: AgentRepository,
        api_key_service: Optional[ApiKeyService] = None,
        settings_service=None,
    ):
        self.agent_repository = agent_repository
        # Only needed to create a remote agent: its credential and its row are
        # issued together, so revoking the key and retiring the agent are visibly
        # the same act.
        self.api_key_service = api_key_service
        # Read to size the built-in agent, which follows the existing
        # `scan_max_concurrent` setting rather than carrying a second number.
        self.settings_service = settings_service

    # --- Registry ---------------------------------------------------------

    def find_all(self) -> List[Agent]:
        return self.agent_repository.find_all()

    def find_by_id(self, agent_id) -> Optional[Agent]:
        return self.agent_repository.find_by_id(agent_id)

    def find_by_api_key_id(self, api_key_id) -> Optional[Agent]:
        return self.agent_repository.find_by_api_key_id(api_key_id)

    def find_by_worker_id(self, worker_id: str) -> Optional[Agent]:
        return self.agent_repository.find_by_worker_id(worker_id)

    def ensure_builtin_agent(self, hostname: Optional[str] = None) -> Agent:
        """This host's built-in agent, created on first call and refreshed after.

        Idempotent, and called on every startup: the row is the web process
        describing itself, so its self-reported fields are refreshed each time
        (a Python upgrade or a scanner-backend change should show up without an
        operator editing anything).

        What is *not* touched on refresh: `enabled`, `labels` and
        `credentials_mode`. Those are operator decisions, and a restart resetting
        "stop running scans here" would be a small disaster — the operator turned
        it off for a reason and would have no way to know it came back.
        """
        hostname = hostname or _hostname()
        agent = self.agent_repository.find_builtin(hostname)
        if agent is None:
            agent = Agent(
                name=f"{BUILTIN_AGENT_NAME_PREFIX} ({hostname})",
                description="Le processus Zanshin lui-même : exécute les scans sans agent distant.",
                kind=KIND_BUILTIN,
                labels="",
                # The control plane cannot "send itself" a key: it reads the key
                # store directly, which is exactly the privilege a remote agent
                # is denied (ADR-002 D3).
                credentials_mode=CREDENTIALS_LOCAL,
                enabled=True,
                # Null: capacity comes from `scan_max_concurrent` (see `capacity_of`).
                max_concurrent=None,
                hostname=hostname,
            )
        agent.platform = platform.platform()
        agent.version = _zanshin_version()
        agent.contract_version = CONTRACT_VERSION
        agent.last_seen_at = utcnow()
        return self.agent_repository.save(agent)

    def create_remote_agent(
        self,
        name: str,
        description: str = "",
        labels: str = "",
        credentials_mode: str = CREDENTIALS_LOCAL,
        max_concurrent: int = 1,
    ) -> Tuple[Agent, str]:
        """Register a remote agent and issue its credential.

        Returns the agent and the raw API key, which is shown once and never
        again — same contract as any other key. The key carries only
        `SCOPE_AGENT`, so a leaked agent credential cannot read the issue history
        or export anything.
        """
        name = (name or "").strip()
        if not name:
            raise ValueError("Le nom de l'agent est obligatoire.")
        if self.agent_repository.find_by_name(name):
            raise ValueError(f"Un agent nommé « {name} » existe déjà.")
        if not self.api_key_service:
            raise RuntimeError("Aucun service de clés API disponible pour créer un agent distant.")

        api_key, raw_key = self.api_key_service.create_key(
            name=f"Agent : {name}", scopes=[SCOPE_AGENT]
        )
        agent = Agent(
            name=name,
            description=(description or "").strip() or None,
            kind=KIND_REMOTE,
            labels=normalize_labels(labels),
            credentials_mode=validate_credentials_mode(credentials_mode),
            enabled=True,
            max_concurrent=max(1, int(max_concurrent or 1)),
            api_key_id=api_key.id,
        )
        return self.agent_repository.save(agent), raw_key

    def update_agent(
        self,
        agent_id,
        labels: Optional[str] = None,
        credentials_mode: Optional[str] = None,
        max_concurrent: Optional[int] = None,
        description: Optional[str] = None,
    ) -> Agent:
        agent = self._require(agent_id)
        if labels is not None:
            agent.labels = normalize_labels(labels)
        if credentials_mode is not None:
            if agent.is_builtin and credentials_mode == CREDENTIALS_DELEGATED:
                # Nothing is delegated to a process that already holds the key
                # store; accepting the value would suggest otherwise.
                raise ValueError(
                    "L'agent intégré lit directement le coffre de clés : le mode « délégué » "
                    "ne s'applique qu'aux agents distants."
                )
            agent.credentials_mode = validate_credentials_mode(credentials_mode)
        if max_concurrent is not None and not agent.is_builtin:
            agent.max_concurrent = max(1, int(max_concurrent))
        if description is not None:
            agent.description = description.strip() or None
        return self.agent_repository.save(agent)

    def set_enabled(self, agent_id, enabled: bool) -> Agent:
        """Take an agent in or out of service.

        Disabling stops it being given new work immediately. It does **not** stop
        a scan it is already running: nothing here can reach into another
        machine's process. That scan finishes and reports normally, or its lease
        lapses and the queue reclaims it — which is the same path as any other
        interruption, deliberately, so there is one recovery mechanism and not two.
        """
        agent = self._require(agent_id)
        agent.enabled = bool(enabled)
        return self.agent_repository.save(agent)

    def delete_agent(self, agent_id) -> bool:
        """Remove an agent.

        The built-in agent cannot be deleted, only disabled: it would reappear on
        the next startup (`ensure_builtin_agent`), minus the operator's settings —
        so deletion would silently mean "re-enable and forget my configuration".
        """
        agent = self._require(agent_id)
        if agent.is_builtin:
            raise ValueError(
                "L'agent intégré ne peut pas être supprimé : il est recréé au démarrage. "
                "Désactivez-le pour que cette instance cesse d'exécuter des scans."
            )
        return self.agent_repository.delete_by_id(agent_id)

    def _require(self, agent_id) -> Agent:
        agent = self.agent_repository.find_by_id(agent_id)
        if not agent:
            raise ValueError("Agent introuvable.")
        return agent

    # --- Liveness ---------------------------------------------------------

    def touch(self, agent: Agent, report: Optional[Dict[str, Any]] = None) -> Agent:
        """Record that `agent` just called in, refreshing what it reports about
        itself. Called on every agent request — registration, claim, heartbeat,
        result — so `last_seen_at` is the only liveness state there is and cannot
        drift from anything else."""
        agent.last_seen_at = utcnow()
        if report:
            for field in ("hostname", "platform", "version", "scanner_engine", "contract_version"):
                value = report.get(field)
                if value:
                    setattr(agent, field, str(value)[:255])
            if report.get("capabilities") is not None:
                agent.capabilities = report["capabilities"]
        return self.agent_repository.save(agent)

    def is_online(self, agent: Agent, now=None) -> bool:
        if not agent.last_seen_at:
            return False
        return (now or utcnow()) - agent.last_seen_at <= timedelta(seconds=ONLINE_TTL_SECONDS)

    def status_of(self, agent: Agent, now=None) -> str:
        if not agent.enabled:
            return STATUS_DISABLED
        return STATUS_ONLINE if self.is_online(agent, now) else STATUS_OFFLINE

    def find_available(self, now=None) -> List[Agent]:
        """Agents that are enabled and have been seen recently."""
        return [a for a in self.find_all() if a.enabled and self.is_online(a, now)]

    def has_agent_for_label(self, required_label: str = "", now=None) -> bool:
        return any(
            agent_matches_label(agent, required_label) for agent in self.find_available(now)
        )

    # --- Capacity ---------------------------------------------------------

    def capacity_of(self, agent: Agent) -> int:
        """How many scans this agent may run at once.

        The built-in agent follows `scan_max_concurrent` — the setting that
        already means "how many scans this host runs at once" — instead of a
        column of its own. Two numbers for one question would eventually
        disagree, and the operator would have no way to tell which one won.
        """
        if not agent.enabled:
            return 0
        if agent.is_builtin:
            from zanshin.services.scan_queue import max_concurrent

            if self.settings_service is None:
                return 1
            return max_concurrent(self.settings_service)
        return max(0, agent.max_concurrent or 1)

def normalize_labels(labels: Optional[str]) -> str:
    """Canonical form: trimmed, lowercased, de-duplicated, order preserved.

    Normalized on write so that matching is a set membership test rather than a
    parsing exercise repeated at every comparison.
    """
    if not labels:
        return ""
    seen = []
    for raw in labels.replace(";", ",").split(","):
        label = raw.strip().lower()
        if label and label not in seen:
            seen.append(label)
    return ",".join(seen)

def validate_credentials_mode(mode: Optional[str]) -> str:
    if mode in (CREDENTIALS_LOCAL, CREDENTIALS_DELEGATED):
        return mode
    raise ValueError(
        f"Mode d'identifiants inconnu : « {mode} ». Valeurs possibles : "
        f"« {CREDENTIALS_LOCAL} » (aucun secret transmis) ou « {CREDENTIALS_DELEGATED} »."
    )

def agent_matches_label(agent: Agent, required_label: Optional[str]) -> bool:
    """Single-label matching, and deliberately not a Jenkins-style boolean label
    expression.

    One label covers the need that exists — "this scan must run on a machine that
    can reach X" — without inventing an expression parser, its precedence rules
    and its error messages. If two labels ever need combining, that is the moment
    to write it, with a real case to test against (ADR-002, étape 4).
    """
    if not required_label:
        return True
    return required_label.strip().lower() in agent.label_set

def _hostname() -> str:
    try:
        return socket.gethostname() or "localhost"
    except Exception:
        # A container with no resolvable hostname must not stop the application
        # from starting.
        return "localhost"

def _zanshin_version() -> str:
    try:
        from importlib.metadata import version

        return version("backend-python")
    except Exception:
        return "dev"
