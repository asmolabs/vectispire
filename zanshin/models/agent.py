"""A worker that executes scans — this process, or another machine.

Before this table, the thing that ran a scan had no identity. The queue claimed
a row, a thread in whatever process happened to be dispatching picked it up, and
that was the whole story: nothing recorded *where* a scan ran, an operator had no
way to see how much capacity existed, and there was no way to say "stop running
scans here". That last one is the point of the exercise — you cannot move
execution off the web instance until the web instance is something you can name
and switch off.

So both kinds of worker are rows in this table:

- **`builtin`** — the web process itself. Created (and refreshed) automatically at
  startup, one per host, no credentials. This is Jenkins' built-in node: the
  default single-process deployment keeps working with no configuration, and
  disabling it is how an operator says "everything must run on agents from now
  on".
- **`remote`** — a separate `python -m zanshin.agent` process, authenticated by an
  API key carrying the `agent` scope (décision 0003). It polls over HTTP, so it can
  live behind NAT and never needs a database connection.

Two design notes worth stating because they are decisions, not consequences:

**There is no `status` column.** An agent is online if it was seen recently;
storing that would mean a writer somewhere had to notice the *absence* of a
heartbeat, which is exactly the kind of bookkeeping that goes stale. `last_seen_at`
plus a TTL answers the question at read time and cannot disagree with itself.

**`credentials_mode` defaults to `local`.** The control plane sends no secret; the
agent clones with whatever credentials its own machine already has. The
alternative — shipping the decrypted deploy key inside the task — is available
per agent (`delegated`) but has to be asked for, because a compromised agent then
holds a long-lived key to every repository it ever scanned. See décision 0003, which
resolves an explicitly open question in favour of "no secret leaves by default".
"""
import uuid

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.types import JSON

from zanshin.clock import utcnow
from zanshin.database import Base
from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime

KIND_BUILTIN = "builtin"
KIND_REMOTE = "remote"

# No secret ever leaves the control plane; the agent uses the git credentials its
# own machine holds. The default, and the recommendation.
CREDENTIALS_LOCAL = "local"
# The deploy key travels inside the task, per job. Opt-in, per agent — see the
# module docstring and décision 0003.
CREDENTIALS_DELEGATED = "delegated"

# How long an agent may stay silent before it is reported offline. Comfortably
# above the agent's own poll interval, so one slow request does not make a
# healthy agent flap between states.
ONLINE_TTL_SECONDS = 120

STATUS_ONLINE = "online"
STATUS_OFFLINE = "offline"
STATUS_DISABLED = "disabled"


class Agent(Base):
    __tablename__ = "agent"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(String(500), nullable=True)

    kind = Column(String(20), default=KIND_REMOTE, nullable=False)

    # Comma-separated, normalized by `AgentService`. Routes work to a subset of
    # machines ("this one can reach the internal registry"). One label per job,
    # not a boolean expression: see `agent_matches_label`.
    labels = Column(String(255), default="", nullable=True)

    credentials_mode = Column(String(20), default=CREDENTIALS_LOCAL, nullable=False)

    enabled = Column(Boolean, default=True, nullable=False)

    # How many scans this agent may run at once. Null for the built-in agent,
    # which follows the existing `scan_max_concurrent` setting instead — one
    # number for "how many scans this host runs at once" rather than two that
    # can contradict each other.
    max_concurrent = Column(Integer, nullable=True)

    # The credential a remote agent authenticates with, so revoking the key and
    # retiring the agent are visibly the same act. Null for `builtin`, which
    # authenticates nothing: it *is* the control plane.
    # `ondelete` declared here as well as in the migration: `alembic check` compares
    # the two, and a difference this small is exactly what it exists to catch.
    api_key_id = Column(GUID, ForeignKey("api_key.id", ondelete="SET NULL"), nullable=True)

    # Self-reported on every call-in. Diagnostic only: the control plane never
    # trusts these for a decision, it only shows them.
    hostname = Column(String(255), nullable=True)
    platform = Column(String(255), nullable=True)
    version = Column(String(50), nullable=True)
    scanner_engine = Column(String(50), nullable=True)
    capabilities = Column(JSON, nullable=True)
    # Which version of the task/result contract this agent speaks (see
    # zanshin/scan_contract.py). Recorded at registration so a mismatch is
    # refused with a message naming both sides, instead of failing later on a
    # missing field.
    contract_version = Column(String(20), nullable=True)

    last_seen_at = Column(SafeDateTime, nullable=True)
    created_at = Column(SafeDateTime, default=utcnow, nullable=False)

    @property
    def is_builtin(self) -> bool:
        return self.kind == KIND_BUILTIN

    @property
    def sends_credentials(self) -> bool:
        """Whether a task for this agent may carry deploy key material."""
        return self.credentials_mode == CREDENTIALS_DELEGATED

    @property
    def label_set(self) -> set:
        return {label for label in (self.labels or "").split(",") if label}

    @property
    def worker_id(self) -> str:
        """What this agent writes into `Scan.claimed_by`.

        The id rather than the name: a rename must not orphan the scans an agent
        is holding, and the UI can resolve the id back to whatever the agent is
        called now.
        """
        return self.id.hex if isinstance(self.id, uuid.UUID) else str(self.id)
