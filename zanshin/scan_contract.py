"""The contract between whoever *runs* a scan and whoever *ingests* it.

Two shapes and a version. `ScanTask` is everything needed to execute one scan;
`ScanArtifacts` is the raw output of having executed it. Nothing else crosses
that line — no `Scan` row, no session, no encryption key.

**Why this is its own module, importing nothing from Zanshin.** The same two
shapes travel between objects in one process (`ScanProcessor` composing
`ScanRunner` and `ScanIngestor`) and between two machines over HTTP (a remote
agent and the control plane). A module that depended on `zanshin.models` would
drag SQLAlchemy into an agent that has no database, which is precisely the
property ADR-002 D3 exists to protect. It is also the future
`zanshin-common` package described in ADR-002 §8.4, minus the packaging.

**Why a version.** Once an agent is a separate deployment, an agent of one
version will eventually talk to a control plane of another. The server compares
`CONTRACT_VERSION` at registration and refuses what it cannot interpret, with a
message naming both versions — rather than failing later, deeper, on a missing
field (ADR-002 §8.5).
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# Bumped when the meaning of a field changes or a required field is added.
# Adding an *optional* field does not require a bump: an older agent simply
# leaves it unset.
CONTRACT_VERSION = "1"

TARGET_REPOSITORY = "repository"
TARGET_CONTAINER = "container"

class ScanTask(BaseModel):
    """One unit of scanning work, self-contained by construction.

    A runner must be able to execute this without reading anything else — no
    database lookup, no settings row, no key store. That constraint is what
    makes the same object usable as an HTTP payload for a remote agent.
    """

    scan_id: int
    kind: str  # TARGET_REPOSITORY | TARGET_CONTAINER

    # Repository targets
    repo_url: Optional[str] = None
    branch: str = "main"
    sub_path: str = ""
    # Deploy key material, present only for an agent whose `credentials_mode` is
    # `delegated` (ADR-002 §5). Empty for a `local`-mode agent — which is the
    # default, and the reason the field is optional rather than required: the
    # normal case is that no secret travels at all. Never written anywhere but a
    # 0600 temp file that the clone deletes.
    ssh_private_key: Optional[str] = None
    # Reserved for the short-lived-credential model of ADR-002 §5, which is the
    # end state for `delegated`. Present in the contract from the start so that
    # moving to it does not change the shape of the message — the server does not
    # emit it yet, and a runner that sees it may refuse an expired task.
    ssh_credential_expires_at: Optional[str] = None

    # Container targets
    image: Optional[str] = None

    # Whether to collect a source sample for the optional AI review. Decided by
    # the control plane (it knows whether the feature is on) and executed by the
    # runner (it is the only one holding the checkout).
    collect_code_sample: bool = False

    @property
    def is_container(self) -> bool:
        return self.kind == TARGET_CONTAINER

    def redacted(self) -> "ScanTask":
        """A copy safe to log or echo back: no key material."""
        return self.model_copy(update={"ssh_private_key": None})

class ScanArtifacts(BaseModel):
    """What a scan produced, in the scanners' own formats.

    Raw on purpose: normalization into `Finding` rows, enrichment, licence
    policy and issue reconciliation all happen in the control plane, so a
    result produced by a remote agent is indistinguishable from a local one and
    a rule change does not require redeploying agents (ADR-002 §8.3).
    """

    sbom: Dict[str, Any] = Field(default_factory=dict)
    cves: Dict[str, Any] = Field(default_factory=dict)
    # gitleaks report entries; empty for container targets.
    secrets: List[Dict[str, Any]] = Field(default_factory=list)
    # checkov failed checks; empty for container targets.
    iac: List[Dict[str, Any]] = Field(default_factory=list)
    # Size-capped concatenation of source files, present only when the task
    # asked for it. Sent to the model by the control plane, not by the runner —
    # an agent has no reason to hold an Ollama URL.
    code_sample: str = ""
    duration_ms: int = 0
    # Step-by-step trace, which for a scan that ran on another machine is the
    # only window an operator has into what happened.
    log: List[str] = Field(default_factory=list)
