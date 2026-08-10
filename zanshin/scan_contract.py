"""The contract between whoever *runs* a scan and whoever *ingests* it.

Two shapes and a version. `ScanTask` is everything needed to execute one scan;
`ScanArtifacts` is the raw output of having executed it. Nothing else crosses
that line — no `Scan` row, no session, no encryption key.

**Why this is its own module, importing nothing from Zanshin.** The same two
shapes travel between objects in one process (`ScanProcessor` composing
`ScanRunner` and `ScanIngestor`) and between two machines over HTTP (a remote
agent and the control plane). A module that depended on `zanshin.models` would
drag SQLAlchemy into an agent that has no database, which is precisely the
property décision 0003 exists to protect. It is also the future
`zanshin-common` package described in docs/architecture/01, minus the packaging.

**Why a version.** Once an agent is a separate deployment, an agent of one
version will eventually talk to a control plane of another. The server compares
`CONTRACT_VERSION` at registration and refuses what it cannot interpret, with a
message naming both versions — rather than failing later, deeper, on a missing
field (docs/architecture/04).
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
    # `delegated` (décision 0003). Empty for a `local`-mode agent — which is the
    # default, and the reason the field is optional rather than required: the
    # normal case is that no secret travels at all. Never written anywhere but a
    # 0600 temp file that the clone deletes.
    ssh_private_key: Optional[str] = None
    # Reserved for the short-lived-credential model of décision 0003, which is the
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
    # Whether to run the Semgrep step. Same division of labour as above: the setting
    # lives in the database, and an agent has no database.
    run_sast: bool = False

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
    a rule change does not require redeploying agents (décision 0003).
    """

    sbom: Dict[str, Any] = Field(default_factory=dict)
    cves: Dict[str, Any] = Field(default_factory=dict)
    # gitleaks report entries; empty for container targets.
    secrets: List[Dict[str, Any]] = Field(default_factory=list)

    # The three fields below distinguish `[]` from `None`, and the distinction is the
    # whole point: `[]` means "the analysis ran and found nothing", which is what lets
    # the control plane *resolve* a target's outstanding issues of that kind. `None`
    # means it did not run — the step was disabled, the backend cannot do it, the tool
    # crashed — and the backlog must then be left exactly as it was.
    #
    # `Optional` rather than a parallel `*_ran` boolean because a boolean can disagree
    # with its payload and this cannot; and because an agent built before a field existed
    # leaves it unset, which lands on the correct behaviour for free (no
    # `CONTRACT_VERSION` bump needed for an optional field).

    # checkov failed checks; `None` for container targets and on a checkov failure.
    iac: Optional[List[Dict[str, Any]]] = None
    # Semgrep `results` entries; `None` for container targets, when the SAST step is
    # switched off, and on any Semgrep failure.
    sast: Optional[List[Dict[str, Any]]] = None
    # Size-capped concatenation of source files, present only when the task
    # asked for it. Sent to the model by the control plane, not by the runner —
    # an agent has no reason to hold an Ollama URL.
    code_sample: str = ""
    duration_ms: int = 0
    # Step-by-step trace, which for a scan that ran on another machine is the
    # only window an operator has into what happened.
    log: List[str] = Field(default_factory=list)
