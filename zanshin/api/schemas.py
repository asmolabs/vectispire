"""Request and response models for the HTTP API.

Separate from the SQLAlchemy models on purpose: the API is a contract with CI
pipelines and scripts, and it should not change shape every time a column is
added or renamed.
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator

from zanshin.services.policy_gate import DEFAULT_FAIL_ON_SEVERITY, SEVERITY_ORDER


class TargetRef(BaseModel):
    """Exactly one of the two ids, mirroring how a `Scan` references its target."""

    repository_id: Optional[int] = None
    container_id: Optional[int] = None

    @model_validator(mode="after")
    def exactly_one(self):
        if (self.repository_id is None) == (self.container_id is None):
            raise ValueError("Fournir soit 'repository_id', soit 'container_id' (pas les deux).")
        return self


class ScanCreated(BaseModel):
    scan_id: int
    status: str
    repository_id: Optional[int] = None
    container_id: Optional[int] = None


class ScanStatus(BaseModel):
    scan_id: int
    status: str
    created_at: Optional[str] = None
    duration_ms: Optional[int] = None
    findings_count: int = 0
    # The delta that makes a scan result readable at a glance (see IssueService).
    new_issues: int = 0
    resolved_issues: int = 0
    summary: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class IssueOut(BaseModel):
    id: int
    type: str
    identifier: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    is_kev: bool = False
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    purl: Optional[str] = None
    file_path: Optional[str] = None
    fix_state: Optional[str] = None
    fix_versions: Optional[str] = None
    link: Optional[str] = None
    state: str
    triage_status: str
    triage_justification: Optional[str] = None
    first_seen_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    times_seen: int = 1
    repository_id: Optional[int] = None
    container_id: Optional[int] = None


class IssuePage(BaseModel):
    """Paginated, and explicit about it: `total` lets a caller know when it has
    only part of the picture, which a bare truncated list never does."""

    items: List[IssueOut]
    total: int
    limit: int
    offset: int


class GatePolicyIn(BaseModel):
    fail_on_severity: Optional[str] = DEFAULT_FAIL_ON_SEVERITY
    fail_on_kev: bool = True
    fixable_only: bool = False
    include_triaged: bool = False

    @model_validator(mode="after")
    def known_severity(self):
        if self.fail_on_severity is not None:
            value = self.fail_on_severity.lower()
            if value not in SEVERITY_ORDER:
                raise ValueError(
                    f"'fail_on_severity' doit être l'une de : {', '.join(SEVERITY_ORDER)}, "
                    "ou null pour ne pas filtrer sur la sévérité."
                )
            self.fail_on_severity = value
        return self


class GateRequest(TargetRef):
    policy: GatePolicyIn = Field(default_factory=GatePolicyIn)


class ViolationOut(BaseModel):
    rule: str
    issue_id: int
    identifier: Optional[str] = None
    severity: Optional[str] = None
    package: Optional[str] = None
    fix_versions: Optional[str] = None
    reason: str


class GateResponse(BaseModel):
    passed: bool
    evaluated: int
    counts_by_severity: Dict[str, int]
    violations: List[ViolationOut]


class TargetOut(BaseModel):
    kind: str  # "repository" | "container"
    id: int
    name: str
    open_issues: int
    last_scan_id: Optional[int] = None
    last_scan_status: Optional[str] = None
    last_scan_at: Optional[str] = None
