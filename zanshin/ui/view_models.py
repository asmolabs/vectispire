"""Typed view models for the UI layer.

Every screen used to carry its rows as `list[dict[str, str]]`, which meant each
builder stringified everything on the way in (`"critical": str(crit)`) and each
view compared strings on the way out (`rx.cond(r["critical"] != "0", ...)`). Three
costs, all paid on every screen:

- numbers stopped being numbers, so a template could only ask "is it the string
  zero", never "is it more than five";
- a typo in a key (`r["secrets"]` vs `r["secret"]`) failed silently at render
  time, since a dict lookup on a Var produces another Var;
- the shape of a row existed nowhere — you had to read the builder to know what
  a template could rely on.

Dataclasses fix all three — the form Reflex currently recommends for custom var
types. Fields are typed, `row.critical > 0` compares numbers because attribute
access on a Var yields a typed Var (`NumberCastedVar`), and a mistyped attribute
is a *compile-time* error because Reflex knows the dataclass.

Formatting (dates, percentages, severity colours) stays here rather than in the
templates, so the same row renders identically wherever it is used.
"""
import dataclasses
from typing import List, Optional

# Severity → Radix colour scheme, in one place. Previously repeated inline in
# four pages, with two of them disagreeing about "negligible".
SEVERITY_COLORS = {
    "critical": "red",
    "high": "orange",
    "medium": "yellow",
    "low": "blue",
    "negligible": "gray",
}


def severity_color(severity: Optional[str]) -> str:
    return SEVERITY_COLORS.get((severity or "").lower(), "gray")


def safe_external_url(url: Optional[str]) -> str:
    """An externally-sourced URL, or the empty string if it isn't safe to link to.

    Reference URLs come from Grype (`vulnerability.dataSource`) and OSV
    (`references[].url`) — that is, ultimately from advisory feeds and from
    package metadata that a package author controls. Rendering one straight into
    `rx.link(href=...)` means a `javascript:` URL becomes a click away from
    executing in an analyst's browser, with their session. Only the two schemes
    that can actually be a reference are allowed through.
    """
    if not url:
        return ""
    candidate = url.strip()
    if candidate.lower().startswith(("https://", "http://")):
        return candidate
    return ""


def format_datetime(value, fmt: str = "%d/%m/%Y %H:%M") -> str:
    return value.strftime(fmt) if value else ""


def format_percent(value: Optional[float]) -> str:
    return f"{value:.1%}" if value is not None else "—"


def format_score(value: Optional[float]) -> str:
    return f"{value:.1f}" if value is not None else "—"


@dataclasses.dataclass
class SeverityCounts:
    """The severity breakdown carried by a scan summary, as numbers."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @classmethod
    def from_summary(cls, summary: Optional[dict]) -> "SeverityCounts":
        summary = summary or {}
        return cls(
            critical=summary.get("critical", 0) or 0,
            high=summary.get("high", 0) or 0,
            medium=summary.get("medium", 0) or 0,
            low=summary.get("low", 0) or 0,
        )


@dataclasses.dataclass
class ScanRow:
    """One line of a scan history table."""

    id: int = 0
    target_name: str = ""
    branch: str = "—"
    status: str = "pending"
    findings: int = 0
    counts: SeverityCounts = dataclasses.field(default_factory=SeverityCounts)
    secrets: int = 0
    new_issues: int = 0
    resolved_issues: int = 0
    duration: str = "—"
    created_at: str = ""
    # Empty when the scan belongs to a container: only repositories can be
    # rescanned from the history table.
    repo_id: str = ""


@dataclasses.dataclass
class RepositoryRow:
    """One line of the repositories table."""

    id: int = 0
    name: str = ""
    url: str = ""
    branch: str = "main"
    status: str = "Non scanné"
    findings: int = 0
    counts: SeverityCounts = dataclasses.field(default_factory=SeverityCounts)
    secrets: int = 0
    open_issues: int = 0
    last_scan_at: str = ""


@dataclasses.dataclass
class ContainerRow:
    """One line of the container images table."""

    id: int = 0
    image_name: str = ""
    tag: str = "latest"
    registry: str = "docker.io"
    status: str = "Non scanné"
    vulns: int = 0
    counts: SeverityCounts = dataclasses.field(default_factory=SeverityCounts)
    open_issues: int = 0
    interval: int = 1440


@dataclasses.dataclass
class RepoScanRow:
    """One line of the per-repository scan list (repository details view)."""

    id: int = 0
    branch: str = "main"
    status: str = "pending"
    findings: int = 0
    counts: SeverityCounts = dataclasses.field(default_factory=SeverityCounts)
    secrets: int = 0
    new_issues: int = 0
    resolved_issues: int = 0
    created_at: str = ""


@dataclasses.dataclass
class VulnerabilityRow:
    """One vulnerability in a scan-detail dialog.

    Built from `Finding` rows, not from the raw `Scan.cves` blob — which is what
    lets the retention policy drop those blobs without blanking the UI.
    """

    identifier: str = "N/A"
    severity: str = "UNKNOWN"
    severity_color: str = "gray"
    component: str = "N/A"
    version: str = ""
    cvss: str = "—"
    epss: str = "—"
    is_kev: bool = False
    fix: str = "—"
    link: str = ""
    description: str = ""


@dataclasses.dataclass
class SecretRow:
    rule: str = "N/A"
    file_path: str = "N/A"


@dataclasses.dataclass
class LicenseRow:
    license: str = "N/A"
    component: str = "N/A"


@dataclasses.dataclass
class IacRow:
    severity: str = "medium"
    severity_color: str = "gray"
    check_id: str = "N/A"
    resource: str = "N/A"
    file_path: str = "N/A"


@dataclasses.dataclass
class AiFindingRow:
    severity: str = "unknown"
    severity_color: str = "gray"
    title: str = "N/A"
    file_path: str = "—"


@dataclasses.dataclass
class AiReviewSummary:
    """The optional AI review attached to a scan. `present` replaces the previous
    "is the dict empty" test, which a typed model can't express."""

    present: bool = False
    model: str = ""
    status: str = ""
    response: str = ""
    error: str = ""


@dataclasses.dataclass
class IssueRow:
    """One line of the issue backlog."""

    id: int = 0
    type: str = ""
    identifier: str = "—"
    severity: str = "UNKNOWN"
    severity_color: str = "gray"
    package: str = "—"
    # "Directe" / "Transitive" / "" — empty when no dependency graph answered, so
    # the column stays blank instead of showing a word about nothing.
    dependency: str = ""
    dependency_color: str = "gray"
    file_path: str = "—"
    target: str = "—"
    state: str = ""
    is_open: bool = True
    triage: str = ""
    triage_color: str = "gray"
    triage_comment: str = ""
    triaged_by: str = ""
    triage_expires: str = ""
    ticket_ref: str = ""
    ticket_url: str = ""
    epss: str = "—"
    is_kev: bool = False
    cvss: str = "—"
    fix: str = "—"
    link: str = ""
    description: str = ""
    times_seen: int = 1
    first_seen: str = ""
    last_seen: str = ""


@dataclasses.dataclass
class GatePolicyRow:
    """One configured gate policy, as the settings screen shows it."""

    id: int = 0
    scope: str = ""
    target_kind: str = ""
    target_id: int = 0
    is_global: bool = True
    version: int = 1
    rules: str = ""
    note: str = ""
    author: str = ""
    changed_at: str = ""


def to_gate_policy_row(policy, scope_name: str) -> GatePolicyRow:
    """Rules rendered as one readable sentence rather than five columns of booleans:
    what an operator checks here is "what does this fail on", not a field list."""
    rules = [f"seuil {policy.fail_on_severity or 'aucun'}"]
    if policy.fail_on_kev:
        rules.append("KEV")
    if policy.fixable_only:
        rules.append("corrigeables uniquement")
    if policy.include_triaged:
        rules.append("triés inclus")
    if policy.include_ai_review:
        rules.append("revue IA incluse")
    return GatePolicyRow(
        id=policy.id,
        scope=scope_name,
        target_kind=policy.target_kind or "",
        target_id=policy.target_id or 0,
        is_global=policy.is_global,
        version=policy.version,
        rules=" · ".join(rules),
        note=policy.note or "",
        author=policy.created_by or "",
        changed_at=format_datetime(policy.created_at, "%d/%m/%Y"),
    )


@dataclasses.dataclass
class UserRow:
    id: int = 0
    username: str = ""
    display_name: str = ""
    email: str = "—"
    role: str = "USER"
    is_active: bool = True
    created_at: str = ""


@dataclasses.dataclass
class ApiKeyRow:
    id: str = ""  # GUID
    name: str = ""
    prefix: str = "—"
    last_used_at: str = "Jamais"
    created_at: str = ""
    scopes: str = ""
    target: str = "Toutes"
    expires_at: str = "Jamais"
    is_expired: bool = False


@dataclasses.dataclass
class AgentRow:
    """A worker that may run scans, as the Agents page shows it.

    `status` is computed from `last_seen_at` at read time rather than stored (see
    `AgentService`), so what this row says is what was true when the page loaded —
    which is the only honest thing a liveness display can claim.
    """

    id: str = ""  # GUID
    name: str = ""
    description: str = ""
    kind: str = "remote"          # builtin | remote
    is_builtin: bool = False
    status: str = "offline"       # online | offline | disabled
    enabled: bool = True
    labels: str = "—"
    credentials_mode: str = "local"
    sends_credentials: bool = False
    max_concurrent: int = 1
    running_jobs: int = 0
    hostname: str = "—"
    platform: str = "—"
    version: str = "—"
    scanner_engine: str = "—"
    last_seen_at: str = "Jamais"
    created_at: str = ""


@dataclasses.dataclass
class QueuedScanRow:
    """A scan in the queue or in flight, with who holds it.

    The queue was invisible before it moved into the database, and then visible only
    as a count. This is the row that answers the two questions an operator actually
    has when nothing seems to be happening: is anything waiting, and is anybody
    working on it.
    """

    scan_id: int = 0
    target: str = "—"
    status: str = "pending"
    # 1-based place in line while waiting, 0 once claimed.
    position: int = 0
    agent_name: str = "—"
    attempts: int = 0
    lease_expires_at: str = "—"
    # True when the lease has lapsed: the row is reclaimable, and the next tick or
    # dispatch will hand it to somebody else.
    lease_expired: bool = False
    created_at: str = ""


@dataclasses.dataclass
class SshKeyRow:
    id: str = ""  # GUID
    name: str = ""
    # Truncated for display; the private half is never sent to the browser.
    public_key: str = "N/A"
    created_at: str = ""


@dataclasses.dataclass
class AuditRow:
    timestamp: str = ""
    operation_type: str = ""
    user_id: str = ""
    resource_id: str = ""
    description: str = ""


# Deliberately dicts, unlike every other row model here: `rx.recharts.pie(data=...)`
# declares its prop as `Sequence[dict[str, Any]]`, so a dataclass is rejected at
# compile time. The chart is a third-party component with a dict-shaped contract —
# wrapping it in a model would mean converting back at the call site for no gain.
def severity_chart(counts: SeverityCounts) -> List[dict]:
    """The donut's four slices, in severity order."""
    return [
        {"name": "Critique", "value": counts.critical, "color": "var(--red-9)"},
        {"name": "Élevé", "value": counts.high, "color": "var(--orange-9)"},
        {"name": "Moyen", "value": counts.medium, "color": "var(--yellow-9)"},
        {"name": "Faible", "value": counts.low, "color": "var(--blue-9)"},
    ]
