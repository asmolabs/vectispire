"""A stored, versioned gate policy.

The gate's policy arrived in the body of the request. That means the rules lived in
each project's CI file, where whoever finds them too strict loosens them — and the
security team learns about it never. It also meant the verdict was unauditable: two
identical calls a month apart could disagree, and nothing recorded why.

Two properties follow from making it a row:

* **Versioned, not updated in place.** Every change inserts a new row and deactivates
  the previous one, so "which policy failed that build in March" has an answer. A
  policy is a security decision; overwriting it would erase the decision along with
  its author.
* **Resolved by target, with a global default.** A row with no target is the
  organisation's default; a row with one overrides it for that repository or image.
  Anything not configured falls back to the code's own defaults, so the gate keeps
  working on a database where this table is empty.

There is deliberately no notion of a policy-level *exception* ("ignore CVE-X until
June"). That already exists, in the right vocabulary and with a review date: triage
`not_affected` with a VEX justification. A second suppression mechanism would mean
two places to look when a finding fails to fail a build.
"""
from sqlalchemy import Boolean, Column, Integer, String, Text, UniqueConstraint

from zanshin.clock import utcnow
from zanshin.database import Base
from zanshin.models.safedatetime import SafeDateTime

# `target_kind` values.
TARGET_REPOSITORY = "repository"
TARGET_CONTAINER = "container"
VALID_TARGET_KINDS = (TARGET_REPOSITORY, TARGET_CONTAINER)

# How the global scope is stored. The service's public spelling for "every target" is
# `None`, and a first version stored it as NULL — which quietly defeated the unique
# constraint below, because SQL treats NULLs as distinct and therefore allowed two
# *active global* policies. A sentinel is less pretty in a SELECT and is the only
# spelling under which the invariant is actually enforced, on all three backends.
GLOBAL_SCOPE_KIND = "*"
GLOBAL_SCOPE_ID = 0


class StoredGatePolicy(Base):
    """One version of one policy.

    Named `StoredGatePolicy` because `policy_gate.GatePolicy` is already the
    evaluation-time value object, and the two must not be confused: this is the
    persisted, versioned record; that one is what `evaluate()` consumes. The service
    converts between them, and only the service.
    """

    __tablename__ = "gate_policy"
    __table_args__ = (
        # At most one active policy per scope. Enforced in the database and not only
        # in code, because two active rows would make the verdict depend on row
        # order — a difference nobody would notice until it mattered.
        UniqueConstraint(
            "target_kind", "target_id", "is_active", name="uq_gate_policy_active_scope"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    # `GLOBAL_SCOPE_KIND`/`GLOBAL_SCOPE_ID` is the global default; the repository
    # translates to and from `None` so callers never see the sentinel.
    target_kind = Column(String(20), nullable=False, default=GLOBAL_SCOPE_KIND)
    target_id = Column(Integer, nullable=False, default=GLOBAL_SCOPE_ID)

    version = Column(Integer, nullable=False, default=1)
    # NULL rather than False for superseded rows: SQL's unique constraints ignore
    # NULLs, which is what lets many historical versions coexist under the
    # constraint above while only one row can hold `True`.
    is_active = Column(Boolean, nullable=True, default=True)

    fail_on_severity = Column(String(20), nullable=True)
    fail_on_kev = Column(Boolean, nullable=False, default=True)
    fixable_only = Column(Boolean, nullable=False, default=False)
    include_triaged = Column(Boolean, nullable=False, default=False)
    include_ai_review = Column(Boolean, nullable=False, default=False)

    # Why this version exists. Optional, and worth asking for: a policy loosened for
    # a stated reason is a decision; loosened silently, it is a leak.
    note = Column(Text, nullable=True)
    created_by = Column(String(255), nullable=True)
    created_at = Column(SafeDateTime, default=utcnow, nullable=False)

    @property
    def is_global(self) -> bool:
        return self.target_kind == GLOBAL_SCOPE_KIND

    @property
    def scope_label(self) -> str:
        if self.is_global:
            return "Toutes les cibles"
        return f"{self.target_kind}:{self.target_id}"
