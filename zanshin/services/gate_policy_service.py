"""Resolution and versioning of the stored gate policy.

The interesting decision is not storage, it is what happens to the policy a pipeline
still sends in its request body. Three options existed:

1. **Ignore it.** Honest, and it breaks every existing pipeline at the next call.
2. **Let it win.** That is today's behaviour, i.e. the loophole this feature exists to
   close.
3. **Let it tighten, never loosen.** A pipeline can hold itself to a higher standard
   than the organisation's default; it cannot hold itself to a lower one.

The third is implemented. It keeps the legitimate use case — a team that wants to fail
on `medium` while the default is `high` — and removes the illegitimate one, without a
breaking change for anybody who was already stricter than the default. A caller who
tries to loosen gets the stored value and a note in the response saying so, rather
than a silent substitution: a gate whose rules differ from what you asked for must say
which rules it used.
"""
import logging
from typing import Any, Dict, List, NamedTuple, Optional

from sqlalchemy.orm import Session

from zanshin.models.gate_policy import VALID_TARGET_KINDS, StoredGatePolicy
from zanshin.repositories.gate_policy_repository import GatePolicyRepository, _stored_scope
from zanshin.services.policy_gate import SEVERITY_ORDER, GatePolicy, severity_rank

logger = logging.getLogger(__name__)

# The policy that applies when nothing is stored: the code's own defaults, so an
# empty table behaves exactly as the gate did before this table existed.
BUILT_IN = GatePolicy()

SOURCE_TARGET = "target"
SOURCE_GLOBAL = "global"
SOURCE_BUILT_IN = "built-in"


class ResolvedPolicy(NamedTuple):
    """The policy to apply, and where it came from.

    The provenance is part of the answer, not debugging trivia: a pipeline that fails
    needs to know whether it was its own rules, its target's, or the organisation's
    default — otherwise the first reaction is to widen its own settings, which now
    changes nothing.
    """

    policy: GatePolicy
    source: str
    version: Optional[int] = None
    # Fields the request asked to loosen and did not get.
    ignored_relaxations: tuple = ()

    @property
    def description(self) -> str:
        if self.source == SOURCE_BUILT_IN:
            return "politique par défaut de l'application"
        scope = "de la cible" if self.source == SOURCE_TARGET else "globale"
        return f"politique {scope} v{self.version}"


class GatePolicyService:
    def __init__(self, gate_policy_repository: GatePolicyRepository):
        self.gate_policy_repository = gate_policy_repository

    # --- Reading ---

    def resolve(
        self,
        target_kind: Optional[str] = None,
        target_id: Optional[int] = None,
        requested: Optional[Dict[str, Any]] = None,
    ) -> ResolvedPolicy:
        """The policy in force for a target, hardened by the request if it asked.

        Target-specific, then global, then built-in. A target policy fully replaces
        the global one rather than merging with it: a half-inherited policy is
        impossible to reason about when a build fails, and "this repository's rules"
        should be readable in one place.
        """
        stored = self.gate_policy_repository.find_active(target_kind, target_id)
        source, version = SOURCE_TARGET, None
        if stored is None and target_kind is not None:
            stored = self.gate_policy_repository.find_active(None, None)
            source = SOURCE_GLOBAL
        elif stored is not None and target_kind is None:
            source = SOURCE_GLOBAL

        if stored is None:
            base, source = BUILT_IN, SOURCE_BUILT_IN
        else:
            base, version = to_gate_policy(stored), stored.version

        if requested is None:
            return ResolvedPolicy(policy=base, source=source, version=version)

        hardened, ignored = harden(base, requested)
        return ResolvedPolicy(
            policy=hardened, source=source, version=version, ignored_relaxations=tuple(ignored)
        )

    def active_policies(self) -> List[StoredGatePolicy]:
        return self.gate_policy_repository.find_all_active()

    def history(
        self, target_kind: Optional[str] = None, target_id: Optional[int] = None
    ) -> List[StoredGatePolicy]:
        return self.gate_policy_repository.find_history(target_kind, target_id)

    # --- Writing ---

    def save_policy(
        self,
        *,
        target_kind: Optional[str] = None,
        target_id: Optional[int] = None,
        fail_on_severity: Optional[str] = None,
        fail_on_kev: bool = True,
        fixable_only: bool = False,
        include_triaged: bool = False,
        include_ai_review: bool = False,
        note: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> StoredGatePolicy:
        """Store a new version, superseding the current one for that scope."""
        target_kind, target_id = _validate_scope(target_kind, target_id)
        fail_on_severity = _validate_severity(fail_on_severity)

        current = self.gate_policy_repository.find_active(target_kind, target_id)
        if current is not None:
            self.gate_policy_repository.deactivate(current)

        stored_kind, stored_id = _stored_scope(target_kind, target_id)
        policy = StoredGatePolicy(
            target_kind=stored_kind,
            target_id=stored_id,
            version=(current.version + 1) if current else 1,
            is_active=True,
            fail_on_severity=fail_on_severity,
            fail_on_kev=bool(fail_on_kev),
            fixable_only=bool(fixable_only),
            include_triaged=bool(include_triaged),
            include_ai_review=bool(include_ai_review),
            note=(note or "").strip() or None,
            created_by=actor,
        )
        saved = self.gate_policy_repository.save(policy)
        logger.info(
            "Gate policy v%d saved for %s by %s",
            saved.version, saved.scope_label, actor or "unknown",
        )
        return saved

    def delete_target_policy(self, target_kind: str, target_id: int) -> bool:
        """Drop a target override so it falls back to the global policy.

        The historical versions stay: they are the record of what was in force when
        past builds were judged.
        """
        target_kind, target_id = _validate_scope(target_kind, target_id)
        if target_kind is None:
            raise ValueError("La politique globale ne peut pas être supprimée, seulement modifiée.")
        current = self.gate_policy_repository.find_active(target_kind, target_id)
        if not current:
            return False
        self.gate_policy_repository.deactivate(current)
        self.gate_policy_repository.db.commit()
        return True


def to_gate_policy(stored: StoredGatePolicy) -> GatePolicy:
    return GatePolicy(
        fail_on_severity=stored.fail_on_severity,
        fail_on_kev=bool(stored.fail_on_kev),
        fixable_only=bool(stored.fixable_only),
        include_triaged=bool(stored.include_triaged),
        include_ai_review=bool(stored.include_ai_review),
    )


# Which value of each flag is the strict one. `fixable_only` is the field that would
# be wrong under a naive "take the True" merge: `True` fails on *fewer* things, since
# it excludes issues with no published fix — and it is the most tempting field to
# loosen, because it silently tolerates an actively-exploited vulnerability that has
# no patch.
_STRICT_FLAG_VALUE = {
    "fail_on_kev": True,
    "include_triaged": True,
    "include_ai_review": True,
    "fixable_only": False,
}


def harden(base: GatePolicy, requested: Dict[str, Any]):
    """Take the stricter of each field, and report what was refused.

    `requested` holds only the fields the caller actually sent — a dict rather than a
    `GatePolicy`, because a value object cannot express "no opinion". Without that
    distinction, every caller who omits `fail_on_severity` would appear to be asking
    for the schema's default and would be told their request was refused, on every
    single call.

    "Stricter" is defined per field, because it does not mean "greater":
    a *lower* severity threshold is stricter, `None` (no severity rule at all) is the
    loosest of all, and see `_STRICT_FLAG_VALUE` for the flags.
    """
    ignored: List[str] = []
    values = base._asdict()

    if "fail_on_severity" in requested:
        wanted = requested["fail_on_severity"]
        if wanted is None:
            # Explicitly removing the severity rule — a loosening, unless there was no
            # rule to begin with.
            if base.fail_on_severity is not None:
                ignored.append("fail_on_severity")
        elif base.fail_on_severity is None:
            # Adding a rule where there was none is a tightening.
            values["fail_on_severity"] = str(wanted).lower()
        else:
            # `SEVERITY_ORDER` is worst-first, so a *higher* rank is a *lower*
            # threshold, which fails on more issues — i.e. stricter. Getting this
            # comparison backwards would have shipped the exact opposite of the
            # feature: a pipeline free to raise its threshold to `critical`.
            wanted_rank = severity_rank(wanted)
            base_rank = severity_rank(base.fail_on_severity)
            if wanted_rank > base_rank:
                values["fail_on_severity"] = str(wanted).lower()
            elif wanted_rank < base_rank:
                ignored.append("fail_on_severity")

    for name, strict_value in _STRICT_FLAG_VALUE.items():
        if name not in requested:
            continue
        wanted = bool(requested[name])
        if wanted == values[name]:
            continue
        if wanted == strict_value:
            values[name] = wanted
        else:
            ignored.append(name)

    return GatePolicy(**values), ignored


def _validate_scope(target_kind: Optional[str], target_id: Optional[int]):
    if target_kind is None and target_id is None:
        return None, None
    if target_kind not in VALID_TARGET_KINDS or target_id is None:
        raise ValueError(
            "Portée invalide : 'repository' ou 'container' avec un identifiant, "
            "ou aucun des deux pour la politique globale."
        )
    return target_kind, int(target_id)


def _validate_severity(severity: Optional[str]) -> Optional[str]:
    if severity is None or not str(severity).strip():
        # An explicit "no severity rule", which is legitimate for a policy that gates
        # only on known-exploited vulnerabilities.
        return None
    value = str(severity).strip().lower()
    if value not in SEVERITY_ORDER:
        raise ValueError(f"Sévérité inconnue : {severity} (attendu : {', '.join(SEVERITY_ORDER)})")
    return value
