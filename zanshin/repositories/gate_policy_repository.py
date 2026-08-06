from typing import List, Optional, Tuple

from sqlalchemy.orm import Session

from zanshin.models.gate_policy import (
    GLOBAL_SCOPE_ID,
    GLOBAL_SCOPE_KIND,
    StoredGatePolicy,
)


def _stored_scope(target_kind: Optional[str], target_id: Optional[int]) -> Tuple[str, int]:
    """`None` in, sentinel out.

    One place performs this translation so that no query has to remember it — and the
    reason it exists at all is that a NULL scope cannot participate in a unique
    constraint (see the model).
    """
    if target_kind is None or target_id is None:
        # A kind without an id is not a scope. Treated as global rather than raising,
        # because every caller of this is on a path — the scheduler tick, a gate
        # request — where an exception costs more than a defensible default.
        return GLOBAL_SCOPE_KIND, GLOBAL_SCOPE_ID
    return target_kind, int(target_id)


class GatePolicyRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_active(self, target_kind: Optional[str], target_id: Optional[int]):
        """The policy in force for one scope, or `None`."""
        kind, identifier = _stored_scope(target_kind, target_id)
        return (
            self.db.query(StoredGatePolicy)
            .filter(
                StoredGatePolicy.is_active.is_(True),
                StoredGatePolicy.target_kind == kind,
                StoredGatePolicy.target_id == identifier,
            )
            .first()
        )

    def find_all_active(self) -> List[StoredGatePolicy]:
        """Every scope currently configured, global first — the order the settings
        screen shows them in."""
        return (
            self.db.query(StoredGatePolicy)
            .filter(StoredGatePolicy.is_active.is_(True))
            .order_by(
                # "*" sorts before every real kind, which is the order the settings
                # screen wants: the global default first.
                StoredGatePolicy.target_kind,
                StoredGatePolicy.target_id,
            )
            .all()
        )

    def find_history(self, target_kind: Optional[str], target_id: Optional[int]) -> List[StoredGatePolicy]:
        """Every version of one scope, newest first."""
        kind, identifier = _stored_scope(target_kind, target_id)
        return (
            self.db.query(StoredGatePolicy)
            .filter(
                StoredGatePolicy.target_kind == kind,
                StoredGatePolicy.target_id == identifier,
            )
            .order_by(StoredGatePolicy.version.desc())
            .all()
        )

    def find_by_id(self, policy_id: int) -> Optional[StoredGatePolicy]:
        return self.db.query(StoredGatePolicy).filter(StoredGatePolicy.id == policy_id).first()

    def save(self, policy: StoredGatePolicy) -> StoredGatePolicy:
        self.db.add(policy)
        self.db.commit()
        self.db.refresh(policy)
        return policy

    def deactivate(self, policy: StoredGatePolicy) -> None:
        """`None`, not `False`: the unique constraint on the active scope relies on
        SQL ignoring NULLs, which is what allows a stack of superseded versions."""
        policy.is_active = None
        self.db.add(policy)
