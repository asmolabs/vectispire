from typing import Dict, Iterable, List, Optional

from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session

from zanshin.models.issue import (
    STATE_OPEN,
    TRIAGE_AFFECTED,
    TRIAGE_UNDER_REVIEW,
    Issue,
)


class IssueRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_by_id(self, issue_id: int) -> Optional[Issue]:
        return self.db.query(Issue).filter(Issue.id == issue_id).first()

    def find_by_fingerprints(self, fingerprints: Iterable[str]) -> Dict[str, Issue]:
        """The lookup `IssueService.sync_from_scan` runs once per scan: every
        issue that might already exist for the findings just produced, keyed by
        fingerprint. One query, not one per finding."""
        fingerprints = list(fingerprints)
        if not fingerprints:
            return {}
        rows = self.db.query(Issue).filter(Issue.fingerprint.in_(fingerprints)).all()
        return {issue.fingerprint: issue for issue in rows}

    def find_with_expired_triage(self, now) -> List[Issue]:
        """Decisions whose review date has passed and that still hold a status.

        Filtered in SQL rather than by loading everything and testing
        `Issue.triage_expired`: this runs on a scheduler tick against the whole
        table, and the set it should return is almost always empty.
        """
        return (
            self.db.query(Issue)
            .filter(
                Issue.triage_expires_at.isnot(None),
                Issue.triage_expires_at <= now,
                Issue.triage_status != TRIAGE_UNDER_REVIEW,
            )
            .all()
        )

    def find_open_by_target(
        self,
        repo_id: Optional[int] = None,
        container_id: Optional[int] = None,
        types: Optional[Iterable[str]] = None,
    ) -> List[Issue]:
        """Open issues of a target, optionally restricted to certain finding
        types — which is how resolution stays honest: a container scan produces
        no secrets, so it must not be allowed to resolve secret issues."""
        query = self.db.query(Issue).filter(Issue.state == STATE_OPEN)
        query = self._apply_target(query, repo_id, container_id)
        if types is not None:
            types = list(types)
            if not types:
                return []
            query = query.filter(Issue.type.in_(types))
        return query.all()

    def find_filtered(
        self,
        state: Optional[str] = None,
        triage_status: Optional[str] = None,
        severity: Optional[str] = None,
        issue_type: Optional[str] = None,
        repo_id: Optional[int] = None,
        container_id: Optional[int] = None,
        search: Optional[str] = None,
        only_direct: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Issue]:
        """One page of issues, worst first.

        Ordered by what needs attention first: KEV (known-exploited) before
        severity before EPSS, since a "medium" that is actively exploited in the
        wild outranks a "critical" that nobody has ever weaponized — that
        ordering is the whole reason the enrichment step exists. `Issue.id` breaks
        remaining ties so that paging is stable: without a total order, a row can
        appear on two pages or on none.

        Callers are expected to pair this with `count_filtered` and show the
        total. The previous default of 500 with no count silently truncated the
        list, which reads exactly like "that's all there is".
        """
        return (
            self._filtered_query(
                state, triage_status, severity, issue_type, repo_id, container_id, search,
                only_direct,
            )
            .order_by(
                Issue.is_kev.desc(),
                _SEVERITY_RANK,
                # Between two otherwise identical problems, the one the project
                # declared itself is the one that can be fixed today.
                Issue.is_direct_dependency.desc().nullslast(),
                Issue.epss_score.desc().nullslast(),
                Issue.last_seen_at.desc(),
                Issue.id.desc(),
            )
            .limit(limit)
            .offset(offset)
            .all()
        )

    def count_filtered(
        self,
        state: Optional[str] = None,
        triage_status: Optional[str] = None,
        severity: Optional[str] = None,
        issue_type: Optional[str] = None,
        repo_id: Optional[int] = None,
        container_id: Optional[int] = None,
        search: Optional[str] = None,
        only_direct: bool = False,
    ) -> int:
        """How many issues match — the number a paginated view has to show."""
        return (
            self._filtered_query(
                state, triage_status, severity, issue_type, repo_id, container_id, search,
                only_direct,
            )
            .with_entities(func.count(Issue.id))
            .scalar()
            or 0
        )

    def _filtered_query(
        self,
        state: Optional[str],
        triage_status: Optional[str],
        severity: Optional[str],
        issue_type: Optional[str],
        repo_id: Optional[int],
        container_id: Optional[int],
        search: Optional[str],
        only_direct: bool = False,
    ):
        query = self.db.query(Issue)
        if state:
            query = query.filter(Issue.state == state)
        if triage_status:
            query = query.filter(Issue.triage_status == triage_status)
        if severity:
            query = query.filter(Issue.severity == severity)
        if issue_type:
            query = query.filter(Issue.type == issue_type)
        query = self._apply_target(query, repo_id, container_id)
        if only_direct:
            # Strictly `is True`: an issue whose directness is unknown is not
            # evidence of a direct dependency, and a filter meant to narrow to
            # "what we can fix ourselves" must not quietly include the undecided.
            query = query.filter(Issue.is_direct_dependency.is_(True))
        if search:
            pattern = f"%{search.lower()}%"
            query = query.filter(
                or_(
                    func.lower(func.coalesce(Issue.identifier, "")).like(pattern),
                    func.lower(func.coalesce(Issue.package_name, "")).like(pattern),
                    func.lower(func.coalesce(Issue.file_path, "")).like(pattern),
                )
            )
        return query

    def count_actionable_by_repo_ids(self, repo_ids: List[int]) -> Dict[int, int]:
        """Outstanding-issue count per repository, for list badges."""
        return self._count_actionable(Issue.repo_id, repo_ids)

    def count_actionable_by_container_ids(self, container_ids: List[int]) -> Dict[int, int]:
        return self._count_actionable(Issue.container_id, container_ids)

    def _count_actionable(self, owner_column, owner_ids: List[int]) -> Dict[int, int]:
        if not owner_ids:
            return {}
        rows = (
            self.db.query(owner_column, func.count(Issue.id))
            .filter(
                owner_column.in_(owner_ids),
                Issue.state == STATE_OPEN,
                Issue.triage_status.in_((TRIAGE_UNDER_REVIEW, TRIAGE_AFFECTED)),
            )
            .group_by(owner_column)
            .all()
        )
        return {owner_id: count for owner_id, count in rows}

    def count_by_state_and_triage(self) -> Dict[str, int]:
        """Global tallies for the issues screen's KPI row, in one query."""
        rows = (
            self.db.query(Issue.state, Issue.triage_status, func.count(Issue.id))
            .group_by(Issue.state, Issue.triage_status)
            .all()
        )
        counts = {"total": 0, "open": 0, "resolved": 0, "actionable": 0}
        for state, triage_status, count in rows:
            counts["total"] += count
            counts[state] = counts.get(state, 0) + count
            if state == STATE_OPEN and triage_status in (TRIAGE_UNDER_REVIEW, TRIAGE_AFFECTED):
                counts["actionable"] += count
            counts[f"triage_{triage_status}"] = counts.get(f"triage_{triage_status}", 0) + count
        return counts

    def count_open_by_severity(self) -> Dict[str, int]:
        rows = (
            self.db.query(Issue.severity, func.count(Issue.id))
            .filter(Issue.state == STATE_OPEN)
            .group_by(Issue.severity)
            .all()
        )
        return {(severity or "unknown"): count for severity, count in rows}

    def save(self, issue: Issue) -> Issue:
        self.db.add(issue)
        self.db.commit()
        self.db.refresh(issue)
        return issue

    @staticmethod
    def _apply_target(query, repo_id: Optional[int], container_id: Optional[int]):
        if repo_id is not None:
            query = query.filter(Issue.repo_id == repo_id)
        if container_id is not None:
            query = query.filter(Issue.container_id == container_id)
        return query


# Severity is a string column (the vocabulary shared with Grype/OSV/gitleaks/
# checkov), so ordering has to be spelled out: alphabetically, "critical" would
# land after "high" and "low" would sit in the middle.
_SEVERITY_RANK = case(
    {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4},
    value=func.lower(func.coalesce(Issue.severity, "")),
    else_=5,
)
