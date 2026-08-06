from datetime import datetime
from typing import Any, Dict, List, NamedTuple, Optional

from sqlalchemy.orm import Session

from zanshin.models.container import Container
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan


class ScanSummary(NamedTuple):
    """The subset of a `Scan` the list/overview screens actually display.

    Every scan list previously walked the `Repository.scans` /
    `Container.scans` relationships, which loads whole `Scan` rows — including
    the `sbom` and `cves` JSON blobs, several megabytes each, deserialized
    into Python only to be thrown away. These queries select columns instead,
    so rendering a list costs a fixed amount of memory no matter how much raw
    scanner output is stored. Fields mirror the attribute names of `Scan` so
    call sites can treat one like the other.
    """

    id: int
    branch: Optional[str]
    status: str
    findings_count: int
    summary: Optional[Dict[str, Any]]
    duration_ms: Optional[int]
    created_at: Optional[datetime]
    # Delta against the previous scan of the same target (see IssueService).
    new_issues_count: int
    resolved_issues_count: int


class ScanHistoryRow(NamedTuple):
    """A `ScanSummary` plus the identity of whatever was scanned, for the
    global history table — resolved by join rather than by touching
    `Scan.repository` / `Scan.container` per row (each of which would lazy-load
    that entity *and* its full scan collection back)."""

    scan: ScanSummary
    repo_id: Optional[int]
    container_id: Optional[int]
    repo_name: Optional[str]
    repo_url: Optional[str]
    image_string: Optional[str]


# Order matters: `_to_summary` reads these positionally.
_SUMMARY_COLUMNS = (
    Scan.id,
    Scan.branch,
    Scan.status,
    Scan.findings_count,
    Scan.summary,
    Scan.duration_ms,
    Scan.created_at,
    Scan.new_issues_count,
    Scan.resolved_issues_count,
)


def _to_summary(row) -> ScanSummary:
    return ScanSummary(
        id=row[0],
        branch=row[1],
        status=row[2] or "pending",
        findings_count=row[3] or 0,
        summary=row[4],
        duration_ms=row[5],
        created_at=row[6],
        new_issues_count=row[7] or 0,
        resolved_issues_count=row[8] or 0,
    )


class ScanRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_all(self):
        return self.db.query(Scan).order_by(Scan.created_at.desc()).all()

    def find_by_id(self, scan_id: int):
        return self.db.query(Scan).filter(Scan.id == scan_id).first()

    def find_all_by_repository_id(self, repo_id: int):
        return self.db.query(Scan).filter(Scan.repo_id == repo_id).order_by(Scan.created_at.desc()).all()

    def find_all_by_container_id(self, container_id: int):
        return self.db.query(Scan).filter(Scan.container_id == container_id).order_by(Scan.created_at.desc()).all()

    def find_summaries_by_repository_id(self, repo_id: int) -> List[ScanSummary]:
        """Every scan of one repository, newest first, without the raw blobs."""
        rows = (
            self.db.query(*_SUMMARY_COLUMNS)
            .filter(Scan.repo_id == repo_id)
            .order_by(Scan.created_at.desc())
            .all()
        )
        return [_to_summary(row) for row in rows]

    def find_latest_summary_by_repository_ids(self, repo_ids: List[int]) -> Dict[int, ScanSummary]:
        """Latest scan per repository id, in a single query.

        Resolved by taking the first row per id from a descending scan rather
        than a correlated `max(created_at)` subquery: it reads the same number
        of (blob-free) rows either way, and this keeps working on rows whose
        `created_at` is null, which the legacy data still contains.
        """
        return self._latest_summary_by(Scan.repo_id, repo_ids)

    def find_latest_summary_by_container_ids(self, container_ids: List[int]) -> Dict[int, ScanSummary]:
        """Latest scan per container id — see the repository-side twin above."""
        return self._latest_summary_by(Scan.container_id, container_ids)

    def _latest_summary_by(self, owner_column, owner_ids: List[int]) -> Dict[int, ScanSummary]:
        if not owner_ids:
            return {}
        rows = (
            self.db.query(owner_column, *_SUMMARY_COLUMNS)
            .filter(owner_column.in_(owner_ids))
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .all()
        )
        latest: Dict[int, ScanSummary] = {}
        for row in rows:
            latest.setdefault(row[0], _to_summary(row[1:]))
        return latest

    def find_all_created_at(self) -> List[datetime]:
        """Creation timestamps of every scan, for the dashboard's activity
        histogram. Filtering happens in Python rather than in SQL because
        `SafeDateTime` tolerates legacy string values, which don't compare
        reliably in the database — one column for every row is still orders of
        magnitude cheaper than loading the rows themselves."""
        return [row[0] for row in self.db.query(Scan.created_at).all() if row[0]]

    def find_history_rows(self) -> List[ScanHistoryRow]:
        """Every scan, newest first, with its target's display identity."""
        rows = (
            self.db.query(
                *_SUMMARY_COLUMNS,
                Scan.repo_id,
                Scan.container_id,
                ZanshinRepository.name,
                ZanshinRepository.url,
                Container.registry,
                Container.image_name,
                Container.tag,
            )
            .outerjoin(ZanshinRepository, Scan.repo_id == ZanshinRepository.id)
            .outerjoin(Container, Scan.container_id == Container.id)
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .all()
        )
        history = []
        for row in rows:
            repo_id, container_id, repo_name, repo_url = row[9], row[10], row[11], row[12]
            registry, image_name, tag = row[13], row[14], row[15]
            # Same composition as `Container.image_string`, rebuilt here
            # because no Container entity is loaded to ask.
            image_string = None
            if image_name:
                image_string = f"{registry + '/' if registry else ''}{image_name}:{tag}"
            history.append(
                ScanHistoryRow(
                    scan=_to_summary(row[:9]),
                    repo_id=repo_id,
                    container_id=container_id,
                    repo_name=repo_name,
                    repo_url=repo_url,
                    image_string=image_string,
                )
            )
        return history

    def save(self, scan: Scan) -> Scan:
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def delete(self, scan: Scan):
        self.db.delete(scan)
        self.db.commit()

    def delete_by_id(self, scan_id: int) -> bool:
        """Delete by id, mirroring `RepositoryRepository.delete_by_id`.

        The scan-history UI has always called this method; it never existed,
        so deleting a scan record raised `AttributeError` and surfaced as a
        generic "Erreur de suppression" toast.
        """
        scan = self.find_by_id(scan_id)
        if not scan:
            return False
        self.db.delete(scan)
        self.db.commit()
        return True
