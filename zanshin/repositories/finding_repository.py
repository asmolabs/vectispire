from typing import Dict, List
from sqlalchemy import func
from sqlalchemy.orm import Session
from zanshin.models.finding import Finding

class FindingRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_all_by_scan_id(self, scan_id: int) -> List[Finding]:
        return self.db.query(Finding).filter(Finding.scan_id == scan_id).all()

    def find_all_by_scan_id_and_type(self, scan_id: int, finding_type: str) -> List[Finding]:
        return self.db.query(Finding).filter(
            Finding.scan_id == scan_id,
            Finding.type == finding_type
        ).all()

    def count_by_scan_ids_and_type(self, scan_ids: List[int], finding_type: str) -> Dict[int, int]:
        """Finding count per scan id, for a given type — used to show a
        "Secrets" badge in scan lists without loading every Finding row.

        Counts what the scan observed, with no state filter: a finding *is* an
        observation, and whether the problem is still open or has been triaged
        is a property of its `Issue`, not of one scan's snapshot."""
        if not scan_ids:
            return {}
        rows = (
            self.db.query(Finding.scan_id, func.count(Finding.id))
            .filter(
                Finding.scan_id.in_(scan_ids),
                Finding.type == finding_type,
            )
            .group_by(Finding.scan_id)
            .all()
        )
        return {scan_id: count for scan_id, count in rows}

    def save(self, finding: Finding) -> Finding:
        self.db.add(finding)
        self.db.commit()
        self.db.refresh(finding)
        return finding

    def delete_by_scan_id(self, scan_id: int):
        self.db.query(Finding).filter(Finding.scan_id == scan_id).delete()
        self.db.commit()
