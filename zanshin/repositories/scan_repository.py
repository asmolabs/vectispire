from sqlalchemy.orm import Session
from zanshin.models.scan import Scan

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

    def save(self, scan: Scan) -> Scan:
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def delete(self, scan: Scan):
        self.db.delete(scan)
        self.db.commit()
