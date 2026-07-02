from sqlalchemy.orm import Session
from zanshin.models.vex_decision import VexDecision

class VexDecisionRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_all(self):
        return self.db.query(VexDecision).all()

    def find_by_id(self, vex_id: int):
        return self.db.query(VexDecision).filter(VexDecision.id == vex_id).first()

    def find_all_by_repository_id(self, repo_id: int):
        return self.db.query(VexDecision).filter(VexDecision.repository_id == repo_id).all()

    def find_by_repo_and_vulnerability_and_package(self, repo_id: int, vulnerability_id: str, package_name: str):
        return self.db.query(VexDecision).filter(
            VexDecision.repository_id == repo_id,
            VexDecision.vulnerability_id == vulnerability_id,
            VexDecision.package_name == package_name
        ).first()

    def save(self, vex: VexDecision) -> VexDecision:
        self.db.add(vex)
        self.db.commit()
        self.db.refresh(vex)
        return vex

    def delete(self, vex: VexDecision):
        self.db.delete(vex)
        self.db.commit()
