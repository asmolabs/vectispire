from sqlalchemy.orm import Session
from zanshin.models.repository import ZanshinRepository

class RepositoryRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_all(self):
        return self.db.query(ZanshinRepository).all()

    def find_by_id(self, repo_id: int):
        return self.db.query(ZanshinRepository).filter(ZanshinRepository.id == repo_id).first()

    def find_by_url_and_branch_and_subpath(self, url: str, branch: str, sub_path: str):
        return self.db.query(ZanshinRepository).filter(
            ZanshinRepository.url == url,
            ZanshinRepository.branch == branch,
            ZanshinRepository.sub_path == sub_path
        ).first()

    def save(self, repo: ZanshinRepository) -> ZanshinRepository:
        self.db.add(repo)
        self.db.commit()
        self.db.refresh(repo)
        return repo

    def delete_by_id(self, repo_id: int):
        repo = self.find_by_id(repo_id)
        if repo:
            self.db.delete(repo)
            self.db.commit()
            return True
        return False
