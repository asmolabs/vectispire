from typing import Optional
from sqlalchemy.orm import Session
from zanshin.models.ai_review_result import AiReviewResult

class AiReviewResultRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_by_scan_id(self, scan_id: int) -> Optional[AiReviewResult]:
        return self.db.query(AiReviewResult).filter(AiReviewResult.scan_id == scan_id).first()

    def save(self, result: AiReviewResult) -> AiReviewResult:
        self.db.add(result)
        self.db.commit()
        self.db.refresh(result)
        return result
