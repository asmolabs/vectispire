import uuid
from sqlalchemy.orm import Session
from zanshin.models.api_key import ApiKey

class ApiKeyRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_all(self):
        return self.db.query(ApiKey).all()

    def find_by_id(self, key_id: uuid.UUID):
        if isinstance(key_id, str):
            key_id = uuid.UUID(key_id)
        return self.db.query(ApiKey).filter(ApiKey.id == key_id).first()

    def save(self, api_key: ApiKey) -> ApiKey:
        self.db.add(api_key)
        self.db.commit()
        self.db.refresh(api_key)
        return api_key

    def delete_by_id(self, key_id: uuid.UUID):
        if isinstance(key_id, str):
            key_id = uuid.UUID(key_id)
        api_key = self.find_by_id(key_id)
        if api_key:
            self.db.delete(api_key)
            self.db.commit()
            return True
        return False
