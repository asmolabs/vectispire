from sqlalchemy.orm import Session
from zanshin.models.user import User

class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_all(self):
        return self.db.query(User).all()

    def find_by_id(self, user_id: int):
        return self.db.query(User).filter(User.id == user_id).first()

    def find_by_username(self, username: str):
        return self.db.query(User).filter(User.username == username).first()

    def find_by_email(self, email: str):
        return self.db.query(User).filter(User.email == email).first()

    def save(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def delete(self, user: User):
        self.db.delete(user)
        self.db.commit()
