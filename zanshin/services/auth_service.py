import bcrypt
from zanshin.repositories.user_repository import UserRepository
from zanshin.models.user import User

class AuthService:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository

    def hash_password(self, password: str) -> str:
        # Bcrypt limit is 72 bytes
        password_bytes = password.encode("utf-8")[:72]
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode("utf-8")

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        if not hashed_password:
            return False
        try:
            plain_bytes = plain_password.encode("utf-8")[:72]
            # Ensure hashed_password is correct format (string to bytes)
            hashed_bytes = hashed_password.encode("utf-8") if isinstance(hashed_password, str) else hashed_password
            return bcrypt.checkpw(plain_bytes, hashed_bytes)
        except Exception:
            return False

    def authenticate_user(self, username: str, plain_password: str) -> User:
        user = self.user_repository.find_by_username(username)
        if not user:
            return None
        if not user.is_active:
            return None
        if not self.verify_password(plain_password, user.password):
            return None
        return user
