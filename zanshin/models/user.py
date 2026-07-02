from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean
from zanshin.database import Base
from zanshin.models.safedatetime import SafeDateTime

class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)
    password = Column(String(255), nullable=True)
    display_name = Column(String(255), nullable=True)
    avatar_url = Column(String(255), nullable=True)
    role = Column(String(255), default="USER", nullable=False)  # SUPERUSER, ADMIN, USER
    is_active = Column(Boolean, default=True, nullable=False)
    github_id = Column(String(255), unique=True, nullable=True)
    keycloak_id = Column(String(255), unique=True, nullable=True)
    created_at = Column(SafeDateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(SafeDateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
