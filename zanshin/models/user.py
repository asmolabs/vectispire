from zanshin.clock import utcnow
from sqlalchemy import Column, Integer, String, Boolean
from zanshin.database import Base
from zanshin.models.safedatetime import SafeDateTime

class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    # Uniqueness was declared on the model but absent from the legacy table, so
    # it was enforced only by a read-then-write in UserService — two concurrent
    # creations of the same login both succeeded. Migration 0003 adds it for real.
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)
    password = Column(String(255), nullable=True)
    display_name = Column(String(255), nullable=True)
    avatar_url = Column(String(255), nullable=True)
    role = Column(String(255), default="USER", nullable=False)  # SUPERUSER, ADMIN, USER
    is_active = Column(Boolean, default=True, nullable=False)
    # Set on the bootstrap account: `ZANSHIN_BOOTSTRAP_PASSWORD` will have lived in
    # an environment file, a compose file, maybe a repository — so it is a
    # provisioning secret, not a password, and the first login must replace it.
    must_change_password = Column(Boolean, default=False, nullable=False)

    github_id = Column(String(255), unique=True, nullable=True)
    keycloak_id = Column(String(255), unique=True, nullable=True)
    created_at = Column(SafeDateTime, default=utcnow, nullable=False)
    updated_at = Column(SafeDateTime, default=utcnow, onupdate=utcnow, nullable=False)
