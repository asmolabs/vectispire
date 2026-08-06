import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Database path (matches the SQLite DB used by the application's previous backend implementation)
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "./database.sqlite"))

# Overridable so that the same code can be pointed at another file without
# editing it — used to generate/verify migrations against a scratch database
# (see migrations/env.py), and available to deployments that keep their data
# outside the source tree.
DATABASE_URL = os.getenv("ZANSHIN_DATABASE_URL", f"sqlite:///{DB_PATH}")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # Needed for SQLite multi-threading
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
