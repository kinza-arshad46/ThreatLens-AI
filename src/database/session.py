"""
session.py
----------
Database engine + session setup (ThreatLens AI blueprint, Section 9:
"PostgreSQL - Redis - FastAPI").

Reads the connection string from the `DATABASE_URL` environment variable so
the exact same code runs against:
  - a local SQLite file (zero setup, good for development and for testing
    this backend without Docker running)
  - a real PostgreSQL instance (production / docker-compose)

Defaulting to SQLite when DATABASE_URL isn't set is a deliberate choice: it
lets you run and test the API immediately after cloning the repo, without
first standing up Postgres. Switching to real PostgreSQL later is just
setting one environment variable -- no code changes required.
"""

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SQLITE_PATH = PROJECT_ROOT / "data" / "processed" / "threatlens_dev.db"

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_SQLITE_PATH}")

# check_same_thread=False is only needed (and only safe) for SQLite, since
# FastAPI may serve requests from different threads.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """
    FastAPI dependency -- yields a DB session and guarantees it's closed
    after the request, even if the request raises an exception. Used as
    `db: Session = Depends(get_db)` in every route that touches the database.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Creates all tables defined in models.py if they don't already exist.
    Safe to call every time the app starts -- it's a no-op on tables that
    already exist. For production PostgreSQL, a real migration tool
    (Alembic) would replace this, but for the current phase this keeps
    setup to a single function call.
    """
    from src.database import models  # noqa: F401  (import registers models on Base)
    Base.metadata.create_all(bind=engine)
