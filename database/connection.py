"""
database/connection.py

SQLAlchemy engine + session factory.
Default: SQLite (zero setup, file-based).
Switch to PostgreSQL: set DATABASE_URL env var to a psycopg2 connection string.
  e.g. DATABASE_URL=postgresql+psycopg2://user:pass@localhost/vapt
"""
import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vapt.db")

# SQLite needs check_same_thread=False for multi-threaded FastAPI
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,          # set True to log all SQL statements
    pool_pre_ping=True,  # reconnect if connection dropped
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency — yields a DB session, closes on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables if they don't exist. Called once at startup."""
    from database import models  # noqa: F401 — import so models register with Base
    Base.metadata.create_all(bind=engine)
    logger.info(f"[DB] Initialised — {DATABASE_URL}")
