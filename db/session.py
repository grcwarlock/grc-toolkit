"""
Database session management for the GRC toolkit.

Supports both SQLite (development) and PostgreSQL (production).
Configure via GRC_DATABASE_URL environment variable.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import sessionmaker, Session

from db.models import Base

DEFAULT_DATABASE_URL = "sqlite:///./grc_toolkit.db"

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine(database_url: str | None = None) -> Engine:
    """Create or return cached SQLAlchemy engine."""
    global _engine
    if _engine is not None and database_url is None:
        return _engine

    url = database_url or os.environ.get("GRC_DATABASE_URL", DEFAULT_DATABASE_URL)

    connect_args = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    _engine = create_engine(
        url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        connect_args=connect_args,
    )
    return _engine


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """Create or return cached session factory."""
    global _session_factory
    if _session_factory is not None and engine is None:
        return _session_factory

    if engine is None:
        engine = get_engine()

    _session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    return _session_factory


def init_db(database_url: str | None = None) -> None:
    """Create all tables. Used for initial setup and testing."""
    engine = get_engine(database_url)
    Base.metadata.create_all(engine)


@contextmanager
def get_db_session(database_url: str | None = None) -> Generator[Session, None, None]:
    """Context manager yielding a database session with automatic commit/rollback."""
    engine = get_engine(database_url)
    factory = get_session_factory(engine)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
