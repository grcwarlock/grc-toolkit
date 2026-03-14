"""
Database session management for the GRC toolkit.

Supports both SQLite (development) and PostgreSQL (production).
Configure via GRC_DATABASE_URL environment variable.

For production PostgreSQL, use sslmode=require in the connection string:
  postgresql+psycopg2://user:pass@host:5432/db?sslmode=require
"""

from __future__ import annotations

import logging
import os
from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from db.models import Base

logger = logging.getLogger(__name__)

DEFAULT_DATABASE_URL = "sqlite:///./grc_toolkit.db"

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine(database_url: str | None = None) -> Engine:
    """Create or return cached SQLAlchemy engine.

    For PostgreSQL connections, enforces SSL if sslmode is specified
    in the connection string.
    """
    global _engine
    if _engine is not None and database_url is None:
        return _engine

    url = database_url or os.environ.get("GRC_DATABASE_URL", DEFAULT_DATABASE_URL)

    connect_args: dict = {}
    pool_kwargs: dict = {
        "pool_pre_ping": True,
        "pool_size": 5,
        "max_overflow": 10,
    }

    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        # SQLite doesn't support pool_size
        pool_kwargs.pop("pool_size", None)
        pool_kwargs.pop("max_overflow", None)
    else:
        # Warn if PostgreSQL without SSL
        if "sslmode" not in url and "postgresql" in url:
            logger.warning(
                "Database connection does not use SSL. "
                "Add ?sslmode=require to GRC_DATABASE_URL for encrypted connections."
            )

    _engine = create_engine(
        url,
        connect_args=connect_args,
        **pool_kwargs,
    )

    # Set statement timeout for PostgreSQL to prevent long-running queries
    if "postgresql" in url:
        @event.listens_for(_engine, "connect")
        def set_pg_settings(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("SET statement_timeout = '30s'")
            cursor.close()

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
