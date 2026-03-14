"""
Dependency injection for FastAPI routes.
"""

from __future__ import annotations

import os
from typing import Generator

import yaml
from sqlalchemy.orm import Session

from db.session import get_engine, get_session_factory


def get_db() -> Generator[Session, None, None]:
    """Yield a database session, auto-closing on completion."""
    factory = get_session_factory(get_engine())
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


_settings_cache: dict | None = None


def get_settings() -> dict:
    """Load and cache settings from config/settings.yaml."""
    global _settings_cache
    if _settings_cache is not None:
        return _settings_cache

    config_path = os.environ.get("GRC_CONFIG_PATH", "config/settings.yaml")
    with open(config_path) as f:
        _settings_cache = yaml.safe_load(f)
    return _settings_cache
