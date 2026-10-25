from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine

from log_analyzer.api.db import make_engine, upgrade


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    """URL of an empty SQLite database file."""
    return f"sqlite:///{tmp_path / 'test.db'}"


@pytest.fixture
def engine(db_url: str) -> Iterator[Engine]:
    """Engine for a migrated database."""
    upgrade(db_url)
    engine = make_engine(db_url)
    yield engine
    engine.dispose()
