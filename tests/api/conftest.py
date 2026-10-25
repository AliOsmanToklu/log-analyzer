from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from log_analyzer.api.app import create_app
from log_analyzer.api.db import make_engine, upgrade
from log_analyzer.api.settings import Settings
from tests.helpers import SAMPLES

UPLOAD_LIMIT = 64 * 1024


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


@pytest.fixture
def client(engine: Engine, db_url: str) -> Iterator[TestClient]:
    app = create_app(Settings(database_url=db_url, max_upload_bytes=UPLOAD_LIMIT))
    with TestClient(app) as client:
        yield client


def upload(
    client: TestClient,
    sample: str = "auth.log",
    *,
    filename: str | None = None,
    content: bytes | None = None,
    **form: Any,
) -> dict[str, Any]:
    """POST a file to /analyses and return the response JSON (asserting 202)."""
    data = (SAMPLES / sample).read_bytes() if content is None else content
    response = client.post(
        "/analyses",
        files={"file": (filename or sample, data)},
        data={key: str(value) for key, value in form.items()},
    )
    assert response.status_code == 202, response.text
    body: dict[str, Any] = response.json()
    return body
