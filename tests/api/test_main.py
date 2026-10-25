from typing import Any

import pytest
from sqlalchemy import inspect

from log_analyzer.api.__main__ import main
from log_analyzer.api.db import make_engine


@pytest.fixture
def env_db(monkeypatch: pytest.MonkeyPatch, db_url: str) -> str:
    monkeypatch.setenv("LOG_ANALYZER_DATABASE_URL", db_url)
    return db_url


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Calls to uvicorn.run, which is replaced so no server starts."""
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: calls.append({"app": app, **kwargs}))
    return calls


def tables(url: str) -> set[str]:
    engine = make_engine(url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_migrate(env_db: str, served: list[dict[str, Any]]) -> None:
    assert main(["migrate"]) == 0

    assert "analyses" in tables(env_db)
    assert served == []


def test_serve_migrates_then_runs(env_db: str, served: list[dict[str, Any]]) -> None:
    assert main(["serve", "--host", "0.0.0.0", "--port", "9000"]) == 0

    assert "analyses" in tables(env_db)
    assert [(c["host"], c["port"], c["app"].title) for c in served] == [
        ("0.0.0.0", 9000, "log-analyzer")
    ]


def test_serve_without_migrating(env_db: str, served: list[dict[str, Any]]) -> None:
    assert main(["serve", "--no-migrate"]) == 0

    assert "analyses" not in tables(env_db)
    assert (served[0]["host"], served[0]["port"]) == ("127.0.0.1", 8000)


def test_command_is_required(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main([])

    assert exc_info.value.code == 2
    assert "required" in capsys.readouterr().err
