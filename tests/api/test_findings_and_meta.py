import logging
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from log_analyzer.api import service
from log_analyzer.api.app import create_app
from log_analyzer.api.db import make_session_factory
from log_analyzer.api.settings import Settings
from tests.api.conftest import upload


class TestFindingsSearch:
    @pytest.fixture(autouse=True)
    def two_analyses(self, client: TestClient) -> None:
        self.ssh = upload(client, "auth.log")
        self.windows = upload(client, "windows_events.csv")

    def test_all_findings_newest_analysis_first(self, client: TestClient) -> None:
        page = client.get("/findings").json()

        assert page["total"] == 5
        assert [(f["filename"], f["detection"]) for f in page["items"]] == [
            ("windows_events.csv", "BRUTE_FORCE"),
            ("windows_events.csv", "POSSIBLE_COMPROMISE"),
            ("auth.log", "BRUTE_FORCE"),
            ("auth.log", "POSSIBLE_COMPROMISE"),
            ("auth.log", "SLOW_SCAN"),
        ]
        assert page["items"][0]["analysis_id"] == self.windows["id"]

    def test_filter_by_severity(self, client: TestClient) -> None:
        page = client.get("/findings", params={"severity": "CRITICAL"}).json()

        assert page["total"] == 2
        assert {f["ip"] for f in page["items"]} == {"203.0.113.45", "203.0.113.99"}

    def test_filter_by_ip_and_detection(self, client: TestClient) -> None:
        page = client.get(
            "/findings", params={"ip": "203.0.113.45", "detection": "BRUTE_FORCE"}
        ).json()

        assert page["total"] == 1
        assert page["items"][0]["details"] == "40 failed attempts"
        assert page["items"][0]["analysis_id"] == self.ssh["id"]

    def test_pagination(self, client: TestClient) -> None:
        page = client.get("/findings", params={"limit": 2, "offset": 4}).json()

        assert (page["total"], len(page["items"])) == (5, 1)

    @pytest.mark.parametrize("params", [{"severity": "LOW"}, {"detection": "PORT_SCAN"}])
    def test_unknown_enum_values(self, client: TestClient, params: dict[str, str]) -> None:
        assert client.get("/findings", params=params).status_code == 422


class TestBackgroundFailures:
    def test_unexpected_error_marks_the_analysis_failed(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        def explode(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(service, "analyze", explode)

        with caplog.at_level(logging.ERROR, logger="log_analyzer.api.service"):
            created = upload(client)

        detail = client.get(f"/analyses/{created['id']}").json()
        assert detail["status"] == "failed"
        assert detail["error"] == service.INTERNAL_ERROR
        assert detail["completed_at"] is not None
        assert "boom" in caplog.text

    def test_analysis_deleted_before_it_ran(self, engine: Engine) -> None:
        # Must not raise: the background task just has nothing to do
        service.run_analysis(make_session_factory(engine), uuid.uuid4(), [])


class TestMeta:
    def test_health(self, client: TestClient) -> None:
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok", "database": "ok"}

    def test_health_without_database(self, tmp_path: Path) -> None:
        url = f"sqlite:///{tmp_path / 'missing' / 'dir' / 'db.sqlite'}"

        with TestClient(create_app(Settings(database_url=url))) as client:
            response = client.get("/health")

        assert response.status_code == 503
        assert response.json() == {"status": "unavailable", "database": "unreachable"}

    def test_root_redirects_to_docs(self, client: TestClient) -> None:
        response = client.get("/", follow_redirects=False)

        assert response.status_code == 307
        assert response.headers["location"] == "/docs"

    def test_openapi_describes_every_endpoint(self, client: TestClient) -> None:
        schema = client.get("/openapi.json").json()

        assert schema["info"]["title"] == "log-analyzer"
        assert set(schema["paths"]) == {
            "/analyses",
            "/analyses/{analysis_id}",
            "/findings",
            "/health",
        }

    def test_settings_from_environment(
        self, monkeypatch: pytest.MonkeyPatch, engine: Engine, db_url: str
    ) -> None:
        monkeypatch.setenv("LOG_ANALYZER_DATABASE_URL", db_url)

        with TestClient(create_app()) as client:
            assert client.get("/health").status_code == 200
