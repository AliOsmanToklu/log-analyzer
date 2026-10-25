import uuid

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, func, inspect, select

from log_analyzer.api.db import alembic_config, make_session_factory
from log_analyzer.api.orm import AnalysisRecord, AnalysisStatus, Base, FindingRecord
from log_analyzer.api.settings import MB, Settings


def test_migrations_create_the_schema(engine: Engine) -> None:
    assert {"analyses", "findings", "alembic_version"} <= set(inspect(engine).get_table_names())


def test_migrations_match_the_models(engine: Engine) -> None:
    """Fails when a model changes without a matching migration."""
    with engine.connect() as connection:
        diff = compare_metadata(MigrationContext.configure(connection), Base.metadata)

    assert diff == []


def test_downgrade_removes_everything(engine: Engine, db_url: str) -> None:
    command.downgrade(alembic_config(db_url), "base")

    assert set(inspect(engine).get_table_names()) == {"alembic_version"}


def test_percent_signs_in_url_survive_config() -> None:
    url = "postgresql+psycopg://user:p%40ss@db/logs"

    assert alembic_config(url).get_main_option("sqlalchemy.url") == url


def test_deleting_an_analysis_deletes_its_findings(engine: Engine) -> None:
    sessions = make_session_factory(engine)

    analysis_id = uuid.uuid4()
    with sessions() as session:
        session.add(
            AnalysisRecord(
                id=analysis_id,
                filename="auth.log",
                format="ssh",
                threshold=10,
                window_seconds=60,
                scan_threshold=3,
                findings=[FindingRecord(ip="1.2.3.4", detection="X", severity="HIGH", details="")],
            )
        )
        session.commit()

    with sessions() as session:
        record = session.get_one(AnalysisRecord, analysis_id)
        assert record.status == AnalysisStatus.PENDING
        assert record.created_at is not None
        session.delete(record)
        session.commit()

        assert session.scalar(select(func.count()).select_from(FindingRecord)) == 0


def test_settings_defaults() -> None:
    assert Settings.from_env({}) == Settings()


def test_settings_from_env() -> None:
    settings = Settings.from_env(
        {
            "LOG_ANALYZER_DATABASE_URL": "postgresql+psycopg://db/logs",
            "LOG_ANALYZER_MAX_UPLOAD_MB": "1.5",
        }
    )

    assert settings == Settings(
        database_url="postgresql+psycopg://db/logs", max_upload_bytes=int(1.5 * MB)
    )
