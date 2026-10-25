from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

MIGRATIONS = Path(__file__).resolve().parent / "migrations"


def make_engine(url: str) -> Engine:
    if not url.startswith("sqlite"):
        return create_engine(url, pool_pre_ping=True)

    # Background tasks use the engine from other threads
    engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        # SQLite ignores ON DELETE CASCADE unless this is switched on per connection
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


def alembic_config(url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    # ConfigParser treats "%" as interpolation, which URL-encoded passwords use
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return config


def upgrade(url: str) -> None:
    """Bring the database schema to the latest migration."""
    command.upgrade(alembic_config(url), "head")
