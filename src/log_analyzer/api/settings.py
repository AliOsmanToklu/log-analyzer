import os
from collections.abc import Mapping
from dataclasses import dataclass

ENV_PREFIX = "LOG_ANALYZER_"
MB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str = "sqlite:///log_analyzer.db"
    max_upload_bytes: int = 20 * MB

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Settings":
        """Read LOG_ANALYZER_DATABASE_URL and LOG_ANALYZER_MAX_UPLOAD_MB."""
        defaults = cls()
        max_upload_mb = env.get(f"{ENV_PREFIX}MAX_UPLOAD_MB")
        return cls(
            database_url=env.get(f"{ENV_PREFIX}DATABASE_URL", defaults.database_url),
            max_upload_bytes=(
                int(float(max_upload_mb) * MB) if max_upload_mb else defaults.max_upload_bytes
            ),
        )
