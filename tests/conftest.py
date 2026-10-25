from pathlib import Path

import pytest

from tests.helpers import SAMPLES


@pytest.fixture
def ssh_sample() -> Path:
    return SAMPLES / "auth.log"


@pytest.fixture
def windows_sample() -> Path:
    return SAMPLES / "windows_events.csv"
