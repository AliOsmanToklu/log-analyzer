import json
from pathlib import Path

import pytest

from log_analyzer.analysis import analyze
from log_analyzer.report import _json_default, to_dict, write_json
from tests.helpers import T0, failures


def test_to_dict_keeps_datetimes_for_the_caller() -> None:
    data = to_dict(analyze(failures(10, every=1)), "x.log")

    assert data["bruteforce"][0]["first_seen"] == T0
    assert data["findings"] == [
        {
            "ip": "203.0.113.1",
            "detection": "BRUTE_FORCE",
            "severity": "HIGH",
            "details": "10 failed attempts",
        }
    ]


def test_write_json_is_utf8_and_readable(tmp_path: Path) -> None:
    path = tmp_path / "r.json"

    write_json(analyze([]), "günlük.log", path)

    assert json.loads(path.read_text(encoding="utf-8"))["source"] == "günlük.log"
    assert "günlük" in path.read_text(encoding="utf-8")


def test_json_default_rejects_unknown_types() -> None:
    with pytest.raises(TypeError, match="set is not JSON serializable"):
        _json_default({1})
