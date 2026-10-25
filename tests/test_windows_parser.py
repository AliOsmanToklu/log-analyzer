from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest

from log_analyzer.models import Event, EventType
from log_analyzer.parsers.windows import parse_windows_csv


def write_csv(tmp_path: Path, *rows: str) -> Path:
    path = tmp_path / "events.csv"
    # Export-Csv writes a BOM and quotes every field; mimic that
    path.write_text('"Time","Id","User","IP"\n' + "\n".join(rows) + "\n", encoding="utf-8-sig")
    return path


def test_maps_logon_event_ids(tmp_path: Path) -> None:
    path = write_csv(
        tmp_path,
        '"2026-10-25 13:00:00","4625","admin","203.0.113.99"',
        '"2026-10-25 13:00:05","4624","administrator","203.0.113.99"',
    )

    assert parse_windows_csv(path) == [
        Event(datetime(2026, 10, 25, 13, 0, 0), EventType.FAILED, "admin", "203.0.113.99"),
        Event(
            datetime(2026, 10, 25, 13, 0, 5), EventType.ACCEPTED, "administrator", "203.0.113.99"
        ),
    ]


def test_drops_local_addresses_and_other_event_ids(tmp_path: Path) -> None:
    path = write_csv(
        tmp_path,
        '"2026-10-25 13:00:00","4624","SYSTEM","-"',
        '"2026-10-25 13:00:00","4624","SYSTEM",""',
        '"2026-10-25 13:00:00","4624","bob","127.0.0.1"',
        '"2026-10-25 13:00:00","4625","bob","::1"',
        '"2026-10-25 13:00:00","4672","bob","203.0.113.5"',
        '"2026-10-25 13:00:00","4625","eve","203.0.113.5"',
    )

    assert [e.user for e in parse_windows_csv(path)] == ["eve"]


def test_skips_rows_with_bad_timestamps(tmp_path: Path) -> None:
    path = write_csv(
        tmp_path,
        '"25.10.2026 13:00","4625","bob","203.0.113.5"',
        '" 2026-10-25 13:00:00 ","4625","eve"," 203.0.113.5 "',
    )

    assert [(e.user, e.ip) for e in parse_windows_csv(path)] == [("eve", "203.0.113.5")]


def test_accepts_iso_timestamps(tmp_path: Path) -> None:
    path = write_csv(
        tmp_path,
        '"2026-10-25T13:00:00","4625","bob","203.0.113.5"',
        '"2026-10-25T13:00:01.5+03:00","4625","bob","203.0.113.5"',
    )

    assert [e.time for e in parse_windows_csv(path)] == [
        datetime(2026, 10, 25, 13, 0, 0),
        datetime(2026, 10, 25, 13, 0, 1, 500000),
    ]


def test_missing_columns_raise(tmp_path: Path) -> None:
    path = tmp_path / "events.csv"
    path.write_text("Time,Id,Account\n2026-10-25 13:00:00,4625,bob\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"missing column\(s\): User, IP"):
        parse_windows_csv(path)


def test_empty_file_raises(tmp_path: Path) -> None:
    path = tmp_path / "events.csv"
    path.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="missing column"):
        parse_windows_csv(path)


def test_sample(windows_sample: Path) -> None:
    events = parse_windows_csv(windows_sample)

    assert len(events) == 41
    assert Counter(e.type for e in events) == {EventType.FAILED: 30, EventType.ACCEPTED: 11}
