from pathlib import Path

import pytest

from log_analyzer.parsers import (
    LogFormat,
    detect_format,
    parse_events,
    parse_file,
    parse_windows_csv,
)


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("auth.log", "ssh"),
        ("auth.log.1", "ssh"),
        ("secure", "ssh"),
        ("windows_events.csv", "windows"),
        ("EXPORT.CSV", "windows"),
    ],
)
def test_detect_format(filename: str, expected: LogFormat) -> None:
    assert detect_format(filename) == expected


def test_parse_events_matches_file_parsers(ssh_sample: Path, windows_sample: Path) -> None:
    ssh_lines = ssh_sample.read_text(encoding="utf-8").splitlines(keepends=True)
    windows_lines = windows_sample.read_text(encoding="utf-8-sig").splitlines(keepends=True)

    assert parse_events(ssh_lines, "ssh", year=2026) == parse_file(ssh_sample, 2026)
    assert parse_events(windows_lines, "windows") == parse_windows_csv(windows_sample)


def test_parse_events_names_the_source_in_errors() -> None:
    with pytest.raises(ValueError, match=r"^upload\.csv: not a Windows logon export"):
        parse_events(["a,b\n", "1,2\n"], "windows", source="upload.csv")
