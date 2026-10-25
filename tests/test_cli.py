import csv
import json
from pathlib import Path

import pytest

from log_analyzer.cli import main
from tests.helpers import SAMPLES


def read_report(path: Path) -> list[list[str]]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.reader(f))


def test_ssh_log_end_to_end(
    ssh_sample: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "report.csv"

    main([str(ssh_sample), "--year", "2026", "--output", str(report)])

    out = capsys.readouterr().out
    assert "Total events: 66" in out
    assert "[!] 203.0.113.45: 40 failed attempts (max 21 within 60s)" in out
    assert "[!!!] 203.0.113.45 -> logged in as 'ahmet' (2026-10-25 11:02:05)" in out
    assert "[!] 198.51.100.7: 6 invalid user attempts (oracle)" in out
    assert read_report(report) == [
        ["IP", "Detection", "Severity", "Details"],
        ["203.0.113.45", "BRUTE_FORCE", "HIGH", "40 failed attempts"],
        ["203.0.113.45", "POSSIBLE_COMPROMISE", "CRITICAL", "successful login as ahmet"],
        ["198.51.100.7", "SLOW_SCAN", "MEDIUM", "6 invalid user attempts"],
    ]


def test_csv_input_uses_windows_parser(
    windows_sample: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main([str(windows_sample), "--output", str(tmp_path / "r.csv")])

    out = capsys.readouterr().out
    assert "Total events: 41" in out
    assert "logged in as 'administrator'" in out


def test_no_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    report = tmp_path / "r.csv"

    main([str(log), "--output", str(report)])

    assert capsys.readouterr().out.count("None found.") == 3
    assert read_report(report) == [["IP", "Detection", "Severity", "Details"]]


@pytest.mark.parametrize(("threshold", "flagged"), [(4, True), (5, False)])
def test_threshold_and_window_options(
    threshold: int,
    flagged: bool,
    ssh_sample: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The sample attacker fails every 3 s, so at most 4 attempts fit in 10 s
    report = tmp_path / "r.csv"
    main(
        [str(ssh_sample), "--threshold", str(threshold), "--window", "10", "--output", str(report)]
    )

    out = capsys.readouterr().out
    assert ("[!] 203.0.113.45: 40 failed attempts (max 4 within 10s)" in out) is flagged
    assert any(row[1] == "BRUTE_FORCE" for row in read_report(report)) is flagged


def test_returns_zero_on_success(ssh_sample: Path, tmp_path: Path) -> None:
    assert main([str(ssh_sample), "--output", str(tmp_path / "r.csv")]) == 0


@pytest.mark.parametrize(
    ("sample", "copy_name", "fmt", "events"),
    [
        ("auth.log", "ssh_export.csv", "ssh", 66),
        ("windows_events.csv", "windows_export.txt", "windows", 41),
    ],
)
def test_format_option_overrides_extension(
    sample: str,
    copy_name: str,
    fmt: str,
    events: int,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / copy_name
    source.write_bytes((SAMPLES / sample).read_bytes())

    assert main([str(source), "--format", fmt, "--output", str(tmp_path / "r.csv")]) == 0
    assert f"Total events: {events}" in capsys.readouterr().out


def test_scan_threshold_option(
    ssh_sample: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main([str(ssh_sample), "--scan-threshold", "7", "--output", str(tmp_path / "r.csv")])

    assert "198.51.100.7" not in capsys.readouterr().out


def test_json_report(ssh_sample: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.json"

    assert main([str(ssh_sample), "--year", "2026", "--output", str(report)]) == 0

    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["source"] == str(ssh_sample)
    assert data["total_events"] == 66
    assert data["parameters"] == {"threshold": 10, "window_seconds": 60, "scan_threshold": 3}
    assert data["findings"][1] == {
        "ip": "203.0.113.45",
        "detection": "POSSIBLE_COMPROMISE",
        "severity": "CRITICAL",
        "details": "successful login as ahmet",
    }
    assert data["bruteforce"][0]["first_seen"] == "2026-10-25T11:00:00"
    assert data["bruteforce"][0]["users_tried"] == ["admin", "ahmet", "root", "test", "ubuntu"]
    assert data["compromises"] == [
        {"time": "2026-10-25T11:02:05", "type": "accepted", "user": "ahmet", "ip": "203.0.113.45"}
    ]
    assert data["scanners"] == [{"ip": "198.51.100.7", "count": 6, "users_tried": ["oracle"]}]


def test_missing_input_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path / "nope.log"), "--output", str(tmp_path / "r.csv")]) == 2

    captured = capsys.readouterr()
    assert captured.err.startswith("log-analyzer: error: ")
    assert "nope.log" in captured.err
    assert captured.out == ""
    assert not (tmp_path / "r.csv").exists()


def test_csv_that_is_not_a_windows_export(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "other.csv"
    source.write_text("name,age\nbob,3\n", encoding="utf-8")

    assert main([str(source), "--output", str(tmp_path / "r.csv")]) == 2
    assert "missing column(s): Time, Id, User, IP" in capsys.readouterr().err


def test_unwritable_output(
    ssh_sample: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A directory cannot be opened as a file
    assert main([str(ssh_sample), "--output", str(tmp_path)]) == 2
    assert "log-analyzer: error: " in capsys.readouterr().err


@pytest.mark.parametrize(
    ("option", "value", "message"),
    [
        ("--threshold", "0", "must be at least 1, got 0"),
        ("--window", "-5", "must be at least 1, got -5"),
        ("--scan-threshold", "many", "not an integer: 'many'"),
    ],
)
def test_rejects_invalid_numbers(
    option: str, value: str, message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["auth.log", option, value])

    assert exc_info.value.code == 2
    assert message in capsys.readouterr().err
