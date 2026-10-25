import csv
from pathlib import Path

import pytest

from log_analyzer.cli import main


def read_report(path: Path) -> list[list[str]]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.reader(f))


def test_ssh_log_end_to_end(
    ssh_sample: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "report.csv"

    main([str(ssh_sample), "--output", str(report)])

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
