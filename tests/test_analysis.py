from pathlib import Path

from log_analyzer.analysis import analyze
from log_analyzer.models import Detection, Finding, Severity
from log_analyzer.parsers import parse_file, parse_windows_csv


def test_ssh_sample_findings(ssh_sample: Path) -> None:
    result = analyze(parse_file(ssh_sample))

    assert result.total_events == 66
    assert result.findings() == [
        Finding("203.0.113.45", Detection.BRUTE_FORCE, Severity.HIGH, "40 failed attempts"),
        Finding(
            "203.0.113.45",
            Detection.POSSIBLE_COMPROMISE,
            Severity.CRITICAL,
            "successful login as ahmet",
        ),
        Finding("198.51.100.7", Detection.SLOW_SCAN, Severity.MEDIUM, "6 invalid user attempts"),
    ]
    assert result.bruteforce[0].max_in_window == 21


def test_windows_sample_findings(windows_sample: Path) -> None:
    result = analyze(parse_windows_csv(windows_sample))

    assert [(f.ip, f.detection) for f in result.findings()] == [
        ("203.0.113.99", "BRUTE_FORCE"),
        ("203.0.113.99", "POSSIBLE_COMPROMISE"),
    ]


def test_thresholds_are_passed_through(ssh_sample: Path) -> None:
    result = analyze(parse_file(ssh_sample), threshold=22, window_seconds=60, scan_threshold=7)

    assert result.findings() == []
    assert (result.threshold, result.window_seconds, result.scan_threshold) == (22, 60, 7)


def test_empty_input() -> None:
    result = analyze([])

    assert result.total_events == 0
    assert result.findings() == []
