from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest

from log_analyzer.models import Event, EventType
from log_analyzer.parsers.ssh import parse_file, parse_line

PREFIX = "Oct 25 11:02:05 server sshd[1234]: "
TIME = datetime(2026, 10, 25, 11, 2, 5)


@pytest.mark.parametrize(
    ("message", "expected_type", "user", "ip"),
    [
        (
            "Failed password for root from 203.0.113.45 port 40000 ssh2",
            EventType.FAILED,
            "root",
            "203.0.113.45",
        ),
        (
            "Failed password for invalid user bob from 10.0.0.9 port 22 ssh2",
            EventType.FAILED,
            "bob",
            "10.0.0.9",
        ),
        (
            "Accepted password for ahmet from 192.168.1.10 port 52000 ssh2",
            EventType.ACCEPTED,
            "ahmet",
            "192.168.1.10",
        ),
        (
            "Invalid user oracle from 198.51.100.7 port 33000",
            EventType.INVALID,
            "oracle",
            "198.51.100.7",
        ),
        (
            "Failed password for root from 2001:db8::1 port 22 ssh2",
            EventType.FAILED,
            "root",
            "2001:db8::1",
        ),
    ],
)
def test_parse_line_recognized(message: str, expected_type: EventType, user: str, ip: str) -> None:
    assert parse_line(PREFIX + message) == Event(time=TIME, type=expected_type, user=user, ip=ip)


@pytest.mark.parametrize(
    "line",
    [
        PREFIX + "Received disconnect from 203.0.113.45 port 40000:11: Bye Bye",
        PREFIX + "pam_unix(sshd:session): session opened for user ahmet",
        "not a syslog line at all",
        "",
    ],
)
def test_parse_line_ignores_other_lines(line: str) -> None:
    assert parse_line(line) is None


def test_parse_line_uses_given_year() -> None:
    event = parse_line(PREFIX + "Invalid user x from 1.2.3.4 port 1", year=2024)
    assert event is not None
    assert event.time.year == 2024


def test_parse_file_sample(ssh_sample: Path) -> None:
    events = parse_file(ssh_sample)

    assert len(events) == 66
    assert Counter(e.type for e in events) == {
        EventType.ACCEPTED: 16,
        EventType.FAILED: 44,
        EventType.INVALID: 6,
    }


def test_parse_file_skips_unknown_lines(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(
        PREFIX + "Accepted password for a from 1.1.1.1 port 1 ssh2\n"
        "garbage\n" + PREFIX + "Server listening on 0.0.0.0 port 22.\n",
        encoding="utf-8",
    )

    assert [e.user for e in parse_file(log)] == ["a"]
