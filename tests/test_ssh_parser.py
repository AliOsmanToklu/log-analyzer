from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from log_analyzer.models import Event, EventType
from log_analyzer.parsers.ssh import parse_file, parse_line, parse_lines

PREFIX = "Oct 25 11:02:05 server sshd[1234]: "
TIME = datetime(2026, 10, 25, 11, 2, 5)


def classic(t: datetime, message: str = "Invalid user x from 1.2.3.4 port 1") -> str:
    return f"{t:%b} {t.day:2d} {t:%H:%M:%S} server sshd[1234]: {message}\n"


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
            "Failed publickey for git from 10.0.0.9 port 22 ssh2: RSA SHA256:abc",
            EventType.FAILED,
            "git",
            "10.0.0.9",
        ),
        (
            "Failed keyboard-interactive/pam for invalid user pi from 10.0.0.9 port 22 ssh2",
            EventType.FAILED,
            "pi",
            "10.0.0.9",
        ),
        (
            "Failed none for invalid user  from 10.0.0.9 port 22 ssh2",
            EventType.FAILED,
            "",
            "10.0.0.9",
        ),
        (
            "Accepted password for ahmet from 192.168.1.10 port 52000 ssh2",
            EventType.ACCEPTED,
            "ahmet",
            "192.168.1.10",
        ),
        (
            "Accepted publickey for deploy from 192.168.1.10 port 52000 ssh2: ED25519 SHA256:x",
            EventType.ACCEPTED,
            "deploy",
            "192.168.1.10",
        ),
        (
            "Invalid user oracle from 198.51.100.7 port 33000",
            EventType.INVALID,
            "oracle",
            "198.51.100.7",
        ),
        (
            "Invalid user  from 198.51.100.7 port 33000",
            EventType.INVALID,
            "",
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
    event = parse_line(PREFIX + message, year=2026)

    assert event == Event(time=TIME, type=expected_type, user=user, ip=ip)


@pytest.mark.parametrize(
    "line",
    [
        PREFIX + "Received disconnect from 203.0.113.45 port 40000:11: Bye Bye",
        PREFIX + "pam_unix(sshd:session): session opened for user ahmet",
        "Foo 25 11:02:05 server sshd[1234]: Invalid user x from 1.2.3.4 port 1",
        "2026-13-45T11:02:05 server sshd[1234]: Invalid user x from 1.2.3.4 port 1",
        "not a syslog line at all",
        "",
    ],
)
def test_parse_line_ignores_other_lines(line: str) -> None:
    assert parse_line(line, year=2026) is None


def test_parse_line_uses_given_year() -> None:
    event = parse_line(PREFIX + "Invalid user x from 1.2.3.4 port 1", year=2024)

    assert event is not None
    assert event.time.year == 2024


def test_parse_line_defaults_to_current_year() -> None:
    event = parse_line(PREFIX + "Invalid user x from 1.2.3.4 port 1")

    assert event is not None
    assert event.time.year == datetime.now().year


def test_single_digit_day_is_space_padded() -> None:
    event = parse_line("Oct  5 11:02:05 server sshd[1]: Invalid user x from 1.2.3.4 port 1", 2026)

    assert event is not None
    assert event.time == datetime(2026, 10, 5, 11, 2, 5)


@pytest.mark.parametrize(
    ("stamp", "expected"),
    [
        ("2026-10-25T11:02:05.123456+03:00", datetime(2026, 10, 25, 11, 2, 5, 123456)),
        ("2026-10-25T11:02:05.123+03:00", datetime(2026, 10, 25, 11, 2, 5, 123000)),
        ("2026-10-25T08:02:05Z", datetime(2026, 10, 25, 8, 2, 5)),
        ("2026-10-25T11:02:05", datetime(2026, 10, 25, 11, 2, 5)),
    ],
)
def test_iso_timestamps(stamp: str, expected: datetime) -> None:
    line = f"{stamp} server sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"

    # The year argument is ignored: ISO timestamps carry their own
    event = parse_line(line, year=1999)

    assert event is not None
    assert event.time == expected


def test_repeated_messages_are_expanded() -> None:
    lines = [
        PREFIX + "Failed password for root from 1.2.3.4 port 22 ssh2\n",
        PREFIX
        + "message repeated 5 times: [ Failed password for root from 1.2.3.4 port 22 ssh2]\n",
    ]

    events = list(parse_lines(lines, 2026))

    assert len(events) == 6
    assert {(e.type, e.user, e.ip) for e in events} == {(EventType.FAILED, "root", "1.2.3.4")}


def test_year_rollover() -> None:
    lines = [
        classic(datetime(2025, 12, 31, 23, 59, 50)),
        classic(datetime(2026, 1, 1, 0, 0, 5)),
        classic(datetime(2026, 1, 1, 0, 0, 1)),  # slightly out of order: not a rollover
        classic(datetime(2026, 12, 20, 9, 0, 0)),
        classic(datetime(2027, 1, 2, 9, 0, 0)),
    ]

    times = [e.time for e in parse_lines(lines, 2025)]

    assert [t.year for t in times] == [2025, 2026, 2026, 2026, 2027]


def test_rollover_line_invalid_in_new_year_is_skipped() -> None:
    lines = [
        classic(datetime(2024, 3, 5)),
        "Feb 29 10:00:00 h sshd[1]: Invalid user y from 5.6.7.8",
    ]

    # 2024 is a leap year, but rolling over makes it Feb 29 2025, which does not exist
    assert [e.user for e in parse_lines(lines, 2024)] == ["x"]


class TestParseFile:
    def test_sample(self, ssh_sample: Path) -> None:
        events = parse_file(ssh_sample)

        assert len(events) == 66
        assert Counter(e.type for e in events) == {
            EventType.ACCEPTED: 16,
            EventType.FAILED: 44,
            EventType.INVALID: 6,
        }

    def test_explicit_year(self, ssh_sample: Path) -> None:
        events = parse_file(ssh_sample, year=2020)

        assert {e.time.year for e in events} == {2020}

    def test_skips_unknown_lines(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_text(
            PREFIX + "Accepted password for a from 1.1.1.1 port 1 ssh2\n"
            "garbage\n" + PREFIX + "Server listening on 0.0.0.0 port 22.\n",
            encoding="utf-8",
        )

        assert [e.user for e in parse_file(log)] == ["a"]

    def test_recent_log_gets_current_year(self, tmp_path: Path) -> None:
        last = datetime.now().replace(microsecond=0) - timedelta(days=2)
        log = tmp_path / "auth.log"
        log.write_text(classic(last - timedelta(days=1)) + classic(last), encoding="utf-8")

        assert parse_file(log)[-1].time == last

    def test_log_that_would_end_in_the_future_gets_previous_year(self, tmp_path: Path) -> None:
        # "Mmm dd" ten days from now can only be from last year (or wrapped from it)
        ahead = datetime.now().replace(microsecond=0) + timedelta(days=10)

        if (ahead.month, ahead.day) == (2, 29):
            ahead += timedelta(days=1)
        log = tmp_path / "auth.log"
        log.write_text(classic(ahead), encoding="utf-8")

        event = parse_file(log)[-1]

        assert event.time == ahead.replace(year=ahead.year - 1)
        assert event.time <= datetime.now()
