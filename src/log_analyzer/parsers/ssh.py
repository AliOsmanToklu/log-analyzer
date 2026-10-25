import re
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timedelta
from pathlib import Path

from ..models import Event, EventType

# sshd messages we care about. The auth method (password, publickey,
# keyboard-interactive/pam, ...) is matched generically, and usernames may be
# empty ("Invalid user  from ...").
PATTERNS = {
    EventType.FAILED: re.compile(r"Failed \S+ for (?:invalid user )?(\S*) from (\S+)"),
    EventType.ACCEPTED: re.compile(r"Accepted \S+ for (\S+) from (\S+)"),
    EventType.INVALID: re.compile(r"Invalid user (\S*) from (\S+)"),
}

# rsyslog collapses identical lines: "message repeated 5 times: [ Failed password ...]"
REPEATED = re.compile(r"message repeated (\d+) times: \[")

# Classic syslog lines have no year: "Oct 25 11:02:05 host ..."
CLASSIC_FORMAT = "%Y %b %d %H:%M:%S"
CLASSIC_LENGTH = 15

# Logs are chronological, so a classic line more than a day older than the one
# before it means the year rolled over (Dec 31 -> Jan 1)
ROLLOVER = timedelta(days=1)


def _is_iso(line: str) -> bool:
    return line[:4].isdigit()


def _timestamp(line: str, year: int) -> datetime | None:
    """Read the leading timestamp: RFC 3339 (modern rsyslog/journald) or classic syslog."""
    try:
        if _is_iso(line):
            # Keep the wall-clock time as logged so both formats compare the same way
            return datetime.fromisoformat(line.split(" ", 1)[0]).replace(tzinfo=None)
        return datetime.strptime(f"{year} {line[:CLASSIC_LENGTH]}", CLASSIC_FORMAT)
    except ValueError:
        return None


def parse_line(line: str, year: int | None = None) -> Event | None:
    """Convert one log line to an Event. Returns None for unrecognized lines.

    `year` is used for classic syslog timestamps and defaults to the current year.
    """
    timestamp = _timestamp(line, datetime.now().year if year is None else year)
    if timestamp is None:
        return None

    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if match:
            return Event(time=timestamp, type=event_type, user=match.group(1), ip=match.group(2))
    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[Event]:
    """Parse a log that starts in `year`, following year rollovers and expanding
    repeated-message lines into one event per repetition."""
    previous: datetime | None = None
    for line in lines:
        event = parse_line(line, year)
        if event is None:
            continue
        if previous and previous - event.time > ROLLOVER and not _is_iso(line):
            year += 1
            event = parse_line(line, year)
            if event is None:  # e.g. Feb 29 in a non-leap year
                continue
        previous = event.time

        repeated = REPEATED.search(line)
        for _ in range(int(repeated.group(1)) if repeated else 1):
            yield event


def parse_ssh_lines(lines: Sequence[str], year: int | None = None) -> list[Event]:
    """Parse the lines of an SSH auth log.

    Without `year`, the log is assumed to end in the current year, or in the
    previous one if that would put its last line in the future.
    """
    if year is not None:
        return list(parse_lines(lines, year))

    now = datetime.now()
    events = list(parse_lines(lines, now.year))
    if events and events[-1].time > now + timedelta(days=1):
        events = list(parse_lines(lines, now.year - 1))
    return events


def parse_file(filepath: str | Path, year: int | None = None) -> list[Event]:
    """Parse an SSH auth log file; see `parse_ssh_lines`."""
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        return parse_ssh_lines(f.readlines(), year)
