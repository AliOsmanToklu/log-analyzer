import re
from datetime import datetime
from pathlib import Path

from ..models import Event, EventType

# Patterns for the three kinds of sshd lines we care about
PATTERNS = {
    EventType.FAILED: re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
    EventType.ACCEPTED: re.compile(r"Accepted password for (\S+) from (\S+)"),
    EventType.INVALID: re.compile(r"Invalid user (\S+) from (\S+)"),
}


def parse_line(line: str, year: int = 2026) -> Event | None:
    """Convert one log line to an Event. Returns None for unrecognized lines."""
    time_str = line[:15]  # e.g. "Oct 25 11:02:05"
    try:
        timestamp = datetime.strptime(f"{year} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if match:
            return Event(time=timestamp, type=event_type, user=match.group(1), ip=match.group(2))
    return None


def parse_file(filepath: str | Path) -> list[Event]:
    events: list[Event] = []
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events
