import csv
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from ..models import Event, EventType

EVENT_TYPES = {
    "4625": EventType.FAILED,
    "4624": EventType.ACCEPTED,
}

REQUIRED_COLUMNS = ("Time", "Id", "User", "IP")

# Local/meaningless addresses are dropped; we only care about remote logons
IGNORED_IPS = {"-", "", "::1", "127.0.0.1"}


def parse_windows_lines(lines: Iterable[str], source: str = "input") -> list[Event]:
    """Convert CSV lines with Time,Id,User,IP columns to the common event format.

    Raises ValueError if a required column is missing; `source` names the input
    in that message.
    """
    reader = csv.DictReader(lines)
    missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
    if missing:
        raise ValueError(
            f"{source}: not a Windows logon export, missing column(s): {', '.join(missing)}"
        )

    events: list[Event] = []
    for row in reader:
        # Short rows leave the missing fields as None
        time, event_id, user, ip = ((row[c] or "").strip() for c in REQUIRED_COLUMNS)
        event_type = EVENT_TYPES.get(event_id)
        if not event_type or ip in IGNORED_IPS:
            continue
        try:
            # Accepts "2026-10-25 13:00:00" as well as ISO 8601 with a "T" or offset
            timestamp = datetime.fromisoformat(time).replace(tzinfo=None)
        except ValueError:
            continue
        events.append(Event(time=timestamp, type=event_type, user=user, ip=ip))
    return events


def parse_windows_csv(filepath: str | Path) -> list[Event]:
    """Parse a Windows logon CSV export file; see `parse_windows_lines`."""
    with open(filepath, encoding="utf-8-sig", newline="") as f:
        return parse_windows_lines(f, str(filepath))
