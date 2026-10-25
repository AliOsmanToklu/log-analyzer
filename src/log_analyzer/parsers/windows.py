import csv
from datetime import datetime
from pathlib import Path

from ..models import Event, EventType

EVENT_TYPES = {
    "4625": EventType.FAILED,
    "4624": EventType.ACCEPTED,
}

# Local/meaningless addresses are dropped; we only care about remote logons
IGNORED_IPS = {"-", "", "::1", "127.0.0.1"}


def parse_windows_csv(filepath: str | Path) -> list[Event]:
    """Convert a CSV with Time,Id,User,IP columns to the common event format."""
    events: list[Event] = []
    with open(filepath, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            event_type = EVENT_TYPES.get(row["Id"].strip())
            ip = row["IP"].strip()
            if not event_type or ip in IGNORED_IPS:
                continue
            try:
                timestamp = datetime.strptime(row["Time"].strip(), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            events.append(Event(time=timestamp, type=event_type, user=row["User"].strip(), ip=ip))
    return events
