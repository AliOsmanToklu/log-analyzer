import csv
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


def parse_windows_csv(filepath: str | Path) -> list[Event]:
    """Convert a CSV with Time,Id,User,IP columns to the common event format.

    Raises ValueError if a required column is missing.
    """
    events: list[Event] = []
    with open(filepath, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(
                f"{filepath}: not a Windows logon export, missing column(s): {', '.join(missing)}"
            )

        for row in reader:
            event_type = EVENT_TYPES.get(row["Id"].strip())
            ip = row["IP"].strip()
            if not event_type or ip in IGNORED_IPS:
                continue
            try:
                # Accepts "2026-10-25 13:00:00" as well as ISO 8601 with a "T" or offset
                timestamp = datetime.fromisoformat(row["Time"].strip()).replace(tzinfo=None)
            except ValueError:
                continue
            events.append(Event(time=timestamp, type=event_type, user=row["User"].strip(), ip=ip))
    return events
