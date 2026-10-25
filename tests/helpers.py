from datetime import datetime, timedelta
from pathlib import Path

from log_analyzer.models import Event, EventType

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
T0 = datetime(2026, 10, 25, 12, 0, 0)


def ev(seconds: float, type: EventType, ip: str = "203.0.113.1", user: str = "root") -> Event:
    """Build an event `seconds` after a fixed reference time."""
    return Event(time=T0 + timedelta(seconds=seconds), type=type, user=user, ip=ip)


def failures(count: int, every: float, ip: str = "203.0.113.1", start: float = 0) -> list[Event]:
    """`count` failed logins from `ip`, one every `every` seconds."""
    return [ev(start + i * every, EventType.FAILED, ip) for i in range(count)]
