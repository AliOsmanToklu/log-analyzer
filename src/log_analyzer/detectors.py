from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import Event, EventType


@dataclass(frozen=True, slots=True)
class BruteForceSuspect:
    ip: str
    total_failed: int
    max_in_window: int
    first_seen: datetime
    last_seen: datetime
    users_tried: list[str]


@dataclass(frozen=True, slots=True)
class ScanSuspect:
    ip: str
    count: int
    users_tried: list[str]


def _group_by_ip(events: Iterable[Event], event_type: EventType) -> dict[str, list[Event]]:
    by_ip: defaultdict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.type == event_type:
            by_ip[e.ip].append(e)
    return by_ip


def detect_bruteforce(
    events: Iterable[Event], threshold: int = 10, window_seconds: int = 60
) -> dict[str, BruteForceSuspect]:
    """Find IPs with at least `threshold` failed attempts within the time window."""
    window = timedelta(seconds=window_seconds)
    suspects: dict[str, BruteForceSuspect] = {}

    for ip, attempts in _group_by_ip(events, EventType.FAILED).items():
        attempts.sort(key=lambda e: e.time)

        # Sliding window: the largest number of attempts that fit in one window
        start = 0
        best = 0
        for end in range(len(attempts)):
            while attempts[end].time - attempts[start].time > window:
                start += 1
            best = max(best, end - start + 1)

        if best >= threshold:
            suspects[ip] = BruteForceSuspect(
                ip=ip,
                total_failed=len(attempts),
                max_in_window=best,
                first_seen=attempts[0].time,
                last_seen=attempts[-1].time,
                users_tried=sorted({a.user for a in attempts}),
            )

    return suspects


def detect_compromise(
    events: Iterable[Event], suspects: dict[str, BruteForceSuspect]
) -> list[Event]:
    """Check whether a brute force suspect later logged in successfully."""
    return [
        e
        for e in events
        if e.type == EventType.ACCEPTED and e.ip in suspects and e.time >= suspects[e.ip].first_seen
    ]


def detect_scanners(events: Iterable[Event], threshold: int = 3) -> dict[str, ScanSuspect]:
    """Find IPs probing non-existent usernames (slow scanning)."""
    return {
        ip: ScanSuspect(ip=ip, count=len(attempts), users_tried=sorted({a.user for a in attempts}))
        for ip, attempts in _group_by_ip(events, EventType.INVALID).items()
        if len(attempts) >= threshold
    }
