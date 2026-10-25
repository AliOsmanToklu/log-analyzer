"""Data types shared by parsers, detectors and reports."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class EventType(StrEnum):
    FAILED = "failed"
    ACCEPTED = "accepted"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class Event:
    """One authentication event, normalized from any log source."""

    time: datetime
    type: EventType
    user: str
    ip: str


class Severity(StrEnum):
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class Finding:
    """One row of the report: what was detected, for which IP, and how bad it is."""

    ip: str
    detection: str
    severity: Severity
    details: str
