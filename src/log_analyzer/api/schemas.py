"""Request and response models; these also generate the OpenAPI documentation."""

import uuid
from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

from ..models import Detection, EventType, Severity
from ..parsers import LogFormat
from .orm import AnalysisRecord, AnalysisStatus

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int = Field(description="Number of matching items across all pages")
    limit: int
    offset: int


class AnalysisParameters(BaseModel):
    threshold: int = Field(
        description="Failed attempts within the window that count as brute force"
    )
    window_seconds: int = Field(description="Sliding window length")
    scan_threshold: int = Field(description="Invalid-user attempts that count as a slow scan")
    year: int | None = Field(description="Year used for classic syslog timestamps; null = guessed")


class AnalysisSummary(BaseModel):
    id: uuid.UUID
    filename: str
    format: LogFormat
    status: AnalysisStatus
    created_at: datetime
    completed_at: datetime | None
    total_events: int | None = Field(description="Parsed events; null until completed")
    error: str | None = Field(description="Why the analysis failed, if it did")
    parameters: AnalysisParameters

    @classmethod
    def from_record(cls, record: AnalysisRecord) -> "AnalysisSummary":
        return cls(
            id=record.id,
            filename=record.filename,
            format=record.format,  # type: ignore[arg-type]  # validated by pydantic
            status=AnalysisStatus(record.status),
            created_at=record.created_at,
            completed_at=record.completed_at,
            total_events=record.total_events,
            error=record.error,
            parameters=AnalysisParameters(
                threshold=record.threshold,
                window_seconds=record.window_seconds,
                scan_threshold=record.scan_threshold,
                year=record.year,
            ),
        )


class FindingOut(BaseModel):
    ip: str
    detection: Detection
    severity: Severity
    details: str


class BruteForceOut(BaseModel):
    ip: str
    total_failed: int
    max_in_window: int
    first_seen: datetime
    last_seen: datetime
    users_tried: list[str]


class CompromiseOut(BaseModel):
    time: datetime
    type: EventType
    user: str
    ip: str


class ScanOut(BaseModel):
    ip: str
    count: int
    users_tried: list[str]


class AnalysisDetail(AnalysisSummary):
    """A summary plus everything that was found; the lists are empty until completed."""

    findings: list[FindingOut] = []
    bruteforce: list[BruteForceOut] = []
    compromises: list[CompromiseOut] = []
    scanners: list[ScanOut] = []

    @classmethod
    def from_record(cls, record: AnalysisRecord) -> "AnalysisDetail":
        result = record.result or {}
        return cls(
            **AnalysisSummary.from_record(record).model_dump(),
            findings=[FindingOut.model_validate(f) for f in result.get("findings", [])],
            bruteforce=[BruteForceOut.model_validate(b) for b in result.get("bruteforce", [])],
            compromises=[CompromiseOut.model_validate(c) for c in result.get("compromises", [])],
            scanners=[ScanOut.model_validate(s) for s in result.get("scanners", [])],
        )


class FindingHit(FindingOut):
    """A finding together with the analysis it came from."""

    analysis_id: uuid.UUID
    filename: str
    analyzed_at: datetime


class Health(BaseModel):
    status: str
    database: str
