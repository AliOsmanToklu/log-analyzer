"""Analysis use cases, independent of HTTP."""

import logging
import uuid
from collections.abc import Sequence
from typing import cast

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ..analysis import analyze
from ..parsers import LogFormat, parse_events
from ..report import to_json_data
from .orm import AnalysisRecord, AnalysisStatus, FindingRecord, utcnow

logger = logging.getLogger(__name__)

INTERNAL_ERROR = "internal error while analyzing the log"


def create_analysis(
    session: Session,
    *,
    filename: str,
    fmt: LogFormat,
    threshold: int,
    window_seconds: int,
    scan_threshold: int,
    year: int | None,
) -> AnalysisRecord:
    """Store a pending analysis; `run_analysis` fills in the results."""
    record = AnalysisRecord(
        filename=filename,
        format=fmt,
        threshold=threshold,
        window_seconds=window_seconds,
        scan_threshold=scan_threshold,
        year=year,
    )
    session.add(record)
    session.commit()
    return record


def _analyze_into(record: AnalysisRecord, lines: Sequence[str]) -> None:
    try:
        events = parse_events(
            lines, cast(LogFormat, record.format), record.year, source=record.filename
        )
    except ValueError as exc:  # input that is not a log of the given format
        record.status = AnalysisStatus.FAILED
        record.error = str(exc)
        return

    result = analyze(events, record.threshold, record.window_seconds, record.scan_threshold)
    record.total_events = result.total_events
    record.result = to_json_data(result, record.filename)
    record.findings = [
        FindingRecord(ip=f.ip, detection=f.detection, severity=f.severity, details=f.details)
        for f in result.findings()
    ]
    record.status = AnalysisStatus.COMPLETED


def run_analysis(
    sessions: sessionmaker[Session], analysis_id: uuid.UUID, lines: Sequence[str]
) -> None:
    """Analyze uploaded log lines and store the outcome. Meant to run as a background task,
    so it never raises: failures are recorded on the analysis instead."""
    with sessions() as session:
        record = session.get(AnalysisRecord, analysis_id)
        if record is None:  # deleted before it ran
            return
        try:
            _analyze_into(record, lines)
        except Exception:
            logger.exception("Analysis %s failed", analysis_id)
            session.rollback()
            record = session.get_one(AnalysisRecord, analysis_id)
            record.status = AnalysisStatus.FAILED
            record.error = INTERNAL_ERROR
        record.completed_at = utcnow()
        session.commit()


def get_analysis(session: Session, analysis_id: uuid.UUID) -> AnalysisRecord | None:
    return session.get(AnalysisRecord, analysis_id)


def delete_analysis(session: Session, analysis_id: uuid.UUID) -> bool:
    """Delete an analysis and its findings. Returns False if it did not exist."""
    record = session.get(AnalysisRecord, analysis_id)
    if record is None:
        return False
    session.delete(record)
    session.commit()
    return True


def list_analyses(
    session: Session, *, limit: int, offset: int, status: AnalysisStatus | None = None
) -> tuple[list[AnalysisRecord], int]:
    """Newest first, with the total number of matches."""
    filters = [AnalysisRecord.status == status] if status else []
    total = session.scalar(select(func.count(AnalysisRecord.id)).where(*filters)) or 0
    records = session.scalars(
        select(AnalysisRecord)
        .where(*filters)
        .order_by(AnalysisRecord.created_at.desc(), AnalysisRecord.id)
        .limit(limit)
        .offset(offset)
    )
    return list(records), total


def search_findings(
    session: Session,
    *,
    limit: int,
    offset: int,
    ip: str | None = None,
    severity: str | None = None,
    detection: str | None = None,
) -> tuple[list[tuple[FindingRecord, AnalysisRecord]], int]:
    """Findings across all analyses, newest analysis first, with the total number of matches."""
    filters = [
        column == value
        for column, value in [
            (FindingRecord.ip, ip),
            (FindingRecord.severity, severity),
            (FindingRecord.detection, detection),
        ]
        if value is not None
    ]
    total = (
        session.scalar(
            select(func.count(FindingRecord.id)).join(FindingRecord.analysis).where(*filters)
        )
        or 0
    )
    rows = session.execute(
        select(FindingRecord, AnalysisRecord)
        .join(FindingRecord.analysis)
        .where(*filters)
        .order_by(AnalysisRecord.created_at.desc(), FindingRecord.id)
        .limit(limit)
        .offset(offset)
    )
    return [(finding, analysis) for finding, analysis in rows], total
