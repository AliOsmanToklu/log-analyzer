"""Database tables for stored analyses and their findings."""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class AnalysisStatus(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class AnalysisRecord(Base):
    """One uploaded log and the outcome of analyzing it.

    The uploaded log itself is never stored, only what was found in it.
    """

    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    filename: Mapped[str] = mapped_column(String(255))
    format: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default=AnalysisStatus.PENDING, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    threshold: Mapped[int]
    window_seconds: Mapped[int]
    scan_threshold: Mapped[int]
    year: Mapped[int | None]

    total_events: Mapped[int | None]
    error: Mapped[str | None] = mapped_column(Text)
    # Full detector output (report.to_json_data), for the detail endpoint
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="FindingRecord.id",
    )


class FindingRecord(Base):
    """One report row, stored separately so findings can be queried across analyses."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    ip: Mapped[str] = mapped_column(String(45), index=True)  # 45 = longest IPv6 text form
    detection: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    details: Mapped[str] = mapped_column(Text)

    analysis: Mapped[AnalysisRecord] = relationship(back_populates="findings")
