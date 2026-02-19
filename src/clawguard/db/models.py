from __future__ import annotations

import datetime

from sqlalchemy import DateTime, Enum, Float, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    agent_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    destination: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(10), nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    findings: Mapped[list[FindingRecord]] = relationship(
        "FindingRecord", back_populates="scan_event", cascade="all, delete-orphan"
    )


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_event_id: Mapped[int] = mapped_column(Integer, nullable=False)
    scanner_type: Mapped[str] = mapped_column(String(20), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    start_offset: Mapped[int] = mapped_column(Integer, nullable=False)
    end_offset: Mapped[int] = mapped_column(Integer, nullable=False)
    redacted_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan_event: Mapped[ScanEvent] = relationship("ScanEvent", back_populates="findings")

    __table_args__ = (
        # ForeignKey defined via string for clarity
        {"comment": "Individual findings from a scan event"},
    )

# Manually add foreign key (avoids import-time issues with async engines)
from sqlalchemy import ForeignKey  # noqa: E402
FindingRecord.__table__.c.scan_event_id.append_foreign_key(
    ForeignKey("scan_events.id")
)
