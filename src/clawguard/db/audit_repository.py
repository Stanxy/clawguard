from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from clawguard.db.models import FindingRecord, ScanEvent
from clawguard.db.repository import AuditRepository


class SQLAlchemyAuditRepository(AuditRepository):
    """SQLAlchemy implementation of the audit repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def log_scan(self, event_data: dict[str, Any]) -> int:
        findings_data = event_data.pop("findings", [])

        async with self._session_factory() as session:
            event = ScanEvent(**event_data)
            session.add(event)
            await session.flush()  # get event.id

            for fd in findings_data:
                fd["scan_event_id"] = event.id
                session.add(FindingRecord(**fd))

            await session.commit()
            return event.id

    async def query_events(
        self,
        agent_id: str | None = None,
        destination: str | None = None,
        action: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        async with self._session_factory() as session:
            stmt = (
                select(ScanEvent)
                .options(selectinload(ScanEvent.findings))
                .order_by(ScanEvent.timestamp.desc())
            )

            if agent_id:
                stmt = stmt.where(ScanEvent.agent_id == agent_id)
            if destination:
                stmt = stmt.where(ScanEvent.destination == destination)
            if action:
                stmt = stmt.where(ScanEvent.action == action)

            stmt = stmt.offset(offset).limit(limit)
            result = await session.execute(stmt)
            events = result.scalars().all()

            return [_event_to_dict(e) for e in events]

    async def get_event(self, event_id: int) -> dict[str, Any] | None:
        async with self._session_factory() as session:
            stmt = (
                select(ScanEvent)
                .options(selectinload(ScanEvent.findings))
                .where(ScanEvent.id == event_id)
            )
            result = await session.execute(stmt)
            event = result.scalar_one_or_none()
            if event is None:
                return None
            return _event_to_dict(event)

    async def get_stats(self) -> dict[str, Any]:
        async with self._session_factory() as session:
            # Total scans
            total_result = await session.execute(
                select(func.count()).select_from(ScanEvent)
            )
            total_scans = total_result.scalar() or 0

            # Action counts
            action_result = await session.execute(
                select(ScanEvent.action, func.count())
                .group_by(ScanEvent.action)
            )
            action_counts = [
                {"action": row[0], "count": row[1]}
                for row in action_result.all()
            ]

            # Severity counts (from findings)
            severity_result = await session.execute(
                select(FindingRecord.severity, func.count())
                .group_by(FindingRecord.severity)
            )
            severity_counts = [
                {"severity": row[0], "count": row[1]}
                for row in severity_result.all()
            ]

            # Top finding types
            finding_type_result = await session.execute(
                select(FindingRecord.finding_type, func.count())
                .group_by(FindingRecord.finding_type)
                .order_by(func.count().desc())
                .limit(10)
            )
            top_finding_types = [
                {"finding_type": row[0], "count": row[1]}
                for row in finding_type_result.all()
            ]

            # Recent 5 scans
            recent_stmt = (
                select(ScanEvent)
                .options(selectinload(ScanEvent.findings))
                .order_by(ScanEvent.timestamp.desc())
                .limit(5)
            )
            recent_result = await session.execute(recent_stmt)
            recent_events = recent_result.scalars().all()

            return {
                "total_scans": total_scans,
                "action_counts": action_counts,
                "severity_counts": severity_counts,
                "top_finding_types": top_finding_types,
                "recent_scans": [_event_to_dict(e) for e in recent_events],
            }


def _event_to_dict(event: ScanEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "agent_id": event.agent_id,
        "destination": event.destination,
        "content_hash": event.content_hash,
        "action": event.action,
        "findings_count": event.findings_count,
        "duration_ms": event.duration_ms,
        "findings": [
            {
                "id": f.id,
                "scanner_type": f.scanner_type,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "start_offset": f.start_offset,
                "end_offset": f.end_offset,
                "redacted_snippet": f.redacted_snippet,
            }
            for f in event.findings
        ],
    }
