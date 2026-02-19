from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AuditRepository(ABC):
    """Abstract repository for audit log operations."""

    @abstractmethod
    async def log_scan(self, event_data: dict[str, Any]) -> int:
        """Persist a scan event and its findings. Returns the event ID."""
        ...

    @abstractmethod
    async def query_events(
        self,
        agent_id: str | None = None,
        destination: str | None = None,
        action: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit log with optional filters."""
        ...

    @abstractmethod
    async def get_event(self, event_id: int) -> dict[str, Any] | None:
        """Get a single scan event by ID."""
        ...

    @abstractmethod
    async def get_stats(self) -> dict[str, Any]:
        """Get aggregated dashboard statistics."""
        ...
