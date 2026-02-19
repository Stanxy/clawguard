from __future__ import annotations

import pytest
import pytest_asyncio

from clawguard.db.audit_repository import SQLAlchemyAuditRepository


@pytest_asyncio.fixture
async def repo(session_factory):
    return SQLAlchemyAuditRepository(session_factory)


@pytest.mark.asyncio
async def test_log_and_query(repo):
    event_id = await repo.log_scan({
        "agent_id": "test-agent",
        "destination": "api.example.com",
        "content_hash": "abc123",
        "action": "BLOCK",
        "findings_count": 2,
        "duration_ms": 5.5,
        "findings": [
            {
                "scanner_type": "SECRET",
                "finding_type": "aws_access_key_id",
                "severity": "CRITICAL",
                "start_offset": 0,
                "end_offset": 20,
                "redacted_snippet": "AKIA************MPLE",
            },
            {
                "scanner_type": "PII",
                "finding_type": "ssn",
                "severity": "CRITICAL",
                "start_offset": 30,
                "end_offset": 41,
                "redacted_snippet": "123-***6789",
            },
        ],
    })
    assert isinstance(event_id, int)

    events = await repo.query_events()
    assert len(events) == 1
    assert events[0]["action"] == "BLOCK"
    assert events[0]["findings_count"] == 2
    assert len(events[0]["findings"]) == 2


@pytest.mark.asyncio
async def test_get_event(repo):
    event_id = await repo.log_scan({
        "agent_id": None,
        "destination": None,
        "content_hash": "xyz789",
        "action": "ALLOW",
        "findings_count": 0,
        "duration_ms": 1.0,
        "findings": [],
    })

    event = await repo.get_event(event_id)
    assert event is not None
    assert event["content_hash"] == "xyz789"


@pytest.mark.asyncio
async def test_get_nonexistent_event(repo):
    event = await repo.get_event(99999)
    assert event is None


@pytest.mark.asyncio
async def test_filter_by_agent(repo):
    await repo.log_scan({
        "agent_id": "agent-a",
        "destination": None,
        "content_hash": "h1",
        "action": "BLOCK",
        "findings_count": 1,
        "duration_ms": 1.0,
        "findings": [],
    })
    await repo.log_scan({
        "agent_id": "agent-b",
        "destination": None,
        "content_hash": "h2",
        "action": "ALLOW",
        "findings_count": 0,
        "duration_ms": 1.0,
        "findings": [],
    })

    results = await repo.query_events(agent_id="agent-a")
    assert len(results) == 1
    assert results[0]["agent_id"] == "agent-a"


@pytest.mark.asyncio
async def test_filter_by_action(repo):
    await repo.log_scan({
        "agent_id": None,
        "destination": None,
        "content_hash": "h1",
        "action": "BLOCK",
        "findings_count": 1,
        "duration_ms": 1.0,
        "findings": [],
    })
    await repo.log_scan({
        "agent_id": None,
        "destination": None,
        "content_hash": "h2",
        "action": "ALLOW",
        "findings_count": 0,
        "duration_ms": 1.0,
        "findings": [],
    })

    results = await repo.query_events(action="ALLOW")
    assert len(results) == 1
    assert results[0]["action"] == "ALLOW"
