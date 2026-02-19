from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_audit_empty(client):
    resp = await client.get("/api/v1/audit")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_audit_after_scan(client):
    # Create a scan first
    await client.post("/api/v1/scan", json={
        "content": "AKIAIOSFODNN7EXAMPLE",
    })
    resp = await client.get("/api/v1/audit")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    entry = data[0]
    assert entry["action"] == "BLOCK"
    assert entry["findings_count"] >= 1
    assert "content_hash" in entry
    # Raw content should never be in the audit log
    assert "AKIAIOSFODNN7EXAMPLE" not in str(entry)


@pytest.mark.asyncio
async def test_audit_filter_by_action(client):
    # Scan with finding (BLOCK) and without (ALLOW)
    await client.post("/api/v1/scan", json={"content": "AKIAIOSFODNN7EXAMPLE"})
    await client.post("/api/v1/scan", json={"content": "clean text"})

    resp = await client.get("/api/v1/audit", params={"action": "BLOCK"})
    data = resp.json()
    assert all(e["action"] == "BLOCK" for e in data)


@pytest.mark.asyncio
async def test_audit_filter_by_agent_id(client):
    await client.post("/api/v1/scan", json={
        "content": "AKIAIOSFODNN7EXAMPLE",
        "agent_id": "agent-1",
    })
    resp = await client.get("/api/v1/audit", params={"agent_id": "agent-1"})
    data = resp.json()
    assert len(data) >= 1
    assert all(e["agent_id"] == "agent-1" for e in data)


@pytest.mark.asyncio
async def test_audit_pagination(client):
    for _ in range(3):
        await client.post("/api/v1/scan", json={"content": "AKIAIOSFODNN7EXAMPLE"})

    resp = await client.get("/api/v1/audit", params={"limit": 2, "offset": 0})
    assert len(resp.json()) == 2

    resp = await client.get("/api/v1/audit", params={"limit": 2, "offset": 2})
    assert len(resp.json()) >= 1
