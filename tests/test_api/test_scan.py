from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_scan_detects_aws_key(client):
    resp = await client.post("/api/v1/scan", json={
        "content": "my aws key is AKIAIOSFODNN7EXAMPLE",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "REDACT"
    assert data["findings_count"] >= 1
    assert any(f["finding_type"] == "aws_access_key_id" for f in data["findings"])


@pytest.mark.asyncio
async def test_scan_detects_ssn(client):
    resp = await client.post("/api/v1/scan", json={
        "content": "ssn: 123-45-6789",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "REDACT"
    assert any(f["finding_type"] == "ssn" for f in data["findings"])


@pytest.mark.asyncio
async def test_scan_clean_content_allows(client):
    resp = await client.post("/api/v1/scan", json={
        "content": "This is a perfectly normal message.",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "ALLOW"
    assert data["findings_count"] == 0


@pytest.mark.asyncio
async def test_scan_multiple_findings(client):
    resp = await client.post("/api/v1/scan", json={
        "content": "key AKIAIOSFODNN7EXAMPLE and ssn 123-45-6789",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings_count"] >= 2


@pytest.mark.asyncio
async def test_scan_returns_scan_id(client):
    resp = await client.post("/api/v1/scan", json={
        "content": "AKIAIOSFODNN7EXAMPLE",
    })
    data = resp.json()
    assert data["scan_id"] is not None
    assert isinstance(data["scan_id"], int)


@pytest.mark.asyncio
async def test_scan_with_destination(client):
    resp = await client.post("/api/v1/scan", json={
        "content": "AKIAIOSFODNN7EXAMPLE",
        "destination": "api.example.com",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_scan_with_agent_id(client):
    resp = await client.post("/api/v1/scan", json={
        "content": "AKIAIOSFODNN7EXAMPLE",
        "agent_id": "test-agent",
    })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_scan_never_returns_raw_secret(client):
    secret = "AKIAIOSFODNN7EXAMPLE"
    resp = await client.post("/api/v1/scan", json={
        "content": f"key = {secret}",
    })
    data = resp.json()
    # The redacted snippet should not contain the full secret
    for f in data["findings"]:
        if f.get("redacted_snippet"):
            assert secret not in f["redacted_snippet"]
