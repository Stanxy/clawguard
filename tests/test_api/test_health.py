from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_health_ok(client):
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["version"] == "0.3.0"
    assert "SECRET" in data["scanners"]
    assert "PII" in data["scanners"]
    assert "CUSTOM" in data["scanners"]
    assert data["policy_loaded"] is True
