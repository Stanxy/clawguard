"""Tests for the dashboard API endpoints and HTML serving."""
from __future__ import annotations

import pytest


# ── HTML serving ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dashboard_html_served(client):
    resp = await client.get("/dashboard")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "ClawGuard Dashboard" in resp.text


@pytest.mark.asyncio
async def test_dashboard_html_contains_tabs(client):
    resp = await client.get("/dashboard")
    assert resp.status_code == 200
    for tab in ["overview", "history", "policies", "scanner", "patterns"]:
        assert tab in resp.text


# ── GET /api/v1/dashboard/stats ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stats_empty(client):
    resp = await client.get("/api/v1/dashboard/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_scans"] == 0
    assert data["action_counts"] == []
    assert data["severity_counts"] == []
    assert data["top_finding_types"] == []
    assert data["recent_scans"] == []


@pytest.mark.asyncio
async def test_stats_after_scans(client):
    # Create some scan events
    await client.post("/api/v1/scan", json={"content": "AKIAIOSFODNN7EXAMPLE"})
    await client.post("/api/v1/scan", json={"content": "clean text with no issues"})

    resp = await client.get("/api/v1/dashboard/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_scans"] == 2
    assert len(data["action_counts"]) >= 1
    assert len(data["recent_scans"]) == 2


@pytest.mark.asyncio
async def test_stats_recent_scans_limited_to_5(client):
    for i in range(7):
        await client.post("/api/v1/scan", json={"content": f"text {i}"})

    resp = await client.get("/api/v1/dashboard/stats")
    data = resp.json()
    assert len(data["recent_scans"]) == 5


@pytest.mark.asyncio
async def test_stats_action_counts(client):
    # BLOCK scan (has findings)
    await client.post("/api/v1/scan", json={"content": "AKIAIOSFODNN7EXAMPLE"})
    # ALLOW scan (no findings)
    await client.post("/api/v1/scan", json={"content": "nothing here"})

    resp = await client.get("/api/v1/dashboard/stats")
    data = resp.json()
    actions = {a["action"]: a["count"] for a in data["action_counts"]}
    assert actions.get("BLOCK", 0) >= 1
    assert actions.get("ALLOW", 0) >= 1


@pytest.mark.asyncio
async def test_stats_severity_counts(client):
    await client.post("/api/v1/scan", json={"content": "AKIAIOSFODNN7EXAMPLE"})

    resp = await client.get("/api/v1/dashboard/stats")
    data = resp.json()
    assert len(data["severity_counts"]) >= 1


@pytest.mark.asyncio
async def test_stats_top_finding_types(client):
    await client.post("/api/v1/scan", json={"content": "AKIAIOSFODNN7EXAMPLE"})

    resp = await client.get("/api/v1/dashboard/stats")
    data = resp.json()
    assert len(data["top_finding_types"]) >= 1
    assert data["top_finding_types"][0]["count"] >= 1


# ── GET /api/v1/dashboard/policy ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_policy_endpoint(client):
    resp = await client.get("/api/v1/dashboard/policy")
    assert resp.status_code == 200
    data = resp.json()
    assert "default_action" in data
    assert "redaction" in data
    assert "severity_overrides" in data
    assert "destination_rules" in data
    assert "agent_rules" in data
    assert "custom_patterns" in data


@pytest.mark.asyncio
async def test_policy_default_action_is_block(client):
    resp = await client.get("/api/v1/dashboard/policy")
    data = resp.json()
    assert data["default_action"] == "BLOCK"


@pytest.mark.asyncio
async def test_policy_redaction_config(client):
    resp = await client.get("/api/v1/dashboard/policy")
    data = resp.json()
    assert data["redaction"]["strategy"] == "mask"
    assert data["redaction"]["mask_char"] == "*"
    assert data["redaction"]["mask_preserve_edges"] == 4


# ── GET /api/v1/dashboard/patterns ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_patterns_endpoint(client):
    resp = await client.get("/api/v1/dashboard/patterns")
    assert resp.status_code == 200
    data = resp.json()
    assert "secrets" in data
    assert "pii" in data
    assert "custom" in data


@pytest.mark.asyncio
async def test_patterns_secrets_populated(client):
    resp = await client.get("/api/v1/dashboard/patterns")
    data = resp.json()
    secrets = data["secrets"]
    assert len(secrets) > 40  # We have 51 secret patterns
    # Check structure
    entry = secrets[0]
    assert "name" in entry
    assert "severity" in entry
    assert "category" in entry
    assert "description" in entry


@pytest.mark.asyncio
async def test_patterns_pii_populated(client):
    resp = await client.get("/api/v1/dashboard/patterns")
    data = resp.json()
    pii = data["pii"]
    assert len(pii) == 10  # We have 10 PII patterns
    names = [p["name"] for p in pii]
    assert "ssn" in names
    assert "email" in names


@pytest.mark.asyncio
async def test_patterns_have_descriptions(client):
    resp = await client.get("/api/v1/dashboard/patterns")
    data = resp.json()
    for entry in data["secrets"]:
        assert entry["description"], f"Missing description for {entry['name']}"
    for entry in data["pii"]:
        assert entry["description"], f"Missing description for {entry['name']}"


@pytest.mark.asyncio
async def test_patterns_categories(client):
    resp = await client.get("/api/v1/dashboard/patterns")
    data = resp.json()
    secret_categories = {e["category"] for e in data["secrets"]}
    assert "Cloud" in secret_categories
    assert "Version Control" in secret_categories
    assert "Payment" in secret_categories
    assert "Private Keys" in secret_categories

    pii_categories = {e["category"] for e in data["pii"]}
    assert "SSN" in pii_categories
    assert "Credit Cards" in pii_categories
    assert "Email" in pii_categories


@pytest.mark.asyncio
async def test_patterns_custom_empty_by_default(client):
    resp = await client.get("/api/v1/dashboard/patterns")
    data = resp.json()
    assert data["custom"] == []


# ── PUT /api/v1/policy ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_put_policy_saves_and_returns(client):
    resp = await client.put("/api/v1/policy", json={
        "default_action": "ALLOW",
        "redaction": {"strategy": "hash", "mask_char": "#", "mask_preserve_edges": 2},
        "severity_overrides": [{"severity": "CRITICAL", "action": "BLOCK"}],
        "destination_allowlist": ["*.trusted.com"],
        "destination_blocklist": ["*.evil.com"],
        "destination_rules": [{"pattern": "api.*", "action": "REDACT", "scanners": ["SECRET"]}],
        "agent_rules": [{"agent_id": "bot-1", "action": "ALLOW", "allowed_destinations": ["safe.io"]}],
        "custom_patterns": [{"name": "test_pat", "regex": "TEST-\\d+", "severity": "HIGH"}],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["default_action"] == "ALLOW"
    assert data["redaction"]["strategy"] == "hash"
    assert data["redaction"]["mask_char"] == "#"
    assert data["redaction"]["mask_preserve_edges"] == 2
    assert len(data["severity_overrides"]) == 1
    assert data["destination_allowlist"] == ["*.trusted.com"]
    assert data["destination_blocklist"] == ["*.evil.com"]
    assert len(data["destination_rules"]) == 1
    assert len(data["agent_rules"]) == 1
    assert len(data["custom_patterns"]) == 1
    assert data["custom_patterns"][0]["name"] == "test_pat"


@pytest.mark.asyncio
async def test_put_policy_invalid_data_returns_422(client):
    resp = await client.put("/api/v1/policy", json={
        "default_action": "INVALID_ACTION",
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_put_policy_updates_custom_patterns_and_redaction(client):
    # Update policy with custom pattern and new redaction config
    await client.put("/api/v1/policy", json={
        "default_action": "REDACT",
        "redaction": {"strategy": "remove", "mask_char": "*", "mask_preserve_edges": 0},
        "custom_patterns": [{"name": "project_id", "regex": "PROJ-\\d{4}", "severity": "MEDIUM"}],
    })

    # Verify scanning picks up the custom pattern
    scan_resp = await client.post("/api/v1/scan", json={"content": "See PROJ-1234 for details"})
    scan_data = scan_resp.json()
    assert scan_data["action"] == "REDACT"
    assert scan_data["findings_count"] >= 1
    custom_findings = [f for f in scan_data["findings"] if f["finding_type"] == "project_id"]
    assert len(custom_findings) == 1


@pytest.mark.asyncio
async def test_put_policy_round_trip(client):
    policy = {
        "default_action": "REDACT",
        "redaction": {"strategy": "mask", "mask_char": "X", "mask_preserve_edges": 3},
        "severity_overrides": [{"severity": "HIGH", "action": "BLOCK"}],
        "destination_allowlist": ["*.safe.org"],
        "destination_blocklist": [],
        "destination_rules": [],
        "agent_rules": [],
        "custom_patterns": [],
    }
    put_resp = await client.put("/api/v1/policy", json=policy)
    assert put_resp.status_code == 200

    get_resp = await client.get("/api/v1/dashboard/policy")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["default_action"] == "REDACT"
    assert get_data["redaction"]["strategy"] == "mask"
    assert get_data["redaction"]["mask_char"] == "X"
    assert get_data["redaction"]["mask_preserve_edges"] == 3
    assert len(get_data["severity_overrides"]) == 1
    assert get_data["severity_overrides"][0]["severity"] == "HIGH"
    assert get_data["severity_overrides"][0]["action"] == "BLOCK"
    assert get_data["destination_allowlist"] == ["*.safe.org"]


# ── v0.2.0: Regex in pattern catalog ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_patterns_include_regex(client):
    """Pattern catalog entries should include a non-empty regex field."""
    resp = await client.get("/api/v1/dashboard/patterns")
    assert resp.status_code == 200
    data = resp.json()
    # Every secret pattern should have a regex string
    for entry in data["secrets"]:
        assert "regex" in entry
        assert isinstance(entry["regex"], str)
        assert len(entry["regex"]) > 0, f"Empty regex for {entry['name']}"
    # Every PII pattern should have a regex string
    for entry in data["pii"]:
        assert "regex" in entry
        assert len(entry["regex"]) > 0, f"Empty regex for {entry['name']}"


@pytest.mark.asyncio
async def test_patterns_custom_include_regex(client):
    """Custom patterns in catalog should include regex."""
    # First add a custom pattern via policy
    await client.put("/api/v1/policy", json={
        "default_action": "BLOCK",
        "custom_patterns": [{"name": "my_token", "regex": "TOK-[A-Z]+", "severity": "HIGH"}],
    })
    resp = await client.get("/api/v1/dashboard/patterns")
    data = resp.json()
    assert len(data["custom"]) == 1
    assert data["custom"][0]["regex"] == "TOK-[A-Z]+"


# ── v0.2.0: Version ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_version_is_020(client):
    """Health endpoint should report version 0.2.0."""
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] == "0.2.0"


# ── v0.2.0: Disabled patterns ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_disabled_patterns_in_policy(client):
    """disabled_patterns should appear in policy response."""
    resp = await client.get("/api/v1/dashboard/policy")
    data = resp.json()
    assert "disabled_patterns" in data
    assert data["disabled_patterns"] == []


@pytest.mark.asyncio
async def test_disabled_patterns_skips_secret_detection(client):
    """Disabling aws_access_key_id should prevent detection of AWS keys."""
    # First verify detection works
    scan1 = await client.post("/api/v1/scan", json={"content": "AKIAIOSFODNN7EXAMPLE"})
    findings1 = [f for f in scan1.json()["findings"] if f["finding_type"] == "aws_access_key_id"]
    assert len(findings1) >= 1

    # Disable the pattern
    await client.put("/api/v1/policy", json={
        "default_action": "BLOCK",
        "disabled_patterns": ["aws_access_key_id"],
    })

    # Now it should not be detected
    scan2 = await client.post("/api/v1/scan", json={"content": "AKIAIOSFODNN7EXAMPLE"})
    findings2 = [f for f in scan2.json()["findings"] if f["finding_type"] == "aws_access_key_id"]
    assert len(findings2) == 0


@pytest.mark.asyncio
async def test_disabled_patterns_skips_pii_detection(client):
    """Disabling ssn should prevent SSN detection."""
    # First verify detection works
    scan1 = await client.post("/api/v1/scan", json={"content": "SSN: 123-45-6789"})
    findings1 = [f for f in scan1.json()["findings"] if f["finding_type"] == "ssn"]
    assert len(findings1) >= 1

    # Disable the pattern
    await client.put("/api/v1/policy", json={
        "default_action": "BLOCK",
        "disabled_patterns": ["ssn"],
    })

    # Now it should not be detected
    scan2 = await client.post("/api/v1/scan", json={"content": "SSN: 123-45-6789"})
    findings2 = [f for f in scan2.json()["findings"] if f["finding_type"] == "ssn"]
    assert len(findings2) == 0


@pytest.mark.asyncio
async def test_disabled_patterns_round_trip(client):
    """disabled_patterns should survive save and reload."""
    await client.put("/api/v1/policy", json={
        "default_action": "BLOCK",
        "disabled_patterns": ["ssn", "email"],
    })
    resp = await client.get("/api/v1/dashboard/policy")
    data = resp.json()
    assert set(data["disabled_patterns"]) == {"ssn", "email"}


# ── v0.2.0: Dashboard HTML enhancements ──────────────────────────────────────


@pytest.mark.asyncio
async def test_dashboard_html_has_help_banners(client):
    """Dashboard HTML should include help banners for each tab."""
    resp = await client.get("/dashboard")
    text = resp.text
    assert "help-overview" in text
    assert "help-history" in text
    assert "help-policies" in text
    assert "help-scanner" in text
    assert "help-patterns" in text


@pytest.mark.asyncio
async def test_dashboard_html_has_hide_test_scans(client):
    """Dashboard HTML should include the hide-test-scans checkbox."""
    resp = await client.get("/dashboard")
    assert "hide-test-scans" in resp.text


@pytest.mark.asyncio
async def test_dashboard_html_has_test_agent_id(client):
    """Dashboard HTML should reference __dashboard_test__ agent_id."""
    resp = await client.get("/dashboard")
    assert "__dashboard_test__" in resp.text


@pytest.mark.asyncio
async def test_dashboard_html_has_pattern_toggle(client):
    """Dashboard JS should include pattern-toggle class for enable/disable."""
    resp = await client.get("/dashboard")
    assert "pattern-toggle" in resp.text


@pytest.mark.asyncio
async def test_dashboard_html_has_catalog_custom_crud(client):
    """Dashboard HTML should include custom pattern CRUD elements."""
    resp = await client.get("/dashboard")
    assert "catalog-cp-add-btn" in resp.text
    assert "catalog-custom-del" in resp.text or "catalog-cp-name" in resp.text
