from __future__ import annotations

import pytest

from clawguard.engine.policy_engine import PolicyEngine
from clawguard.models.enums import Action, ScannerType, Severity
from clawguard.models.policy import (
    AgentRule,
    DestinationRule,
    PolicyConfig,
    SeverityOverride,
)
from clawguard.scanners.base import Finding


def _make_finding(severity: Severity = Severity.HIGH, scanner_type=ScannerType.SECRET) -> Finding:
    return Finding(
        scanner_type=scanner_type,
        finding_type="test",
        severity=severity,
        matched_text="secret",
        start=0,
        end=6,
    )


class TestDefaultBehavior:
    def test_no_findings_allows(self):
        engine = PolicyEngine()
        assert engine.evaluate([]) == Action.ALLOW

    def test_findings_use_default_action(self):
        engine = PolicyEngine(PolicyConfig(default_action=Action.BLOCK))
        assert engine.evaluate([_make_finding()]) == Action.BLOCK

    def test_default_action_redact(self):
        engine = PolicyEngine(PolicyConfig(default_action=Action.REDACT))
        assert engine.evaluate([_make_finding()]) == Action.REDACT


class TestSeverityOverrides:
    def test_critical_blocks(self):
        policy = PolicyConfig(
            default_action=Action.REDACT,
            severity_overrides=[SeverityOverride(severity=Severity.CRITICAL, action=Action.BLOCK)],
        )
        engine = PolicyEngine(policy)
        assert engine.evaluate([_make_finding(Severity.CRITICAL)]) == Action.BLOCK

    def test_non_critical_falls_through(self):
        policy = PolicyConfig(
            default_action=Action.REDACT,
            severity_overrides=[SeverityOverride(severity=Severity.CRITICAL, action=Action.BLOCK)],
        )
        engine = PolicyEngine(policy)
        assert engine.evaluate([_make_finding(Severity.MEDIUM)]) == Action.REDACT


class TestDestinationAllowBlockList:
    def test_allowlist_bypasses(self):
        policy = PolicyConfig(
            default_action=Action.BLOCK,
            destination_allowlist=["*.internal.corp"],
        )
        engine = PolicyEngine(policy)
        assert engine.evaluate([_make_finding()], destination="api.internal.corp") == Action.ALLOW

    def test_blocklist_blocks(self):
        policy = PolicyConfig(
            default_action=Action.ALLOW,
            destination_blocklist=["*.pastebin.com"],
        )
        engine = PolicyEngine(policy)
        assert engine.evaluate([_make_finding()], destination="www.pastebin.com") == Action.BLOCK


class TestDestinationRules:
    def test_destination_specific_action(self):
        policy = PolicyConfig(
            default_action=Action.BLOCK,
            destination_rules=[DestinationRule(pattern="api.openai.com", action=Action.REDACT)],
        )
        engine = PolicyEngine(policy)
        assert engine.evaluate([_make_finding()], destination="api.openai.com") == Action.REDACT

    def test_no_matching_destination_uses_default(self):
        policy = PolicyConfig(
            default_action=Action.BLOCK,
            destination_rules=[DestinationRule(pattern="api.openai.com", action=Action.REDACT)],
        )
        engine = PolicyEngine(policy)
        assert engine.evaluate([_make_finding()], destination="other.com") == Action.BLOCK


class TestAgentRules:
    def test_agent_specific_action(self):
        policy = PolicyConfig(
            default_action=Action.BLOCK,
            agent_rules=[AgentRule(agent_id="trusted-bot", action=Action.ALLOW)],
        )
        engine = PolicyEngine(policy)
        assert engine.evaluate([_make_finding()], agent_id="trusted-bot") == Action.ALLOW

    def test_agent_allowed_destination(self):
        policy = PolicyConfig(
            default_action=Action.BLOCK,
            agent_rules=[
                AgentRule(
                    agent_id="deploy-bot",
                    action=Action.ALLOW,
                    allowed_destinations=["*.internal.corp"],
                )
            ],
        )
        engine = PolicyEngine(policy)
        assert engine.evaluate(
            [_make_finding()], agent_id="deploy-bot", destination="api.internal.corp"
        ) == Action.ALLOW

    def test_agent_blocked_destination(self):
        policy = PolicyConfig(
            default_action=Action.ALLOW,
            agent_rules=[
                AgentRule(
                    agent_id="deploy-bot",
                    blocked_destinations=["*.evil.com"],
                )
            ],
        )
        engine = PolicyEngine(policy)
        assert engine.evaluate(
            [_make_finding()], agent_id="deploy-bot", destination="api.evil.com"
        ) == Action.BLOCK


class TestScannerSelection:
    def test_returns_scanners_for_destination(self):
        policy = PolicyConfig(
            destination_rules=[
                DestinationRule(
                    pattern="api.openai.com",
                    action=Action.REDACT,
                    scanners=["SECRET", "PII"],
                )
            ],
        )
        engine = PolicyEngine(policy)
        result = engine.get_scanners_for_destination("api.openai.com")
        assert result == [ScannerType.SECRET, ScannerType.PII]

    def test_returns_none_for_unknown_destination(self):
        engine = PolicyEngine()
        assert engine.get_scanners_for_destination("unknown.com") is None


class TestLoadFromFile:
    def test_load_default_policy(self, tmp_path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("default_action: REDACT\n")
        engine = PolicyEngine()
        engine.load_from_file(policy_file)
        assert engine.policy.default_action == Action.REDACT

    def test_load_missing_file(self, tmp_path):
        engine = PolicyEngine()
        engine.load_from_file(tmp_path / "nonexistent.yaml")
        assert engine.policy.default_action == Action.BLOCK  # default
