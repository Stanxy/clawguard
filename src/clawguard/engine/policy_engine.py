from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

import yaml

from clawguard.models.enums import Action, ScannerType, Severity
from clawguard.models.policy import PolicyConfig
from clawguard.scanners.base import Finding


_SEV_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


@dataclass
class PolicyDecision:
    action: Action
    suggested_action: Action | None = None


class PolicyEngine:
    """Loads YAML policy and evaluates findings to produce an action decision."""

    def __init__(self, policy: PolicyConfig | None = None) -> None:
        self._policy = policy or PolicyConfig()

    @property
    def policy(self) -> PolicyConfig:
        return self._policy

    def load_from_file(self, path: str | Path) -> None:
        path = Path(path)
        if not path.exists():
            self._policy = PolicyConfig()
            return
        with open(path) as f:
            raw = yaml.safe_load(f)
        if raw is None:
            self._policy = PolicyConfig()
            return
        self._policy = PolicyConfig.model_validate(raw)

    def save_to_file(self, path: str | Path, policy: PolicyConfig) -> None:
        path = Path(path)
        data = policy.model_dump(mode="json")
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
        self._policy = policy

    def reload(self, path: str | Path) -> None:
        self.load_from_file(path)

    def evaluate(
        self,
        findings: list[Finding],
        destination: str | None = None,
        agent_id: str | None = None,
    ) -> Action:
        """Evaluate findings against policy. Returns the strictest action.

        Priority:
        1. Severity overrides (CRITICAL always blocks)
        2. Destination allowlist/blocklist
        3. Destination-specific rules
        4. Agent-specific rules
        5. Global default
        """
        # If no findings, allow
        if not findings:
            return Action.ALLOW

        # 1. Severity overrides
        for override in self._policy.severity_overrides:
            if any(f.severity == override.severity for f in findings):
                return Action(override.action.value)

        # 2. Destination allowlist — trusted destinations bypass
        if destination and self._policy.destination_allowlist:
            for pattern in self._policy.destination_allowlist:
                if fnmatch.fnmatch(destination, pattern):
                    return Action.ALLOW

        # 2b. Destination blocklist
        if destination and self._policy.destination_blocklist:
            for pattern in self._policy.destination_blocklist:
                if fnmatch.fnmatch(destination, pattern):
                    return Action.BLOCK

        # 3. Destination-specific rules
        if destination:
            for rule in self._policy.destination_rules:
                if fnmatch.fnmatch(destination, rule.pattern):
                    return Action(rule.action.value)

        # 4. Agent-specific rules
        if agent_id:
            for rule in self._policy.agent_rules:
                if rule.agent_id == agent_id:
                    # Check if destination is in the agent's allowed list
                    if destination and rule.allowed_destinations:
                        if any(fnmatch.fnmatch(destination, p) for p in rule.allowed_destinations):
                            return Action(rule.action.value) if rule.action else Action.ALLOW
                    if destination and rule.blocked_destinations:
                        if any(fnmatch.fnmatch(destination, p) for p in rule.blocked_destinations):
                            return Action.BLOCK
                    if rule.action:
                        return Action(rule.action.value)

        # 5. Global default
        return Action(self._policy.default_action.value)

    def evaluate_with_prompt(
        self,
        findings: list[Finding],
        destination: str | None = None,
        agent_id: str | None = None,
    ) -> PolicyDecision:
        """Evaluate findings, then upgrade to PROMPT if any finding >= threshold."""
        base_action = self.evaluate(findings, destination, agent_id)
        if not findings or base_action == Action.ALLOW:
            return PolicyDecision(action=base_action)
        threshold = self._policy.prompt_threshold
        if threshold is None:
            return PolicyDecision(action=base_action)
        max_sev = max(_SEV_ORDER[f.severity] for f in findings)
        if max_sev >= _SEV_ORDER[threshold]:
            return PolicyDecision(action=Action.PROMPT, suggested_action=base_action)
        return PolicyDecision(action=base_action)

    def get_scanners_for_destination(self, destination: str | None) -> list[ScannerType] | None:
        """Return scanner types to run for a destination, or None for all."""
        if destination is None:
            return None
        for rule in self._policy.destination_rules:
            if fnmatch.fnmatch(destination, rule.pattern) and rule.scanners:
                return [ScannerType(s) for s in rule.scanners]
        return None
