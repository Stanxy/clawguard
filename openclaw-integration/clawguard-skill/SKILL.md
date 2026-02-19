---
name: clawguard
version: 0.2.1
description: "DLP surveillance layer for OpenClaw — prevents AI agents from leaking secrets, PII, and sensitive data through outbound tool calls. 51 secret patterns, PII detection with Luhn validation, entropy analysis, configurable policy engine, audit log, and web dashboard."
author: Stanxy
---

# ClawGuard — DLP Surveillance Layer for OpenClaw

**GitHub:** https://github.com/Stanxy/clawguard

ClawGuard sits between AI agents and the outside world. Every outbound tool call is intercepted, scanned against 60+ detection patterns, and either allowed, blocked, or redacted according to configurable policy — before anything leaves the machine.

## Installation

### Prerequisites

- Python 3.10+
- [Poetry](https://python-poetry.org/) 2.0+

### 1. Install & Start the ClawGuard Service

```bash
git clone https://github.com/Stanxy/clawguard.git
cd clawguard
poetry install
poetry run python -m clawguard
```

The service starts on **http://localhost:8642**.
Open **http://localhost:8642/dashboard** for the web UI.

### 2. Install the OpenClaw Plugin

The plugin hooks into OpenClaw's `before_tool_call` lifecycle — every outbound tool call is automatically scanned.

```bash
cd openclaw-integration/clawguard-plugin
npm install
npm run build
```

Then register the plugin in your OpenClaw config:

```json
{
  "plugins": {
    "clawguard": {
      "path": "./openclaw-integration/clawguard-plugin/dist/index.js",
      "config": {
        "serviceUrl": "http://127.0.0.1:8642",
        "blockOnError": false,
        "timeoutMs": 5000
      }
    }
  }
}
```

### 3. (Optional) Install this Skill

This skill file teaches the agent DLP best practices — what ClawGuard monitors and how to handle blocked calls.

```bash
clawhub install stanxy-clawguard
```

## Configuration

All settings can be overridden with environment variables prefixed `CLAWGUARD_`:

| Variable | Default | Description |
|---|---|---|
| `CLAWGUARD_HOST` | `0.0.0.0` | Bind address |
| `CLAWGUARD_PORT` | `8642` | Port |
| `CLAWGUARD_DATABASE_URL` | `sqlite+aiosqlite:///clawguard.db` | Database connection |
| `CLAWGUARD_POLICY_PATH` | `config/default_policy.yaml` | Policy file path |
| `CLAWGUARD_LOG_LEVEL` | `INFO` | Log verbosity |

## What ClawGuard Detects

- **Secrets (51 patterns):** AWS, GCP, Azure, GitHub, Stripe, Slack, PayPal, Square, SSH/PGP private keys, database URIs, JWT tokens, and more
- **PII (10 patterns):** SSNs, credit cards (Visa/MC/Amex/Discover with Luhn validation), emails, phone numbers, IP addresses
- **Entropy Analysis:** catches high-entropy strings that don't match any known pattern
- **Custom Patterns:** define your own regex patterns with severity levels via the dashboard or policy YAML

## Policy

The default policy YAML is at `config/default_policy.yaml`. Edit via the dashboard or directly:

```yaml
default_action: BLOCK        # BLOCK | REDACT | ALLOW
redaction:
  strategy: mask             # mask | hash | remove
  mask_char: "*"
  mask_preserve_edges: 4
severity_overrides: []
destination_allowlist: []    # trusted destinations bypass scanning
destination_blocklist: []    # always reject these destinations
custom_patterns: []
disabled_patterns: []        # disable specific built-in patterns by name
```

### Quick Start: Scan Content via API

```bash
curl -s -X POST http://localhost:8642/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "My AWS key is AKIAIOSFODNN7EXAMPLE", "destination": "api.example.com"}'
```

Response:
```json
{
  "action": "BLOCK",
  "findings": [
    {
      "finding_type": "aws_access_key_id",
      "severity": "CRITICAL",
      "redacted_snippet": "AKIA************MPLE"
    }
  ],
  "duration_ms": 2.45
}
```

## Agent Instructions

You are operating in an environment protected by **ClawGuard**. All outbound tool calls are automatically scanned before leaving the machine.

### Scan Results

| Action | Meaning |
|--------|---------|
| `ALLOW` | Content is clean — no sensitive data detected |
| `REDACT` | Sensitive portions were masked before sending |
| `BLOCK` | Tool call rejected — sensitive data found, nothing was sent |

### Best Practices

- Never include raw API keys, tokens, credentials, or PII in outbound messages or tool calls
- Use environment variable names (e.g., `$OPENAI_API_KEY`) instead of literal values
- Refer to credentials by name ("the Stripe key"), not by value
- Do not attempt to encode or obfuscate secrets to bypass detection

### When a Tool Call is Blocked

1. Check `findings` in the response to see what was detected
2. Remove or replace the sensitive data
3. Retry the tool call with clean content
4. If you believe it's a false positive, tell the user so they can adjust the policy via the dashboard at http://localhost:8642/dashboard
