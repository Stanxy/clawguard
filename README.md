# ClawGuard

**DLP Surveillance Layer for OpenClaw** -- scans outbound content for secrets, PII, and policy violations before it leaves the machine.

ClawGuard sits between AI agents and the outside world. Every outbound tool call is intercepted, scanned against 60+ detection patterns, and either allowed, blocked, or redacted according to configurable policy.

## Features

- **Secret Detection** -- 51 regex patterns covering AWS, GCP, Azure, GitHub, Stripe, Slack, private keys, database URIs, and more
- **PII Detection** -- SSNs, credit cards (Visa/MC/Amex/Discover with Luhn validation), emails, phone numbers, IP addresses
- **Entropy Analysis** -- catches high-entropy strings that don't match known patterns
- **Custom Patterns** -- define your own regex patterns with severity levels
- **Policy Engine** -- per-severity, per-destination, and per-agent rules with allowlists and blocklists
- **Three Actions** -- `BLOCK` (reject), `REDACT` (mask/hash/remove sensitive data), `ALLOW` (pass through)
- **Audit Log** -- every scan is recorded with findings, action taken, and duration (never stores raw content)
- **Dashboard** -- built-in web UI for monitoring, policy editing, pattern browsing, and ad-hoc testing
- **OpenClaw Integration** -- plugin hooks into `before_tool_call`; skill teaches agents DLP awareness

## Quick Start

### Prerequisites

- Python 3.10+
- [Poetry](https://python-poetry.org/) 2.0+

### Install & Run

```bash
git clone https://github.com/Stanxy/clawguard.git
cd clawguard
poetry install
poetry run python -m clawguard
```

The service starts on `http://localhost:8642`. Open `http://localhost:8642/dashboard` for the web UI.

### Configuration

All settings can be overridden with environment variables prefixed `CLAWGUARD_`:

| Variable | Default | Description |
|---|---|---|
| `CLAWGUARD_HOST` | `0.0.0.0` | Bind address |
| `CLAWGUARD_PORT` | `8642` | Port |
| `CLAWGUARD_DATABASE_URL` | `sqlite+aiosqlite:///clawguard.db` | Database connection string |
| `CLAWGUARD_POLICY_PATH` | `config/default_policy.yaml` | Path to YAML policy file |
| `CLAWGUARD_LOG_LEVEL` | `INFO` | Log level |
| `CLAWGUARD_DEBUG` | `false` | Debug mode |

## API

All endpoints live under `/api/v1/`.

### Scan Content

```
POST /api/v1/scan
```

```json
{
  "content": "My AWS key is AKIAIOSFODNN7EXAMPLE",
  "destination": "api.example.com",
  "agent_id": "agent-1"
}
```

Response:

```json
{
  "action": "BLOCK",
  "content": null,
  "findings": [
    {
      "scanner_type": "SECRET",
      "finding_type": "aws_access_key_id",
      "severity": "CRITICAL",
      "start": 14,
      "end": 34,
      "redacted_snippet": "AKIA************MPLE"
    }
  ],
  "findings_count": 1,
  "scan_id": 1,
  "duration_ms": 2.45
}
```

### Other Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Service health and version |
| `GET` | `/api/v1/audit` | Query audit log (supports `agent_id`, `destination`, `action`, `limit`, `offset` filters) |
| `GET` | `/api/v1/dashboard/stats` | Scan statistics and recent activity |
| `GET` | `/api/v1/dashboard/policy` | Current policy as JSON |
| `GET` | `/api/v1/dashboard/patterns` | Full pattern catalog with regex |
| `PUT` | `/api/v1/policy` | Update policy (takes full PolicyConfig JSON) |
| `POST` | `/api/v1/policy/reload` | Reload policy from disk |
| `GET` | `/dashboard` | Web dashboard UI |

## Policy

Policies are YAML files. The default policy blocks all content with findings:

```yaml
default_action: BLOCK
redaction:
  strategy: mask        # mask | hash | remove
  mask_char: "*"
  mask_preserve_edges: 4
severity_overrides: []
destination_allowlist: []
destination_blocklist: []
destination_rules: []
agent_rules: []
custom_patterns: []
disabled_patterns: []
```

### Policy Evaluation Order

1. **Severity overrides** -- e.g., always block CRITICAL findings
2. **Destination allowlist** -- trusted destinations bypass scanning
3. **Destination blocklist** -- blocked destinations are always rejected
4. **Destination rules** -- per-destination action and scanner selection
5. **Agent rules** -- per-agent action with allowed/blocked destination lists
6. **Default action** -- fallback when no rules match

### Custom Patterns

Add regex patterns directly in the policy:

```yaml
custom_patterns:
  - name: internal_project_id
    regex: "PROJ-\\d{4,}"
    severity: MEDIUM
```

### Disabling Built-in Patterns

Disable specific built-in patterns by name:

```yaml
disabled_patterns:
  - email
  - ipv4_address
```

## Dashboard

The web dashboard at `/dashboard` provides five tabs:

- **Overview** -- service health, scan stats, top finding types, recent scans
- **Scan History** -- filterable audit log with expandable finding details; test scans can be hidden
- **Policies** -- live policy editor with save/reload
- **Test Scanner** -- scan content ad-hoc without affecting production audit trail (tagged as `__dashboard_test__`)
- **Pattern Catalog** -- browse all 61+ patterns with regex, toggle built-in patterns on/off, manage custom patterns

## OpenClaw Integration

### Plugin

The `openclaw-integration/clawguard-plugin/` directory contains a TypeScript plugin that hooks into OpenClaw's `before_tool_call` lifecycle:

```bash
cd openclaw-integration/clawguard-plugin
npm install
npm run build
```

Configure in your OpenClaw setup:

```json
{
  "serviceUrl": "http://127.0.0.1:8642",
  "blockOnError": false,
  "timeoutMs": 5000
}
```

### Skill

The `openclaw-integration/clawguard-skill/SKILL.md` file teaches LLM agents about DLP best practices -- what ClawGuard monitors, how to handle blocked tool calls, and how to avoid triggering false positives.

## Architecture

```
                  OpenClaw Agent
                       |
                       v
              [ClawGuard Plugin]     (before_tool_call hook)
                       |
                  POST /api/v1/scan
                       |
                       v
               +---------------+
               |   FastAPI App |
               +-------+-------+
                       |
          +------------+------------+
          |            |            |
    SecretScanner  PIIScanner  CustomScanner
          |            |            |
          +-----+------+------+----+
                |             |
          PolicyEngine    Redactor
                |
          ActionHandler
                |
        AuditRepository (SQLite)
```

## Development

### Running Tests

```bash
poetry install --with dev
poetry run pytest
```

The test suite includes 142 tests covering scanners, policy engine, redaction, API endpoints, and the dashboard.

### Project Structure

```
clawguard/
  config/                    # Default policy YAML
  openclaw-integration/      # OpenClaw plugin + skill
  src/clawguard/
    api/                     # FastAPI route handlers
    dashboard/               # HTML dashboard (single-page)
    db/                      # SQLAlchemy models + audit repository
    engine/                  # Policy engine, action handler, redactor
    models/                  # Pydantic models (scan, policy, audit, dashboard)
    scanners/                # Secret, PII, and custom scanners
      patterns/              # Compiled regex pattern definitions
    utils/                   # Entropy analysis, hashing
  tests/                     # pytest async test suite
```

## License

MIT -- see [LICENSE](LICENSE).
