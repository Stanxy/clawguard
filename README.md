```
  ██████╗██╗      █████╗ ██╗    ██╗██╗    ██╗ █████╗ ██╗     ██╗
 ██╔════╝██║     ██╔══██╗██║    ██║██║    ██║██╔══██╗██║     ██║
 ██║     ██║     ███████║██║ █╗ ██║██║ █╗ ██║███████║██║     ██║
 ██║     ██║     ██╔══██║██║███╗██║██║███╗██║██╔══██║██║     ██║
 ╚██████╗███████╗██║  ██║╚███╔███╔╝╚███╔███╔╝██║  ██║███████╗███████╗
  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
```

**Outbound DLP for AI agents — 60+ regex patterns block secrets & PII before anything leaves the machine.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![PyPI](https://img.shields.io/pypi/v/clawwall)](https://pypi.org/project/clawwall)

---

## How It Works

```
  ┌─────────────┐
  │  AI  Agent   │
  └──────┬───────┘
         │  outbound tool call
         ▼
  ┌──────────────┐     ┌─────────────────────────────────────┐
  │  OpenClaw    │     │         ClawWall Service             │
  │  Plugin      │────▶│                                     │
  │              │     │  ┌───────┐ ┌─────┐ ┌────────┐      │
  │before_tool   │     │  │Secret │ │ PII │ │Custom  │      │
  │  _call       │     │  │Scanner│ │Scan.│ │Scanner │      │
  └──────────────┘     │  └───┬───┘ └──┬──┘ └───┬────┘      │
                       │      └────────┼────────┘            │
                       │               ▼                     │
                       │        ┌─────────────┐              │
                       │        │Policy Engine│              │
                       │        └──────┬──────┘              │
                       │               ▼                     │
                       │     ┌───────────────────┐           │
                       │     │  ALLOW │REDACT│BLOCK│          │
                       │     └───────────────────┘           │
                       │               │                     │
                       │        ┌──────┴──────┐              │
                       │        │ Audit Log   │              │
                       │        │  (SQLite)   │              │
                       │        └─────────────┘              │
                       └─────────────────────────────────────┘
         │
         ▼
  ┌──────────────┐
  │  External    │   Only if ALLOW or REDACT
  │  Service     │
  └──────────────┘
```

Every outbound tool call is intercepted by the plugin, scanned against 60+ regex patterns plus entropy analysis, and then either **allowed**, **redacted** (sensitive parts masked), or **blocked** (nothing sent). No LLM involved — pure pattern matching.

---

## Quick Start

### As an OpenClaw Skill (recommended)

One command installs everything:

```bash
# Install the skill
clawhub install clawwall

# Run setup
cd ~/.openclaw/skills/clawwall
bash setup.sh
```

The `gateway:startup` hook auto-starts the service whenever OpenClaw boots.

### Standalone

```bash
# Install from PyPI
pip install clawwall

# Start the service
clawwall
```

Service runs on `http://localhost:8642`. Dashboard at `http://localhost:8642/dashboard`.

### From Source

```bash
git clone https://github.com/Stanxy/clawguard.git
cd clawguard
poetry install
poetry run python -m clawguard
```

---

## Dashboard

The web dashboard at `http://localhost:8642/dashboard` provides five tabs:

### Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  ClawWall Dashboard                           ● Service: OK     │
├────────┬──────────┬───────────┬──────────┬──────────────────────┤
│Overview│ History  │ Policies  │ Scanner  │ Pattern Catalog      │
├────────┴──────────┴───────────┴──────────┴──────────────────────┤
│                                                                 │
│  Total Scans     Blocked     Redacted     Allowed               │
│  ┌────────┐     ┌────────┐  ┌────────┐   ┌────────┐            │
│  │  1,247 │     │    83  │  │   401  │   │   763  │            │
│  └────────┘     └────────┘  └────────┘   └────────┘            │
│                                                                 │
│  Top Finding Types               Recent Scans                   │
│  ┌───────────────────────┐      ┌──────────────────────────┐   │
│  │ aws_access_key_id  23 │      │ 14:32 BLOCK  api.gh.com │   │
│  │ jwt_token          18 │      │ 14:31 ALLOW  slack.com  │   │
│  │ email              12 │      │ 14:30 REDACT hooks.sl.. │   │
│  │ generic_secret      9 │      │ 14:29 ALLOW  api.com   │   │
│  └───────────────────────┘      └──────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Pattern Catalog

```
┌─────────────────────────────────────────────────────────────────┐
│ Pattern Catalog                          Total: 62 patterns     │
├─────────────────────────────────────────────────────────────────┤
│  Filter: [All Categories ▼]  [All Severities ▼]  [________]   │
│                                                                 │
│  ● aws_access_key_id       CRITICAL   cloud     AKIA[0-9A..   │
│  ● github_pat              CRITICAL   vcs       ghp_[0-9a..   │
│  ● stripe_secret_key       CRITICAL   payment   sk_live_[..   │
│  ● private_key_rsa         CRITICAL   key       -----BEGI..   │
│  ● jwt_token               HIGH       auth      eyJ[A-Za-..   │
│  ● ssn                     CRITICAL   pii       \b\d{3}-\..   │
│  ● credit_card_visa        CRITICAL   pii       \b4\d{3}[..   │
│  ○ email                   MEDIUM     pii       \b[A-Za-z..   │
│  ...                                                            │
└─────────────────────────────────────────────────────────────────┘
```

### Test Scanner

```
┌─────────────────────────────────────────────────────────────────┐
│ Test Scanner                                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Content:                                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ My API key is sk-ant-abc123xyz and my SSN is            │   │
│  │ 123-45-6789. Send to api.example.com                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Destination: [api.example.com     ]   [ Scan ]                │
│                                                                 │
│  Result: BLOCK — 2 findings                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ anthropic_api_key  CRITICAL  sk-ant-****23xyz           │   │
│  │ ssn                CRITICAL  123-**-6789                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Detection Coverage

### Secrets (52 patterns)

| Category | Patterns | Severity |
|----------|----------|----------|
| **Cloud: AWS** | `aws_access_key_id`, `aws_mws_key` | CRITICAL |
| **Cloud: GCP** | `gcp_api_key`, `gcp_service_account` | CRITICAL/HIGH |
| **Cloud: Azure** | `azure_storage_key`, `azure_connection_string` | CRITICAL |
| **VCS: GitHub** | `github_pat`, `github_fine_grained_pat`, `github_oauth`, `github_app_token`, `github_refresh_token` | CRITICAL/HIGH |
| **VCS: GitLab** | `gitlab_pat`, `gitlab_runner_token` | CRITICAL/HIGH |
| **Payment: Stripe** | `stripe_secret_key`, `stripe_publishable_key`, `stripe_restricted_key` | CRITICAL/HIGH |
| **Payment: Square** | `square_access_token`, `square_oauth` | CRITICAL |
| **Payment: PayPal** | `paypal_braintree` | CRITICAL |
| **Comms: Slack** | `slack_token`, `slack_webhook` | HIGH |
| **Comms: Discord** | `discord_bot_token`, `discord_webhook` | HIGH |
| **Comms: Telegram** | `telegram_bot_token` | HIGH |
| **Comms: Twilio** | `twilio_api_key` | HIGH |
| **Auth** | `jwt_token`, `bearer_token`, `basic_auth` | HIGH |
| **Private Keys** | `private_key_rsa`, `private_key_dsa`, `private_key_ec`, `private_key_openssh`, `private_key_pgp`, `private_key_generic`, `private_key_encrypted` | CRITICAL |
| **Database** | `postgres_uri`, `mysql_uri`, `mongodb_uri`, `redis_uri` | CRITICAL |
| **SaaS** | `openai_api_key`, `anthropic_api_key`, `npm_token`, `pypi_token`, `sendgrid_api_key`, `mailgun_api_key`, `mailchimp_api_key`, `heroku_api_key`, `datadog_api_key`, `shopify_access_token`, `shopify_shared_secret` | HIGH/MEDIUM |
| **Generic** | `password_in_url`, `generic_secret_assignment` | HIGH/MEDIUM |
| **Entropy** | High-entropy strings (Shannon > 4.5, length >= 20) | MEDIUM |

### PII (10 patterns)

| Pattern | Detection | Validation |
|---------|-----------|------------|
| `ssn` | XXX-XX-XXXX | Area code validation (rejects 000, 666, 900+) |
| `credit_card_visa` | 4XXX-XXXX-XXXX-XXXX | Luhn checksum |
| `credit_card_mastercard` | 51-55XX-XXXX-XXXX-XXXX | Luhn checksum |
| `credit_card_amex` | 34/37XX-XXXXXX-XXXXX | Luhn checksum |
| `credit_card_discover` | 6011/65XX-XXXX-XXXX-XXXX | Luhn checksum |
| `email` | user@domain.tld | Format validation |
| `phone_us` | +1-XXX-XXX-XXXX | US format |
| `phone_e164` | +XXXXXXXXXXX | E.164 international |
| `ipv4_address` | 0-255.0-255.0-255.0-255 | Octet range |
| `ipv6_address` | Full & shorthand notation | Hex format |

---

## Policy Reference

### Evaluation Order

```
  Incoming scan request
         │
         ▼
  ┌──────────────────┐     Match?
  │ Severity Override │────────────▶ Return override action
  └────────┬─────────┘
           │ no match
           ▼
  ┌──────────────────┐     Match?
  │ Dest. Allowlist  │────────────▶ ALLOW (skip scanning)
  └────────┬─────────┘
           │ no match
           ▼
  ┌──────────────────┐     Match?
  │ Dest. Blocklist  │────────────▶ BLOCK
  └────────┬─────────┘
           │ no match
           ▼
  ┌──────────────────┐     Match?
  │ Destination Rules│────────────▶ Return rule action
  └────────┬─────────┘
           │ no match
           ▼
  ┌──────────────────┐     Match?
  │   Agent Rules    │────────────▶ Return rule action
  └────────┬─────────┘
           │ no match
           ▼
  ┌──────────────────┐
  │  Default Action  │────────────▶ BLOCK / REDACT / ALLOW
  └──────────────────┘
```

### Example Policy

```yaml
default_action: REDACT
redaction:
  strategy: mask           # mask | hash | remove
  mask_char: "*"
  mask_preserve_edges: 4

# Severity-based overrides
severity_overrides:
  - severity: CRITICAL
    action: BLOCK          # Always block critical findings

# Trusted destinations bypass scanning entirely
destination_allowlist:
  - "internal.corp.com"
  - "*.trusted.dev"

# Blocked destinations are always rejected
destination_blocklist:
  - "pastebin.com"

# Per-destination rules
destination_rules:
  - pattern: "api.github.com"
    action: REDACT
    scanners: [SECRET]     # Only scan for secrets, not PII

# Per-agent rules
agent_rules:
  - agent_id: "deploy-bot"
    action: ALLOW
    allowed_destinations: ["*.internal.com"]

# Custom regex patterns
custom_patterns:
  - name: internal_project_id
    regex: "PROJ-\\d{4,}"
    severity: MEDIUM

# Disable specific built-in patterns
disabled_patterns:
  - email
  - ipv4_address
```

### Redaction Strategies

| Strategy | Example Input | Example Output |
|----------|--------------|----------------|
| `mask` | `AKIAIOSFODNN7EXAMPLE` | `AKIA************MPLE` |
| `hash` | `AKIAIOSFODNN7EXAMPLE` | `[REDACTED:sha256:a1b2]` |
| `remove` | `AKIAIOSFODNN7EXAMPLE` | `[REDACTED]` |

---

## Architecture

```
clawguard/
├── src/clawguard/
│   ├── api/                     # FastAPI route handlers
│   │   ├── scan.py              #   POST /api/v1/scan (main DLP endpoint)
│   │   ├── health.py            #   GET  /api/v1/health
│   │   ├── audit.py             #   GET  /api/v1/audit
│   │   ├── policy.py            #   PUT  /api/v1/policy, POST /policy/reload
│   │   └── dashboard_api.py     #   GET  /api/v1/dashboard/*
│   ├── dashboard/               # Single-page web UI
│   │   └── index.html           #   5 tabs: overview, history, policy, test, catalog
│   ├── db/                      # SQLAlchemy async ORM
│   │   ├── models.py            #   ScanEvent + FindingRecord tables
│   │   └── audit_repository.py  #   Audit log persistence
│   ├── engine/                  # Core DLP logic
│   │   ├── policy_engine.py     #   Multi-layer policy evaluation
│   │   ├── action_handler.py    #   ALLOW/BLOCK/REDACT dispatch
│   │   └── redactor.py          #   Content redaction (mask/hash/remove)
│   ├── scanners/                # Pattern matching
│   │   ├── secret_scanner.py    #   52 secret patterns + entropy
│   │   ├── pii_scanner.py       #   10 PII patterns with validators
│   │   ├── custom_scanner.py    #   User-defined regex from policy
│   │   └── patterns/            #   Compiled regex definitions
│   └── models/                  # Pydantic models
│       ├── scan.py              #   ScanRequest, ScanResponse
│       ├── policy.py            #   PolicyConfig, rules
│       ├── audit.py             #   AuditEntry, AuditFinding
│       └── enums.py             #   Action, Severity, ScannerType
├── openclaw-integration/
│   ├── clawguard-skill/         # OpenClaw skill package
│   │   ├── SKILL.md             #   Skill definition & agent instructions
│   │   ├── setup.sh             #   One-command installer
│   │   ├── hooks/openclaw/      #   gateway:startup auto-start hook
│   │   └── plugin/              #   before_tool_call DLP bridge
│   └── clawguard-plugin/        # Standalone plugin (also in skill)
├── config/
│   └── default_policy.yaml      # Default policy
└── tests/                       # 142 tests
```

### Data Flow

```
Agent tool call
       │
       ▼
Plugin extracts content + infers destination
       │
       ▼
POST /api/v1/scan ──▶ SecretScanner (52 patterns)
                      PIIScanner    (10 patterns + validators)
                      CustomScanner (user-defined)
                      Entropy       (Shannon > 4.5)
                             │
                             ▼
                      PolicyEngine evaluates rules
                             │
                    ┌────────┼────────┐
                    ▼        ▼        ▼
                 ALLOW    REDACT    BLOCK
                    │        │        │
                    │     Redactor    │
                    │     masks      │
                    │     content    │
                    ▼        ▼        ▼
              AuditRepository logs scan event
                    │        │        │
                    ▼        ▼        ▼
              Tool call   Modified   Tool call
              proceeds    args sent  rejected
```

---

## API Reference

All endpoints live under `/api/v1/`.

### Scan Content

```
POST /api/v1/scan
```

```bash
curl -s -X POST http://localhost:8642/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "content": "My AWS key is AKIAIOSFODNN7EXAMPLE",
    "destination": "api.example.com",
    "agent_id": "agent-1",
    "tool_name": "http_request"
  }'
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

### Health Check

```
GET /api/v1/health
```

```json
{
  "status": "ok",
  "version": "0.3.0",
  "scanners": ["SECRET", "PII", "CUSTOM"],
  "policy_loaded": true,
  "default_action": "REDACT"
}
```

### All Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scan` | Scan content for secrets/PII |
| `GET` | `/api/v1/health` | Service health and version |
| `GET` | `/api/v1/audit` | Query audit log (`agent_id`, `destination`, `action`, `limit`, `offset`) |
| `GET` | `/api/v1/dashboard/stats` | Scan statistics and recent activity |
| `GET` | `/api/v1/dashboard/policy` | Current policy as JSON |
| `GET` | `/api/v1/dashboard/patterns` | Full pattern catalog with regex |
| `PUT` | `/api/v1/policy` | Update policy (full PolicyConfig JSON body) |
| `POST` | `/api/v1/policy/reload` | Reload policy from disk |
| `GET` | `/dashboard` | Web dashboard UI |

---

## Configuration

All settings via environment variables (prefixed `CLAWGUARD_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAWGUARD_HOST` | `0.0.0.0` | Bind address |
| `CLAWGUARD_PORT` | `8642` | Service port |
| `CLAWGUARD_DATABASE_URL` | `sqlite+aiosqlite:///~/.config/clawwall/clawwall.db` | Database connection |
| `CLAWGUARD_POLICY_PATH` | `~/.config/clawwall/policy.yaml` | Policy YAML path |
| `CLAWGUARD_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `CLAWGUARD_DEBUG` | `false` | Debug mode |

---

## Development

### Running Tests

```bash
poetry install --with dev
poetry run pytest
```

The test suite includes 142 tests covering scanners, policy engine, redaction, API endpoints, and the dashboard.

### Building the Plugin

```bash
cd openclaw-integration/clawguard-plugin
npm install && npm run build
```

### Building the Hook

```bash
cd openclaw-integration/clawguard-skill/hooks/openclaw
npm install && npm run build
```

### Project Structure

See [Architecture](#architecture) above for the full annotated tree.

---

## FAQ

**Q: Does ClawWall send data to external servers?**
No. Everything runs locally. No telemetry, no phone-home, no external connections. The service binds to `127.0.0.1:8642` by default.

**Q: What happens if the service is down?**
By default the plugin fails open — tool calls go through unscanned. Set `blockOnError: true` in the plugin config to fail closed instead.

**Q: Does it store my secrets?**
No. The audit log stores only metadata: finding type, severity, position offsets, action taken, and scan duration. Raw content is never persisted. Content is hashed (SHA-256) for deduplication only.

**Q: How do I disable a noisy pattern?**
Add its name to `disabled_patterns` in your policy YAML, or toggle it off in the Pattern Catalog tab of the dashboard.

**Q: Can I add my own patterns?**
Yes. Add entries to `custom_patterns` in the policy YAML:
```yaml
custom_patterns:
  - name: my_internal_id
    regex: "INTERNAL-\\d{6}"
    severity: HIGH
```

**Q: How fast is scanning?**
Typical scans complete in 1-5ms. All patterns are pre-compiled at startup.

---

## License

MIT — see [LICENSE](LICENSE).
