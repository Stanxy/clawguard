# Changelog

All notable changes to ClawGuard are documented here.

## [0.2.0] - 2025-02-18

### Added

- **Pattern regex in catalog** -- the `/api/v1/dashboard/patterns` endpoint and dashboard UI now expose the regex for every detection pattern
- **Help banners** -- each dashboard tab has a collapsible "?" help button with contextual instructions
- **Test scan separation** -- the Test Scanner tab defaults to agent ID `__dashboard_test__`; Scan History has a "Hide test scans" checkbox (on by default) to filter these out
- **Pattern enable/disable** -- toggle built-in secret and PII patterns on/off from the Pattern Catalog; disabled patterns are stored as `disabled_patterns` in the policy and skipped during scanning
- **Custom pattern CRUD in catalog** -- add, edit, and delete custom patterns directly from the Pattern Catalog tab (in addition to the existing Policies tab editor)
- **Responsive dashboard** -- mobile-friendly layout with horizontal-scroll tables, stacked form fields, and collapsible navigation on small screens

### Changed

- **Version** bumped from 0.1.0 to 0.2.0 across `pyproject.toml`, `__init__.py`, and FastAPI app metadata
- **Health endpoint** now reads version from `clawguard.__version__` instead of a hardcoded string
- **Policy model** gained `disabled_patterns: list[str]` field (defaults to empty, fully backwards-compatible)
- **Policy save/reload** now syncs `disabled_patterns` to scanner instances

## [0.1.0] - 2025-02-17

### Added

- Initial release
- Secret scanner with 51 regex patterns (AWS, GCP, Azure, GitHub, Stripe, Slack, private keys, database URIs, and more)
- PII scanner with 10 patterns (SSN, credit cards with Luhn validation, email, phone, IP)
- Entropy-based high-entropy string detection
- Custom pattern scanner loaded from policy YAML
- Policy engine with severity overrides, destination allow/blocklists, destination rules, and agent rules
- Three actions: BLOCK, REDACT (mask/hash/remove), ALLOW
- Audit log with SQLite persistence (never stores raw content)
- Full REST API under `/api/v1/` (scan, health, audit, policy, dashboard)
- Web dashboard with Overview, Scan History, Policies, Test Scanner, and Pattern Catalog tabs
- OpenClaw plugin (`before_tool_call` hook) and DLP awareness skill
- 142-test async pytest suite
