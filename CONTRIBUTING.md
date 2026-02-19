# Contributing to ClawGuard

Thanks for your interest in contributing to ClawGuard! This document covers the basics for getting started.

## Development Setup

```bash
git clone https://github.com/<your-org>/clawguard.git
cd clawguard
poetry install --with dev
```

## Running the Service

```bash
poetry run python -m clawguard
```

The dashboard is at `http://localhost:8642/dashboard`.

## Running Tests

```bash
poetry run pytest
```

All tests are async and use an in-memory SQLite database. No external services are required.

## Code Style

- Python 3.10+ with `from __future__ import annotations`
- Type hints on all function signatures
- Pydantic models for all API request/response shapes
- `async def` for all route handlers and database operations

## Adding a New Detection Pattern

### Built-in secret pattern

1. Add a `SecretPattern` entry in `src/clawguard/scanners/patterns/secrets.py`
2. Append it to the `SECRET_PATTERNS` list at the bottom of the file
3. Add a human-readable description in `src/clawguard/api/dashboard_api.py` (`_SECRET_DESCRIPTIONS`)
4. Write a test in `tests/test_scanners/test_secret_scanner.py`

### Built-in PII pattern

1. Add a `PIIPattern` entry in `src/clawguard/scanners/patterns/pii.py`
2. Add a validator function if the pattern needs post-match validation (e.g., Luhn check)
3. Append it to the `PII_PATTERNS` list
4. Add description and category mappings in `dashboard_api.py`
5. Write a test in `tests/test_scanners/test_pii_scanner.py`

### Custom pattern (user-defined)

Custom patterns are added at runtime via the policy YAML or dashboard UI. No code changes needed.

## Project Layout

```
src/clawguard/
  api/          Route handlers (FastAPI routers)
  dashboard/    Single-page HTML dashboard
  db/           SQLAlchemy async models and repository
  engine/       Policy evaluation, action handling, redaction
  models/       Pydantic data models
  scanners/     Detection engines and compiled pattern sets
  utils/        Entropy analysis, hashing helpers
```

## Pull Requests

1. Fork the repo and create a feature branch
2. Make your changes and add tests
3. Run `poetry run pytest` and confirm all tests pass
4. Open a PR with a clear description of what changed and why

## Reporting Issues

Open an issue on GitHub with:

- What you expected to happen
- What actually happened
- Steps to reproduce
- ClawGuard version (`GET /api/v1/health`)
