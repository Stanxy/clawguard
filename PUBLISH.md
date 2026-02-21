# Publishing ClawWall to ClawHub

Instructions for publishing ClawWall v0.3.0 as an OpenClaw skill.

## Prerequisites

- OpenClaw CLI installed and authenticated
- All files built and tested locally

## Pre-Publish Checklist

1. **Version is correct:**
   ```bash
   grep version pyproject.toml          # Should show 0.3.0
   grep __version__ src/clawguard/__init__.py  # Should show 0.3.0
   ```

2. **Skill directory is complete:**
   ```
   openclaw-integration/clawguard-skill/
   ├── SKILL.md
   ├── setup.sh
   ├── hooks/openclaw/
   │   ├── HOOK.md
   │   ├── handler.ts
   │   ├── package.json
   │   └── tsconfig.json
   ├── plugin/
   │   ├── index.ts
   │   ├── package.json
   │   ├── tsconfig.json
   │   └── openclaw.plugin.json
   └── .clawhub/origin.json
   ```

3. **Plugin builds cleanly:**
   ```bash
   cd openclaw-integration/clawguard-skill/plugin
   npm install && npm run build
   ```

4. **Hook builds cleanly:**
   ```bash
   cd openclaw-integration/clawguard-skill/hooks/openclaw
   npm install && npm run build
   ```

5. **Service health check passes:**
   ```bash
   clawwall &
   curl -s http://127.0.0.1:8642/api/v1/health | python3 -m json.tool
   ```

## Publish to ClawHub

From the skill directory:

```bash
cd openclaw-integration/clawguard-skill
clawhub publish
```

This will:
- Read SKILL.md frontmatter for name, version, and metadata
- Package the skill directory contents
- Upload to the ClawHub registry
- Make it available via `clawhub install clawwall`

## Post-Publish Verification

```bash
# Search for the skill
clawhub search clawwall

# Install on a clean system
clawhub install clawwall

# Verify it appears in the list
clawhub list | grep clawwall
```

## PyPI Publish (Python Service)

The Python service is published separately to PyPI:

```bash
# Build
poetry build

# Publish (requires PyPI credentials)
poetry publish
```

## Git Tag

Tag the release after publishing:

```bash
git tag -a v0.3.0 -m "ClawWall v0.3.0 — skill repackaging, auto-start, setup script"
git push origin v0.3.0
```
