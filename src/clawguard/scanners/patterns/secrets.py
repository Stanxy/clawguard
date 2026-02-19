"""50+ compiled regex patterns for secret detection, organized by category."""
from __future__ import annotations

import re
from dataclasses import dataclass

from clawguard.models.enums import Severity


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    category: str


# ── Cloud: AWS ────────────────────────────────────────────────────────────────
_AWS_ACCESS_KEY = SecretPattern(
    name="aws_access_key_id",
    pattern=re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
    severity=Severity.CRITICAL,
    category="cloud",
)
_AWS_SECRET_KEY = SecretPattern(
    name="aws_secret_access_key",
    pattern=re.compile(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
    severity=Severity.CRITICAL,
    category="cloud",
)
_AWS_MWS_KEY = SecretPattern(
    name="aws_mws_key",
    pattern=re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    severity=Severity.CRITICAL,
    category="cloud",
)

# ── Cloud: GCP ────────────────────────────────────────────────────────────────
_GCP_API_KEY = SecretPattern(
    name="gcp_api_key",
    pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    severity=Severity.CRITICAL,
    category="cloud",
)
_GCP_SERVICE_ACCOUNT = SecretPattern(
    name="gcp_service_account",
    pattern=re.compile(r'"type"\s*:\s*"service_account"'),
    severity=Severity.HIGH,
    category="cloud",
)

# ── Cloud: Azure ──────────────────────────────────────────────────────────────
_AZURE_STORAGE_KEY = SecretPattern(
    name="azure_storage_key",
    pattern=re.compile(r"AccountKey=[A-Za-z0-9+/=]{86,88}"),
    severity=Severity.CRITICAL,
    category="cloud",
)
_AZURE_CONNECTION_STRING = SecretPattern(
    name="azure_connection_string",
    pattern=re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88}"),
    severity=Severity.CRITICAL,
    category="cloud",
)

# ── Version Control: GitHub ───────────────────────────────────────────────────
_GITHUB_PAT = SecretPattern(
    name="github_pat",
    pattern=re.compile(r"ghp_[0-9a-zA-Z]{30,}"),
    severity=Severity.CRITICAL,
    category="vcs",
)
_GITHUB_FINE_GRAINED_PAT = SecretPattern(
    name="github_fine_grained_pat",
    pattern=re.compile(r"github_pat_[0-9a-zA-Z_]{30,}"),
    severity=Severity.CRITICAL,
    category="vcs",
)
_GITHUB_OAUTH = SecretPattern(
    name="github_oauth",
    pattern=re.compile(r"gho_[0-9a-zA-Z]{30,}"),
    severity=Severity.HIGH,
    category="vcs",
)
_GITHUB_APP_TOKEN = SecretPattern(
    name="github_app_token",
    pattern=re.compile(r"ghu_[0-9a-zA-Z]{30,}"),
    severity=Severity.HIGH,
    category="vcs",
)
_GITHUB_REFRESH_TOKEN = SecretPattern(
    name="github_refresh_token",
    pattern=re.compile(r"ghr_[0-9a-zA-Z]{30,}"),
    severity=Severity.HIGH,
    category="vcs",
)

# ── Version Control: GitLab ───────────────────────────────────────────────────
_GITLAB_PAT = SecretPattern(
    name="gitlab_pat",
    pattern=re.compile(r"glpat-[0-9a-zA-Z\-_]{20,}"),
    severity=Severity.CRITICAL,
    category="vcs",
)
_GITLAB_RUNNER_TOKEN = SecretPattern(
    name="gitlab_runner_token",
    pattern=re.compile(r"GR1348941[0-9a-zA-Z\-_]{20,}"),
    severity=Severity.HIGH,
    category="vcs",
)

# ── Payment: Stripe ───────────────────────────────────────────────────────────
_STRIPE_SECRET_KEY = SecretPattern(
    name="stripe_secret_key",
    pattern=re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    severity=Severity.CRITICAL,
    category="payment",
)
_STRIPE_PUBLISHABLE_KEY = SecretPattern(
    name="stripe_publishable_key",
    pattern=re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    severity=Severity.HIGH,
    category="payment",
)
_STRIPE_RESTRICTED_KEY = SecretPattern(
    name="stripe_restricted_key",
    pattern=re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),
    severity=Severity.CRITICAL,
    category="payment",
)

# ── Payment: Square ───────────────────────────────────────────────────────────
_SQUARE_ACCESS_TOKEN = SecretPattern(
    name="square_access_token",
    pattern=re.compile(r"sq0atp-[0-9A-Za-z\-_]{22,}"),
    severity=Severity.CRITICAL,
    category="payment",
)
_SQUARE_OAUTH = SecretPattern(
    name="square_oauth",
    pattern=re.compile(r"sq0csp-[0-9A-Za-z\-_]{43,}"),
    severity=Severity.CRITICAL,
    category="payment",
)

# ── Payment: PayPal ───────────────────────────────────────────────────────────
_PAYPAL_BRAINTREE = SecretPattern(
    name="paypal_braintree",
    pattern=re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    severity=Severity.CRITICAL,
    category="payment",
)

# ── Communication: Slack ──────────────────────────────────────────────────────
_SLACK_TOKEN = SecretPattern(
    name="slack_token",
    pattern=re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,250}"),
    severity=Severity.HIGH,
    category="communication",
)
_SLACK_WEBHOOK = SecretPattern(
    name="slack_webhook",
    pattern=re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}"),
    severity=Severity.HIGH,
    category="communication",
)

# ── Communication: Discord ────────────────────────────────────────────────────
_DISCORD_BOT_TOKEN = SecretPattern(
    name="discord_bot_token",
    pattern=re.compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}"),
    severity=Severity.HIGH,
    category="communication",
)
_DISCORD_WEBHOOK = SecretPattern(
    name="discord_webhook",
    pattern=re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
    severity=Severity.HIGH,
    category="communication",
)

# ── Communication: Telegram ───────────────────────────────────────────────────
_TELEGRAM_BOT_TOKEN = SecretPattern(
    name="telegram_bot_token",
    pattern=re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
    severity=Severity.HIGH,
    category="communication",
)

# ── Communication: Twilio ─────────────────────────────────────────────────────
_TWILIO_API_KEY = SecretPattern(
    name="twilio_api_key",
    pattern=re.compile(r"SK[0-9a-fA-F]{32}"),
    severity=Severity.HIGH,
    category="communication",
)

# ── Auth/Tokens: JWT ──────────────────────────────────────────────────────────
_JWT_TOKEN = SecretPattern(
    name="jwt_token",
    pattern=re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}"),
    severity=Severity.HIGH,
    category="auth",
)
_BEARER_TOKEN = SecretPattern(
    name="bearer_token",
    pattern=re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}"),
    severity=Severity.HIGH,
    category="auth",
)
_BASIC_AUTH = SecretPattern(
    name="basic_auth",
    pattern=re.compile(r"Basic\s+[A-Za-z0-9+/=]{20,}"),
    severity=Severity.HIGH,
    category="auth",
)

# ── Private Keys ──────────────────────────────────────────────────────────────
_PRIVATE_KEY_RSA = SecretPattern(
    name="private_key_rsa",
    pattern=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    severity=Severity.CRITICAL,
    category="private_key",
)
_PRIVATE_KEY_DSA = SecretPattern(
    name="private_key_dsa",
    pattern=re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
    severity=Severity.CRITICAL,
    category="private_key",
)
_PRIVATE_KEY_EC = SecretPattern(
    name="private_key_ec",
    pattern=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
    severity=Severity.CRITICAL,
    category="private_key",
)
_PRIVATE_KEY_OPENSSH = SecretPattern(
    name="private_key_openssh",
    pattern=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    severity=Severity.CRITICAL,
    category="private_key",
)
_PRIVATE_KEY_PGP = SecretPattern(
    name="private_key_pgp",
    pattern=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    severity=Severity.CRITICAL,
    category="private_key",
)
_PRIVATE_KEY_GENERIC = SecretPattern(
    name="private_key_generic",
    pattern=re.compile(r"-----BEGIN PRIVATE KEY-----"),
    severity=Severity.CRITICAL,
    category="private_key",
)
_PRIVATE_KEY_ENCRYPTED = SecretPattern(
    name="private_key_encrypted",
    pattern=re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    severity=Severity.CRITICAL,
    category="private_key",
)

# ── Database URIs ─────────────────────────────────────────────────────────────
_POSTGRES_URI = SecretPattern(
    name="postgres_uri",
    pattern=re.compile(r"postgres(?:ql)?://[^\s\"'`]+:[^\s\"'`]+@[^\s\"'`]+"),
    severity=Severity.CRITICAL,
    category="database",
)
_MYSQL_URI = SecretPattern(
    name="mysql_uri",
    pattern=re.compile(r"mysql://[^\s\"'`]+:[^\s\"'`]+@[^\s\"'`]+"),
    severity=Severity.CRITICAL,
    category="database",
)
_MONGODB_URI = SecretPattern(
    name="mongodb_uri",
    pattern=re.compile(r"mongodb(?:\+srv)?://[^\s\"'`]+:[^\s\"'`]+@[^\s\"'`]+"),
    severity=Severity.CRITICAL,
    category="database",
)
_REDIS_URI = SecretPattern(
    name="redis_uri",
    pattern=re.compile(r"redis://[^\s\"'`]*:[^\s\"'`]+@[^\s\"'`]+"),
    severity=Severity.CRITICAL,
    category="database",
)

# ── SaaS APIs ─────────────────────────────────────────────────────────────────
_OPENAI_API_KEY = SecretPattern(
    name="openai_api_key",
    pattern=re.compile(r"sk-[A-Za-z0-9]{20,}"),
    severity=Severity.HIGH,
    category="saas",
)
_ANTHROPIC_API_KEY = SecretPattern(
    name="anthropic_api_key",
    pattern=re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"),
    severity=Severity.HIGH,
    category="saas",
)
_NPM_TOKEN = SecretPattern(
    name="npm_token",
    pattern=re.compile(r"npm_[A-Za-z0-9]{36}"),
    severity=Severity.HIGH,
    category="saas",
)
_PYPI_TOKEN = SecretPattern(
    name="pypi_token",
    pattern=re.compile(r"pypi-[A-Za-z0-9\-_]{50,}"),
    severity=Severity.HIGH,
    category="saas",
)
_SENDGRID_API_KEY = SecretPattern(
    name="sendgrid_api_key",
    pattern=re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    severity=Severity.HIGH,
    category="saas",
)
_MAILGUN_API_KEY = SecretPattern(
    name="mailgun_api_key",
    pattern=re.compile(r"key-[0-9a-zA-Z]{32}"),
    severity=Severity.HIGH,
    category="saas",
)
_MAILCHIMP_API_KEY = SecretPattern(
    name="mailchimp_api_key",
    pattern=re.compile(r"[0-9a-f]{32}-us\d{1,2}"),
    severity=Severity.HIGH,
    category="saas",
)
_HEROKU_API_KEY = SecretPattern(
    name="heroku_api_key",
    pattern=re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    severity=Severity.MEDIUM,
    category="saas",
)
_DATADOG_API_KEY = SecretPattern(
    name="datadog_api_key",
    pattern=re.compile(r"dd[a-z]{1,2}_[A-Za-z0-9]{32,40}"),
    severity=Severity.HIGH,
    category="saas",
)
_SHOPIFY_ACCESS_TOKEN = SecretPattern(
    name="shopify_access_token",
    pattern=re.compile(r"shpat_[0-9a-fA-F]{32}"),
    severity=Severity.HIGH,
    category="saas",
)
_SHOPIFY_SECRET = SecretPattern(
    name="shopify_shared_secret",
    pattern=re.compile(r"shpss_[0-9a-fA-F]{32}"),
    severity=Severity.HIGH,
    category="saas",
)

# ── Generic secrets (password in URL, generic API key assignments) ────────────
_GENERIC_PASSWORD_URL = SecretPattern(
    name="password_in_url",
    pattern=re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:]+:([^@\s]{8,})@"),
    severity=Severity.HIGH,
    category="generic",
)
_GENERIC_SECRET_ASSIGNMENT = SecretPattern(
    name="generic_secret_assignment",
    pattern=re.compile(
        r"""(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth)"""
        r"""\s*[=:]\s*['"][^\s'"]{8,}['"]""",
        re.IGNORECASE,
    ),
    severity=Severity.MEDIUM,
    category="generic",
)

# ── Aggregated pattern list ───────────────────────────────────────────────────
SECRET_PATTERNS: list[SecretPattern] = [
    # Cloud
    _AWS_ACCESS_KEY,
    _AWS_MWS_KEY,
    _GCP_API_KEY,
    _GCP_SERVICE_ACCOUNT,
    _AZURE_STORAGE_KEY,
    _AZURE_CONNECTION_STRING,
    # VCS
    _GITHUB_PAT,
    _GITHUB_FINE_GRAINED_PAT,
    _GITHUB_OAUTH,
    _GITHUB_APP_TOKEN,
    _GITHUB_REFRESH_TOKEN,
    _GITLAB_PAT,
    _GITLAB_RUNNER_TOKEN,
    # Payment
    _STRIPE_SECRET_KEY,
    _STRIPE_PUBLISHABLE_KEY,
    _STRIPE_RESTRICTED_KEY,
    _SQUARE_ACCESS_TOKEN,
    _SQUARE_OAUTH,
    _PAYPAL_BRAINTREE,
    # Communication
    _SLACK_TOKEN,
    _SLACK_WEBHOOK,
    _DISCORD_BOT_TOKEN,
    _DISCORD_WEBHOOK,
    _TELEGRAM_BOT_TOKEN,
    _TWILIO_API_KEY,
    # Auth/Tokens
    _JWT_TOKEN,
    _BEARER_TOKEN,
    _BASIC_AUTH,
    # Private Keys
    _PRIVATE_KEY_RSA,
    _PRIVATE_KEY_DSA,
    _PRIVATE_KEY_EC,
    _PRIVATE_KEY_OPENSSH,
    _PRIVATE_KEY_PGP,
    _PRIVATE_KEY_GENERIC,
    _PRIVATE_KEY_ENCRYPTED,
    # Database
    _POSTGRES_URI,
    _MYSQL_URI,
    _MONGODB_URI,
    _REDIS_URI,
    # SaaS
    _OPENAI_API_KEY,
    _ANTHROPIC_API_KEY,
    _NPM_TOKEN,
    _PYPI_TOKEN,
    _SENDGRID_API_KEY,
    _MAILGUN_API_KEY,
    _MAILCHIMP_API_KEY,
    _HEROKU_API_KEY,
    _DATADOG_API_KEY,
    _SHOPIFY_ACCESS_TOKEN,
    _SHOPIFY_SECRET,
    # Generic
    _GENERIC_PASSWORD_URL,
    _GENERIC_SECRET_ASSIGNMENT,
]

# NOTE: _AWS_SECRET_KEY is intentionally excluded from default patterns
# because its broad 40-char base64 regex generates too many false positives.
# The entropy scanner handles these high-entropy strings instead.
