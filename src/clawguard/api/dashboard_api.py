"""Dashboard API endpoints: stats, policy, and pattern catalog."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from clawguard.dependencies import ServiceContainer, get_container
from clawguard.models.dashboard import (
    DashboardStats,
    PatternCatalog,
    PatternCatalogEntry,
)
from clawguard.models.enums import ScannerType
from clawguard.scanners.custom_scanner import CustomScanner
from clawguard.scanners.patterns.pii import PII_PATTERNS
from clawguard.scanners.patterns.secrets import SECRET_PATTERNS

router = APIRouter()

# Human-readable descriptions for secret patterns
_SECRET_DESCRIPTIONS: dict[str, str] = {
    "aws_access_key_id": "AWS Access Key ID (starts with AKIA)",
    "aws_secret_access_key": "AWS Secret Access Key (40-char base64)",
    "aws_mws_key": "Amazon Marketplace Web Service key",
    "gcp_api_key": "Google Cloud Platform API key",
    "gcp_service_account": "GCP service account JSON credential",
    "azure_storage_key": "Azure Storage account key",
    "azure_connection_string": "Azure Storage connection string",
    "github_pat": "GitHub personal access token (classic)",
    "github_fine_grained_pat": "GitHub fine-grained personal access token",
    "github_oauth": "GitHub OAuth access token",
    "github_app_token": "GitHub App user-to-server token",
    "github_refresh_token": "GitHub App refresh token",
    "gitlab_pat": "GitLab personal access token",
    "gitlab_runner_token": "GitLab CI runner registration token",
    "stripe_secret_key": "Stripe live secret API key",
    "stripe_publishable_key": "Stripe live publishable key",
    "stripe_restricted_key": "Stripe live restricted API key",
    "square_access_token": "Square access token",
    "square_oauth": "Square OAuth secret",
    "paypal_braintree": "PayPal/Braintree production access token",
    "slack_token": "Slack API token (bot, app, user)",
    "slack_webhook": "Slack incoming webhook URL",
    "discord_bot_token": "Discord bot authentication token",
    "discord_webhook": "Discord webhook URL",
    "telegram_bot_token": "Telegram Bot API token",
    "twilio_api_key": "Twilio API key",
    "jwt_token": "JSON Web Token (JWT)",
    "bearer_token": "HTTP Bearer authentication token",
    "basic_auth": "HTTP Basic authentication credentials",
    "private_key_rsa": "RSA private key (PEM format)",
    "private_key_dsa": "DSA private key (PEM format)",
    "private_key_ec": "Elliptic Curve private key (PEM format)",
    "private_key_openssh": "OpenSSH private key",
    "private_key_pgp": "PGP private key block",
    "private_key_generic": "Generic PKCS#8 private key (PEM format)",
    "private_key_encrypted": "Encrypted PKCS#8 private key (PEM format)",
    "postgres_uri": "PostgreSQL connection URI with credentials",
    "mysql_uri": "MySQL connection URI with credentials",
    "mongodb_uri": "MongoDB connection URI with credentials",
    "redis_uri": "Redis connection URI with credentials",
    "openai_api_key": "OpenAI API key",
    "anthropic_api_key": "Anthropic API key",
    "npm_token": "npm registry authentication token",
    "pypi_token": "PyPI API token",
    "sendgrid_api_key": "SendGrid email API key",
    "mailgun_api_key": "Mailgun API key",
    "mailchimp_api_key": "Mailchimp API key",
    "heroku_api_key": "Heroku platform API key",
    "datadog_api_key": "Datadog monitoring API key",
    "shopify_access_token": "Shopify Admin API access token",
    "shopify_shared_secret": "Shopify app shared secret",
    "password_in_url": "Password embedded in a URL",
    "generic_secret_assignment": "Secret/password/token assigned in code",
}

# Human-readable descriptions for PII patterns
_PII_DESCRIPTIONS: dict[str, str] = {
    "ssn": "US Social Security Number (XXX-XX-XXXX)",
    "credit_card_visa": "Visa credit card number (starts with 4)",
    "credit_card_mastercard": "Mastercard credit card number (starts with 51-55)",
    "credit_card_amex": "American Express card number (starts with 34/37)",
    "credit_card_discover": "Discover credit card number (starts with 6011/65)",
    "email": "Email address",
    "phone_us": "US phone number",
    "phone_e164": "International phone number (E.164 format)",
    "ipv4_address": "IPv4 address",
    "ipv6_address": "IPv6 address",
}

# Category labels for secret patterns
_CATEGORY_LABELS: dict[str, str] = {
    "cloud": "Cloud",
    "vcs": "Version Control",
    "payment": "Payment",
    "communication": "Communication",
    "auth": "Authentication",
    "private_key": "Private Keys",
    "database": "Database",
    "saas": "SaaS",
    "generic": "Generic",
}

# Category labels for PII patterns
_PII_CATEGORY_MAP: dict[str, str] = {
    "ssn": "SSN",
    "credit_card_visa": "Credit Cards",
    "credit_card_mastercard": "Credit Cards",
    "credit_card_amex": "Credit Cards",
    "credit_card_discover": "Credit Cards",
    "email": "Email",
    "phone_us": "Phone",
    "phone_e164": "Phone",
    "ipv4_address": "IP Addresses",
    "ipv6_address": "IP Addresses",
}


@router.get("/dashboard/stats", response_model=DashboardStats)
async def dashboard_stats(
    container: ServiceContainer = Depends(get_container),
) -> DashboardStats:
    stats = await container.audit_repo.get_stats()
    return DashboardStats.model_validate(stats)


@router.get("/dashboard/policy")
async def dashboard_policy(
    container: ServiceContainer = Depends(get_container),
) -> dict:
    return container.policy_engine.policy.model_dump(mode="json")


@router.get("/dashboard/patterns", response_model=PatternCatalog)
async def dashboard_patterns(
    container: ServiceContainer = Depends(get_container),
) -> PatternCatalog:
    sev_overrides = container.policy_engine.policy.pattern_severity_overrides

    secrets = [
        PatternCatalogEntry(
            name=sp.name,
            severity=sev_overrides[sp.name].value if sp.name in sev_overrides else sp.severity.value,
            default_severity=sp.severity.value,
            category=_CATEGORY_LABELS.get(sp.category, sp.category),
            description=_SECRET_DESCRIPTIONS.get(sp.name, sp.name),
            regex=sp.pattern.pattern,
        )
        for sp in SECRET_PATTERNS
    ]

    pii = [
        PatternCatalogEntry(
            name=pp.name,
            severity=sev_overrides[pp.name].value if pp.name in sev_overrides else pp.severity.value,
            default_severity=pp.severity.value,
            category=_PII_CATEGORY_MAP.get(pp.name, "PII"),
            description=_PII_DESCRIPTIONS.get(pp.name, pp.name),
            regex=pp.pattern.pattern,
        )
        for pp in PII_PATTERNS
    ]

    custom: list[PatternCatalogEntry] = []
    custom_scanner = container.registry.get(ScannerType.CUSTOM)
    if isinstance(custom_scanner, CustomScanner):
        for cp in custom_scanner._patterns:
            custom.append(PatternCatalogEntry(
                name=cp.name,
                severity=cp.severity.value,
                category="Custom",
                description=f"Custom pattern: {cp.name}",
                regex=cp.regex,
            ))

    return PatternCatalog(secrets=secrets, pii=pii, custom=custom)
