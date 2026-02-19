from __future__ import annotations

import pytest

from clawguard.scanners.secret_scanner import SecretScanner


@pytest.fixture
def scanner():
    return SecretScanner()


class TestAWSPatterns:
    def test_aws_access_key(self, scanner):
        findings = scanner.scan("key = AKIAIOSFODNN7EXAMPLE")
        names = [f.finding_type for f in findings]
        assert "aws_access_key_id" in names

    def test_aws_mws_key(self, scanner):
        findings = scanner.scan("amzn.mws.4ea38b7b-f563-7709-4bae-87aea0d12345")
        assert any(f.finding_type == "aws_mws_key" for f in findings)


class TestGCPPatterns:
    def test_gcp_api_key(self, scanner):
        findings = scanner.scan("key = AIzaSyA1234567890abcdefghijklmnopqrstuv")
        assert any(f.finding_type == "gcp_api_key" for f in findings)

    def test_gcp_service_account(self, scanner):
        findings = scanner.scan('{"type": "service_account", "project_id": "test"}')
        assert any(f.finding_type == "gcp_service_account" for f in findings)


class TestAzurePatterns:
    def test_azure_storage_key(self, scanner):
        key = "A" * 88
        findings = scanner.scan(f"AccountKey={key}")
        assert any(f.finding_type == "azure_storage_key" for f in findings)


class TestGitHubPatterns:
    def test_github_pat(self, scanner):
        findings = scanner.scan("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh")
        assert any(f.finding_type == "github_pat" for f in findings)

    def test_github_fine_grained_pat(self, scanner):
        token = "github_pat_" + "a" * 82
        findings = scanner.scan(f"token = {token}")
        assert any(f.finding_type == "github_fine_grained_pat" for f in findings)

    def test_github_oauth(self, scanner):
        findings = scanner.scan("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh")
        assert any(f.finding_type == "github_oauth" for f in findings)


class TestGitLabPatterns:
    def test_gitlab_pat(self, scanner):
        findings = scanner.scan("glpat-ABCDEFghijKL1234567890")
        assert any(f.finding_type == "gitlab_pat" for f in findings)


class TestStripePatterns:
    def test_stripe_secret_key(self, scanner):
        # Assembled at runtime so static scanners don't flag the test fixture
        key = "sk_live_" + "ABCDEFghijklmnopqrstuvwx"  # fake test credential
        findings = scanner.scan(key)
        assert any(f.finding_type == "stripe_secret_key" for f in findings)

    def test_stripe_publishable_key(self, scanner):
        key = "pk_live_" + "ABCDEFghijklmnopqrstuvwx"  # fake test credential
        findings = scanner.scan(key)
        assert any(f.finding_type == "stripe_publishable_key" for f in findings)


class TestSquarePatterns:
    def test_square_access_token(self, scanner):
        # Assembled at runtime so static scanners don't flag the test fixture
        token = "sq0atp-" + "ABCDEFghijklmnopqrstuv"  # fake test credential
        findings = scanner.scan(token)
        assert any(f.finding_type == "square_access_token" for f in findings)


class TestSlackPatterns:
    def test_slack_bot_token(self, scanner):
        findings = scanner.scan("xoxb-1234567890-abcdefghij")
        assert any(f.finding_type == "slack_token" for f in findings)

    def test_slack_webhook(self, scanner):
        # Assembled at runtime so static scanners don't flag the test fixture
        url = "https://hooks.slack.com/services/" + "T12345678/B12345678/ABCDEFGHIJKLMNOpqrstuvwx"  # fake
        findings = scanner.scan(f"webhook: {url}")
        assert any(f.finding_type == "slack_webhook" for f in findings)


class TestDiscordPatterns:
    def test_discord_webhook(self, scanner):
        url = "https://discord.com/api/webhooks/123456789/ABCDEFghij_klmnop"
        findings = scanner.scan(url)
        assert any(f.finding_type == "discord_webhook" for f in findings)


class TestAuthPatterns:
    def test_jwt_token(self, scanner):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        findings = scanner.scan(jwt)
        assert any(f.finding_type == "jwt_token" for f in findings)

    def test_bearer_token(self, scanner):
        findings = scanner.scan("Authorization: Bearer abcdef1234567890abcdef")
        assert any(f.finding_type == "bearer_token" for f in findings)

    def test_basic_auth(self, scanner):
        findings = scanner.scan("Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=")
        assert any(f.finding_type == "basic_auth" for f in findings)


class TestPrivateKeyPatterns:
    def test_rsa_private_key(self, scanner):
        findings = scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        assert any(f.finding_type == "private_key_rsa" for f in findings)

    def test_ec_private_key(self, scanner):
        findings = scanner.scan("-----BEGIN EC PRIVATE KEY-----\nMHQC...")
        assert any(f.finding_type == "private_key_ec" for f in findings)

    def test_openssh_private_key(self, scanner):
        findings = scanner.scan("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...")
        assert any(f.finding_type == "private_key_openssh" for f in findings)

    def test_pgp_private_key(self, scanner):
        findings = scanner.scan("-----BEGIN PGP PRIVATE KEY BLOCK-----\n...")
        assert any(f.finding_type == "private_key_pgp" for f in findings)


class TestDatabaseURIPatterns:
    def test_postgres_uri(self, scanner):
        findings = scanner.scan("postgres://user:pass@localhost:5432/db")
        assert any(f.finding_type == "postgres_uri" for f in findings)

    def test_mysql_uri(self, scanner):
        findings = scanner.scan("mysql://root:secret@db.host.com/mydb")
        assert any(f.finding_type == "mysql_uri" for f in findings)

    def test_mongodb_uri(self, scanner):
        findings = scanner.scan("mongodb+srv://user:pass@cluster0.mongodb.net/db")
        assert any(f.finding_type == "mongodb_uri" for f in findings)

    def test_redis_uri(self, scanner):
        findings = scanner.scan("redis://:mypassword@redis.host:6379/0")
        assert any(f.finding_type == "redis_uri" for f in findings)


class TestSaaSPatterns:
    def test_openai_key(self, scanner):
        findings = scanner.scan("sk-proj1234567890abcdefghij")
        assert any(f.finding_type == "openai_api_key" for f in findings)

    def test_anthropic_key(self, scanner):
        findings = scanner.scan("sk-ant-api03-abcdefghijklmnopqrstuv")
        assert any(f.finding_type == "anthropic_api_key" for f in findings)

    def test_npm_token(self, scanner):
        findings = scanner.scan("npm_abcdefghijklmnopqrstuvwxyz1234567890")
        assert any(f.finding_type == "npm_token" for f in findings)

    def test_sendgrid_key(self, scanner):
        name = "A" * 22
        secret = "B" * 43
        findings = scanner.scan(f"SG.{name}.{secret}")
        assert any(f.finding_type == "sendgrid_api_key" for f in findings)

    def test_shopify_access_token(self, scanner):
        findings = scanner.scan("shpat_" + "a" * 32)
        assert any(f.finding_type == "shopify_access_token" for f in findings)


class TestGenericPatterns:
    def test_password_in_url(self, scanner):
        findings = scanner.scan("https://admin:supersecretpass@example.com")
        assert any(f.finding_type == "password_in_url" for f in findings)

    def test_generic_secret_assignment(self, scanner):
        findings = scanner.scan('api_key = "sk_test_abcdef1234567890"')
        assert any(f.finding_type == "generic_secret_assignment" for f in findings)


class TestEntropyDetection:
    def test_high_entropy_string(self, scanner):
        # A sufficiently random string that exceeds the entropy threshold
        high_ent = "aK3xR9mQ2pL7wN5vBjT8cF1dG6hY0iZs"
        findings = scanner.scan(f"token = {high_ent}")
        assert any(f.finding_type == "high_entropy_string" for f in findings)

    def test_low_entropy_not_flagged(self, scanner):
        # Repetitive string should not trigger
        low_ent = "aaaaaaaaaaaaaaaaaaaaaaaaa"
        findings = scanner.scan(low_ent)
        assert not any(f.finding_type == "high_entropy_string" for f in findings)


class TestNoFalsePositives:
    def test_clean_text(self, scanner):
        findings = scanner.scan("This is a normal message with no secrets.")
        assert len(findings) == 0
