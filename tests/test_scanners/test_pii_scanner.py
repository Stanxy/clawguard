from __future__ import annotations

import pytest

from clawguard.scanners.pii_scanner import PIIScanner


@pytest.fixture
def scanner():
    return PIIScanner()


class TestSSN:
    def test_valid_ssn(self, scanner):
        findings = scanner.scan("my ssn is 123-45-6789")
        assert any(f.finding_type == "ssn" for f in findings)

    def test_invalid_area_000(self, scanner):
        findings = scanner.scan("000-12-3456")
        assert not any(f.finding_type == "ssn" for f in findings)

    def test_invalid_area_666(self, scanner):
        findings = scanner.scan("666-12-3456")
        assert not any(f.finding_type == "ssn" for f in findings)

    def test_invalid_area_900(self, scanner):
        findings = scanner.scan("900-12-3456")
        assert not any(f.finding_type == "ssn" for f in findings)

    def test_invalid_group_00(self, scanner):
        findings = scanner.scan("123-00-6789")
        assert not any(f.finding_type == "ssn" for f in findings)

    def test_invalid_serial_0000(self, scanner):
        findings = scanner.scan("123-45-0000")
        assert not any(f.finding_type == "ssn" for f in findings)


class TestCreditCards:
    def test_visa_valid(self, scanner):
        # 4111 1111 1111 1111 is a well-known Luhn-valid test card
        findings = scanner.scan("card: 4111111111111111")
        assert any(f.finding_type == "credit_card_visa" for f in findings)

    def test_visa_with_spaces(self, scanner):
        findings = scanner.scan("card: 4111 1111 1111 1111")
        assert any(f.finding_type == "credit_card_visa" for f in findings)

    def test_visa_with_dashes(self, scanner):
        findings = scanner.scan("card: 4111-1111-1111-1111")
        assert any(f.finding_type == "credit_card_visa" for f in findings)

    def test_visa_invalid_luhn(self, scanner):
        findings = scanner.scan("card: 4111111111111112")
        assert not any(f.finding_type == "credit_card_visa" for f in findings)

    def test_mastercard_valid(self, scanner):
        # 5500 0000 0000 0004 is Luhn-valid
        findings = scanner.scan("card: 5500000000000004")
        assert any(f.finding_type == "credit_card_mastercard" for f in findings)

    def test_amex_valid(self, scanner):
        # 3782 822463 10005 is Luhn-valid
        findings = scanner.scan("card: 378282246310005")
        assert any(f.finding_type == "credit_card_amex" for f in findings)

    def test_discover_valid(self, scanner):
        # 6011 1111 1111 1117 is Luhn-valid
        findings = scanner.scan("card: 6011111111111117")
        assert any(f.finding_type == "credit_card_discover" for f in findings)


class TestEmail:
    def test_standard_email(self, scanner):
        findings = scanner.scan("contact: user@example.com")
        assert any(f.finding_type == "email" for f in findings)

    def test_email_with_plus(self, scanner):
        findings = scanner.scan("user+tag@gmail.com")
        assert any(f.finding_type == "email" for f in findings)


class TestPhone:
    def test_us_phone_standard(self, scanner):
        findings = scanner.scan("call me at (555) 123-4567")
        assert any(f.finding_type == "phone_us" for f in findings)

    def test_us_phone_dashes(self, scanner):
        findings = scanner.scan("call me at 555-123-4567")
        assert any(f.finding_type == "phone_us" for f in findings)

    def test_e164_format(self, scanner):
        findings = scanner.scan("phone: +14155551234")
        phone_findings = [f for f in findings if f.finding_type in ("phone_us", "phone_e164")]
        assert len(phone_findings) > 0


class TestIPAddresses:
    def test_ipv4(self, scanner):
        findings = scanner.scan("server at 192.168.1.1")
        assert any(f.finding_type == "ipv4_address" for f in findings)

    def test_ipv4_invalid_octet(self, scanner):
        findings = scanner.scan("not an IP: 999.999.999.999")
        assert not any(f.finding_type == "ipv4_address" for f in findings)

    def test_ipv6_full(self, scanner):
        findings = scanner.scan("addr: 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert any(f.finding_type == "ipv6_address" for f in findings)


class TestCleanContent:
    def test_no_pii(self, scanner):
        findings = scanner.scan("This is a normal message with no PII.")
        assert len(findings) == 0
