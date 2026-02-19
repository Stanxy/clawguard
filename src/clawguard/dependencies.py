"""FastAPI dependency injection wiring."""
from __future__ import annotations

from clawguard.config import Settings
from clawguard.db.audit_repository import SQLAlchemyAuditRepository
from clawguard.db.repository import AuditRepository
from clawguard.db.session import get_engine, get_session_factory
from clawguard.engine.action_handler import ActionHandler
from clawguard.engine.policy_engine import PolicyEngine
from clawguard.engine.redactor import Redactor
from clawguard.models.enums import ScannerType
from clawguard.scanners.custom_scanner import CustomScanner
from clawguard.scanners.pii_scanner import PIIScanner
from clawguard.scanners.registry import ScannerRegistry, create_default_registry
from clawguard.scanners.secret_scanner import SecretScanner


class ServiceContainer:
    """Holds all service singletons for the application lifetime."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

        # Scanners
        self.registry: ScannerRegistry = create_default_registry()

        # Policy
        self.policy_engine = PolicyEngine()
        self.policy_engine.load_from_file(settings.policy_path)

        # Load custom patterns from policy into custom scanner
        custom_scanner = self.registry.get(ScannerType.CUSTOM)
        if isinstance(custom_scanner, CustomScanner) and self.policy_engine.policy.custom_patterns:
            custom_scanner.load_patterns(self.policy_engine.policy.custom_patterns)

        # Sync disabled patterns from policy to scanners
        self._sync_disabled_patterns()

        # Redaction + Action
        self.redactor = Redactor(self.policy_engine.policy.redaction)
        self.action_handler = ActionHandler(self.redactor)

        # Database
        self.engine = get_engine(settings.database_url)
        self.session_factory = get_session_factory(self.engine)
        self.audit_repo: AuditRepository = SQLAlchemyAuditRepository(self.session_factory)

    def _sync_disabled_patterns(self) -> None:
        """Push disabled_patterns from policy to secret/PII scanners."""
        disabled = set(self.policy_engine.policy.disabled_patterns)
        secret_scanner = self.registry.get(ScannerType.SECRET)
        if isinstance(secret_scanner, SecretScanner):
            secret_scanner.disabled_patterns = disabled
        pii_scanner = self.registry.get(ScannerType.PII)
        if isinstance(pii_scanner, PIIScanner):
            pii_scanner.disabled_patterns = disabled


_container: ServiceContainer | None = None


def init_container(settings: Settings) -> ServiceContainer:
    global _container
    _container = ServiceContainer(settings)
    return _container


def get_container() -> ServiceContainer:
    if _container is None:
        raise RuntimeError("ServiceContainer not initialized. Call init_container() first.")
    return _container
