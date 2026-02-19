from __future__ import annotations

from fastapi import APIRouter

from clawguard.api import audit, dashboard_api, health, policy, scan

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(scan.router, tags=["scan"])
api_router.include_router(health.router, tags=["health"])
api_router.include_router(audit.router, tags=["audit"])
api_router.include_router(policy.router, tags=["policy"])
api_router.include_router(dashboard_api.router, tags=["dashboard"])
