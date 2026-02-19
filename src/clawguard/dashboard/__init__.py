"""Dashboard HTML-serving router."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

_HTML_PATH = Path(__file__).parent / "index.html"


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    html = _HTML_PATH.read_text(encoding="utf-8")
    return HTMLResponse(content=html)
