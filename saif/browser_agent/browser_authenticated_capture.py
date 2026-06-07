from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from saif.config import get_settings
from saif.services.endpoint_sanitizer import sanitize_candidate_endpoint


def capture_authenticated_browser_traffic(scan_id: int, target_url: str, storage_state: str | None = None, manual_login: bool = False) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return _write_capture(
            scan_id,
            {
                "status": "skipped_playwright_missing",
                "error": str(exc),
                "observed_endpoints": [],
                "message": "Browser capture unavailable: Playwright not installed",
                "install_commands": ["pip install playwright", "python -m playwright install chromium"],
            },
        )

    observed: list[dict] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not manual_login)
        context_kwargs = {}
        if storage_state and Path(storage_state).exists():
            context_kwargs["storage_state"] = storage_state
        context = browser.new_context(**context_kwargs)
        page = context.new_page()

        def on_request(request):
            if request.resource_type not in {"xhr", "fetch"}:
                return
            sanitized = sanitize_candidate_endpoint(request.url, target_url, "browser_authenticated_capture")
            if sanitized:
                observed.append({"url": sanitized.url, "method": request.method, "source": "browser_authenticated_capture", "confidence": "high", "candidate_type": sanitized.candidate_type})

        page.on("request", on_request)
        page.goto(target_url, wait_until="networkidle", timeout=30000)
        if manual_login:
            page.wait_for_timeout(30000)
        storage = context.storage_state()
        cookies = context.cookies()
        browser.close()
    status = "completed_with_requests" if observed else "completed_no_requests"
    return _write_capture(scan_id, {"status": status, "observed_endpoints": observed, "storage_state": _mask_storage(storage), "cookies_count": len(cookies)})


def _write_capture(scan_id: int, payload: dict) -> dict:
    payload = {"scan_id": scan_id, "captured_at": datetime.now(timezone.utc).isoformat(), **payload}
    directory = get_settings().evidence_dir / f"scan-{scan_id}"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "browser_authenticated_capture.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    payload["evidence_path"] = str(path)
    return payload


def _mask_storage(storage: dict) -> dict:
    masked = dict(storage or {})
    for origin in masked.get("origins", []) or []:
        for item in origin.get("localStorage", []) or []:
            if any(token in str(item.get("name", "")).lower() for token in ["token", "secret", "password"]):
                item["value"] = "<masked>"
    return masked
