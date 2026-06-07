from __future__ import annotations

from saif.browser_agent.browser_authenticated_capture import capture_authenticated_browser_traffic
from saif.core.request_map import upsert_request_response


def run_browser_workflow(scan_id: int, target_url: str, *, storage_state: str | None = None, manual_login: bool = False) -> dict:
    capture = capture_authenticated_browser_traffic(scan_id, target_url, storage_state=storage_state, manual_login=manual_login)
    for item in (capture.get("requests") or capture.get("observed_endpoints") or []):
        upsert_request_response(scan_id, {**item, "source": "browser", "response": item.get("response") or {}})
    return capture
