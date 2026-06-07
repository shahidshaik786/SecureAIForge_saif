from __future__ import annotations

from saif.browser_agent.browser_authenticated_capture import capture_authenticated_browser_traffic


def capture_har(scan_id: int, target_url: str, storage_state: str | None = None) -> dict:
    return capture_authenticated_browser_traffic(scan_id, target_url, storage_state=storage_state)
