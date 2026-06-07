from __future__ import annotations

from saif.browser_agent.browser_authenticated_capture import capture_authenticated_browser_traffic


def login_and_capture(scan_id: int, target_url: str, storage_state: str | None = None, manual_login: bool = False) -> dict:
    return capture_authenticated_browser_traffic(scan_id, target_url, storage_state=storage_state, manual_login=manual_login)
