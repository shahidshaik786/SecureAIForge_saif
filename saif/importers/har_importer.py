from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urljoin

from saif.core.request_map import body_shape_from_body, upsert_request_response


def import_har(scan_id: int, har_file: str | Path, target_url: str | None = None) -> list[dict]:
    path = Path(har_file)
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    entries = ((data.get("log") or {}).get("entries") or []) if isinstance(data, dict) else []
    records = []
    for entry in entries:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = request.get("url") or ""
        if target_url and url.startswith("/"):
            url = urljoin(target_url.rstrip("/") + "/", url.lstrip("/"))
        headers = {item.get("name"): item.get("value") for item in request.get("headers") or [] if item.get("name")}
        response_headers = {item.get("name"): item.get("value") for item in response.get("headers") or [] if item.get("name")}
        post_data = request.get("postData") or {}
        body = post_data.get("text") or ""
        content = response.get("content") or {}
        record = upsert_request_response(
            scan_id,
            {
                "source": "har",
                "method": request.get("method") or "GET",
                "url": url,
                "headers": headers,
                "content_type": post_data.get("mimeType") or headers.get("content-type"),
                "body": body,
                "body_shape": body_shape_from_body(body),
                "response": {
                    "status": response.get("status"),
                    "headers": response_headers,
                    "content_type": content.get("mimeType") or response_headers.get("content-type"),
                    "body_length": content.get("size") or len(str(content.get("text") or "")),
                    "body_preview": str(content.get("text") or "")[:4000],
                    "redirect_location": response.get("redirectURL") or response_headers.get("location"),
                    "set_cookie": bool(response.get("cookies") or response_headers.get("set-cookie")),
                },
            },
        )
        records.append(record)
    return records
