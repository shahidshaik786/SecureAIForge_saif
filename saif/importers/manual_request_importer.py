from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin, urlparse

from saif.core.request_map import body_shape_from_body, upsert_request_response


def import_manual_request(scan_id: int, raw_request: str | Path, target_url: str) -> dict:
    text = Path(raw_request).read_text(encoding="utf-8", errors="replace") if isinstance(raw_request, Path) or Path(str(raw_request)).exists() else str(raw_request)
    head, _, body = text.replace("\r\n", "\n").partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise ValueError("manual request is empty")
    first = lines[0].split()
    method = first[0].upper()
    path = first[1] if len(first) > 1 else "/"
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    url = path if path.startswith(("http://", "https://")) else urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
    return upsert_request_response(
        scan_id,
        {
            "source": "manual",
            "method": method,
            "url": url,
            "headers": headers,
            "content_type": headers.get("content-type") or headers.get("Content-Type"),
            "body": body,
            "body_shape": body_shape_from_body(body),
            "auth_attached": bool(headers.get("Authorization") or headers.get("Cookie")),
            "response": {},
        },
    )
