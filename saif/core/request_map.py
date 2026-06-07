from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from saif.ai.tracing import mask_secrets
from saif.config import get_settings


SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}


def upsert_request_response(scan_id: int, item: dict) -> dict:
    request = normalize_request(item)
    request_id = request["request_id"]
    path = request_map_path(scan_id)
    existing = load_request_map(scan_id)
    rows = existing.get("requests") or []
    merged = False
    now = _now()
    for row in rows:
        if row.get("request_id") == request_id:
            row["last_seen_at"] = now
            row["seen_count"] = int(row.get("seen_count") or 1) + 1
            row["tags"] = sorted(set(row.get("tags") or []) | set(request.get("tags") or []))
            row["ollama_analysis_refs"] = sorted(set(row.get("ollama_analysis_refs") or []) | set(request.get("ollama_analysis_refs") or []))
            row["agent_reaction_refs"] = sorted(set(row.get("agent_reaction_refs") or []) | set(request.get("agent_reaction_refs") or []))
            if request.get("response"):
                row["response"] = request["response"]
            merged = True
            request = row
            break
    if not merged:
        rows.append(request)
    payload = {"scan_id": scan_id, "generated_at": now, "total_requests": len(rows), "requests": rows}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(mask_secrets(payload), indent=2, sort_keys=True, default=str), encoding="utf-8")
    return request


def load_request_map(scan_id: int) -> dict:
    path = request_map_path(scan_id)
    if not path.exists():
        return {"scan_id": scan_id, "generated_at": _now(), "total_requests": 0, "requests": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"scan_id": scan_id, "generated_at": _now(), "total_requests": 0, "requests": []}
    if not isinstance(data, dict):
        return {"scan_id": scan_id, "generated_at": _now(), "total_requests": 0, "requests": []}
    data.setdefault("requests", [])
    data["total_requests"] = len(data.get("requests") or [])
    return data


def request_map_path(scan_id: int) -> Path:
    return get_settings().evidence_dir / f"scan-{scan_id}" / "request_map.json"


def normalize_request(item: dict) -> dict:
    method = str(item.get("method") or "GET").upper()
    url = str(item.get("url") or "")
    parsed = urlparse(url)
    path = parsed.path or "/"
    headers = _mask_headers(item.get("headers") or {})
    response = item.get("response") or {}
    content_type = str(item.get("content_type") or headers.get("content-type") or headers.get("Content-Type") or "")
    body_shape = item.get("body_shape") or body_shape_from_body(item.get("body"))
    request_id = item.get("request_id") or _request_id(method, url, body_shape, content_type)
    now = _now()
    tag_set = set(item.get("tags") or []) | infer_tags(method, url, headers, item.get("body"), response)
    tags = sorted(tag_set)
    return {
        "request_id": request_id,
        "source": str(item.get("source") or "tool"),
        "method": method,
        "url": url,
        "path": path,
        "query_params": {key: values for key, values in parse_qs(parsed.query, keep_blank_values=True).items()},
        "path_params": _path_params(path),
        "headers": headers,
        "content_type": content_type,
        "body_shape": body_shape,
        "auth_attached": bool(item.get("auth_attached") or headers.get("authorization") or headers.get("Authorization") or headers.get("cookie") or headers.get("Cookie")),
        "cookies_present": bool(headers.get("cookie") or headers.get("Cookie")),
        "csrf_present": _csrf_present(headers, item.get("body")),
        "response": normalize_response(response),
        "tags": tags,
        "ollama_analysis_refs": list(item.get("ollama_analysis_refs") or []),
        "agent_reaction_refs": list(item.get("agent_reaction_refs") or []),
        "tested": bool(item.get("tested") or False),
        "risk_relevance": item.get("risk_relevance") or _risk_relevance(tag_set),
        "first_seen_at": item.get("first_seen_at") or now,
        "last_seen_at": now,
        "seen_count": int(item.get("seen_count") or 1),
    }


def normalize_response(response: dict) -> dict:
    headers = response.get("headers") or {}
    content_type = str(response.get("content_type") or headers.get("content-type") or headers.get("Content-Type") or "")
    body = str(response.get("body") or response.get("body_preview") or "")
    return {
        "status": response.get("status") if response.get("status") is not None else response.get("status_code"),
        "content_type": content_type,
        "body_hash": hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest() if body else "",
        "body_length": int(response.get("body_length") or len(body)),
        "redirect_location": response.get("redirect_location") or headers.get("location") or headers.get("Location"),
        "set_cookie": bool(response.get("set_cookie") or headers.get("set-cookie") or headers.get("Set-Cookie")),
        "markers": sorted(set(response.get("markers") or _body_markers(body, content_type))),
    }


def body_shape_from_body(body) -> dict:
    if body is None or body == "":
        return {"type": "empty"}
    if isinstance(body, dict):
        return {"type": "json", "keys": sorted(str(key) for key in body.keys())}
    text = str(body)
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return {"type": "json", "keys": sorted(str(key) for key in parsed.keys())}
        if isinstance(parsed, list):
            return {"type": "json_array", "length": len(parsed)}
    except Exception:
        pass
    if "=" in text and "&" in text:
        return {"type": "form", "keys": sorted(parse_qs(text).keys())}
    return {"type": "raw", "length": len(text), "sha256": hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]}


def infer_tags(method: str, url: str, headers: dict, body, response: dict) -> set[str]:
    parsed = urlparse(url)
    lowered = f"{parsed.path}?{parsed.query}".lower()
    tags: set[str] = set()
    content_type = str(headers.get("content-type") or headers.get("Content-Type") or response.get("content_type") or "").lower()
    status = response.get("status") if response.get("status") is not None else response.get("status_code")
    if "json" in content_type or "/api/" in lowered:
        tags.add("api")
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        tags.add("state_changing")
    if any(token in lowered for token in ["login", "signin", "auth", "session", "oauth", "saml"]):
        tags.add("auth_related")
    if any(token in lowered for token in ["admin", "role", "permission"]):
        tags.add("role_sensitive")
    if re.search(r"/(?:[0-9]{2,}|[0-9a-f]{8,}(?:-[0-9a-f]{4,})+)(?:/|$)", parsed.path, re.I) or any(key in lowered for key in ["id=", "user=", "account=", "tenant="]):
        tags.add("object_id")
    if status and int(status) in {301, 302, 303, 307, 308}:
        tags.add("redirect")
    if status and int(status) >= 400:
        tags.add("error")
    if response.get("set_cookie"):
        tags.add("session_change")
    if response.get("body_length") or response.get("body_preview") or response.get("body"):
        tags.add("data_returning")
    if body:
        tags.add("parameterized")
    return tags


def _request_id(method: str, url: str, body_shape: dict, content_type: str) -> str:
    parsed = urlparse(url)
    normalized_query = urlencode(sorted(parse_qs(parsed.query, keep_blank_values=True).items()), doseq=True)
    normalized_url = urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", normalized_query, ""))
    raw = json.dumps({"method": method.upper(), "url": normalized_url, "body_shape": body_shape, "content_type": content_type}, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _mask_headers(headers: dict) -> dict:
    return {key: ("<masked>" if str(key).lower() in SECRET_HEADERS else value) for key, value in dict(headers or {}).items()}


def _path_params(path: str) -> list[str]:
    return re.findall(r"/([0-9]{2,}|[0-9a-f]{8,}(?:-[0-9a-f]{4,})+)(?=/|$)", path, re.I)


def _csrf_present(headers: dict, body) -> bool:
    text = json.dumps(body, default=str).lower() if isinstance(body, (dict, list)) else str(body or "").lower()
    return any(token in text for token in ["csrf", "_token", "xsrf"]) or any("csrf" in str(key).lower() or "xsrf" in str(key).lower() for key in headers.keys())


def _body_markers(body: str, content_type: str) -> list[str]:
    lowered = str(body or "")[:4000].lower()
    markers = []
    for token in ["login", "csrf", "jwt", "token", "email", "username", "role", "admin", "error", "stack", "graphql", "swagger", "openapi"]:
        if token in lowered or token in str(content_type).lower():
            markers.append(token)
    return markers


def _risk_relevance(tags: set[str]) -> str:
    if tags & {"object_id", "role_sensitive", "state_changing", "session_change"}:
        return "high"
    if tags & {"api", "parameterized", "error", "auth_related"}:
        return "medium"
    return "low"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
