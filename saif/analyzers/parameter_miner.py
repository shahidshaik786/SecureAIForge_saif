from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlparse


SECURITY_TAGS = {
    "id": "object_id",
    "user": "user_id",
    "owner": "user_id",
    "role": "role",
    "permission": "permission",
    "price": "price",
    "quantity": "quantity",
    "redirect": "redirect",
    "return": "redirect",
    "next": "redirect",
    "url": "url",
    "uri": "url",
    "file": "file",
    "path": "path",
    "email": "email",
    "phone": "phone",
    "token": "token",
}


def mine_parameters(record: dict) -> list[dict]:
    params: list[dict] = []
    request_id = record.get("request_id")
    parsed = urlparse(str(record.get("url") or ""))
    for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        params.append(_param(name, "query", values[0] if values else "", request_id, "high"))
    for value in record.get("path_params") or []:
        params.append(_param("path_id", "path", value, request_id, "medium"))
    headers = record.get("headers") or {}
    for name in headers.keys():
        if any(token in str(name).lower() for token in ["csrf", "xsrf", "token", "role"]):
            params.append(_param(str(name), "header", headers.get(name), request_id, "medium"))
    body_shape = record.get("body_shape") or {}
    for name in body_shape.get("keys") or []:
        params.append(_param(str(name), "json" if body_shape.get("type") == "json" else "form", "", request_id, "medium"))
    return params


def _param(name: str, location: str, value, request_id: str | None, confidence: str) -> dict:
    lowered = name.lower()
    tags = sorted({tag for token, tag in SECURITY_TAGS.items() if token in lowered})
    return {
        "name": name,
        "location": location,
        "type_guess": _type_guess(value, name),
        "security_tags": tags,
        "source_request_id": request_id,
        "confidence": confidence,
    }


def _type_guess(value, name: str) -> str:
    text = str(value or "")
    if re.fullmatch(r"[0-9]+", text):
        return "number"
    if re.fullmatch(r"[0-9a-f]{8,}(?:-[0-9a-f]{4,})+", text, re.I):
        return "uuid"
    if str(name).lower() in {"file", "upload"}:
        return "file"
    if str(name).lower().startswith(("is", "has", "allow")):
        return "boolean"
    return "string" if text else "unknown"
