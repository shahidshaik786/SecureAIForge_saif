from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse


def analyze_request_response(record: dict) -> dict:
    request = record or {}
    response = request.get("response") or {}
    headers = request.get("headers") or {}
    tags = set(request.get("tags") or [])
    observations = []
    candidates = []
    markers = set(response.get("markers") or [])
    body_markers = set(markers)
    path = str(request.get("path") or urlparse(str(request.get("url") or "")).path or "").lower()
    method = str(request.get("method") or "GET").upper()
    if request.get("auth_attached"):
        observations.append({"type": "auth_material_attached", "confidence": "high"})
    if response.get("set_cookie"):
        observations.append({"type": "session_cookie_set", "confidence": "high"})
        tags.add("session_change")
    if "csrf" in body_markers or any("csrf" in str(key).lower() for key in headers.keys()):
        observations.append({"type": "csrf_token_observed", "confidence": "medium"})
        tags.add("auth_related")
    if response.get("status") and int(response.get("status")) >= 500:
        observations.append({"type": "server_error_or_stack_trace_candidate", "confidence": "medium"})
        candidates.append({"family": "error_disclosure", "reason": "server error response"})
    if re.search(r"/(?:admin|role|permission|users?)(?:/|$)", path):
        tags.add("role_sensitive")
        candidates.append({"family": "bfla", "reason": "role/function-sensitive path"})
    if "object_id" in tags:
        candidates.append({"family": "bola", "reason": "object identifier observed"})
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        tags.add("state_changing")
        candidates.append({"family": "business_logic", "reason": "state-changing request"})
    if any(key in str(request.get("query_params") or {}).lower() for key in ["redirect", "url", "next", "return"]):
        candidates.append({"family": "open_redirect", "reason": "redirect-like parameter"})
    return {"tags": sorted(tags), "observations": observations, "candidate_tests": candidates, "evidence_refs": [request.get("request_id")] if request.get("request_id") else []}


def is_important_for_ai(record: dict) -> bool:
    response = record.get("response") or {}
    tags = set(record.get("tags") or [])
    status = response.get("status")
    content_type = str(response.get("content_type") or "").lower()
    if tags & {"auth_related", "session_change", "object_id", "state_changing", "role_sensitive", "parameterized", "error"}:
        return True
    if response.get("set_cookie") or response.get("redirect_location"):
        return True
    if status and (int(status) >= 400 or int(status) in {301, 302, 303, 307, 308}):
        return True
    if "json" in content_type or "openapi" in content_type or "swagger" in content_type:
        return True
    return False
