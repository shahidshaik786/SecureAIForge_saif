from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlunparse


REJECT_TOKENS = [
    "/*",
    "*/",
    "licensed under",
    "apache license",
    "fallback of ie",
    "import {",
    "export ",
    "function ",
    "const ",
    "let ",
    "var ",
    "window.",
    "document.",
    "service worker",
    "sourcemappingurl",
]


@dataclass(frozen=True)
class SanitizedEndpoint:
    url: str
    method: str = "GET"
    source: str = "unknown"
    confidence: str = "medium"
    candidate_type: str = "api_route"


def sanitize_candidate_endpoint(raw: str, base_url: str, source: str = "unknown") -> SanitizedEndpoint | None:
    value = str(raw or "").strip()
    if not value:
        return None
    if len(value) > 200:
        return None
    lowered = value.lower()
    if any(char in value for char in ["\n", "\r", "\t", " ", '"', "'", "`"]):
        return None
    if "\\" in value:
        return None
    if any(token in lowered for token in REJECT_TOKENS) or _contains_js_line_comment(value):
        return None
    value = value.rstrip(".,;:)]}")
    if not (value.startswith("/") or value.startswith("http://") or value.startswith("https://")):
        return None
    try:
        parsed = urlparse(urljoin(base_url.rstrip("/") + "/", value) if value.startswith("/") else value)
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    path = parsed.path or "/"
    if len([segment for segment in path.split("/") if segment]) > 20:
        return None
    if _looks_like_code(path):
        return None
    query = parsed.query if _valid_query(parsed.query) else ""
    url = urlunparse((parsed.scheme, parsed.netloc, path, "", query, ""))
    return SanitizedEndpoint(url=url, source=source, confidence=_confidence_for_path(path), candidate_type=_candidate_type(path))


def rejection_sample(raw: str, source: str = "unknown") -> dict:
    value = str(raw or "")
    return {"raw_preview": value[:120], "reject_reason": _reject_reason(value), "source": source}


def _reject_reason(value: str) -> str:
    lowered = value.lower()
    if any(char in value for char in ["\n", "\r", "\t"]):
        return "contains_control_whitespace"
    if len(value) > 200:
        return "too_long"
    if any(token in lowered for token in REJECT_TOKENS) or _contains_js_line_comment(value):
        return "looks_like_source_or_comment"
    if " " in value:
        return "contains_spaces"
    return "not_a_safe_endpoint"


def _valid_query(query: str) -> bool:
    if not query:
        return False
    return not any(token in query.lower() for token in REJECT_TOKENS) and "\n" not in query and "\r" not in query


def _looks_like_code(path: str) -> bool:
    lowered = path.lower()
    if re.search(r"[{};=<>]", path):
        return True
    return any(token in lowered for token in ["import", "function", "window.", "document.", "licensed"])


def _contains_js_line_comment(value: str) -> bool:
    parsed = urlparse(value if "://" in value else f"//local{value}")
    path = parsed.path or value
    return "//" in path


def _confidence_for_path(path: str) -> str:
    lowered = path.lower()
    if any(token in lowered for token in ["/api/", "/identity/", "/community/", "/workshop/", "swagger", "openapi"]):
        return "high"
    return "medium"


def _candidate_type(path: str) -> str:
    lowered = path.lower()
    if any(token in lowered for token in ["login", "signup", "register", "auth", "token"]):
        return "auth_workflow"
    if any(token in lowered for token in ["/api/", "/identity/", "/community/", "/workshop/"]):
        return "api_route"
    return "profile_hint"
