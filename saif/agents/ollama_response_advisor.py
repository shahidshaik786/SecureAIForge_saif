from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy.orm import Session

from saif.ai.advisor import _ask_guarded_ai
from saif.analyzers.passive_analyzer import is_important_for_ai
from saif.db.models import Scan


RESPONSE_SCHEMA = {
    "decision": "string",
    "reason": "string",
    "confidence": "high|medium|low",
    "next_action": "crawl_more|replay_exact|compare_user2|mutate_parameter|test_content_type|test_method|schedule_payload_family|stop",
    "response_classification": "login_response|session_change|api_data|redirect|error|object_response|state_change|static|documentation|unknown",
    "interesting_signals": [],
    "security_relevance": "high|medium|low",
    "auth_relevance": "none|possible|confirmed",
    "authorization_relevance": "none|possible|high",
    "object_candidates": [],
    "parameter_candidates": [],
    "next_actions": [],
    "payload_strategy": [],
}


def review_important_response(
    session: Session,
    scan: Scan,
    *,
    request_record: dict,
    phase: str,
    selected_categories: list[str] | None = None,
    source: str = "tool",
) -> dict:
    if not is_important_for_ai(request_record):
        return {"skipped": True, "reason": "response not important enough for AI advisor"}
    endpoint = request_record.get("url") or ""
    evidence = response_evidence_packet(request_record, phase=phase, selected_categories=selected_categories or [], source=source)
    allowed = [
        "crawl_more",
        "replay_exact",
        "compare_user2",
        "mutate_parameter",
        "test_content_type",
        "test_method",
        "schedule_payload_family",
        "stop",
    ]
    return _ask_guarded_ai(
        session,
        scan,
        stage="response_advisor",
        current_phase=phase,
        scope=_scope(endpoint),
        evidence=evidence,
        allowed_actions=allowed,
        output_schema=RESPONSE_SCHEMA,
        discovered_endpoints={endpoint} if endpoint else set(),
        endpoint=endpoint or None,
        destructive_allowed=False,
    )


def response_evidence_packet(record: dict, *, phase: str, selected_categories: list[str], source: str) -> dict:
    response = record.get("response") or {}
    return {
        "request_ids": [record.get("request_id")] if record.get("request_id") else [],
        "request": {
            "method": record.get("method"),
            "url": record.get("url"),
            "headers_summary": _headers_summary(record.get("headers") or {}),
            "content_type": record.get("content_type"),
            "body_shape": record.get("body_shape") or {},
        },
        "response": {
            "status": response.get("status"),
            "headers_summary": {},
            "content_type": response.get("content_type"),
            "body_length": response.get("body_length"),
            "body_markers": response.get("markers") or [],
            "redirect_location": response.get("redirect_location"),
            "set_cookie": bool(response.get("set_cookie")),
            "body_sample_safe": "",
        },
        "context": {"phase": phase, "selected_categories": selected_categories, "known_auth_material": bool(record.get("auth_attached")), "source": source},
        "selected_categories": selected_categories,
        "raw_evidence_refs": [record.get("request_id")] if record.get("request_id") else [],
    }


def _headers_summary(headers: dict) -> dict:
    return {
        "authorization": bool(headers.get("authorization") or headers.get("Authorization")),
        "cookie": bool(headers.get("cookie") or headers.get("Cookie")),
        "content_type": headers.get("content-type") or headers.get("Content-Type"),
    }


def _scope(url: str) -> dict:
    parsed = urlparse(url)
    return {"target": url, "allowed_hosts": [parsed.hostname] if parsed.hostname else []}
