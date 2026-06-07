from __future__ import annotations

from sqlalchemy.orm import Session

from saif.ai.advisor import ask_ai_for_payload_strategy
from saif.db.models import Scan


def choose_payload_strategy(
    session: Session,
    scan: Scan,
    *,
    request_template: dict,
    response_analysis: dict,
    parameter_classification: list[dict],
    selected_categories: list[str],
    previous_attempts: list[dict] | None = None,
) -> dict:
    endpoint = request_template.get("url") or ""
    evidence = {
        "request_ids": [request_template.get("request_id")] if request_template.get("request_id") else [],
        "request_template": request_template,
        "response_analysis": response_analysis,
        "parameter_classification": parameter_classification,
        "selected_categories": selected_categories,
        "previous_attempts": previous_attempts or [],
    }
    result = ask_ai_for_payload_strategy(
        session,
        scan,
        current_phase="controlled_payload_execution",
        scope={"target": endpoint, "allowed_hosts": []},
        evidence=evidence,
        discovered_endpoints={endpoint} if endpoint else set(),
        endpoint=endpoint,
        destructive_allowed=bool(getattr(scan, "enable_destructive_tests", False)),
    )
    if not result.get("approved"):
        return {"status": "fallback", "payloads": [], "reason": result.get("reason"), "ai_validation": result}
    decision = result.get("decision") or {}
    return {"status": "accepted", "family": decision.get("next_payload_strategy"), "payloads": [decision.get("next_payload")] if decision.get("next_payload") else [], "ai_validation": result}
