from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from saif.ai.advisor import ask_ai_for_phase_decision
from saif.db.models import Scan


INSTALL_PLAN_SCHEMA = {
    "type": "object",
    "required": ["tool", "commands", "verify_commands", "rationale"],
    "properties": {
        "tool": {"type": "string"},
        "commands": {"type": "array", "items": {"type": "string"}},
        "verify_commands": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
        "fallback": {"type": "string"},
    },
}


def install_plan_contract(*, tool: str, capability: str, phase: str, scope: dict, evidence: dict) -> dict:
    return {
        "current_phase": phase,
        "scope": scope,
        "evidence_packet": evidence,
        "allowed_actions": ["recommend_open_source_tool_install_commands", "recommend_verify_commands"],
        "forbidden_actions": ["execute_commands", "modify_scan_scope", "delete_files", "exfiltrate_data", "invent_required_capability"],
        "json_schema": INSTALL_PLAN_SCHEMA,
        "timeout": "profile_runtime_timeout",
        "retry_limit": "SAIF_TOOL_INSTALL_MAX_RETRIES",
        "request": {
            "tool": tool,
            "capability": capability,
            "instruction": "Return only a JSON install plan. SAIF will validate and execute commands outside Ollama.",
        },
    }


def ask_ollama_for_install_plan(
    session: Session | None,
    scan: Scan | None,
    *,
    tool: str,
    capability: str,
    phase: str,
    scope: dict,
    evidence: dict,
) -> dict:
    if session is None or scan is None:
        return {}
    contract = install_plan_contract(tool=tool, capability=capability, phase=phase, scope=scope, evidence=evidence)
    decision = ask_ai_for_phase_decision(
        session,
        scan,
        current_phase=phase,
        scope=scope,
        evidence=contract,
        allowed_actions=contract["allowed_actions"],
        output_schema=INSTALL_PLAN_SCHEMA,
    )
    payload = decision.get("decision") if isinstance(decision, dict) else {}
    return _extract_install_plan(payload, tool)


def _extract_install_plan(payload: Any, tool: str) -> dict:
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            return {}
    if not isinstance(payload, dict):
        return {}
    plan = payload.get("install_plan") if isinstance(payload.get("install_plan"), dict) else payload
    commands = [str(item).strip() for item in plan.get("commands") or plan.get("install_commands") or [] if str(item).strip()]
    verify = [str(item).strip() for item in plan.get("verify_commands") or plan.get("verification_commands") or [] if str(item).strip()]
    if str(plan.get("tool") or tool).strip().lower() != tool.strip().lower():
        return {}
    if not commands:
        return {}
    return {"tool": tool, "commands": commands, "verify_commands": verify, "rationale": str(plan.get("rationale") or plan.get("reason") or "")}
