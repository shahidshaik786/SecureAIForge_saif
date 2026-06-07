from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from saif.ai.runtime import runtime_for_stage
from saif.config import get_settings


SECRET_KEYS = {"password", "authorization", "cookie", "set-cookie", "secret", "token", "jwt", "bearer", "api_key", "apikey"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stage_timeout(stage: str, default_timeout: int | None = None) -> int:
    return runtime_for_stage(stage).per_attempt_timeout_seconds


def begin_ai_trace(
    scan_id: int | None,
    *,
    stage: str,
    phase: str,
    agent: str,
    model: str,
    base_url: str,
    timeout_seconds: int,
    system_prompt: str,
    user_prompt: str,
    messages: list[dict] | None = None,
    options: dict | None = None,
    evidence_packet: dict | None = None,
) -> dict:
    settings = get_settings()
    runtime = runtime_for_stage(stage)
    ai_call_id = f"{uuid.uuid4().hex[:12]}-{_safe_name(stage)}"
    started_at = utc_now()
    request = {
        "system_prompt": system_prompt if settings.store_full_ai_prompts else _truncate(system_prompt),
        "user_prompt": user_prompt if settings.store_full_ai_prompts else _truncate(user_prompt),
        "messages": mask_secrets(messages or []),
        "options": options or {},
        "full_prompt_text": f"{system_prompt}\n\n{user_prompt}" if settings.store_full_ai_prompts else _truncate(f"{system_prompt}\n\n{user_prompt}"),
        "prompt_size_chars": len(system_prompt) + len(user_prompt),
    }
    safe_evidence = _evidence_packet(evidence_packet or {})
    prompt_hash = sha256_json(request)
    evidence_hash = sha256_json(safe_evidence)
    payload = {
        "ai_call_id": ai_call_id,
        "scan_id": scan_id,
        "stage": stage,
        "phase": phase,
        "agent": agent,
        "tool": "ollama",
        "model": model,
        "base_url": base_url,
        "ollama_profile": runtime.profile,
        "status": "started",
        "started_at": started_at,
        "completed_at": None,
        "duration_ms": 0,
        "timeout_seconds": timeout_seconds,
        "per_attempt_timeout_seconds": runtime.per_attempt_timeout_seconds,
        "total_budget_seconds": runtime.total_budget_seconds,
        "max_attempts": runtime.max_attempts,
        "attempts_used": 0,
        "request_to_ollama": request,
        "evidence_sent_to_ollama": safe_evidence,
        "raw_ollama_response": "",
        "parsed_ollama_response": {},
        "schema_validation": {"valid": False, "errors": []},
        "guardrail_validation": {"accepted": False, "rejected_reasons": [], "normalized_decision": {}},
        "agent_reaction": _default_agent_reaction(agent),
        "hashes": {"prompt_sha256": prompt_hash, "response_sha256": "", "evidence_packet_sha256": evidence_hash},
    }
    payload["request_to_ollama"]["prompt_sha256"] = prompt_hash
    path = None
    if scan_id is not None and settings.ai_debug and settings.ai_trace_every_call:
        directory = _ai_dir(scan_id)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = directory / f"{timestamp}-{_safe_name(stage)}-{_safe_name(agent)}-{ai_call_id}.json"
        _write_json(path, payload)
    return {"ai_call_id": ai_call_id, "path": path, "payload": payload, "started_perf": time.perf_counter()}


def complete_ai_trace(
    trace: dict | None,
    *,
    status: str,
    raw_response: str = "",
    parsed_response: dict | None = None,
    schema_valid: bool = False,
    schema_errors: list[str] | None = None,
    accepted: bool = False,
    rejected_reasons: list[str] | None = None,
    normalized_decision: dict | None = None,
    agent_reaction: dict | None = None,
    attempts_used: int | None = None,
    used_for_execution: bool = False,
    used_as_advisory: bool = True,
) -> dict:
    if not trace:
        return {}
    payload = dict(trace.get("payload") or {})
    duration_ms = int((time.perf_counter() - float(trace.get("started_perf") or time.perf_counter())) * 1000)
    response_text = raw_response if get_settings().store_full_ai_responses else _truncate(raw_response)
    reaction = _default_agent_reaction(str(payload.get("agent") or "ai_advisor_agent")) | (agent_reaction or {})
    payload.update(
        {
            "status": status,
            "completed_at": utc_now(),
            "duration_ms": duration_ms,
            "attempts_used": int(attempts_used if attempts_used is not None else payload.get("attempts_used") or 0),
            "raw_ollama_response": mask_secrets(response_text),
            "parsed_ollama_response": mask_secrets(parsed_response or {}),
            "schema_validation": {"valid": schema_valid, "errors": schema_errors or []},
            "guardrail_validation": {
                "accepted": accepted,
                "rejected_reasons": rejected_reasons or [],
                "normalized_decision": mask_secrets(normalized_decision or parsed_response or {}),
            },
            "agent_reaction": mask_secrets(reaction),
            "hashes": {
                **(payload.get("hashes") or {}),
                "response_sha256": hashlib.sha256(str(raw_response or "").encode("utf-8", errors="ignore")).hexdigest(),
            },
        }
    )
    path = trace.get("path")
    scan_id = payload.get("scan_id")
    if path:
        _write_json(Path(path), payload)
        payload["trace_path"] = str(path)
    if scan_id is not None:
        append_ai_trace_index(
            int(scan_id),
            {
                "ai_call_id": payload.get("ai_call_id"),
                "stage": payload.get("stage"),
                "phase": payload.get("phase"),
                "agent": payload.get("agent"),
                "status": status,
                "accepted": accepted,
                "used_for_execution": used_for_execution,
                "used_as_advisory": used_as_advisory,
                "duration_ms": duration_ms,
                "attempts_used": payload.get("attempts_used"),
                "per_attempt_timeout_seconds": payload.get("per_attempt_timeout_seconds"),
                "total_budget_seconds": payload.get("total_budget_seconds"),
                "prompt_hash": (payload.get("hashes") or {}).get("prompt_sha256"),
                "response_hash": (payload.get("hashes") or {}).get("response_sha256"),
                "trace_path": str(path) if path else None,
            },
        )
        if get_settings().store_agent_reactions:
            append_agent_reaction(int(scan_id), payload, accepted=accepted, rejected_reasons=rejected_reasons or [])
    trace["payload"] = payload
    return payload


def append_ai_trace_index(scan_id: int, entry: dict) -> None:
    directory = _ai_dir(scan_id)
    index_path = directory / "ai_trace_index.json"
    try:
        existing = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else {}
    except Exception:
        existing = {}
    if isinstance(existing, list):
        calls = existing
    else:
        calls = list(existing.get("calls") or [])
    calls.append(mask_secrets(entry))
    payload = {"scan_id": scan_id, "ai_debug_enabled": get_settings().ai_debug, "ollama_profile": get_settings().ollama_profile, "total_ai_calls": len(calls), "calls": calls}
    _write_json(index_path, payload)


def append_agent_reaction(scan_id: int, trace_payload: dict, *, accepted: bool, rejected_reasons: list[str]) -> Path:
    path = get_settings().evidence_dir / f"scan-{scan_id}" / "agent_reactions.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    reaction = trace_payload.get("agent_reaction") or {}
    row = {
        "time": utc_now(),
        "scan_id": scan_id,
        "ai_call_id": trace_payload.get("ai_call_id"),
        "agent": trace_payload.get("agent"),
        "stage": trace_payload.get("stage"),
        "ollama_decision_summary": _decision_summary(trace_payload.get("parsed_ollama_response") or {}),
        "accepted": accepted,
        "rejected": not accepted,
        "rejected_reasons": rejected_reasons,
        "action_taken": reaction.get("action_taken") or "fallback",
        "action_details": reaction.get("action_details") or {},
        "selected_categories_checked": (trace_payload.get("evidence_sent_to_ollama") or {}).get("selected_categories") or [],
        "prerequisites_checked": reaction.get("prerequisites_checked") or [],
        "scope_check": reaction.get("scope_check") or ("not_evaluated_timeout" if "ollama_timeout" in rejected_reasons else "passed" if accepted else "failed"),
        "policy_check": reaction.get("policy_check") or ("not_evaluated_timeout" if "ollama_timeout" in rejected_reasons else "passed" if accepted else "failed"),
        "selected_category_check": reaction.get("selected_category_check") or ("not_evaluated_timeout" if "ollama_timeout" in rejected_reasons else "passed" if accepted else "failed"),
        "prerequisite_check": reaction.get("prerequisite_check") or ("not_evaluated_timeout" if "ollama_timeout" in rejected_reasons else "passed" if accepted else "failed"),
        "evidence_refs": (trace_payload.get("evidence_sent_to_ollama") or {}).get("raw_evidence_refs") or [],
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(mask_secrets(row), sort_keys=True, default=str) + "\n")
    return path


def mask_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(secret in lowered for secret in SECRET_KEYS):
                result[key] = "<masked>"
            else:
                result[key] = mask_secrets(item)
        return result
    if isinstance(value, list):
        return [mask_secrets(item) for item in value[:500]]
    if isinstance(value, str):
        if "Bearer " in value or value.startswith("eyJ") or "access_token" in value.lower():
            return "<masked_secret_ref>"
        return value
    return value


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(mask_secrets(value), sort_keys=True, default=str).encode("utf-8", errors="ignore")).hexdigest()


def _ai_dir(scan_id: int) -> Path:
    directory = get_settings().evidence_dir / f"scan-{scan_id}" / "ai"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _evidence_packet(evidence: dict) -> dict:
    safe = mask_secrets(evidence)
    return {
        "request_ids": safe.get("request_ids") or safe.get("next_request_ids") or [],
        "response_ids": safe.get("response_ids") or [],
        "tool_outputs": safe.get("tool_outputs") or [],
        "summaries": safe.get("summaries") or {k: v for k, v in safe.items() if k not in {"raw", "body", "body_sample_safe"}},
        "raw_evidence_refs": safe.get("raw_evidence_refs") or safe.get("evidence_ids") or [],
        "selected_categories": safe.get("selected_categories") or [],
        "allowed_actions": safe.get("allowed_actions") or [],
        "forbidden_actions": safe.get("forbidden_actions") or [],
        "scope": safe.get("scope") or {},
    }


def _default_agent_reaction(agent: str) -> dict:
    return {
        "agent_name": agent,
        "accepted_ollama_suggestion": False,
        "rejected_ollama_suggestion": False,
        "reason": "",
        "action_taken": "none",
        "action_details": {},
        "next_request_ids": [],
        "next_tool_names": [],
        "payloads_selected": [],
        "payloads_rejected": [],
        "why_payloads_selected": "",
        "why_payloads_rejected": "",
    }


def _decision_summary(decision: dict) -> str:
    if not decision:
        return ""
    return str(decision.get("decision") or decision.get("response_classification") or decision.get("reason") or "")[:500]


def _truncate(value: str, limit: int = 4000) -> str:
    return value if len(value) <= limit else value[:limit] + "\n...[truncated]"


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value or ""))[:100] or "ai"
