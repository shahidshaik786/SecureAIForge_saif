from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from saif.ai.ollama import OllamaClient
from saif.ai.tracing import begin_ai_trace, complete_ai_trace, mask_secrets, stage_timeout
from saif.config import get_settings
from saif.db.models import AiCallRun, AiDecision, Evidence, Log, Scan
from saif.services.pentest_engine import ai_decision_contract, validate_ai_decision


def ask_ai_for_phase_decision(
    session: Session | None,
    scan: Scan | None,
    *,
    current_phase: str,
    evidence: dict,
    allowed_actions: list[str],
    discovered_endpoints: set[str] | None = None,
    endpoint: str | None = None,
    scope: dict | None = None,
    destructive_allowed: bool = False,
    client: OllamaClient | None = None,
    output_schema: dict | None = None,
) -> dict:
    return _ask_guarded_ai(
        session,
        scan,
        stage=f"phase_decision:{current_phase}",
        current_phase=current_phase,
        scope=scope,
        evidence=evidence,
        allowed_actions=allowed_actions,
        output_schema=output_schema,
        discovered_endpoints=discovered_endpoints,
        endpoint=endpoint,
        destructive_allowed=destructive_allowed,
        client=client,
    )


def ask_ai_for_plan_suggestions(
    *,
    prompt: str,
    target_url: str,
    parsed_intent: dict,
    selected_tools: list[str],
    client: OllamaClient | None = None,
    debug: bool = False,
) -> dict:
    scope = _scope_from_target(target_url)
    evidence = {
        "prompt": prompt[:1200],
        "target": target_url,
        "parsed_intent": parsed_intent,
        "candidate_tools": selected_tools,
    }
    schema = {
        "decision": "plan",
        "reason": "string",
        "confidence": "low|medium|high",
        "next_action": "suggest_test_plan",
        "approved": True,
        "mode": "default-enumeration",
        "target": target_url,
        "environment": "testing",
        "authorized_testing_mode": True,
        "scope_confirmation": "string",
        "tools": selected_tools,
        "test_cases": [],
        "not_applicable": [],
        "missing_prerequisites": [],
    }
    result = _ask_guarded_ai(
        None,
        None,
        stage="initial_planning",
        current_phase="enumeration_strategy",
        scope=scope,
        evidence=evidence,
        allowed_actions=["suggest_test_plan"],
        output_schema=schema,
        client=client,
    )
    decision = result.get("decision") or {}
    if debug:
        print("Guarded AI planning response:")
        print(json.dumps(decision, indent=2, sort_keys=True))
    if not result.get("approved"):
        return {**_fallback_plan(target_url, selected_tools), "ai_planning_status": "warning", "ai_planning_error": result.get("reason"), "ai_available": False, "deterministic_mode": True, "ai_validation": result}
    plan = _normalize_plan_suggestion(decision, target_url, selected_tools)
    plan["ai_validation"] = result
    if not plan.get("approved"):
        plan.update({"ai_planning_status": "warning", "ai_planning_error": plan.get("reason"), "ai_available": False, "deterministic_mode": True, "ai_validation": result})
    return plan


def ask_ai_for_response_analysis(
    session: Session,
    scan: Scan,
    *,
    current_phase: str,
    scope: dict,
    evidence: dict,
    discovered_endpoints: set[str],
    endpoint: str,
) -> dict:
    return _ask_guarded_ai(
        session,
        scan,
        stage="response_review",
        current_phase=current_phase,
        scope=scope,
        evidence=evidence,
        allowed_actions=["classify_endpoint_auth_requirement", "build_request_template", "continue_enumeration", "verify_error_signature_with_baseline"],
        output_schema={
            "decision": "string",
            "reason": "string",
            "confidence": "low|medium|high",
            "next_action": "one of allowed_actions",
            "endpoint": endpoint,
            "signals": [],
        },
        discovered_endpoints=discovered_endpoints,
        endpoint=endpoint,
    )


def ask_ai_for_payload_strategy(
    session: Session,
    scan: Scan,
    *,
    current_phase: str,
    scope: dict,
    evidence: dict,
    discovered_endpoints: set[str],
    endpoint: str,
    destructive_allowed: bool,
    client: OllamaClient | None = None,
) -> dict:
    return _ask_guarded_ai(
        session,
        scan,
        stage="payload_strategy",
        current_phase=current_phase,
        scope=scope,
        evidence=evidence,
        allowed_actions=["verify_candidate", "stop_testing", "run_payload_family"],
        output_schema={
            "decision": "string",
            "reason": "string",
            "confidence": "low|medium|high",
            "next_action": "verify_candidate|stop_testing|run_payload_family",
            "endpoint": endpoint,
            "finding_candidate": False,
            "reportable": False,
            "needs_manual_confirmation": False,
            "next_payload_strategy": "",
            "next_payload": "",
            "stop_condition": "",
        },
        discovered_endpoints=discovered_endpoints,
        endpoint=endpoint,
        destructive_allowed=destructive_allowed,
        client=client,
    )


def ask_ai_for_finding_review(
    session: Session,
    scan: Scan,
    *,
    current_phase: str,
    scope: dict,
    evidence: dict,
    discovered_endpoints: set[str],
    endpoint: str | None = None,
) -> dict:
    return _ask_guarded_ai(
        session,
        scan,
        stage="finding_review",
        current_phase=current_phase,
        scope=scope,
        evidence=evidence,
        allowed_actions=["promote_candidate", "reject_candidate"],
        output_schema={
            "decision": "string",
            "reason": "string",
            "confidence": "low|medium|high",
            "next_action": "promote_candidate|reject_candidate",
            "evidence_ids": [],
            "finding_candidate": False,
        },
        discovered_endpoints=discovered_endpoints,
        endpoint=endpoint,
    )


def ask_ai_for_report_wording(
    session: Session,
    scan: Scan,
    *,
    current_phase: str,
    scope: dict,
    evidence: dict,
    stage: str = "report_wording",
) -> dict:
    return _ask_guarded_ai(
        session,
        scan,
        stage=stage,
        current_phase=current_phase,
        scope=scope,
        evidence=evidence,
        allowed_actions=["draft_report_wording"],
        output_schema={
            "decision": "string",
            "reason": "string",
            "confidence": "low|medium|high",
            "next_action": "draft_report_wording",
            "executive_summary": "",
            "remediation_text": "",
        },
    )


def _ask_guarded_ai(
    session: Session | None,
    scan: Scan | None,
    *,
    stage: str,
    current_phase: str,
    scope: dict | None,
    evidence: dict,
    allowed_actions: list[str],
    output_schema: dict,
    discovered_endpoints: set[str] | None = None,
    endpoint: str | None = None,
    destructive_allowed: bool = False,
    client: OllamaClient | None = None,
) -> dict:
    settings = get_settings()
    client = client or OllamaClient()
    timeout_seconds = stage_timeout(stage, settings.ollama_timeout_seconds)
    contract = ai_decision_contract(
        current_phase,
        evidence,
        allowed_actions,
        scope=scope,
        output_schema=output_schema,
        timeout_seconds=timeout_seconds,
        retry_limit=settings.ollama_max_retries,
    )
    system_prompt = (
        "Return strict JSON only. You are an evidence-bound pentest advisor. "
        "Use only supplied evidence, scope, and allowed_actions. Do not invent endpoints, tools, findings, or credentials."
    )
    user_prompt = json.dumps(contract, sort_keys=True)
    trace = begin_ai_trace(
        scan.id if scan is not None else None,
        stage=stage.split(":", 1)[0] if stage.startswith("phase_decision:") else stage,
        phase=current_phase,
        agent="ai_advisor_agent",
        model=getattr(client, "model", settings.ollama_model),
        base_url=getattr(client, "base_url", settings.ollama_base_url),
        timeout_seconds=timeout_seconds,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
        options={"temperature": settings.ollama_temperature, "num_ctx": settings.ollama_num_ctx, "num_predict": settings.ollama_num_predict},
        evidence_packet={**(evidence or {}), "allowed_actions": allowed_actions, "forbidden_actions": contract.get("forbidden_actions") or [], "scope": scope or {}},
    )
    _emit_ai_event(session, scan, "ai_advisor_called", stage, "AI advisor called", {"current_phase": current_phase, "allowed_actions": allowed_actions})
    try:
        decision = client.chat_json(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            timeout=timeout_seconds,
            stage=stage,
        )
        validation = validate_ai_decision(
            decision,
            current_phase=current_phase,
            allowed_actions=allowed_actions,
            discovered_endpoints=discovered_endpoints,
            endpoint=endpoint,
            scope=scope,
            evidence=evidence,
            destructive_allowed=destructive_allowed,
        )
        status = "accepted" if validation.get("approved") else "rejected"
        event_type = _event_type_for_stage(stage, status)
        validation["decision"] = decision if validation.get("approved") else decision
        validation["ai_call_attempts"] = client.last_call_attempts
        raw_response = getattr(client, "last_raw_response", "") or json.dumps(decision or {}, sort_keys=True)
        agent_reaction = _agent_reaction_for_validation("ai_advisor_agent", decision, validation, status)
        trace_payload = complete_ai_trace(
            trace,
            status="completed" if validation.get("approved") else "rejected",
            raw_response=raw_response,
            parsed_response=decision,
            schema_valid=bool(decision),
            schema_errors=[] if decision else ["empty response"],
            accepted=bool(validation.get("approved")),
            rejected_reasons=[] if validation.get("approved") else [str(validation.get("reason") or "rejected")],
            normalized_decision=decision,
            agent_reaction=agent_reaction,
            used_for_execution=False,
            used_as_advisory=True,
        )
        validation["ai_trace"] = _trace_context(stage, current_phase, contract, client, decision, trace_payload)
        _record_ai_decision(session, scan, stage, current_phase, contract, decision, validation, status, client, trace_payload=trace_payload)
        _emit_ai_event(session, scan, event_type, stage, validation.get("reason") or event_type, {"status": status, "current_phase": current_phase})
        if not validation.get("approved"):
            _emit_ai_event(session, scan, "ai_fallback_used", stage, "AI decision rejected; deterministic fallback used", {"reason": validation.get("reason")}, level="WARNING")
        return validation
    except Exception as exc:
        attempts = getattr(client, "last_call_attempts", [])
        is_timeout = "timeout" in exc.__class__.__name__.lower() or any("timeout" in str(item.get("response_status") or "").lower() for item in attempts)
        status = "timeout" if is_timeout else "failed"
        fallback = {
            "approved": False,
            "reason": f"AI advisor unavailable: {exc}",
            "event_type": "ai_decision_rejected",
            "decision": None,
            "ai_call_attempts": attempts,
        }
        trace_payload = complete_ai_trace(
            trace,
            status=status,
            raw_response=getattr(client, "last_raw_response", "") or "",
            parsed_response={},
            schema_valid=False,
            schema_errors=["timed out"] if is_timeout else [str(exc)],
            accepted=False,
            rejected_reasons=["timed out"] if is_timeout else [str(exc)],
            normalized_decision={},
            agent_reaction={"agent_name": "ai_advisor_agent", "rejected_ollama_suggestion": True, "reason": str(exc), "action_taken": "fallback", "action_details": {"fallback": "deterministic workflow continued"}},
            used_for_execution=False,
            used_as_advisory=True,
        )
        fallback["ai_trace"] = _trace_context(stage, current_phase, contract, client, None, trace_payload)
        _record_ai_decision(session, scan, stage, current_phase, contract, None, fallback, status, client, str(exc), trace_payload=trace_payload)
        _emit_ai_event(session, scan, "ai_fallback_used", stage, "AI unavailable; deterministic fallback used", {"reason": str(exc)}, level="WARNING")
        return fallback


def persist_ai_trace_from_validation(session: Session, scan: Scan, validation: dict | None, status: str = "accepted") -> None:
    if not validation or not isinstance(validation, dict):
        return
    trace = validation.get("ai_trace") or {}
    contract = trace.get("contract")
    if not contract:
        return

    class TraceClient:
        model = trace.get("model") or "ollama"
        base_url = trace.get("base_url") or ""
        last_call_attempts = validation.get("ai_call_attempts") or []
        last_raw_response = trace.get("raw_response") or ""

    _record_ai_decision(
        session,
        scan,
        str(trace.get("stage") or "initial_planning"),
        str(trace.get("phase") or "ai_planning"),
        contract,
        validation.get("decision"),
        validation,
        "accepted" if validation.get("approved") else status,
        TraceClient(),
        None if validation.get("approved") else validation.get("reason"),
    )


def _trace_context(stage: str, phase: str, contract: dict, client: OllamaClient, decision: dict | None, trace_payload: dict | None = None) -> dict:
    return {
        "stage": stage,
        "phase": phase,
        "contract": contract,
        "model": getattr(client, "model", "ollama"),
        "base_url": getattr(client, "base_url", ""),
        "raw_response": getattr(client, "last_raw_response", "") or json.dumps(decision or {}, sort_keys=True),
        "ai_call_id": (trace_payload or {}).get("ai_call_id"),
        "trace_path": (trace_payload or {}).get("trace_path"),
    }


def _record_ai_decision(
    session: Session | None,
    scan: Scan | None,
    stage: str,
    phase: str,
    contract: dict,
    decision: dict | None,
    validation: dict,
    status: str,
    client: OllamaClient,
    error: str | None = None,
    trace_payload: dict | None = None,
) -> None:
    if session is None or scan is None:
        return
    now = datetime.now(timezone.utc)
    attempts = validation.get("ai_call_attempts") or getattr(client, "last_call_attempts", [])
    raw_response = getattr(client, "last_raw_response", "") or (trace_payload or {}).get("raw_ollama_response") or ""
    prompt_text = json.dumps(contract, sort_keys=True, default=str)
    prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
    response_hash = hashlib.sha256(raw_response.encode("utf-8")).hexdigest()
    accepted = bool(validation.get("approved"))
    rejected_reasons = [] if accepted else [str(validation.get("reason") or error or "rejected")]
    ai_call_id = str((trace_payload or {}).get("ai_call_id") or f"scan-{scan.id}-{stage}-{now.strftime('%Y%m%dT%H%M%S%fZ')}")
    payload = trace_payload or {
        "ai_call_id": ai_call_id,
        "scan_id": scan.id,
        "phase": phase,
        "stage": stage,
        "agent": "ai_advisor_agent",
        "tool": "ollama",
        "model": client.model,
        "base_url": client.base_url,
        "started_at": now.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": sum(int(item.get("duration_ms") or 0) for item in attempts) if attempts else 0,
        "timeout_seconds": contract.get("timeout_seconds"),
        "request_to_ollama": {
            "system_prompt": "Return strict JSON only. You are an evidence-bound pentest advisor.",
            "user_prompt": prompt_text,
            "messages": [],
            "options": {
                "temperature": get_settings().ollama_temperature,
                "num_ctx": get_settings().ollama_num_ctx,
                "num_predict": get_settings().ollama_num_predict,
            },
        },
        "evidence_sent_to_ollama": {
            "current_phase": phase,
            "scope": contract.get("scope") or {},
            "allowed_actions": contract.get("allowed_actions") or [],
            "forbidden_actions": contract.get("forbidden_actions") or [],
            "input_evidence_refs": (contract.get("evidence") or {}).get("evidence_ids", []),
            "summarized_evidence": _sanitize_ai_trace(contract.get("evidence") or {}),
        },
        "raw_ollama_response": _sanitize_ai_trace(raw_response),
        "parsed_ollama_response": _sanitize_ai_trace(decision or {}),
        "schema_validation": {"valid": bool(decision), "errors": [] if decision else [error or validation.get("reason") or "no parsed response"]},
        "guardrail_validation": {"accepted": accepted, "rejected_reasons": rejected_reasons, "normalized_decision": _sanitize_ai_trace(decision or {})},
        "hashes": {"prompt_sha256": prompt_hash, "response_sha256": response_hash},
    }
    path = (trace_payload or {}).get("trace_path") or (trace_payload or {}).get("path")
    if not path:
        path = _write_ai_trace(scan.id, stage, ai_call_id, payload)
    session.add(Evidence(scan_id=scan.id, kind="ai_decision", path=str(path), summary=f"AI advisor {stage}: {status}", metadata_json={"phase": phase, "stage": stage, "status": status}))
    session.add(
        AiDecision(
            scan_id=scan.id,
            ai_call_id=ai_call_id,
            stage=stage[:80],
            phase=phase,
            agent="ai_advisor_agent",
            tool="ollama",
            model=client.model,
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            evidence_path=str(path),
            parsed_response_json=_sanitize_ai_trace(decision or {}),
            decision=str((decision or {}).get("decision") or ""),
            confidence=str((decision or {}).get("confidence") or ""),
            accepted=accepted,
            rejected_reasons=rejected_reasons,
            used_for_execution=False,
            used_as_advisory=True,
        )
    )
    final_attempt = attempts[-1] if attempts else {}
    session.add(
        AiCallRun(
            scan_id=scan.id,
            stage=stage[:80],
            model=client.model,
            response_status=status,
            http_status=final_attempt.get("http_status"),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            duration_ms=sum(int(item.get("duration_ms") or 0) for item in attempts) if attempts else None,
            retry_count=max(0, len(attempts) - 1),
            error_message=error,
            request_summary={"ai_call_id": ai_call_id, "current_phase": phase, "allowed_actions": contract.get("allowed_actions"), "timeout_seconds": contract.get("timeout_seconds"), "retry_limit": contract.get("retry_limit"), "prompt_hash": prompt_hash},
            parsed_response_json=decision,
            response_summary=validation.get("reason"),
            evidence_path=str(path),
        )
    )
    _emit_ai_event(session, scan, "ai_raw_response_received", stage, "AI raw response recorded", {"ai_call_id": ai_call_id})
    _emit_ai_event(session, scan, "ai_response_parsed", stage, "AI response parsed", {"ai_call_id": ai_call_id, "parsed": bool(decision)})
    _emit_ai_event(session, scan, "ai_schema_validation_passed" if decision else "ai_schema_validation_failed", stage, "AI schema validation recorded", {"ai_call_id": ai_call_id})
    _emit_ai_event(session, scan, "ai_execution_effect_recorded", stage, "AI execution effect recorded", {"ai_call_id": ai_call_id, "used_for_execution": False})


def _write_ai_trace(scan_id: int, stage: str, ai_call_id: str, payload: dict):
    directory = get_settings().evidence_dir / f"scan-{scan_id}" / "ai"
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"{timestamp}-{_safe_name(stage)}-{_safe_name(ai_call_id)}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def _update_ai_trace_index(scan_id: int, entry: dict) -> None:
    directory = get_settings().evidence_dir / f"scan-{scan_id}" / "ai"
    directory.mkdir(parents=True, exist_ok=True)
    index_path = directory / "ai_trace_index.json"
    try:
        items = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else []
    except Exception:
        items = []
    items.append(entry)
    index_path.write_text(json.dumps(items, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _sanitize_ai_trace(value):
    return mask_secrets(value)


def _emit_ai_event(session: Session | None, scan: Scan | None, event_type: str, stage: str, message: str, context: dict | None = None, level: str = "INFO") -> None:
    if session is None or scan is None:
        return
    try:
        from saif.services.progress import emit_progress

        emit_progress(
            session,
            scan,
            message,
            level=level,
            phase=stage,
            agent="ai_advisor_agent",
            tool="ollama",
            event_type=event_type,
            context={"stage": stage, **(context or {})},
        )
    except Exception:
        session.add(Log(scan_id=scan.id, level=level.lower(), message=message, context={"event_type": event_type, "stage": stage, **(context or {})}))


def _event_type_for_stage(stage: str, status: str) -> str:
    if stage == "payload_strategy":
        return "ai_payload_strategy_accepted" if status == "accepted" else "ai_payload_strategy_rejected"
    return "ai_decision_accepted" if status == "accepted" else "ai_decision_rejected"


def _agent_reaction_for_validation(agent: str, decision: dict | None, validation: dict, status: str) -> dict:
    accepted = bool(validation.get("approved"))
    next_action = str((decision or {}).get("next_action") or "")
    return {
        "agent_name": agent,
        "accepted_ollama_suggestion": accepted,
        "rejected_ollama_suggestion": not accepted,
        "reason": str(validation.get("reason") or ("accepted" if accepted else status)),
        "action_taken": "scheduled_payload" if accepted and next_action == "run_payload_family" else "scheduled_tool" if accepted and next_action else "fallback" if not accepted else "none",
        "action_details": {"next_action": next_action, "decision": (decision or {}).get("decision")},
        "next_request_ids": [],
        "next_tool_names": [next_action] if accepted and next_action else [],
        "payloads_selected": [str((decision or {}).get("next_payload"))] if accepted and (decision or {}).get("next_payload") else [],
        "payloads_rejected": [],
        "why_payloads_selected": str((decision or {}).get("reason") or ""),
        "why_payloads_rejected": "" if accepted else str(validation.get("reason") or status),
        "scope_check": "passed" if accepted else "failed",
        "policy_check": "passed" if accepted else "failed",
    }


def _normalize_plan_suggestion(decision: dict, target_url: str, selected_tools: list[str]) -> dict:
    if decision.get("target") and decision.get("target") != target_url:
        return _fallback_plan(target_url, selected_tools, "AI plan changed target")
    requested_tools = [str(item) for item in decision.get("tools") or selected_tools]
    allowed = set(selected_tools)
    tools = [tool for tool in requested_tools if tool in allowed] or selected_tools
    return {
        "approved": True,
        "mode": str(decision.get("mode") or "default-enumeration"),
        "target": target_url,
        "environment": str(decision.get("environment") or "testing"),
        "authorized_testing_mode": True,
        "scope_confirmation": str(decision.get("scope_confirmation") or "Tester is responsible for confirming authorization and non-production usage."),
        "tools": tools,
        "test_cases": decision.get("test_cases") if isinstance(decision.get("test_cases"), list) else [],
        "not_applicable": decision.get("not_applicable") if isinstance(decision.get("not_applicable"), list) else [],
        "missing_prerequisites": decision.get("missing_prerequisites") if isinstance(decision.get("missing_prerequisites"), list) else [],
        "reason": str(decision.get("reason") or "Guarded AI plan suggestion accepted."),
        "ai_planning_status": "approved",
        "ai_available": True,
        "deterministic_mode": False,
    }


def _fallback_plan(target_url: str, selected_tools: list[str], reason: str | None = None) -> dict:
    return {
        "approved": True,
        "mode": "default-enumeration",
        "target": target_url,
        "environment": "testing",
        "authorized_testing_mode": True,
        "scope_confirmation": "Tester is responsible for confirming authorization and non-production usage.",
        "tools": selected_tools,
        "test_cases": [],
        "not_applicable": [],
        "missing_prerequisites": [],
        "reason": reason or "Deterministic fallback plan used.",
    }


def _scope_from_target(target_url: str) -> dict:
    parsed = urlparse(target_url if "://" in target_url else f"//{target_url}")
    return {"target": target_url, "allowed_hosts": [parsed.hostname] if parsed.hostname else []}


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)[:100] or "advisor"
