from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from saif.ai.advisor import ask_ai_for_plan_suggestions, ask_ai_for_report_wording, persist_ai_trace_from_validation
from saif.ai.ollama import OllamaChatError, OllamaClient, OllamaHTTPError, OllamaJSONError, OllamaServerError, OllamaTimeoutError
from saif.config import get_settings
from saif.db.models import Evidence, Finding, Log, Project, Scan, ScanStatus, ToolRun
from saif.services.evidence import write_evidence
from saif.services.pentest_engine import ai_decision_contract


class AIPrecheckError(RuntimeError):
    code = "AI_PRECHECK_ERROR"


class OllamaNotReachableError(AIPrecheckError):
    code = "OLLAMA_NOT_REACHABLE"


class AIChatFailedError(AIPrecheckError):
    code = "AI_CHAT_FAILED"

    def __init__(self, message: str, ai_call_attempts: list[dict] | None = None) -> None:
        self.ai_call_attempts = ai_call_attempts or []
        super().__init__(message)


class AIPlanParseFailedError(AIPrecheckError):
    code = "AI_PLAN_PARSE_FAILED"

    def __init__(self, raw_response: str) -> None:
        self.raw_response = raw_response
        super().__init__("AI did not return a valid executable test plan.")


class AIPlanNotApprovedError(AIPrecheckError):
    code = "AI_PLAN_NOT_APPROVED"

    def __init__(self, reason: str | None = None, raw_plan: dict | None = None) -> None:
        self.reason = reason or "AI did not return a valid executable test plan."
        self.raw_plan = raw_plan or {}
        super().__init__(self.reason)


class AIPlanningTimeoutError(AIPrecheckError):
    code = "AI_PLANNING_TIMEOUT"

    def __init__(self, base_url: str, model: str, timeout_seconds: int, prompt: str, target: str, error: str, ai_call_attempts: list[dict] | None = None) -> None:
        self.base_url = base_url
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.prompt = prompt
        self.target = target
        self.error = error
        self.ai_call_attempts = ai_call_attempts or []
        super().__init__(error)


class AIBasicPromptFailedError(AIPrecheckError):
    code = "AI_CHAT_FAILED"


class OllamaConfigError(AIPrecheckError):
    code = "OLLAMA_NOT_REACHABLE"


class OllamaModelMissingError(AIPrecheckError):
    code = "OLLAMA_MODEL_MISSING"

    def __init__(self, configured_model: str, installed_models: list[str]) -> None:
        self.configured_model = configured_model
        self.installed_models = installed_models
        super().__init__(f"Configured model {configured_model!r} is not installed")


@dataclass(frozen=True)
class AIContext:
    provider: str
    model: str
    base_url: str
    prompt: str
    scan_plan: dict
    ai_call_attempts: list[dict] | None = None


def required_ai_error_message(reason: str | None = None) -> str:
    settings = get_settings()
    message = (
        "ERROR: SAIF requires AI, but Ollama is not reachable.\n"
        f"Checked: {settings.ollama_base_url}\n"
        f"Model: {settings.ollama_model}\n\n"
        "Fix:\n"
        "- Start Ollama\n"
        "- Confirm OLLAMA_BASE_URL in .env\n"
        f"- Test: curl {settings.ollama_base_url.rstrip('/')}/api/tags"
    )
    if reason:
        message = f"{message}\n\nReason: {reason}"
    return message


def ai_error_message(exc: AIPrecheckError) -> str:
    if isinstance(exc, AIPlanningTimeoutError):
        return (
            "ERROR: AI planning timed out.\n"
            f"Ollama URL: {exc.base_url}\n"
            f"Model: {exc.model}\n"
            f"Timeout: {exc.timeout_seconds}s\n"
            "Suggested fixes:\n"
            "- use smaller/faster model\n"
            "- increase OLLAMA_TIMEOUT_SECONDS\n"
            "- check host CPU/GPU load\n"
            "- retry the command"
        )
    if isinstance(exc, OllamaModelMissingError):
        return missing_model_error_message(exc.configured_model, exc.installed_models)
    if isinstance(exc, OllamaNotReachableError):
        return required_ai_error_message(str(exc))
    if isinstance(exc, AIChatFailedError):
        return f"ERROR: Ollama chat request failed.\nReason: {exc}"
    if isinstance(exc, AIPlanParseFailedError):
        return "ERROR: AI scan planning failed.\nReason: AI did not return a valid executable test plan."
    if isinstance(exc, AIPlanNotApprovedError):
        return f"ERROR: AI scan planning failed.\nReason: {exc.reason}"
    return f"ERROR: AI precheck failed.\nReason: {exc}"


def missing_model_error_message(configured_model: str, installed_models: list[str]) -> str:
    installed = ", ".join(installed_models) if installed_models else "(none)"
    return (
        "ERROR: Configured Ollama model is not installed.\n"
        f"Configured model: {configured_model}\n"
        f"Installed models: {installed}\n\n"
        "Fix:\n"
        "- update OLLAMA_MODEL in .env to one of installed models, or\n"
        f"- run: ollama pull {configured_model}"
    )


def ensure_ai_ready() -> OllamaClient:
    client = OllamaClient()
    try:
        client.require_configured_base_url()
        client.require_configured_model()
        models = client.installed_models()
        if client.model not in models:
            raise OllamaModelMissingError(client.model, models)
        test = client.chat(
            [
                {
                    "role": "user",
                    "content": "Reply only with OK",
                },
            ],
            timeout=30,
        )
        content = str(test.get("message", {}).get("content", "")).strip()
        if content != "OK":
            raise AIBasicPromptFailedError(f"basic test prompt did not return OK, got: {content!r}")
        return client
    except OllamaModelMissingError:
        raise
    except OllamaHTTPError as exc:
        if exc.status_code == 404:
            raise AIChatFailedError(f"HTTP {exc.status_code}: {exc.body}") from exc
        raise OllamaNotReachableError(f"HTTP {exc.status_code}: {exc.body}") from exc
    except OllamaChatError as exc:
        raise AIChatFailedError(str(exc)) from exc
    except httpx.TimeoutException as exc:
        raise OllamaNotReachableError(f"timed out while checking Ollama: {exc}") from exc
    except (httpx.ConnectError, httpx.ReadError, httpx.HTTPStatusError) as exc:
        raise OllamaNotReachableError(str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise AIChatFailedError(f"Ollama returned invalid JSON: {exc}") from exc
    except Exception as exc:
        if isinstance(exc, AIPrecheckError):
            raise
        raise OllamaNotReachableError(str(exc)) from exc


def build_ai_scan_plan(prompt: str, target_url: str, parsed_intent: dict, selected_tools: list[str], debug: bool = False) -> AIContext:
    client = ensure_ai_ready()
    plan = ask_ai_for_plan_suggestions(
        prompt=prompt,
        target_url=target_url,
        parsed_intent=parsed_intent,
        selected_tools=selected_tools,
        client=client,
        debug=debug,
    )
    if not _is_executable_plan(plan):
        plan = {
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
            "reason": "AI planning unavailable; deterministic fallback plan used.",
            "ai_planning_status": "warning",
            "ai_planning_error": "AI did not return a valid executable test plan.",
            "ai_available": False,
            "deterministic_mode": True,
        }
    return AIContext(provider="Ollama", model=client.model, base_url=client.base_url, prompt=prompt, scan_plan=plan, ai_call_attempts=client.last_call_attempts)


def _planning_messages(prompt: str, target_url: str, parsed_intent: dict, selected_tools: list[str], simplified: bool) -> list[dict]:
    if simplified:
        return [
            {
                "role": "system",
                "content": "Return strict JSON only. Create an executable SAIF plan for authorized testing/staging.",
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "target": target_url,
                        "tools": selected_tools,
                        "schema": {
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
                            "reason": "Executable plan for authorized test environment.",
                        },
                    }
                ),
            },
        ]
    return [
        {
            "role": "system",
            "content": (
                "SAIF planner. Authorized testing/staging only. Strict JSON only. "
                "Return executable plan JSON with approved, mode, target, environment, authorized_testing_mode, "
                "scope_confirmation, tools, test_cases, not_applicable, missing_prerequisites, reason."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "target": target_url,
                    "prompt": prompt,
                    "parsed_intent": parsed_intent,
                    "candidate_tools": selected_tools,
                    "expected_response": {
                        "approved": True,
                        "mode": "default-enumeration",
                        "target": target_url,
                        "environment": "testing",
                        "authorized_testing_mode": True,
                        "scope_confirmation": "Tester is responsible for confirming authorization and non-production usage.",
                        "tools": selected_tools,
                        "test_cases": [
                            {
                                "id": "api.auth.broken_authentication",
                                "name": "Broken authentication testing",
                                "applicability": "applicable",
                                "required_prerequisites": ["valid user account", "login endpoint"],
                                "execution_status": "planned",
                            }
                        ],
                        "not_applicable": [],
                        "missing_prerequisites": [],
                        "reason": "Default enumeration and applicable Web/API test planning for authorized test environment.",
                    },
                }
            ),
        },
    ]


def _parse_json_object(raw: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise AIPlanParseFailedError(raw) from exc
    raise AIPlanParseFailedError(raw)


def _is_executable_plan(plan: object) -> bool:
    if not isinstance(plan, dict):
        return False
    if plan.get("approved") is not True:
        return False
    if not isinstance(plan.get("target"), str) or not plan["target"]:
        return False
    if plan.get("authorized_testing_mode") is not True:
        return False
    if not isinstance(plan.get("tools"), list):
        return False
    if not isinstance(plan.get("test_cases"), list):
        return False
    return True


def _fallback_evidence_review(status: str, error: str) -> dict:
    return {
        "evidence_review": "AI evidence review did not complete. A local rule-engine summary was used so the scan report can still be generated.",
        "discovered_attack_surface_summary": {},
        "likely_auth_model": "unknown",
        "likely_api_model": "unknown",
        "missing_prerequisites": [],
        "applicable_next_stage_test_cases": ["Review executed tool evidence", "Run credentialed authentication and authorization checks when roles are available"],
        "recommended_next_stage": "Review tool evidence and continue with applicable authenticated Web/API testing.",
        "finding_summary": [],
        "risk_notes": [],
        "ai_evidence_review_status": status,
        "ai_evidence_review_error": error,
        "local_fallback_summary_used": True,
    }


def _compact_plan(plan: dict) -> dict:
    settings = get_settings()
    compact = dict(plan or {})
    if isinstance(compact.get("test_cases"), list):
        compact["test_cases"] = compact["test_cases"][: settings.ai_max_findings_in_prompt]
    return _sanitize_ai_payload(compact)


def _sanitize_ai_payload(value):
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(token in lowered for token in ["authorization", "cookie", "secret", "password", "refresh_token", "access_token"]):
                sanitized[key] = "<masked>"
            elif "jwt" in lowered or "token" in lowered:
                sanitized[key] = _jwt_metadata(item)
            else:
                sanitized[key] = _sanitize_ai_payload(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_ai_payload(item) for item in value[:100]]
    if isinstance(value, str) and (value.startswith("eyJ") or "Bearer " in value):
        return _jwt_metadata(value.replace("Bearer ", ""))
    return value


def _jwt_metadata(token: object) -> dict | str:
    if not isinstance(token, str) or token.count(".") < 2:
        return "<masked>"
    try:
        import base64

        header_raw, payload_raw, _signature = token.split(".", 2)
        header = json.loads(base64.urlsafe_b64decode(header_raw + "=" * (-len(header_raw) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(payload_raw + "=" * (-len(payload_raw) % 4)))
        return {
            "alg": header.get("alg"),
            "role": payload.get("role") or payload.get("roles"),
            "subject": _mask_identity(payload.get("sub")),
            "email": _mask_identity(payload.get("email")),
            "iat": payload.get("iat"),
            "exp": payload.get("exp"),
        }
    except Exception:
        return "<masked_jwt>"


def _mask_identity(value: object) -> str | None:
    if not value:
        return None
    text = str(value)
    if "@" in text:
        name, domain = text.split("@", 1)
        return f"{name[:2]}***@{domain}"
    return f"{text[:4]}***"


def _cap_text(value: str, max_chars: int) -> str:
    return value if len(value) <= max_chars else value[:max_chars] + "\n...[truncated]"


def ai_review_evidence(session: Session, scan: Scan, ai_context: AIContext) -> dict:
    settings = get_settings()
    client = OllamaClient(model=ai_context.model, base_url=ai_context.base_url)
    try:
        client.tags(timeout=settings.ollama_connect_timeout_seconds)
    except Exception as exc:
        review = _fallback_evidence_review("failed_ai_unavailable", f"Ollama health check failed before evidence review: {exc}")
        _persist_failed_ai_trace(session, scan, "evidence_review", "report_generation", client, review["ai_evidence_review_error"], [], ai_context)
        return review

    tool_runs = session.scalars(select(ToolRun).where(ToolRun.scan_id == scan.id)).all()
    evidence_summary = _cap_text(
        json.dumps(
            [
                {
                    "tool": item.tool_name,
                    "status": item.status,
                    "command": item.command,
                    "output_summary": _summarize_output(_sanitize_ai_payload(item.output)),
                }
                for item in tool_runs
            ],
            sort_keys=True,
        ),
        settings.ai_max_evidence_chars,
    )
    try:
        advisor_result = ask_ai_for_report_wording(
            session,
            scan,
            current_phase="report_generation",
            scope={"target": ai_context.scan_plan.get("target"), "allowed_hosts": [_host_from_target(ai_context.scan_plan.get("target"))]},
            evidence={
                "target_prompt": ai_context.prompt[:1200],
                "scan_plan": _compact_plan(ai_context.scan_plan),
                "evidence_summary": evidence_summary,
            },
            stage="evidence_review",
        )
        decision = advisor_result.get("decision") or {}
        if not advisor_result.get("approved"):
            review = _fallback_evidence_review("failed_ai_rejected", str(advisor_result.get("reason") or "AI evidence review rejected by guardrails"))
            review["ai_call_attempts"] = advisor_result.get("ai_call_attempts") or []
            return review
        return {
            "evidence_review": str(decision.get("executive_summary") or decision.get("reason") or "AI advisory wording accepted."),
            "discovered_attack_surface_summary": {},
            "likely_auth_model": "unknown",
            "likely_api_model": "unknown",
            "missing_prerequisites": [],
            "applicable_next_stage_test_cases": [],
            "recommended_next_stage": str(decision.get("remediation_text") or "Continue deterministic validation of applicable findings."),
            "finding_summary": [],
            "risk_notes": [],
            "ai_evidence_review_status": "completed",
            "ai_evidence_review_error": None,
            "local_fallback_summary_used": False,
            "ai_call_attempts": advisor_result.get("ai_call_attempts") or [],
            "ai_decision_memory": advisor_result,
        }
    except OllamaTimeoutError as exc:
        status = "failed_ai_timeout"
        error = str(exc)
    except OllamaServerError as exc:
        status = "failed_ai_500"
        error = str(exc)
    except (OllamaJSONError, json.JSONDecodeError) as exc:
        status = "failed_ai_parse"
        error = str(exc)
    except OllamaChatError as exc:
        status = getattr(exc, "status", "failed_ai_chat")
        error = str(exc)
    except Exception as exc:
        status = "failed_ai_chat"
        error = str(exc)
    review = _fallback_evidence_review(status, error)
    review["ai_call_attempts"] = client.last_call_attempts
    _persist_failed_ai_trace(session, scan, "evidence_review", "report_generation", client, error, client.last_call_attempts, ai_context)
    return review


def _persist_failed_ai_trace(
    session: Session,
    scan: Scan,
    stage: str,
    phase: str,
    client: OllamaClient,
    error: str,
    attempts: list[dict],
    ai_context: AIContext,
) -> None:
    target = ai_context.scan_plan.get("target")
    contract = ai_decision_contract(
        phase,
        {"target_prompt": ai_context.prompt[:1200], "scan_plan": _compact_plan(ai_context.scan_plan), "error": error},
        ["draft_report_wording"],
        scope={"target": target, "allowed_hosts": [_host_from_target(target)]},
        output_schema={"decision": "string", "reason": "string", "confidence": "low|medium|high", "next_action": "draft_report_wording"},
        timeout_seconds=90 if stage in {"evidence_review", "report_wording"} else 60,
        retry_limit=get_settings().ollama_max_retries,
    )
    persist_ai_trace_from_validation(
        session,
        scan,
        {
            "approved": False,
            "reason": error,
            "decision": None,
            "ai_call_attempts": attempts,
            "ai_trace": {
                "stage": stage,
                "phase": phase,
                "contract": contract,
                "model": client.model,
                "base_url": client.base_url,
                "raw_response": getattr(client, "last_raw_response", "") or "",
            },
        },
        "failed",
    )


def log_ai_context(session: Session, scan: Scan, ai_context: AIContext, parsed_intent: dict, selected_target: str, selected_tools: list[str]) -> None:
    persist_ai_trace_from_validation(session, scan, ai_context.scan_plan.get("ai_validation"), "accepted")
    if ai_context.ai_call_attempts and not ai_context.scan_plan.get("ai_validation"):
        final_statuses = {str(item.get("response_status") or "") for item in ai_context.ai_call_attempts}
        trace_status = "timeout" if "failed_ai_timeout" in final_statuses else "failed"
        persist_ai_trace_from_validation(
            session,
            scan,
            {
                "approved": False,
                "reason": ai_context.scan_plan.get("ai_planning_error") or "AI planning attempt failed; deterministic fallback continued.",
                "decision": None,
                "ai_call_attempts": ai_context.ai_call_attempts,
                "ai_trace": {
                    "stage": "initial_planning",
                    "phase": "ai_planning",
                    "contract": {
                        "scope": {"target": selected_target},
                        "allowed_actions": ["suggest_test_plan"],
                        "evidence": {"prompt": ai_context.prompt[:1200], "selected_tools": selected_tools},
                        "timeout_seconds": get_settings().ollama_timeout_seconds,
                        "retry_limit": get_settings().ollama_max_retries,
                    },
                    "model": ai_context.model,
                    "base_url": ai_context.base_url,
                    "raw_response": "",
                },
            },
            trace_status,
        )
    session.add(
        Log(
            scan_id=scan.id,
            level="info",
            message="AI scan plan",
            context={
                "ai_provider": ai_context.provider,
                "ai_model": ai_context.model,
                "ai_base_url": ai_context.base_url,
                "ai_timeout_seconds": get_settings().ollama_timeout_seconds,
                "prompt": ai_context.prompt,
                "parsed_intent": parsed_intent,
                "selected_target": selected_target,
                "selected_tools": selected_tools,
                "ai_scan_plan": ai_context.scan_plan,
                "ai_planning_status": ai_context.scan_plan.get("ai_planning_status") or "approved",
                "ai_planning_error": ai_context.scan_plan.get("ai_planning_error"),
                "ai_planning_warning": ai_context.scan_plan.get("ai_planning_warning") or ai_context.scan_plan.get("warning"),
                "ai_available": ai_context.scan_plan.get("ai_available", True),
                "deterministic_mode": ai_context.scan_plan.get("deterministic_mode", False),
                "ai_planning_attempts": ai_context.ai_call_attempts or [],
                "environment_assumption": "testing/staging/non-production",
                "authorized_testing_caution": "Use only on authorized testing/staging environments. Tester is responsible for confirming scope and approval.",
                "test_cases": ai_context.scan_plan.get("test_cases", []),
                "not_applicable": ai_context.scan_plan.get("not_applicable", []),
                "missing_prerequisites": ai_context.scan_plan.get("missing_prerequisites", []),
            },
        )
    )


def log_ai_review(session: Session, scan: Scan, ai_context: AIContext, review: dict) -> None:
    session.add(
        Log(
            scan_id=scan.id,
            level="info",
            message="AI evidence review",
            context={
                "ai_provider": ai_context.provider,
                "ai_model": ai_context.model,
                "ai_evidence_review": review.get("evidence_review"),
                "ai_evidence_review_status": review.get("ai_evidence_review_status", "completed"),
                "ai_evidence_review_error": review.get("ai_evidence_review_error"),
                "local_fallback_summary_used": review.get("local_fallback_summary_used", False),
                "ai_finding_summary": review.get("finding_summary"),
                "ai_review": review,
            },
        )
    )
    summary = review.get("finding_summary") or []
    if isinstance(summary, str):
        summary = [summary]
    for item in summary[:20]:
        if isinstance(item, dict):
            title = str(item.get("title") or item.get("name") or "AI finding summary")
            description = str(item.get("description") or item.get("summary") or item)
        else:
            title = "AI finding summary"
            description = str(item)
        session.add(
            Finding(
                scan_id=scan.id,
                finding_type="observation",
                title=title[:255],
                severity="info",
                description=description,
                status="informational",
                confidence="medium",
                business_impact="Informational observation to support tester review, coverage tracking, and follow-up validation.",
                technical_impact=description,
                remediation="Review this observation during triage and document whether it affects scope, attack surface, or follow-up testing.",
                ai_reasoning_summary=description,
                retest_status="not_retested",
            )
        )


def record_failed_precheck(session: Session, project_name: str, reason: str, context: dict | None = None) -> Scan:
    project = session.scalar(select(Project).where(Project.name == project_name))
    if not project:
        project = Project(name=project_name)
        session.add(project)
        session.flush()
    status = ScanStatus.FAILED_AI_TIMEOUT.value if context and context.get("code") == "AI_PLANNING_TIMEOUT" else ScanStatus.FAILED_PRECHECK.value
    scan = Scan(
        project_id=project.id,
        profile="ai-precheck",
        ai_provider="Ollama",
        authorized_testing_mode=True,
        status=status,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    session.add(scan)
    session.flush()
    payload = {"reason": reason}
    if context:
        payload.update(context)
    session.add(Log(scan_id=scan.id, level="error", message="AI precheck failed", context=payload))
    if payload.get("raw_ai_response"):
        path = write_evidence(scan.id, "ai_planning_raw_response", {"event": "ai_plan_parse_failed", "raw_ai_response": payload["raw_ai_response"]})
        session.add(
            Evidence(
                scan_id=scan.id,
                kind="ai",
                path=str(path),
                summary="Raw AI planning response captured after plan parse failure.",
                metadata_json={"code": payload.get("code")},
            )
        )
    if payload.get("code") == "AI_PLANNING_TIMEOUT":
        path = write_evidence(
            scan.id,
            "ai_planning_timeout",
            {
                "event": "ai_planning_timeout",
                "prompt": payload.get("prompt"),
                "target": payload.get("target"),
                "model": payload.get("model"),
                "timeout_seconds": payload.get("timeout_seconds"),
                "error": payload.get("error") or reason,
            },
        )
        session.add(
            Evidence(
                scan_id=scan.id,
                kind="ai",
                path=str(path),
                summary="AI planning timed out.",
                metadata_json={"code": payload.get("code"), "model": payload.get("model"), "timeout_seconds": payload.get("timeout_seconds")},
            )
        )
    if payload.get("ai_call_attempts"):
        path = write_evidence(
            scan.id,
            "ai_planning_attempts",
            {
                "event": "ai_planning_failed",
                "model": payload.get("model") or get_settings().ollama_model,
                "target": payload.get("target"),
                "prompt": payload.get("prompt"),
                "ai_call_attempts": payload.get("ai_call_attempts"),
                "error": payload.get("error") or reason,
            },
        )
        session.add(
            Evidence(
                scan_id=scan.id,
                kind="ai",
                path=str(path),
                summary="AI planning call attempts captured after failure.",
                metadata_json={"code": payload.get("code"), "model": payload.get("model") or get_settings().ollama_model},
            )
        )
    return scan


def _summarize_output(output: dict | None) -> str:
    if not output:
        return ""
    if output.get("reason"):
        return str(output["reason"])
    if output.get("error"):
        return str(output["error"])[:300]
    if output.get("status_code") is not None:
        return f"HTTP {output['status_code']}"
    if output.get("count") is not None:
        return f"count={output['count']}"
    return str(output)[:300]


def _host_from_target(target: object) -> str | None:
    if not target:
        return None
    parsed = urlparse(str(target) if "://" in str(target) else f"//{target}")
    return parsed.hostname
