import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from saif.config import get_settings
from saif.db.models import (
    AgentJob,
    AiCallRun,
    ApplicationProfile,
    AuthorizationMatrix,
    DiscoveredAsset,
    DiscoveredApiSpec,
    DiscoveredAuthFlow,
    DiscoveredAuthMechanism,
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredService,
    DiscoveredSessionMechanism,
    DiscoveredTenant,
    DiscoveredToken,
    Evidence,
    Finding,
    Log,
    PipelineArtifact,
    PayloadAttempt,
    Project,
    Report,
    Scan,
    ScanPhase,
    AuthenticatedSession,
    Target,
    TestCase,
    TestRun,
    ToolRegistry,
    ToolRun,
)
from saif.services.resource_manager import resource_limits_payload
from saif.services.payloads import payload_library_status
from saif.services.case_management import assign_finding_uids, production_readiness_for_scan, sync_scan_phases


def _mask_token(token: str | None) -> str | None:
    if not token:
        return None
    value = str(token)
    if "<masked>" in value:
        return value
    if len(value) <= 20:
        return value[:6] + "...<masked>"
    return f"{value[:10]}...<masked>...{value[-8:]}"


def _sanitize_tokens(value):
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(token in lowered for token in ["token", "authorization", "cookie", "jwt", "bearer", "secret", "password"]):
                sanitized[key] = _mask_token(str(item)) if item else item
            else:
                sanitized[key] = _sanitize_tokens(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_tokens(item) for item in value]
    if isinstance(value, str) and (value.startswith("eyJ") or "Bearer " in value):
        return _mask_token(value.replace("Bearer ", ""))
    return value


def _sanitize_scope(scope: dict | None) -> dict | None:
    if not scope:
        return scope
    return {key: value for key, value in scope.items() if key != "safe_mode"}


def _production_readiness(scan: Scan | None, findings: list[Finding], execution_context: dict) -> dict:
    severe = [item for item in findings if item.severity in {"critical", "high"} and item.status in {"open", "finding_created"}]
    manual = [item for item in findings if item.status == "manual_confirmation_required"]
    failed_stages = [
        item
        for item in execution_context.get("execution_summary", [])
        if item.get("status") in {"execution_error", "missing_credentials"}
    ]
    if severe:
        status = "not_ready"
        reason = "critical/high findings are open"
    elif failed_stages:
        status = "manual_review_required"
        reason = "one or more required stages failed or lacked credentials"
    elif manual:
        status = "manual_review_required"
        reason = "manual confirmation items remain open"
    elif not scan or scan.status != "completed":
        status = "manual_review_required"
        reason = "scan/report is incomplete"
    else:
        status = "ready"
        reason = "no high/critical findings or failed required stages recorded"
    return {"status": status, "reason": reason, "high_or_critical_findings": len(severe), "manual_review_items": len(manual), "failed_stages": failed_stages}


def build_report_payload(session: Session, project_name: str | None = None, scan_id: int | None = None) -> dict:
    if scan_id is not None:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id!r} was not found")
        project = session.get(Project, scan.project_id)
    else:
        project = session.scalar(select(Project).where(Project.name == project_name))
        scan = session.scalar(select(Scan).where(Scan.project_id == project.id).order_by(desc(Scan.id)).limit(1)) if project else None
    if not project:
        raise ValueError(f"Project {project_name!r} was not found")

    if scan:
        assign_finding_uids(session, scan.id)
        sync_scan_phases(session, scan)
        session.flush()
    targets = session.scalars(select(Target).where(Target.project_id == project.id)).all()
    test_runs = session.scalars(select(TestRun).where(TestRun.scan_id == scan.id)).all() if scan else []
    test_cases = session.scalars(select(TestCase).where(TestCase.scan_id == scan.id).order_by(TestCase.priority, TestCase.id)).all() if scan else []
    tool_runs = session.scalars(select(ToolRun).where(ToolRun.scan_id == scan.id)).all() if scan else []
    agent_jobs = session.scalars(select(AgentJob).where(AgentJob.scan_id == scan.id).order_by(AgentJob.id)).all() if scan else []
    ai_call_runs = session.scalars(select(AiCallRun).where(AiCallRun.scan_id == scan.id).order_by(AiCallRun.id)).all() if scan else []
    tool_registry = session.scalars(select(ToolRegistry).order_by(ToolRegistry.tool_name)).all()
    evidence = session.scalars(select(Evidence).where(Evidence.scan_id == scan.id)).all() if scan else []
    findings = session.scalars(select(Finding).where(Finding.scan_id == scan.id)).all() if scan else []
    logs = session.scalars(select(Log).where(Log.scan_id == scan.id)).all() if scan else []
    discovered_assets = session.scalars(select(DiscoveredAsset).where(DiscoveredAsset.scan_id == scan.id)).all() if scan else []
    application_profiles = session.scalars(select(ApplicationProfile).where(ApplicationProfile.scan_id == scan.id).order_by(ApplicationProfile.id)).all() if scan else []
    discovered_services = session.scalars(select(DiscoveredService).where(DiscoveredService.scan_id == scan.id)).all() if scan else []
    discovered_api_specs = session.scalars(select(DiscoveredApiSpec).where(DiscoveredApiSpec.scan_id == scan.id)).all() if scan else []
    discovered_auth_mechanisms = session.scalars(select(DiscoveredAuthMechanism).where(DiscoveredAuthMechanism.scan_id == scan.id)).all() if scan else []
    discovered_session_mechanisms = session.scalars(select(DiscoveredSessionMechanism).where(DiscoveredSessionMechanism.scan_id == scan.id)).all() if scan else []
    discovered_tenants = session.scalars(select(DiscoveredTenant).where(DiscoveredTenant.scan_id == scan.id)).all() if scan else []
    discovered_endpoints = session.scalars(select(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan.id)).all() if scan else []
    discovered_parameters = session.scalars(select(DiscoveredParameter).where(DiscoveredParameter.scan_id == scan.id)).all() if scan else []
    discovered_auth_flows = session.scalars(select(DiscoveredAuthFlow).where(DiscoveredAuthFlow.scan_id == scan.id)).all() if scan else []
    discovered_tokens = session.scalars(select(DiscoveredToken).where(DiscoveredToken.scan_id == scan.id)).all() if scan else []
    authorization_entries = session.scalars(select(AuthorizationMatrix).where(AuthorizationMatrix.scan_id == scan.id)).all() if scan else []
    pipeline_artifacts = session.scalars(select(PipelineArtifact).where(PipelineArtifact.scan_id == scan.id)).all() if scan else []
    scan_phases = session.scalars(select(ScanPhase).where(ScanPhase.scan_id == scan.id).order_by(ScanPhase.id)).all() if scan else []
    payload_attempts = session.scalars(select(PayloadAttempt).where(PayloadAttempt.scan_id == scan.id).order_by(PayloadAttempt.id)).all() if scan else []
    authenticated_sessions = session.scalars(select(AuthenticatedSession).where(AuthenticatedSession.scan_id == scan.id)).all() if scan else []
    prompt_context = next((item.context for item in reversed(logs) if item.message == "Prompt received" and item.context), {})
    ai_plan_context = next((item.context for item in reversed(logs) if item.message == "AI scan plan" and item.context), {})
    ai_review_context = next((item.context for item in reversed(logs) if item.message == "AI evidence review" and item.context), {})
    tool_prep_context = next((item.context for item in reversed(logs) if item.message == "Tool preparation" and item.context), {})
    execution_context = next((item.context for item in reversed(logs) if item.message == "Execution summary" and item.context), {})
    endpoint_inventory_context = next((item.data for item in reversed(pipeline_artifacts) if item.name == "endpoint_inventory" and item.data), {})
    workflow_request_inventory = next((item.data for item in reversed(pipeline_artifacts) if item.name == "workflow_request_inventory" and item.data), {})
    authenticated_behavior_proof = next((item.data for item in reversed(pipeline_artifacts) if item.name == "authenticated_behavior_proof" and item.data), {})
    request_map_payload = _read_scan_json(scan.id, "request_map.json", {"scan_id": scan.id, "total_requests": 0, "requests": []}) if scan else {}
    ai_trace_index_payload = _read_scan_json(scan.id, "ai/ai_trace_index.json", {"scan_id": scan.id, "total_ai_calls": 0, "calls": []}) if scan else {}
    agent_reactions_payload = _read_scan_jsonl(scan.id, "agent_reactions.jsonl") if scan else []
    target_classification_context = next((item.data for item in reversed(pipeline_artifacts) if item.name == "target_classification" and item.data), {})
    response_analysis_items = [item.data for item in pipeline_artifacts if item.artifact_type == "response_analysis" and item.data]
    auth_coverage_blocker = next((item.data for item in reversed(pipeline_artifacts) if item.name == "auth_coverage_blocked" and item.data), None)
    unavailable_tools = [
        {
            "tool": item.tool_name,
            "status": item.status,
            "reason": (item.output or {}).get("reason"),
        }
        for item in tool_runs
        if item.status in {"missing_prerequisite", "missing_credentials", "missing_tool", "tool_install_failed", "target_unreachable", "out_of_scope", "manual_confirmation_required", "execution_error"}
    ]
    ai_plan = ai_plan_context.get("ai_scan_plan") or {}
    ai_decision_memory = [
        {
            "summary": item.summary,
            "path": item.path,
            "metadata": item.metadata_json,
        }
        for item in evidence
        if item.kind == "ai_decision"
    ]
    evidence_by_tool = {
        (item.metadata_json or {}).get("tool"): item.path
        for item in evidence
        if item.metadata_json and item.metadata_json.get("tool")
    }
    execution_summary = execution_context.get("execution_summary") or [
        {
            "tool": item.tool_name,
            "status": item.status,
            "command": item.command,
            "evidence_path": evidence_by_tool.get(item.tool_name),
            "reason": (item.output or {}).get("reason"),
        }
        for item in tool_runs
    ]
    executive_findings = [item for item in findings if _is_executive_finding(item)]
    observations = [item for item in findings if not _is_executive_finding(item)]
    test_case_by_id = {item.id: item for item in test_cases}

    def tool_run_case(item: ToolRun) -> TestCase | None:
        return test_case_by_id.get(item.test_case_id) if item.test_case_id else None

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": {"id": project.id, "name": project.name},
        "targets": [{"id": target.id, "url": target.url, "scope": _sanitize_scope(target.scope)} for target in targets],
        "target": prompt_context.get("selected_target") or (targets[0].url if targets else None),
        "target_classification": target_classification_context.get("target_classification", {}),
        "pentest_phase_order": target_classification_context.get("phase_order", []),
        "decision_loop": target_classification_context.get("decision_loop"),
        "target_source": prompt_context.get("target_source"),
        "tester_prompt": prompt_context.get("prompt"),
        "prompt": prompt_context.get("prompt"),
        "environment_assumption": "testing/staging/non-production",
        "authorized_testing_caution": "Use only on authorized testing/staging environments. Tester is responsible for confirming scope and approval.",
        "ai_provider": ai_plan_context.get("ai_provider") or (scan.ai_provider if scan else None),
        "ai_model": ai_plan_context.get("ai_model"),
        "ai_planning_status": ai_plan_context.get("ai_planning_status") or ("approved" if ai_plan_context.get("ai_scan_plan") else (scan.status if scan else None)),
        "ai_planning_error": ai_plan_context.get("ai_planning_error"),
        "ai_planning_warning": ai_plan_context.get("ai_planning_warning"),
        "ai_available": ai_plan_context.get("ai_available"),
        "deterministic_mode": ai_plan_context.get("deterministic_mode"),
        "ai_timeout_seconds": get_settings().ollama_timeout_seconds,
        "ai_prompt": ai_plan_context.get("prompt") or prompt_context.get("prompt"),
        "ai_scan_plan": ai_plan,
        "ai_generated_test_plan": ai_plan,
        "ai_planning_attempts": ai_plan_context.get("ai_planning_attempts", []),
        "ai_evidence_review": ai_review_context.get("ai_evidence_review"),
        "ai_evidence_review_status": ai_review_context.get("ai_evidence_review_status"),
        "ai_evidence_review_error": ai_review_context.get("ai_evidence_review_error"),
        "ai_review_consistency": ai_review_context.get("ai_review", {}).get("ai_review_consistency"),
        "ai_review_consistency_warnings": ai_review_context.get("ai_review", {}).get("ai_review_consistency_warnings", []),
        "ai_local_fallback_summary_used": ai_review_context.get("local_fallback_summary_used", False),
        "ai_finding_summary": ai_review_context.get("ai_finding_summary"),
        "ai_call_runs": [
            {
                "id": item.id,
                "stage": item.stage,
                "agent_name": item.agent_name,
                "model": item.model,
                "prompt_tokens_estimate": item.prompt_tokens_estimate,
                "status": item.status or item.response_status,
                "response_status": item.response_status,
                "http_status": item.http_status,
                "started_at": item.started_at.isoformat() if item.started_at else None,
                "completed_at": item.completed_at.isoformat() if item.completed_at else None,
                "duration_ms": item.duration_ms,
                "retry_count": item.retry_count,
                "prompt_summary": item.prompt_summary,
                "prompt_hash": item.prompt_hash,
                "error_message": item.error_message,
                "request_summary": item.request_summary,
                "response_summary": item.response_summary,
                "parsed_response_json": item.parsed_response_json,
                "evidence_path": item.evidence_path,
            }
            for item in ai_call_runs
        ],
        "coverage_blockers": [auth_coverage_blocker] if auth_coverage_blocker else [],
        "auth_coverage_blocker_message": (
            "Authorization testing requires confirmed authenticated behavior and testable workflow requests. "
            "SAIF captured login/session material but could not prove post-login application behavior or identify authorization-sensitive requests. "
            "This is a coverage blocker, not a vulnerability."
            if auth_coverage_blocker
            else None
        ),
        "ai_decision_memory": ai_decision_memory,
        "request_map": {
            "total_requests": request_map_payload.get("total_requests") or len(request_map_payload.get("requests") or []),
            "requests": (request_map_payload.get("requests") or [])[:200],
        },
        "ai_trace_index": ai_trace_index_payload,
        "agent_reactions": agent_reactions_payload[-200:],
        "ai_retry_count": max([item.retry_count for item in ai_call_runs], default=0),
        "parsed_intent": prompt_context.get("parsed_intent"),
        "selected_target": prompt_context.get("selected_target") or (targets[0].url if targets else None),
        "selected_tools": [item.get("tool") for item in execution_summary if item.get("tool")] or prompt_context.get("selected_tools") or [item.tool_name for item in tool_runs],
        "execution_summary": execution_summary,
        "scan_lifecycle": scan.status if scan else None,
        "resource_settings": resource_limits_payload(),
        "payload_sources": payload_library_status(),
        "application_profiles": [
            {
                "primary_profile": item.primary_profile,
                "secondary_profiles": item.secondary_profiles,
                "lab_profile": item.lab_profile,
                "confidence": item.confidence,
                "detection_rules": item.detection_rules,
                "observed": item.observed,
            }
            for item in application_profiles
        ],
        "pipeline_stage_status": execution_context.get("pipeline", []),
        "discovery_summary": execution_context.get("discovery_summary", {}),
        "auth_testing_status": execution_context.get("auth_testing_status", {}),
        "vulnerability_coverage_matrix": _vulnerability_coverage_matrix(tool_runs, test_cases),
        "coverage_status": _coverage_overall(_vulnerability_coverage_matrix(tool_runs, test_cases), application_profiles),
        "installed_tools": tool_prep_context.get("installed_tools", []),
        "missing_tools": tool_prep_context.get("missing_tools", []),
        "auto_install_attempts": tool_prep_context.get("auto_install_attempts", []),
        "tool_install_failed_entries": [item for item in unavailable_tools if item["status"] == "tool_install_failed"],
        "missing_tool_entries": [item for item in unavailable_tools if item["status"] == "missing_tool"],
        "unavailable_tools": unavailable_tools,
        "agent_jobs": [
            {
                "id": item.id,
                "agent_name": item.agent_name,
                "job_type": item.job_type,
                "status": item.status,
                "priority": item.priority,
                "input": item.input,
                "output": _sanitize_tokens(item.output),
                "error": item.error,
                "started_at": item.started_at.isoformat() if item.started_at else None,
                "completed_at": item.completed_at.isoformat() if item.completed_at else None,
            }
            for item in agent_jobs
        ],
        "planned_test_cases": [
            {
                "id": item.id,
                "case_id": item.case_id,
                "test_id": item.test_id,
                "agent_name": item.agent_name or item.agent,
                "name": item.name,
                "category": item.category,
                "target": item.target,
                "applicability": item.applicability,
                "prerequisites": item.prerequisites,
                "selected_tool": item.selected_tool or item.tool,
                "alternate_tools": item.alternate_tools,
                "status": item.status,
                "priority": item.priority,
            }
            for item in test_cases
        ],
        "tool_registry_snapshot": [
            {
                "tool_name": item.tool_name,
                "install_method": item.install_method,
                "command_path": item.command_path,
                "version": item.version,
                "status": item.status,
                "last_checked_at": item.last_checked_at.isoformat() if item.last_checked_at else None,
                "install_attempt_count": item.install_attempt_count,
                "last_error": item.last_error,
                "metadata": item.metadata_json,
            }
            for item in tool_registry
        ],
        "ai_plan_test_cases": ai_plan.get("test_cases", []),
        "executed_test_cases": [
            {
                "id": tool_run_case(item).case_id if tool_run_case(item) else item.tool_name,
                "name": tool_run_case(item).name if tool_run_case(item) else item.tool_name,
                "execution_status": item.status,
                "command": item.command,
            }
            for item in tool_runs
        ],
        "not_applicable_test_cases": ai_plan.get("not_applicable", []),
        "missing_prerequisite_test_cases": ai_plan.get("missing_prerequisites", []),
        "discovered_urls": [item.url for item in discovered_endpoints if item.endpoint_type in {"web", "external", "web_service"}],
        "endpoint_inventory": endpoint_inventory_context.get("endpoint_inventory", []),
        "response_analysis": response_analysis_items[:200],
        "workflow_request_inventory": workflow_request_inventory,
        "authenticated_behavior_proof": authenticated_behavior_proof,
        "discovered_endpoints": [{"url": item.url, "method": item.method, "type": item.endpoint_type, "source": item.source, "metadata": item.metadata_json} for item in discovered_endpoints],
        "discovered_forms": [{"endpoint": item.endpoint, "name": item.name, "source": item.source, "metadata": item.metadata_json} for item in discovered_parameters if item.location == "form"],
        "discovered_auth_endpoints": [{"type": item.flow_type, "url": item.url, "evidence": item.evidence} for item in discovered_auth_flows],
        "discovered_tokens_cookies_summary": [{"type": item.token_type, "location": item.location, "sample": _mask_token(item.sample), "metadata": _sanitize_tokens(item.metadata_json)} for item in discovered_tokens],
        "authenticated_sessions": [
            {
                "credential_label": item.credential_label,
                "username": item.username,
                "role": item.role,
                "tenant": item.tenant,
                "auth_type": item.auth_type,
                "token_type": item.token_type,
                "login_status": item.login_status,
                "session_status": item.session_status,
                "authorization_header_type": item.authorization_header_type,
                "authorization_header": "Bearer <masked>" if item.authorization_header else None,
                "access_token": item.access_token_masked or _mask_token(item.access_token),
                "access_token_masked": item.access_token_masked or _mask_token(item.access_token),
                "access_token_hash": item.access_token_hash,
                "secret_ref_configured": bool(item.secret_ref),
                "refresh_token": _mask_token(item.refresh_token),
                "cookie": "<masked>" if item.cookie else None,
                "metadata": _sanitize_tokens(item.metadata_json),
            }
            for item in authenticated_sessions
        ],
        "discovered_static_assets": [{"url": item.url, "type": item.asset_type, "source": item.source} for item in discovered_assets],
        "discovered_services": [{"service_name": item.service_name, "host": item.host, "port": item.port, "protocol": item.protocol, "product": item.product, "version": item.version, "source": item.source, "metadata": item.metadata_json} for item in discovered_services],
        "discovered_api_specs": [{"spec_type": item.spec_type, "url": item.url, "status": item.status, "title": item.title, "version": item.version, "metadata": item.metadata_json} for item in discovered_api_specs],
        "discovered_auth_mechanisms": [{"mechanism_type": item.mechanism_type, "endpoint": item.endpoint, "confidence": item.confidence, "evidence": item.evidence} for item in discovered_auth_mechanisms],
        "discovered_session_mechanisms": [{"mechanism_type": item.mechanism_type, "location": item.location, "token_type": item.token_type, "confidence": item.confidence, "metadata": item.metadata_json} for item in discovered_session_mechanisms],
        "discovered_tenants": [{"tenant_ref": item.tenant_ref, "source": item.source, "metadata": item.metadata_json} for item in discovered_tenants],
        "authorization_matrix_status": {
            "entries": len(authorization_entries),
            "statuses": sorted({item.status for item in authorization_entries}),
        },
        "pipeline_artifacts": [{"type": item.artifact_type, "name": item.name, "data": _sanitize_tokens(item.data)} for item in pipeline_artifacts],
        "next_recommended_tests": ai_review_context.get("ai_review", {}).get("recommended_next_stage") or ai_review_context.get("ai_review", {}).get("applicable_next_stage_test_cases"),
        "scan": None
        if not scan
        else {
            "id": scan.id,
            "profile": scan.profile,
            "engagement_mode": scan.engagement_mode,
            "credentials_path": scan.credentials_path,
            "source_path": scan.source_path,
            "scan_config": getattr(scan, "scan_config", None),
            "auth_mode": scan.auth_mode,
            "destructive_method_policy": scan.destructive_method_policy,
            "enable_destructive_tests": getattr(scan, "enable_destructive_tests", False),
            "destructive_test_policy": getattr(scan, "destructive_test_policy", None),
            "allow_test_owned_object_creation": getattr(scan, "allow_test_owned_object_creation", False),
            "confirm_destructive_testing": getattr(scan, "confirm_destructive_testing", False),
            "allow_account_generation": scan.allow_account_generation,
            "allow_authenticated_testing": scan.allow_authenticated_testing,
            "allow_authorization_testing": scan.allow_authorization_testing,
            "allow_payload_testing": scan.allow_payload_testing,
            "allow_rate_limit_testing": scan.allow_rate_limit_testing,
            "ai_provider": scan.ai_provider,
            "authorized_testing_mode": scan.authorized_testing_mode,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        "test_runs": [
            {
                "id": item.id,
                "test_case_id": item.test_case.case_id if item.test_case else None,
                "agent_name": item.agent_name,
                "tool_name": item.tool_name,
                "command": item.command,
                "status": item.status,
                "duration_ms": item.duration_ms,
                "output_summary": item.output_summary,
                "evidence_id": item.evidence_id,
                "error_message": item.error_message,
                "retry_count": item.retry_count,
                "output": _sanitize_tokens(item.output),
            }
            for item in test_runs
        ],
        "tool_runs": [
            {
                "id": item.id,
                "tool": item.tool_name,
                "test_case_id": item.test_case_id,
                "agent_name": item.agent_name,
                "status": item.status,
                "command": item.command,
                "duration_ms": item.duration_ms,
                "evidence_path": item.evidence_path,
                "output": item.output,
                "summary": _summarize_tool_output(item.output),
            }
            for item in tool_runs
        ],
        "evidence": [
            {
                "id": item.id,
                "kind": item.kind,
                "path": item.path,
                "summary": item.summary,
                "metadata": item.metadata_json,
            }
            for item in evidence
        ],
        "findings": [
            {
                "id": item.id,
                "finding_id": item.finding_uid or f"SAIF-{scan.id if scan else 'X'}-F{item.id:03d}",
                "title": item.title,
                "severity": item.severity,
                "description": item.description,
                "status": item.status,
                "confidence": item.confidence or ("medium" if item.severity == "info" else "low"),
                "affected_endpoint": item.affected_endpoint,
                "http_method": item.http_method,
                "parameter": item.parameter,
                "header_or_body_field": item.parameter,
                "payload": _mask_token(item.payload),
                "payload_used": _mask_token(item.payload),
                "payload_source": item.payload_source,
                "agent_name": item.agent_name,
                "test_case_id": item.test_case_id,
                "business_impact": item.business_impact or _default_business_impact(item),
                "technical_impact": item.technical_impact or item.description,
                "reproduction_steps": item.reproduction_steps,
                "replication_steps": item.reproduction_steps or _default_replication_steps(item),
                "baseline_request_summary": _evidence_summary(item.baseline_evidence_path),
                "attack_request_summary": _evidence_summary(item.attack_evidence_path),
                "baseline_response_summary": _evidence_summary(item.baseline_evidence_path),
                "attack_response_summary": _evidence_summary(item.attack_evidence_path),
                "evidence_path": _finding_evidence_path(item, evidence),
                "ai_reasoning_summary": item.ai_reasoning_summary or item.description,
                "remediation": item.remediation or _default_remediation(item),
                "closure_evidence_path": item.closure_evidence_path,
                "retest_status": item.retest_status or "not_retested",
                "fixed_at": item.fixed_at.isoformat() if item.fixed_at else None,
            }
            for item in executive_findings
        ],
        "observations": [
            {
                "id": item.id,
                "title": item.title,
                "severity": item.severity,
                "status": item.status,
                "confidence": item.confidence or "observed",
                "description": item.description,
                "evidence_path": _finding_evidence_path(item, evidence),
            }
            for item in observations
        ],
        "manual_review_items": [
            {"id": item.id, "title": item.title, "endpoint": item.affected_endpoint, "parameter": item.parameter, "confidence": item.confidence}
            for item in findings
            if item.status == "manual_confirmation_required"
        ],
        "professional_report": True,
        "assessment_type": "Web/API penetration test",
        "overall_risk_rating": _overall_risk(executive_findings),
        "findings_by_severity": _findings_by_severity(executive_findings),
        "business_impact_summary": _business_impact_summary(executive_findings),
        "key_risks": [item.title for item in executive_findings if item.severity in {"critical", "high"}][:10],
        "recommended_next_steps": _recommended_next_steps(findings, execution_context),
        "scan_timeline": [
            {
                "phase": item.phase_name,
                "status": item.status,
                "started_at": item.started_at.isoformat() if item.started_at else None,
                "completed_at": item.completed_at.isoformat() if item.completed_at else None,
                "duration_ms": item.duration_ms,
                "agent": item.agent_name,
                "notes": item.error_message or ((item.summary_json or {}).get("reason") if item.summary_json else None),
                "summary": item.summary_json,
            }
            for item in scan_phases
        ],
        "finding_index": [
            {
                "finding_id": item.finding_uid,
                "title": item.title,
                "severity": item.severity,
                "status": item.status,
                "confidence": item.confidence,
                "affected_endpoint": item.affected_endpoint,
                "agent": item.agent_name,
                "cwe": item.cwe,
                "owasp_category": item.owasp_category,
            }
            for item in executive_findings
        ],
        "payload_attempts": [
            {
                "id": item.id,
                "vulnerability_type": item.vulnerability_type,
                "payload_source": item.payload_source,
                "payload": _mask_token(item.payload),
                "endpoint": item.endpoint,
                "method": item.method,
                "parameter_location": item.parameter_location,
                "parameter_name": item.parameter_name,
                "baseline_status": item.baseline_status,
                "attack_status": item.attack_status,
                "body_length_delta": item.body_length_delta,
                "reflection_detected": item.reflection_detected,
                "error_marker_detected": item.error_marker_detected,
                "protected_data_detected": item.protected_data_detected,
                "ai_decision": item.ai_decision_json,
                "status": item.status,
                "evidence_path": item.evidence_path,
            }
            for item in payload_attempts
        ],
        "production_readiness": production_readiness_for_scan(session, scan) if scan else _production_readiness(scan, findings, execution_context),
        "logs": [
            {
                "id": item.id,
                "level": item.level,
                "message": item.message,
                "context": item.context,
            }
            for item in logs
        ],
    }


def _summarize_tool_output(output: dict | None) -> str:
    if not output:
        return ""
    if output.get("reason"):
        return str(output["reason"])
    if output.get("error"):
        return str(output["error"])[:240]
    if output.get("status_code") is not None:
        return f"HTTP {output['status_code']}"
    if output.get("count") is not None:
        return f"count={output['count']}"
    if output.get("found"):
        return f"found={len(output['found'])}"
    if output.get("stdout"):
        return str(output["stdout"]).splitlines()[0][:240] if str(output["stdout"]).splitlines() else ""
    return ""


def _vulnerability_coverage_matrix(tool_runs: list[ToolRun], test_cases: list[TestCase] | None = None) -> list[dict]:
    test_cases = test_cases or []
    coverage_cases = [case for case in test_cases if (case.case_id or "").startswith("coverage.")]
    if coverage_cases:
        rows = []
        for case in coverage_cases:
            definition = case.definition or {}
            rows.append(
                {
                    "category": case.category or case.name,
                    "applicable": case.applicability != "not_applicable",
                    "status": case.status,
                    "test_cases_planned": 1,
                    "test_cases_executed": 0 if case.status in {"missing_prerequisite", "not_applicable"} else 1,
                    "findings": 0,
                    "missing_prerequisites": definition.get("required_artifact") if case.status == "missing_prerequisite" else None,
                    "not_applicable_reason": definition.get("reason") if case.status == "not_applicable" else None,
                    "evidence_path": None,
                    "next_action": definition.get("next_action"),
                    "reason": definition.get("reason"),
                    "how_to_make_testable": definition.get("how_to_make_testable"),
                    "client_action_required": definition.get("client_action_required"),
                }
            )
        return rows
    status_by_tool = {item.tool_name: item.status for item in tool_runs}
    mapping = [
        ("Broken Authentication", ["account_provisioning", "login_session", "auth_session_mapping"]),
        ("BOLA/IDOR", ["authorization_matrix", "idor_bola_bfla_planner"]),
        ("BFLA", ["authorization_matrix", "idor_bola_bfla_planner"]),
        ("Mass Assignment", ["input_validation_planner"]),
        ("SSRF", ["ssrf_adaptive"]),
        ("JWT/Session", ["jwt_adaptive", "token_analysis"]),
        ("Rate Limiting/OTP", ["business_logic_planner", "auth_session_mapping"]),
        ("Input Validation", ["input_validation_planner", "xss_adaptive", "sqli_adaptive", "ssrf_adaptive"]),
        ("Business Logic", ["business_logic_planner"]),
    ]
    return [{"category": name, "status": _coverage_status([status_by_tool.get(tool) for tool in tools]), "tools": tools} for name, tools in mapping]


def _coverage_status(statuses: list[str | None]) -> str:
    present = [status for status in statuses if status]
    if not present:
        return "not_run"
    if any(status == "finding_created" for status in present):
        return "finding_created"
    if any(status == "manual_confirmation_required" for status in present):
        return "manual_confirmation_required"
    if any(status == "missing_prerequisite" for status in present):
        return "missing_prerequisite"
    if any(status == "missing_credentials" for status in present):
        return "missing_credentials"
    if any(status == "completed" for status in present):
        return "completed"
    return present[0]


def _coverage_overall(matrix: list[dict], application_profiles: list[ApplicationProfile]) -> str:
    crapi = any(item.primary_profile == "crapi" or item.lab_profile == "crapi" for item in application_profiles)
    incomplete = any(item.get("status") in {"not_run", "missing_prerequisite", "missing_credentials", "execution_error"} for item in matrix)
    if crapi and incomplete:
        return "incomplete"
    if incomplete:
        return "partial"
    return "complete"


def _finding_evidence_path(finding: Finding, evidence: list[Evidence]) -> str | None:
    if finding.attack_evidence_path:
        return finding.attack_evidence_path
    if finding.baseline_evidence_path:
        return finding.baseline_evidence_path
    if finding.evidence_id:
        match = next((item for item in evidence if item.id == finding.evidence_id), None)
        return match.path if match else None
    return None


def _evidence_summary(path: str | None) -> str | None:
    if not path:
        return None
    return f"See evidence file: {path}"


def _default_business_impact(finding: Finding) -> str:
    if finding.severity == "info":
        return "Informational observation to support tester review, coverage tracking, and follow-up validation."
    return "Potential impact depends on affected data, role, and endpoint exposure. Validate exploitability and business context during retest."


def _default_replication_steps(finding: Finding) -> str:
    parts = []
    if finding.http_method or finding.affected_endpoint:
        parts.append(f"Send {finding.http_method or 'the relevant method'} request to {finding.affected_endpoint or 'the affected endpoint'}.")
    if finding.parameter:
        parts.append(f"Review parameter or field: {finding.parameter}.")
    if finding.payload:
        parts.append("Use the recorded payload from the evidence record.")
    return " ".join(parts) or "Review the attached evidence path and rerun the associated tool/test case."


def _default_remediation(finding: Finding) -> str:
    if finding.severity == "info":
        return "Review this observation during triage and document whether it affects scope, attack surface, or follow-up testing."
    if finding.vulnerability_type in {"jwt", "session"}:
        return "Harden token/session handling, validate signatures and claims server-side, enforce expiration, and retest session controls."
    if finding.vulnerability_type in {"xss", "sqli", "ssrf"}:
        return "Apply server-side validation, contextual encoding or parameterized queries, egress restrictions where relevant, and regression tests."
    return "Apply least-privilege controls, validate authorization server-side, reduce exposed attack surface, and retest the affected workflow."


def _findings_by_severity(findings: list[Finding]) -> dict:
    severities = ["critical", "high", "medium", "low", "info"]
    return {severity: len([item for item in findings if item.severity == severity]) for severity in severities}


def _is_executive_finding(finding: Finding) -> bool:
    if getattr(finding, "finding_type", "finding") == "observation":
        return False
    if finding.severity == "info" or finding.status == "informational":
        return False
    if finding.confidence not in {"confirmed", "high"}:
        return False
    if not finding.affected_endpoint:
        return False
    if not (finding.business_impact and finding.remediation):
        return False
    return finding.status not in {"closed", "false_positive"}


def _overall_risk(findings: list[Finding]) -> str:
    severities = {item.severity for item in findings if item.status not in {"closed", "false_positive"}}
    if "critical" in severities:
        return "critical"
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    if "low" in severities:
        return "low"
    return "informational"


def _business_impact_summary(findings: list[Finding]) -> str:
    severe = [item for item in findings if item.severity in {"critical", "high"} and item.status not in {"closed", "false_positive"}]
    if severe:
        return "High-impact findings may affect confidentiality, integrity, authorization boundaries, or business workflow assurance."
    if findings:
        return "Findings were recorded and should be reviewed for applicability, exploitability, and remediation priority."
    return "No confirmed vulnerability findings were recorded in this scan."


def _recommended_next_steps(findings: list[Finding], execution_context: dict) -> list[str]:
    steps = []
    if any(item.severity in {"critical", "high"} for item in findings):
        steps.append("Prioritize remediation and retest high/critical findings.")
    if any(item.status == "manual_confirmation_required" for item in findings):
        steps.append("Manually confirm low-confidence or environment-dependent findings.")
    pipeline = execution_context.get("pipeline") or []
    if any(item.get("status") == "execution_error" for item in pipeline if isinstance(item, dict)):
        steps.append("Review failed phases and resume the scan from the first incomplete phase.")
    if not steps:
        steps.append("Review evidence, preserve report artifacts, and schedule retest if fixes are applied.")
    return steps


def generate_json_report(session: Session, project_name: str | None = None, scan_id: int | None = None) -> Path:
    payload = build_report_payload(session, project_name, scan_id)
    project = session.get(Project, payload["project"]["id"])
    scan_id = payload["scan"]["id"] if payload["scan"] else None
    report_dir = get_settings().report_dir / project.name
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = report_dir / f"report-{timestamp}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    session.add(
        Report(
            project_id=project.id,
            scan_id=scan_id,
            format="json",
            path=str(path),
            summary={"findings": len(payload["findings"]), "evidence": len(payload["evidence"])},
        )
    )
    return path


def generate_html_report(session: Session, project_name: str | None = None, scan_id: int | None = None) -> Path:
    payload = build_report_payload(session, project_name, scan_id)
    project = session.get(Project, payload["project"]["id"])
    scan_id = payload["scan"]["id"] if payload["scan"] else None
    report_dir = get_settings().report_dir / project.name
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = report_dir / f"report-{timestamp}.html"

    finding_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(item.get('finding_id') or item.get('id')))}</td>"
        f"<td>{escape(str(item['severity']))}</td>"
        f"<td>{escape(str(item['title']))}</td>"
        f"<td>{escape(str(item['status']))}</td>"
        f"<td>{escape(str(item.get('confidence') or ''))}</td>"
        f"<td>{escape(str(item.get('affected_endpoint') or ''))}</td>"
        f"<td>{escape(str(item.get('http_method') or ''))}</td>"
        f"<td>{escape(str(item.get('parameter') or ''))}</td>"
        f"<td>{escape(str(item.get('payload_used') or ''))}</td>"
        f"<td>{escape(str(item.get('payload_source') or ''))}</td>"
        f"<td>{escape(str(item.get('agent_name') or ''))}</td>"
        f"<td>{escape(str(item.get('test_case_id') or ''))}</td>"
        f"<td>{escape(str(item.get('description') or ''))}</td>"
        f"<td>{escape(str(item.get('business_impact') or ''))}</td>"
        f"<td>{escape(str(item.get('technical_impact') or ''))}</td>"
        f"<td>{escape(str(item.get('replication_steps') or ''))}</td>"
        f"<td>{escape(str(item.get('baseline_request_summary') or ''))}</td>"
        f"<td>{escape(str(item.get('attack_request_summary') or ''))}</td>"
        f"<td><code>{escape(str(item.get('evidence_path') or ''))}</code></td>"
        f"<td>{escape(str(item.get('ai_reasoning_summary') or ''))}</td>"
        f"<td>{escape(str(item.get('remediation') or ''))}</td>"
        f"<td>{escape(str(item.get('retest_status') or ''))}</td>"
        "</tr>"
        for item in payload["findings"]
    )
    evidence_items = "\n".join(
        "<tr>"
        f"<td>{escape(str(item['kind']))}</td>"
        f"<td><code>{escape(str(item['path']))}</code></td>"
        f"<td>{escape(str(item.get('summary') or ''))}</td>"
        "</tr>"
        for item in payload["evidence"]
    )
    tool_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(item['tool']))}</td>"
        f"<td>{escape(str(item['status']))}</td>"
        f"<td><code>{escape(str(item.get('command') or ''))}</code></td>"
        f"<td>{escape(str(item.get('summary') or ''))}</td>"
        "</tr>"
        for item in payload["tool_runs"]
    )
    execution_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(item.get('tool')))}</td>"
        f"<td>{escape(str(item.get('status')))}</td>"
        f"<td>{escape(str(item.get('reason') or ''))}</td>"
        f"<td><code>{escape(str(item.get('evidence_path') or ''))}</code></td>"
        "</tr>"
        for item in payload["execution_summary"]
    )
    finding_index_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(item.get('finding_id') or ''))}</td>"
        f"<td>{escape(str(item.get('title') or ''))}</td>"
        f"<td>{escape(str(item.get('severity') or ''))}</td>"
        f"<td>{escape(str(item.get('status') or ''))}</td>"
        f"<td>{escape(str(item.get('confidence') or ''))}</td>"
        f"<td>{escape(str(item.get('affected_endpoint') or ''))}</td>"
        f"<td>{escape(str(item.get('agent') or ''))}</td>"
        f"<td>{escape(str(item.get('cwe') or item.get('owasp_category') or ''))}</td>"
        "</tr>"
        for item in payload.get("finding_index") or []
    )
    observation_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(item.get('title') or ''))}</td>"
        f"<td>{escape(str(item.get('confidence') or 'observed'))}</td>"
        f"<td>{escape(str(item.get('status') or ''))}</td>"
        f"<td>{escape(str(item.get('description') or ''))}</td>"
        "</tr>"
        for item in payload.get("observations") or []
    )
    payload_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(item.get('vulnerability_type') or ''))}</td>"
        f"<td>{escape(str(item.get('payload_source') or ''))}</td>"
        f"<td>{escape(str(item.get('payload') or ''))}</td>"
        f"<td>{escape(str(item.get('endpoint') or ''))}</td>"
        f"<td>{escape(str(item.get('parameter_name') or ''))}</td>"
        f"<td>{escape(str(item.get('attack_status') or ''))}</td>"
        f"<td>{escape(str(item.get('body_length_delta') or ''))}</td>"
        f"<td>{escape(str(item.get('reflection_detected') or ''))}</td>"
        f"<td>{escape(str(item.get('status') or ''))}</td>"
        f"<td><code>{escape(str(item.get('evidence_path') or ''))}</code></td>"
        "</tr>"
        for item in payload.get("payload_attempts") or []
    )
    timeline_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(item.get('phase') or ''))}</td>"
        f"<td>{escape(str(item.get('status') or ''))}</td>"
        f"<td>{escape(str(item.get('started_at') or ''))}</td>"
        f"<td>{escape(str(item.get('completed_at') or ''))}</td>"
        f"<td>{escape(str(item.get('duration_ms') or ''))}</td>"
        f"<td>{escape(str(item.get('agent') or ''))}</td>"
        f"<td>{escape(str(item.get('notes') or ''))}</td>"
        "</tr>"
        for item in payload.get("scan_timeline") or []
    )

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SAIF - Secure AI Forge Report - {escape(project.name)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #18202a; }}
    h1, h2 {{ color: #101820; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #ccd3dc; padding: 0.5rem; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f6; }}
    code {{ background: #f4f6f8; padding: 0.1rem 0.25rem; }}
    .notice {{ border-left: 4px solid #557; padding: 0.75rem 1rem; background: #f7f8fa; }}
  </style>
</head>
<body>
  <h1>SAIF - Secure AI Forge Report</h1>
  <h2>Cover Page</h2>
  <table><tbody>
    <tr><th>Assessment type</th><td>{escape(str(payload.get("assessment_type") or "Web/API penetration test"))}</td></tr>
    <tr><th>Project</th><td>{escape(project.name)}</td></tr>
    <tr><th>Target</th><td>{escape(str(payload.get("target") or ""))}</td></tr>
    <tr><th>Engagement mode</th><td>{escape(str((payload.get("scan") or {}).get("engagement_mode") or "black_box"))}</td></tr>
    <tr><th>Generated at</th><td>{escape(str(payload.get("generated_at") or ""))}</td></tr>
  </tbody></table>
  <p class="notice">{escape(str(payload.get("authorized_testing_caution")))}</p>
  <h2>Project</h2>
  <p><strong>{escape(project.name)}</strong></p>
  <h2>Executive Summary</h2>
  <table>
    <tbody>
      <tr><th>Overall risk rating</th><td>{escape(str(payload.get("overall_risk_rating") or ""))}</td></tr>
      <tr><th>Findings by severity</th><td><pre>{escape(json.dumps(payload.get("findings_by_severity"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Production readiness</th><td><pre>{escape(json.dumps(payload.get("production_readiness"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Business impact summary</th><td>{escape(str(payload.get("business_impact_summary") or ""))}</td></tr>
      <tr><th>Key risks</th><td><pre>{escape(json.dumps(payload.get("key_risks"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Recommended next steps</th><td><pre>{escape(json.dumps(payload.get("recommended_next_steps"), indent=2, sort_keys=True))}</pre></td></tr>
    </tbody>
  </table>
  <h2>Scan</h2>
  <pre>{escape(json.dumps(payload["scan"], indent=2, sort_keys=True))}</pre>
  <h2>Targets</h2>
  <pre>{escape(json.dumps(payload["targets"], indent=2, sort_keys=True))}</pre>
  <h2>Scope</h2>
  <pre>{escape(json.dumps(payload.get("targets"), indent=2, sort_keys=True))}</pre>
  <h2>Methodology</h2>
  <p>SAIF - Secure AI Forge executed AI-planned Web/API discovery, profile detection, authentication/session mapping, authorization checks, adaptive payload validation, evidence capture, and report generation according to available prerequisites and selected tools.</p>
  <h2>Prompt Context</h2>
  <table>
    <tbody>
      <tr><th>Prompt</th><td>{escape(str(payload.get("prompt") or ""))}</td></tr>
      <tr><th>Engagement mode</th><td>{escape(str((payload.get("scan") or {}).get("engagement_mode") or "black_box"))}</td></tr>
      <tr><th>Target source</th><td>{escape(str(payload.get("target_source") or ""))}</td></tr>
      <tr><th>Target classification</th><td><pre>{escape(json.dumps(payload.get("target_classification"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Pentest phase order</th><td><pre>{escape(json.dumps(payload.get("pentest_phase_order"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Environment assumption</th><td>{escape(str(payload.get("environment_assumption") or ""))}</td></tr>
      <tr><th>AI provider</th><td>{escape(str(payload.get("ai_provider") or ""))}</td></tr>
      <tr><th>AI model</th><td>{escape(str(payload.get("ai_model") or ""))}</td></tr>
      <tr><th>AI planning status</th><td>{escape(str(payload.get("ai_planning_status") or ""))}</td></tr>
      <tr><th>AI planning warning</th><td>{escape(str(payload.get("ai_planning_warning") or ""))}</td></tr>
      <tr><th>AI planning error</th><td>{escape(str(payload.get("ai_planning_error") or ""))}</td></tr>
      <tr><th>AI available</th><td>{escape(str(payload.get("ai_available")))}</td></tr>
      <tr><th>Deterministic mode</th><td>{escape(str(payload.get("deterministic_mode")))}</td></tr>
      <tr><th>AI timeout setting</th><td>{escape(str(payload.get("ai_timeout_seconds") or ""))}s</td></tr>
      <tr><th>AI prompt</th><td>{escape(str(payload.get("ai_prompt") or ""))}</td></tr>
      <tr><th>AI scan plan</th><td><pre>{escape(json.dumps(payload.get("ai_scan_plan"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>AI planning attempts</th><td><pre>{escape(json.dumps(payload.get("ai_planning_attempts"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>AI evidence review</th><td>{escape(str(payload.get("ai_evidence_review") or ""))}</td></tr>
      <tr><th>AI evidence review status</th><td>{escape(str(payload.get("ai_evidence_review_status") or ""))}</td></tr>
      <tr><th>AI evidence review error</th><td>{escape(str(payload.get("ai_evidence_review_error") or ""))}</td></tr>
      <tr><th>AI review consistency</th><td>{escape(str(payload.get("ai_review_consistency") or ""))}</td></tr>
      <tr><th>AI review consistency warnings</th><td><pre>{escape(json.dumps(payload.get("ai_review_consistency_warnings"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>AI local fallback summary used</th><td>{escape(str(payload.get("ai_local_fallback_summary_used")))}</td></tr>
      <tr><th>AI decision memory</th><td><pre>{escape(json.dumps(payload.get("ai_decision_memory"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Coverage blockers</th><td><pre>{escape(json.dumps(payload.get("coverage_blockers"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Auth coverage blocker</th><td>{escape(str(payload.get("auth_coverage_blocker_message") or ""))}</td></tr>
      <tr><th>AI call runs</th><td><pre>{escape(json.dumps(payload.get("ai_call_runs"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>AI finding summary</th><td><pre>{escape(json.dumps(payload.get("ai_finding_summary"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Parsed intent</th><td><pre>{escape(json.dumps(payload.get("parsed_intent"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Selected target</th><td>{escape(str(payload.get("selected_target") or ""))}</td></tr>
      <tr><th>Selected tools</th><td>{escape(", ".join(payload.get("selected_tools") or []))}</td></tr>
      <tr><th>Scan lifecycle</th><td>{escape(str(payload.get("scan_lifecycle") or ""))}</td></tr>
      <tr><th>Resource settings</th><td><pre>{escape(json.dumps(payload.get("resource_settings"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Payload sources</th><td><pre>{escape(json.dumps(payload.get("payload_sources"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Application profiles</th><td><pre>{escape(json.dumps(payload.get("application_profiles"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Production readiness</th><td><pre>{escape(json.dumps(payload.get("production_readiness"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Agent jobs</th><td><pre>{escape(json.dumps(payload.get("agent_jobs"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Planned test cases</th><td><pre>{escape(json.dumps(payload.get("planned_test_cases"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Tool registry snapshot</th><td><pre>{escape(json.dumps(payload.get("tool_registry_snapshot"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Execution summary</th><td><pre>{escape(json.dumps(payload.get("execution_summary"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Pipeline stage status</th><td><pre>{escape(json.dumps(payload.get("pipeline_stage_status"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Discovery summary</th><td><pre>{escape(json.dumps(payload.get("discovery_summary"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Auth testing status</th><td><pre>{escape(json.dumps(payload.get("auth_testing_status"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Coverage status</th><td>{escape(str(payload.get("coverage_status") or ""))}</td></tr>
      <tr><th>Vulnerability coverage matrix</th><td><pre>{escape(json.dumps(payload.get("vulnerability_coverage_matrix"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Authenticated sessions</th><td><pre>{escape(json.dumps(payload.get("authenticated_sessions"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Installed tools</th><td>{escape(", ".join(payload.get("installed_tools") or []))}</td></tr>
      <tr><th>Missing tools</th><td>{escape(", ".join(payload.get("missing_tools") or []))}</td></tr>
      <tr><th>Auto-install attempts</th><td><pre>{escape(json.dumps(payload.get("auto_install_attempts"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Tool install failures</th><td><pre>{escape(json.dumps(payload.get("tool_install_failed_entries"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Missing tool entries</th><td><pre>{escape(json.dumps(payload.get("missing_tool_entries"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Unavailable tools/prerequisites</th><td><pre>{escape(json.dumps(payload.get("unavailable_tools"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Executed test cases</th><td><pre>{escape(json.dumps(payload.get("executed_test_cases"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Not applicable test cases</th><td><pre>{escape(json.dumps(payload.get("not_applicable_test_cases"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Missing prerequisite test cases</th><td><pre>{escape(json.dumps(payload.get("missing_prerequisite_test_cases"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Discovered URLs</th><td><pre>{escape(json.dumps(payload.get("discovered_urls"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Endpoint inventory</th><td><pre>{escape(json.dumps(payload.get("endpoint_inventory"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Response analysis memory</th><td><pre>{escape(json.dumps(payload.get("response_analysis"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Workflow request inventory</th><td><pre>{escape(json.dumps(payload.get("workflow_request_inventory"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Authenticated behavior proof</th><td><pre>{escape(json.dumps(payload.get("authenticated_behavior_proof"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Discovered endpoints</th><td><pre>{escape(json.dumps(payload.get("discovered_endpoints"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Discovered forms</th><td><pre>{escape(json.dumps(payload.get("discovered_forms"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Discovered auth endpoints</th><td><pre>{escape(json.dumps(payload.get("discovered_auth_endpoints"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Discovered tokens/cookies summary</th><td><pre>{escape(json.dumps(payload.get("discovered_tokens_cookies_summary"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Authorization matrix status</th><td><pre>{escape(json.dumps(payload.get("authorization_matrix_status"), indent=2, sort_keys=True))}</pre></td></tr>
      <tr><th>Next recommended tests</th><td><pre>{escape(json.dumps(payload.get("next_recommended_tests"), indent=2, sort_keys=True))}</pre></td></tr>
    </tbody>
  </table>
  <h2>Scan Timeline</h2>
  <table>
    <thead><tr><th>Phase</th><th>Status</th><th>Start</th><th>End</th><th>Duration ms</th><th>Agent</th><th>Notes</th></tr></thead>
    <tbody>{timeline_rows or '<tr><td colspan="7">No phase records.</td></tr>'}</tbody>
  </table>
  <h2>Executive Findings</h2>
  <p>{'No confirmed vulnerabilities were produced. Coverage may be incomplete if authenticated behavior proof or workflow request inventory was not available for selected authorization tests.' if not payload.get('finding_index') else ''}</p>
  <table>
    <thead><tr><th>Finding ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Confidence</th><th>Affected endpoint</th><th>Agent</th><th>CWE/OWASP</th></tr></thead>
    <tbody>{finding_index_rows or '<tr><td colspan="8">No confirmed vulnerabilities recorded.</td></tr>'}</tbody>
  </table>
  <h2>Observations</h2>
  <table>
    <thead><tr><th>Title</th><th>Confidence</th><th>Status</th><th>Description</th></tr></thead>
    <tbody>{observation_rows or '<tr><td colspan="4">No observations recorded.</td></tr>'}</tbody>
  </table>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Finding ID</th><th>Severity</th><th>Title</th><th>Status</th><th>Confidence</th><th>Affected endpoint</th><th>Method</th><th>Parameter/field</th><th>Payload</th><th>Payload source</th><th>Agent</th><th>Test case</th><th>Description</th><th>Business impact</th><th>Technical impact</th><th>Replication steps</th><th>Baseline request</th><th>Attack request</th><th>Evidence path</th><th>AI reasoning</th><th>Remediation</th><th>Retest status</th></tr></thead>
    <tbody>{finding_rows or '<tr><td colspan="22">No findings recorded.</td></tr>'}</tbody>
  </table>
  <h2>Execution Summary</h2>
  <table>
    <thead><tr><th>Tool</th><th>Status</th><th>Reason</th><th>Evidence Path</th></tr></thead>
    <tbody>{execution_rows or '<tr><td colspan="4">No execution summary recorded.</td></tr>'}</tbody>
  </table>
  <h2>Evidence</h2>
  <table>
    <thead><tr><th>Kind</th><th>Path</th><th>Summary</th></tr></thead>
    <tbody>{evidence_items or '<tr><td colspan="3">No evidence recorded.</td></tr>'}</tbody>
  </table>
  <h2>Tool Run Output Summary</h2>
  <table>
    <thead><tr><th>Tool</th><th>Status</th><th>Command</th><th>Summary</th></tr></thead>
    <tbody>{tool_rows or '<tr><td colspan="4">No tool runs recorded.</td></tr>'}</tbody>
  </table>
  <h2>Payload Execution Details</h2>
  <table>
    <thead><tr><th>Type</th><th>Source</th><th>Payload</th><th>Endpoint</th><th>Parameter</th><th>Status code</th><th>Length delta</th><th>Reflection</th><th>Status</th><th>Evidence</th></tr></thead>
    <tbody>{payload_rows or '<tr><td colspan="10">No payload attempts recorded.</td></tr>'}</tbody>
  </table>
  <h2>Ollama / AI Activity</h2>
  <pre>{escape(json.dumps(payload.get("ai_call_runs"), indent=2, sort_keys=True))}</pre>
  <h2>AI Trace Index</h2>
  <pre>{escape(json.dumps(payload.get("ai_trace_index"), indent=2, sort_keys=True))}</pre>
  <h2>Agent Reactions</h2>
  <pre>{escape(json.dumps(payload.get("agent_reactions"), indent=2, sort_keys=True))}</pre>
  <h2>Request Map</h2>
  <pre>{escape(json.dumps(payload.get("request_map"), indent=2, sort_keys=True))}</pre>
  <h2>Agent Activity</h2>
  <pre>{escape(json.dumps(payload.get("agent_jobs"), indent=2, sort_keys=True))}</pre>
  <h2>Tool Runs</h2>
  <pre>{escape(json.dumps(payload.get("tool_runs"), indent=2, sort_keys=True))}</pre>
  <h2>Evidence Appendix</h2>
  <pre>{escape(json.dumps(payload.get("evidence"), indent=2, sort_keys=True))}</pre>
  <h2>Retest and Closure</h2>
  <pre>{escape(json.dumps(payload.get("manual_review_items"), indent=2, sort_keys=True))}</pre>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")
    session.add(
        Report(
            project_id=project.id,
            scan_id=scan_id,
            format="html",
            path=str(path),
            summary={"findings": len(payload["findings"]), "evidence": len(payload["evidence"])},
        )
    )
    return path


def _read_scan_json(scan_id: int, relative_path: str, fallback: dict) -> dict:
    path = get_settings().evidence_dir / f"scan-{scan_id}" / relative_path
    if not path.exists():
        return fallback
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return {"error": str(exc), **fallback}
    return value if isinstance(value, dict) else fallback


def _read_scan_jsonl(scan_id: int, relative_path: str) -> list[dict]:
    path = get_settings().evidence_dir / f"scan-{scan_id}" / relative_path
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except Exception:
            value = {"raw": line[:2000]}
        if isinstance(value, dict):
            rows.append(value)
    return rows


def generate_report(session: Session, project_name: str | None, format_: str, scan_id: int | None = None) -> Path:
    if format_ == "json":
        return generate_json_report(session, project_name, scan_id)
    if format_ == "html":
        return generate_html_report(session, project_name, scan_id)
    raise ValueError(f"Unsupported report format {format_!r}")
