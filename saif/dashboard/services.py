from __future__ import annotations

import json
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from saif.config import get_settings
from saif.db.models import (
    AgentJob,
    AiCallRun,
    AuthenticatedSession,
    Evidence,
    Finding,
    PayloadAttempt,
    Project,
    Report,
    Scan,
    ScanEvent,
    ScanPhase,
    ScanProcess,
    Target,
    TestCase,
    ToolRegistry,
    ToolRun,
)
from saif.services.case_management import production_readiness_for_scan, scan_summary, scan_target, sync_scan_phases
from saif.services.payloads import payload_library_status
from saif.services.progress import emit_progress, status_snapshot, watch_snapshot
from saif.services.reporting import build_report_payload, generate_report
from saif.services.resource_manager import resource_limits_payload
from saif.dashboard.actions import finding_actions, validate_finding_action, scan_actions, validate_scan_action


SECRET_KEYS = {"token", "authorization", "cookie", "jwt", "bearer", "secret", "password", "refresh"}


def iso(value) -> str | None:
    return value.isoformat() if value else None


def safe_json(value: Any, _seen: set[int] | None = None):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    _seen = _seen or set()
    obj_id = id(value)
    if obj_id in _seen:
        return "<recursive>"
    if isinstance(value, (dict, list, tuple, set)):
        _seen.add(obj_id)
    if isinstance(value, dict):
        return {str(key): safe_json(item, _seen) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [safe_json(item, _seen) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__table__"):
        return row(value)
    return str(value)


def row(item) -> dict:
    data = {}
    for column in item.__table__.columns:
        value = getattr(item, column.name)
        data[column.name] = safe_json(sanitize(value))
    return data


def sanitize(value):
    if isinstance(value, dict):
        return {key: _mask(str(item)) if any(secret in str(key).lower() for secret in SECRET_KEYS) else sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str) and (value.startswith("eyJ") or "Bearer " in value):
        return _mask(value.replace("Bearer ", ""))
    return value


def serialize_scan(session: Session, scan: Scan) -> dict:
    return safe_json(
        {
            "id": scan.id,
            "scan_id": scan.id,
            "project_id": scan.project_id,
            "profile": scan.profile,
            "engagement_mode": scan.engagement_mode,
            "authorized_testing_mode": getattr(scan, "authorized_testing_mode", None),
            "status": scan.status,
            "target": scan_target(session, scan),
            "started_at": iso(scan.started_at),
            "completed_at": iso(scan.completed_at),
            "last_activity_at": iso(scan.last_activity_at),
            "last_activity": iso(scan.last_activity_at),
            "current_phase": scan.current_phase,
            "current_agent": scan.current_agent,
            "current_tool": scan.current_tool,
            "progress_message": scan.progress_message,
            "progress_percent": scan.progress_percent,
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
            "pause_requested": getattr(scan, "pause_requested", False),
            "stop_requested": getattr(scan, "stop_requested", False),
            "created_at": iso(getattr(scan, "created_at", None)),
            "updated_at": iso(getattr(scan, "updated_at", None)),
        }
    )


def serialize_event(event: ScanEvent) -> dict:
    return safe_json(
        {
            "id": event.id,
            "scan_id": event.scan_id,
            "timestamp": iso(event.timestamp),
            "level": event.level,
            "phase": event.phase,
            "agent_name": event.agent_name,
            "tool_name": event.tool_name,
            "event_type": event.event_type,
            "message": event.message,
            "context_json": event.context_json,
        }
    )


def serialize_phase(phase: ScanPhase) -> dict:
    return safe_json(
        {
            "id": phase.id,
            "scan_id": phase.scan_id,
            "phase_name": phase.phase_name,
            "status": phase.status,
            "started_at": iso(phase.started_at),
            "completed_at": iso(phase.completed_at),
            "duration_ms": phase.duration_ms,
            "agent_name": phase.agent_name,
            "error_message": phase.error_message,
            "summary_json": phase.summary_json,
        }
    )


def serialize_scan_process(process: ScanProcess) -> dict:
    return safe_json(
        {
            "id": process.id,
            "scan_id": process.scan_id,
            "pid": process.pid,
            "command": process.command,
            "status": process.status,
            "started_at": iso(process.started_at),
            "ended_at": iso(process.ended_at),
            "exit_code": process.exit_code,
            "log_path": process.log_path,
        }
    )


def serialize_tool_run(run: ToolRun) -> dict:
    return safe_json(
        {
            "id": run.id,
            "scan_id": run.scan_id,
            "test_run_id": getattr(run, "test_run_id", None),
            "tool_name": run.tool_name,
            "command": getattr(run, "command", None),
            "status": run.status,
            "started_at": iso(run.started_at),
            "completed_at": iso(run.completed_at),
            "duration_seconds": getattr(run, "duration_seconds", None),
            "exit_code": getattr(run, "exit_code", None),
            "evidence_path": getattr(run, "evidence_path", None),
            "error": getattr(run, "error", None) or getattr(run, "error_message", None),
            "reason": (getattr(run, "output", None) or {}).get("reason") if isinstance(getattr(run, "output", None), dict) else None,
            "retry_status": (getattr(run, "output", None) or {}).get("resolver") if isinstance(getattr(run, "output", None), dict) else None,
        }
    )


def serialize_ai_call(call: AiCallRun) -> dict:
    return safe_json(
        {
            "id": call.id,
            "scan_id": call.scan_id,
            "stage": call.stage,
            "agent_name": call.agent_name,
            "model": call.model,
            "prompt_tokens_estimate": call.prompt_tokens_estimate,
            "status": call.status,
            "response_status": call.response_status,
            "http_status": call.http_status,
            "started_at": iso(call.started_at),
            "completed_at": iso(call.completed_at),
            "duration_ms": call.duration_ms,
            "retry_count": call.retry_count,
            "prompt_summary": call.prompt_summary,
            "error_message": call.error_message,
            "request_summary": call.request_summary,
            "response_summary": call.response_summary,
            "parsed_response_json": call.parsed_response_json,
            "evidence_path": call.evidence_path,
        }
    )


def serialize_agent_job(job: AgentJob) -> dict:
    return safe_json(
        {
            "id": job.id,
            "scan_id": job.scan_id,
            "agent_name": job.agent_name,
            "job_type": job.job_type,
            "status": job.status,
            "started_at": iso(job.started_at),
            "completed_at": iso(job.completed_at),
            "duration_ms": getattr(job, "duration_ms", None),
            "input": getattr(job, "input", None),
            "output": getattr(job, "output", None),
            "error": getattr(job, "error", None) or getattr(job, "error_message", None),
            "evidence_path": getattr(job, "evidence_path", None),
        }
    )


def serialize_payload_attempt(attempt: PayloadAttempt) -> dict:
    return safe_json(
        {
            "id": attempt.id,
            "scan_id": attempt.scan_id,
            "finding_id": attempt.finding_id,
            "test_case_id": attempt.test_case_id,
            "agent_name": attempt.agent_name,
            "vulnerability_type": attempt.vulnerability_type,
            "endpoint": attempt.endpoint,
            "method": attempt.method,
            "parameter_location": attempt.parameter_location,
            "parameter_name": attempt.parameter_name,
            "payload_masked": attempt.payload_masked,
            "payload_source": attempt.payload_source,
            "baseline_status": attempt.baseline_status,
            "attack_status": attempt.attack_status,
            "reflection_detected": attempt.reflection_detected,
            "error_marker_detected": attempt.error_marker_detected,
            "protected_data_detected": attempt.protected_data_detected,
            "ai_decision_json": attempt.ai_decision_json,
            "status": attempt.status,
            "evidence_path": attempt.evidence_path,
        }
    )


def serialize_finding(finding: Finding) -> dict:
    return safe_json(
        {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "finding_id": getattr(finding, "finding_id", None) or finding.finding_uid,
            "finding_uid": finding.finding_uid,
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "status": finding.status,
            "endpoint": getattr(finding, "endpoint", None) or finding.affected_endpoint,
            "method": getattr(finding, "method", None) or finding.http_method,
            "parameter": finding.parameter,
            "agent_name": finding.agent_name,
            "test_case_id": finding.test_case_id,
            "created_at": iso(getattr(finding, "created_at", None)),
            "updated_at": iso(getattr(finding, "updated_at", None)),
            "actions": finding_actions(finding),
        }
    )


def serialize_evidence(evidence: Evidence) -> dict:
    return safe_json(
        {
            "id": evidence.id,
            "scan_id": evidence.scan_id,
            "test_run_id": evidence.test_run_id,
            "kind": evidence.kind,
            "path": evidence.path,
            "summary": evidence.summary,
            "metadata": evidence.metadata_json,
        }
    )


def serialize_report(report: Report) -> dict:
    return safe_json(
        {
            "id": report.id,
            "project_id": report.project_id,
            "scan_id": report.scan_id,
            "format": report.format,
            "path": report.path,
            "summary": report.summary,
        }
    )


def serialize_authenticated_session(session_record) -> dict:
    return safe_json(
        {
            "id": session_record.id,
            "scan_id": session_record.scan_id,
            "credential_label": session_record.credential_label,
            "username": session_record.username,
            "role": session_record.role,
            "tenant": session_record.tenant,
            "auth_type": session_record.auth_type,
            "access_token_hash": session_record.access_token_hash,
            "access_token_masked": session_record.access_token_masked,
            "secret_ref": session_record.secret_ref,
            "authorization_header_type": session_record.authorization_header_type,
            "token_type": session_record.token_type,
            "login_status": session_record.login_status,
            "session_status": session_record.session_status,
            "metadata": session_record.metadata_json,
        }
    )


def _mask(value: str) -> str:
    if not value:
        return value
    if len(value) <= 16:
        return value[:4] + "...<masked>"
    return value[:8] + "...<masked>..." + value[-6:]


def overview(session: Session) -> dict:
    scans = session.scalars(select(Scan)).all()
    findings = session.scalars(select(Finding)).all()
    severities = ["critical", "high", "medium", "low", "info"]
    statuses = sorted({finding.status for finding in findings})
    severity_counts = {severity: len([finding for finding in findings if finding.severity == severity]) for severity in severities}
    status_counts = {status: len([finding for finding in findings if finding.status == status]) for status in statuses}
    active_scan_count = len([scan for scan in scans if _is_fresh_active_scan(session, scan)])
    readiness_counts = {}
    for scan in scans:
        status = production_readiness_for_scan(session, scan).get("status")
        readiness_counts[status] = readiness_counts.get(status, 0) + 1
    return {
        "total_scans": len(scans),
        "running_scans": active_scan_count,
        "completed_scans": len([scan for scan in scans if scan.status == "completed"]),
        "failed_scans": len([scan for scan in scans if str(scan.status).startswith("failed")]),
        "total_findings": len(findings),
        "critical_findings": severity_counts["critical"],
        "high_findings": severity_counts["high"],
        "medium_findings": severity_counts["medium"],
        "low_findings": severity_counts["low"],
        "info_findings": severity_counts["info"],
        "open_findings": len([finding for finding in findings if finding.status not in {"closed", "false_positive"}]),
        "closed_findings": len([finding for finding in findings if finding.status == "closed"]),
        "manual_review_items": len([finding for finding in findings if finding.status == "manual_confirmation_required"]),
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "readiness_counts": readiness_counts,
        "production_readiness_summary": readiness_counts,
        "top_affected_targets": top_targets(session),
        "latest_scan_id": latest_scan_id(session),
        "latest_active_scan_id": latest_active_scan_id(session),
}


def _is_fresh_active_scan(session: Session, scan: Scan) -> bool:
    try:
        snapshot = status_snapshot(session, scan.id)
        status = str(snapshot.get("status") or "").lower()
    except Exception:
        status = str(scan.status or "").lower()
    return status in {"created", "planning", "running", "resuming", "stopping"}


def latest_scan_id(session: Session) -> int | None:
    scan = session.scalars(select(Scan).order_by(desc(Scan.id))).first()
    return scan.id if scan else None


def latest_active_scan_id(session: Session) -> int | None:
    scans = session.scalars(select(Scan)).all()
    if not scans:
        return None
    scans_with_activity = [scan for scan in scans if scan.last_activity_at]
    if scans_with_activity:
        def activity_key(scan: Scan):
            value = scan.last_activity_at
            if value and value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return (value, scan.id)

        return max(scans_with_activity, key=activity_key).id
    return max(scans, key=lambda scan: scan.id).id


def top_targets(session: Session) -> list[dict]:
    rows = []
    for scan in session.scalars(select(Scan).order_by(desc(Scan.id))).all():
        rows.append({"scan_id": scan.id, "target": scan_target(session, scan), "findings": session.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan.id)) or 0})
    return rows[:10]


def scans(session: Session) -> list[dict]:
    items = []
    for scan in session.scalars(select(Scan).order_by(desc(Scan.id))).all():
        items.append(safe_json(serialize_scan(session, scan) | scan_summary(session, scan) | status_snapshot(session, scan.id)))
    return items


def scan_detail(session: Session, scan_id: int) -> dict:
    scan = _scan(session, scan_id)
    sync_scan_phases(session, scan)
    summary = scan_summary(session, scan)
    report = build_report_payload(session, scan_id=scan_id)
    return {
        "summary": safe_json(summary | status_snapshot(session, scan_id)),
        "target": scan_target(session, scan),
        "production_readiness": safe_json(production_readiness_for_scan(session, scan)),
        "coverage": safe_json(report.get("vulnerability_coverage_matrix", [])),
        "coverage_status": report.get("coverage_status"),
        "report_payload": safe_json(report),
        "request_map": request_map(scan_id),
        "ai_trace_index": ai_trace_index(scan_id),
        "agent_reactions": agent_reactions(scan_id),
        "tool_install_events": tool_install_events(scan_id),
        "actions": scan_actions(session, scan),
    }


def tool_install_events(scan_id: int) -> list[dict]:
    path = get_settings().evidence_dir / f"scan-{scan_id}" / "tool_install_events.jsonl"
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
            rows.append(safe_json(value))
    return rows


def table(session: Session, scan_id: int, model, order=True) -> list[dict]:
    stmt = select(model).where(model.scan_id == scan_id)
    if order:
        stmt = stmt.order_by(desc(model.id))
    serializer = {
        ScanPhase: serialize_phase,
        ScanProcess: serialize_scan_process,
        ScanEvent: serialize_event,
        ToolRun: serialize_tool_run,
        AiCallRun: serialize_ai_call,
        AgentJob: serialize_agent_job,
        Finding: serialize_finding,
        PayloadAttempt: serialize_payload_attempt,
        Evidence: serialize_evidence,
        Report: serialize_report,
        AuthenticatedSession: serialize_authenticated_session,
    }.get(model, row)
    return [safe_json(serializer(item)) for item in session.scalars(stmt).all()]


def request_map(scan_id: int) -> dict:
    path = get_settings().evidence_dir / f"scan-{scan_id}" / "request_map.json"
    return _read_json_file(path, {"scan_id": scan_id, "total_requests": 0, "requests": []})


def ai_trace_index(scan_id: int) -> dict:
    path = get_settings().evidence_dir / f"scan-{scan_id}" / "ai" / "ai_trace_index.json"
    return _read_json_file(path, {"scan_id": scan_id, "ai_debug_enabled": get_settings().ai_debug, "total_ai_calls": 0, "calls": []})


def agent_reactions(scan_id: int) -> list[dict]:
    path = get_settings().evidence_dir / f"scan-{scan_id}" / "agent_reactions.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            rows.append({"raw": line[:2000]})
    return safe_json(rows[-200:])


def discovery_sources(scan_id: int) -> dict:
    rows = request_map(scan_id).get("requests") or []
    counts = {}
    for row_item in rows:
        source = str(row_item.get("source") or "unknown")
        counts[source] = counts.get(source, 0) + 1
    return safe_json({"scan_id": scan_id, "sources": counts, "total_requests": len(rows)})


def _read_json_file(path: Path, fallback):
    if not path.exists():
        return safe_json(fallback)
    try:
        return safe_json(json.loads(path.read_text(encoding="utf-8", errors="replace")))
    except Exception as exc:
        return safe_json({"error": str(exc), "path": str(path), "fallback": fallback})


def reports(session: Session, scan_id: int) -> list[dict]:
    scan = _scan(session, scan_id)
    project = session.get(Project, scan.project_id)
    items = [serialize_report(item) for item in session.scalars(select(Report).where(Report.project_id == scan.project_id).order_by(desc(Report.id))).all()]
    report_dir = get_settings().report_dir / project.name
    if report_dir.exists():
        for path in sorted(report_dir.glob("report-*"), reverse=True):
            items.append({"format": path.suffix.lstrip("."), "path": str(path), "created_at": path.stat().st_mtime})
    return items


def evidence_preview(session: Session, evidence_id: int, allow_secret: bool = False) -> dict:
    evidence = session.get(Evidence, evidence_id)
    if not evidence:
        raise ValueError("evidence not found")
    path = Path(evidence.path)
    text = path.read_text(encoding="utf-8", errors="replace")[:20000] if path.exists() else ""
    try:
        parsed = json.loads(text)
        preview = parsed if allow_secret else sanitize(parsed)
    except Exception:
        preview = text if allow_secret else _mask(text) if "eyJ" in text else text
    return safe_json({"evidence": row(evidence), "preview": preview})


def settings_payload(session: Session) -> dict:
    settings = get_settings()
    return {
        "ollama_base_url": settings.ollama_base_url,
        "ollama_model": settings.ollama_model,
        "ollama_timeout_seconds": settings.ollama_timeout_seconds,
        "allow_secret_view": settings.allow_secret_view,
        "payload_sources": payload_library_status(),
        "tool_registry": [row(item) for item in session.scalars(select(ToolRegistry).order_by(ToolRegistry.tool_name)).all()],
        "resource_limits": resource_limits_payload(),
        "method_safety_policy": {
            "authorized_testing_mode": settings.authorized_testing_mode,
            "destructive_method_requires_test_owned_object": True,
        },
    }


def finding_action(session: Session, finding_id: int, action: str, value: str | None = None) -> dict:
    finding = session.get(Finding, finding_id)
    if not finding:
        raise ValueError("finding not found")
    ok, reason = validate_finding_action(finding, action)
    if not ok:
        raise PermissionError(reason or "Finding action is not available.")
    if action == "mark-false-positive":
        finding.status = "false_positive"
    elif action == "mark-accepted-risk":
        finding.status = "accepted_risk"
    elif action == "retest":
        finding.retest_status = "retest_requested"
    elif action == "close":
        finding.status = "closed"
    elif action == "update-severity" and value:
        finding.severity = value
    elif action == "update-status" and value:
        finding.status = value
    else:
        raise ValueError("unsupported finding action")
    return safe_json(row(finding))


def scan_action(session: Session, scan_id: int, action: str, phase: str | None = None) -> dict:
    scan = _scan(session, scan_id)
    ok, reason = validate_scan_action(session, scan, action)
    if not ok:
        raise PermissionError(reason or "Scan action is not available.")
    if action == "pause":
        scan.pause_requested = True
        scan.status = "paused"
        emit_progress(session, scan, "pause requested", event_type="pause_requested", context={"requested_by": "dashboard"})
    elif action == "resume":
        scan.pause_requested = False
        scan.status = "resuming"
        emit_progress(session, scan, "resume requested", event_type="resume_requested", context={"requested_by": "dashboard"})
    elif action == "stop":
        scan.stop_requested = True
        scan.status = "stopping"
        emit_progress(session, scan, "stop requested", event_type="stop_requested", context={"requested_by": "dashboard"})
    elif action == "continue":
        scan.status = "ready"
        scan.progress_message = f"Continue requested for {phase or 'next phase'}"
        emit_progress(session, scan, scan.progress_message, event_type="continue_requested", context={"phase": phase, "requested_by": "dashboard"})
    elif action == "report":
        generate_report(session, None, "json", scan_id=scan_id)
        generate_report(session, None, "html", scan_id=scan_id)
    else:
        raise ValueError("unsupported scan action")
    return safe_json({"ok": True, "scan_id": scan_id, "action": action, "status": scan.status, "summary": scan_summary(session, scan)})


def actions_for_scan(session: Session, scan_id: int) -> dict:
    scan = _scan(session, scan_id)
    try:
        display_status = status_snapshot(session, scan_id).get("status")
    except Exception:
        display_status = scan.status
    return safe_json({"scan_id": scan_id, "status": display_status, "db_status": scan.status, "actions": scan_actions(session, scan), "production_readiness": production_readiness_for_scan(session, scan)})


def _scan(session: Session, scan_id: int) -> Scan:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise ValueError("scan not found")
    return scan


MODELS = {
    "phases": ScanPhase,
    "processes": ScanProcess,
    "events": ScanEvent,
    "agent-jobs": AgentJob,
    "tool-runs": ToolRun,
    "ai-calls": AiCallRun,
    "payload-attempts": PayloadAttempt,
    "findings": Finding,
    "evidence": Evidence,
    "test-cases": TestCase,
    "auth-sessions": AuthenticatedSession,
}


def watch(session: Session, scan_id: int) -> dict:
    return safe_json(watch_snapshot(session, scan_id))


def live_state(session: Session, scan_id: int) -> dict:
    scan = _scan(session, scan_id)
    status = status_snapshot(session, scan_id)
    latest_events = [
        serialize_event(item)
        for item in session.scalars(
            select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(desc(ScanEvent.id)).limit(20)
        ).all()
    ]
    latest_tool_runs = [
        serialize_tool_run(item)
        for item in session.scalars(
            select(ToolRun).where(ToolRun.scan_id == scan_id).order_by(desc(ToolRun.id)).limit(20)
        ).all()
    ]
    latest_ai_calls = [
        serialize_ai_call(item)
        for item in session.scalars(
            select(AiCallRun).where(AiCallRun.scan_id == scan_id).order_by(desc(AiCallRun.id)).limit(10)
        ).all()
    ]
    latest_payload_attempts = [
        serialize_payload_attempt(item)
        for item in session.scalars(
            select(PayloadAttempt).where(PayloadAttempt.scan_id == scan_id).order_by(desc(PayloadAttempt.id)).limit(10)
        ).all()
    ]
    latest_evidence = [
        row(item)
        for item in session.scalars(
            select(Evidence).where(Evidence.scan_id == scan_id).order_by(desc(Evidence.id)).limit(10)
        ).all()
    ]
    processes = [
        serialize_scan_process(item)
        for item in session.scalars(
            select(ScanProcess).where(ScanProcess.scan_id == scan_id).order_by(desc(ScanProcess.id)).limit(5)
        ).all()
    ]
    running_tool = session.scalar(
        select(ToolRun).where(ToolRun.scan_id == scan_id, ToolRun.status == "running").order_by(desc(ToolRun.id)).limit(1)
    )
    completed_count = session.scalar(select(func.count(ToolRun.id)).where(ToolRun.scan_id == scan_id, ToolRun.status.in_(["completed", "finding_created"]))) or 0
    failed_count = session.scalar(select(func.count(ToolRun.id)).where(ToolRun.scan_id == scan_id, ToolRun.status.in_(["failed", "execution_error", "tool_install_failed", "invalid_request_template"]))) or 0
    missing_count = session.scalar(select(func.count(ToolRun.id)).where(ToolRun.scan_id == scan_id, ToolRun.status == "missing_prerequisite")) or 0
    total_planned_count = session.scalar(select(func.count(TestCase.id)).where(TestCase.scan_id == scan_id)) or 0
    seconds = status.get("seconds_since_activity")
    stale = bool(status.get("status") in {"running", "running_stale", "worker_stale"} and seconds is not None and int(seconds) > 60)
    return safe_json(
        {
            "scan_id": scan_id,
            "status": status.get("status") or scan.status,
            "current_phase": status.get("current_phase") or scan.current_phase,
            "current_agent": status.get("current_agent") or scan.current_agent,
            "current_tool": status.get("current_tool") or scan.current_tool,
            "progress_message": status.get("progress_message") or scan.progress_message,
            "last_activity_at": status.get("last_activity") or iso(scan.last_activity_at),
            "process_status": status.get("worker_status"),
            "latest_events": latest_events,
            "latest_tool_runs": latest_tool_runs,
            "latest_ai_calls": latest_ai_calls,
            "latest_payload_attempts": latest_payload_attempts,
            "latest_evidence": latest_evidence,
            "processes": processes,
            "running_tool": serialize_tool_run(running_tool) if running_tool else None,
            "completed_count": completed_count,
            "failed_count": failed_count,
            "missing_prerequisite_count": missing_count,
            "total_planned_count": total_planned_count,
            "progress_percent": status.get("progress_percent") or scan.progress_percent or _progress_percent(completed_count, total_planned_count),
            "stale": stale,
            "stale_message": "No worker heartbeat detected" if stale else None,
        }
    )


def _progress_percent(completed_count: int, total_planned_count: int) -> int:
    if total_planned_count <= 0:
        return 0
    return min(100, int((completed_count / total_planned_count) * 100))
