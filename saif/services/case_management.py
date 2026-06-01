from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from saif.db.models import (
    AgentJob,
    AiCallRun,
    ApplicationProfile,
    AuthenticatedSession,
    DiscoveredAuthFlow,
    Evidence,
    Finding,
    PayloadAttempt,
    Project,
    RunStatus,
    Scan,
    ScanPhase,
    ScanStatus,
    Target,
    TestCase,
    ToolRun,
)


PHASES = [
    "precheck",
    "ai_planning",
    "enumeration",
    "api_discovery",
    "auth_mapping",
    "account_provisioning",
    "login_session",
    "token_analysis",
    "authenticated_crawling",
    "authorization_testing",
    "input_validation_testing",
    "business_logic_testing",
    "ai_evidence_review",
    "reporting",
    "retest",
    "closure",
]

PHASE_TOOLS = {
    "enumeration": ["http_client", "technology_fingerprint", "root_link_inventory", "robots_txt", "sitemap_xml", "static_asset_inventory", "api_path_hints", "crawler", "katana", "gobuster_dir", "ffuf_dir", "nmap_top_ports"],
    "api_discovery": ["openapi_discovery", "api_profile_probe", "api_method_probe", "ffuf_api_paths", "gobuster_api_paths"],
    "auth_mapping": ["auth_session_mapping"],
    "account_provisioning": ["account_provisioning"],
    "login_session": ["login_session"],
    "token_analysis": ["token_analysis", "jwt_adaptive"],
    "authenticated_crawling": ["authenticated_crawling"],
    "authorization_testing": ["authorization_matrix", "idor_bola_bfla_planner"],
    "input_validation_testing": ["input_validation_planner", "xss_adaptive", "sqli_adaptive", "ssrf_adaptive", "jwt_adaptive"],
    "business_logic_testing": ["business_logic_planner"],
}

AGENT_BY_PHASE = {
    "precheck": "orchestrator_agent",
    "ai_planning": "ai_planner_agent",
    "enumeration": "recon_agent",
    "api_discovery": "api_discovery_agent",
    "auth_mapping": "auth_agent",
    "account_provisioning": "auth_agent",
    "login_session": "auth_agent",
    "token_analysis": "token_agent",
    "authenticated_crawling": "auth_agent",
    "authorization_testing": "authorization_agent",
    "input_validation_testing": "input_validation_agent",
    "business_logic_testing": "business_logic_agent",
    "ai_evidence_review": "ai_reviewer_agent",
    "reporting": "reporting_agent",
    "retest": "retest_agent",
    "closure": "closure_agent",
}


def ensure_scan_phases(session: Session, scan: Scan) -> list[ScanPhase]:
    existing = {item.phase_name: item for item in session.scalars(select(ScanPhase).where(ScanPhase.scan_id == scan.id)).all()}
    missing = [
        {
            "scan_id": scan.id,
            "phase_name": phase,
            "status": RunStatus.PLANNED.value,
            "agent_name": AGENT_BY_PHASE.get(phase),
            "summary_json": {},
        }
        for phase in PHASES
        if phase not in existing
    ]
    if missing:
        stmt = insert(ScanPhase.__table__).values(missing).on_conflict_do_nothing(index_elements=["scan_id", "phase_name"])
        session.execute(stmt)
    session.flush()
    existing = {item.phase_name: item for item in session.scalars(select(ScanPhase).where(ScanPhase.scan_id == scan.id)).all()}
    return [existing[name] for name in PHASES]


def mark_phase(session: Session, scan: Scan, phase_name: str, status: str, summary: dict | None = None, error: str | None = None) -> ScanPhase:
    ensure_scan_phases(session, scan)
    phase = session.scalar(select(ScanPhase).where(ScanPhase.scan_id == scan.id, ScanPhase.phase_name == phase_name))
    if not phase:
        raise ValueError(f"unknown phase {phase_name!r}")
    now = datetime.now(timezone.utc)
    if status == RunStatus.RUNNING.value and not phase.started_at:
        phase.started_at = now
    if status in {RunStatus.COMPLETED.value, RunStatus.FINDING_CREATED.value, RunStatus.NOT_APPLICABLE.value, RunStatus.MISSING_PREREQUISITE.value, RunStatus.MISSING_CREDENTIALS.value, RunStatus.EXECUTION_ERROR.value}:
        if not phase.started_at:
            phase.started_at = now
        phase.completed_at = now
        if phase.started_at:
            phase.duration_ms = int((phase.completed_at - phase.started_at).total_seconds() * 1000)
    phase.status = status
    phase.error_message = error
    if summary is not None:
        phase.summary_json = summary
    return phase


def sync_scan_phases(session: Session, scan: Scan) -> list[ScanPhase]:
    phases = ensure_scan_phases(session, scan)
    tool_runs = session.scalars(select(ToolRun).where(ToolRun.scan_id == scan.id)).all()
    by_tool = {item.tool_name: item for item in tool_runs}
    for phase_name, tools in PHASE_TOOLS.items():
        present = [by_tool[tool] for tool in tools if tool in by_tool]
        if not present:
            continue
        statuses = [item.status for item in present]
        if any(status == RunStatus.FINDING_CREATED.value for status in statuses):
            status = RunStatus.FINDING_CREATED.value
        elif any(status == RunStatus.EXECUTION_ERROR.value for status in statuses):
            status = RunStatus.EXECUTION_ERROR.value
        elif any(status in {RunStatus.MISSING_CREDENTIALS.value, RunStatus.MISSING_PREREQUISITE.value, RunStatus.MISSING_TOOL.value, RunStatus.TOOL_INSTALL_FAILED.value} for status in statuses):
            status = RunStatus.MISSING_PREREQUISITE.value
        elif all(status in {RunStatus.COMPLETED.value, RunStatus.NOT_APPLICABLE.value, RunStatus.ALTERNATE_TOOL_USED.value} for status in statuses):
            status = RunStatus.COMPLETED.value
        else:
            status = RunStatus.RUNNING.value
        mark_phase(
            session,
            scan,
            phase_name,
            status,
            {
                "tools": [{"tool": item.tool_name, "status": item.status, "evidence_path": item.evidence_path} for item in present],
                "evidence_count": session.scalar(select(func.count(Evidence.id)).where(Evidence.scan_id == scan.id)) or 0,
                "finding_count": session.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan.id)) or 0,
            },
        )
    if session.scalar(select(AiCallRun).where(AiCallRun.scan_id == scan.id, AiCallRun.stage == "initial_planning")):
        mark_phase(session, scan, "ai_planning", RunStatus.COMPLETED.value)
    if session.scalar(select(AiCallRun).where(AiCallRun.scan_id == scan.id, AiCallRun.stage == "evidence_review", AiCallRun.response_status == "completed")):
        mark_phase(session, scan, "ai_evidence_review", RunStatus.COMPLETED.value)
    return phases


def assign_finding_uids(session: Session, scan_id: int) -> None:
    findings = session.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)).all()
    counter = 1
    for finding in findings:
        if not finding.finding_uid:
            finding.finding_uid = f"SAIF-{scan_id}-F{counter:03d}"
        counter += 1


def production_readiness_for_scan(session: Session, scan: Scan) -> dict:
    findings = session.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    phases = {item.phase_name: item for item in sync_scan_phases(session, scan)}
    tool_runs = session.scalars(select(ToolRun).where(ToolRun.scan_id == scan.id)).all()
    tool_status = {item.tool_name: item.status for item in tool_runs}
    profiles = session.scalars(select(ApplicationProfile).where(ApplicationProfile.scan_id == scan.id)).all()
    crapi_detected = any(item.primary_profile == "crapi" or item.lab_profile == "crapi" for item in profiles)
    auth_sessions = session.scalar(select(func.count(AuthenticatedSession.id)).where(AuthenticatedSession.scan_id == scan.id, AuthenticatedSession.login_status == "login_success")) or 0
    flow_types = {
        item.flow_type
        for item in session.scalars(select(DiscoveredAuthFlow).where(DiscoveredAuthFlow.scan_id == scan.id)).all()
    }
    authenticated_api = bool(flow_types.intersection({"login", "registration", "token", "oauth", "oidc", "saml"}))
    severe = [item for item in findings if item.severity in {"critical", "high"} and item.status not in {"closed", "false_positive"}]
    manual = [item for item in findings if item.status == RunStatus.MANUAL_CONFIRMATION_REQUIRED.value]
    failed_auth = [
        phase
        for name, phase in phases.items()
        if name in {"authenticated_crawling", "authorization_testing"} and phase.status == RunStatus.EXECUTION_ERROR.value
    ]
    failed_ai = phases.get("ai_evidence_review") and phases["ai_evidence_review"].status == RunStatus.EXECUTION_ERROR.value
    missing = [phase for phase in phases.values() if phase.status in {RunStatus.MISSING_PREREQUISITE.value, RunStatus.MISSING_CREDENTIALS.value}]
    required_tools = {
        "authenticated_crawling": "authenticated_crawling",
        "authorization_testing": "authorization_matrix",
        "input_validation_testing": "input_validation_planner",
        "jwt_testing": "jwt_adaptive",
        "business_logic_testing": "business_logic_planner",
    }
    not_run = [label for label, tool in required_tools.items() if tool not in tool_status]
    coverage_cases = session.scalars(select(TestCase).where(TestCase.scan_id == scan.id, TestCase.case_id.like("coverage.%"))).all()
    unjustified_coverage = [
        case
        for case in coverage_cases
        if case.status not in {
            RunStatus.COMPLETED.value,
            RunStatus.FINDING_CREATED.value,
            RunStatus.MANUAL_CONFIRMATION_REQUIRED.value,
            RunStatus.NOT_APPLICABLE.value,
            RunStatus.MISSING_PREREQUISITE.value,
            RunStatus.SKIPPED_REQUIRES_TEST_OWNED_OBJECT.value,
            RunStatus.SKIPPED_REQUIRES_MANUAL_CONFIRMATION.value,
        }
    ]
    default_only = scan.profile == "default-enumeration" and bool(not_run)
    if default_only:
        return {
            "status": "manual_review_required",
            "reason": "Only enumeration was completed. Authenticated testing and vulnerability validation were not executed.",
            "high_or_critical_findings": len(severe),
            "manual_confirmation_items": len(manual),
            "failed_auth_phases": [item.phase_name for item in failed_auth],
            "ai_review_failed": bool(failed_ai),
            "missing_prerequisite_phases": [item.phase_name for item in missing],
            "not_run": not_run,
            "authenticated_sessions": auth_sessions,
        }
    if crapi_detected and (not_run or auth_sessions == 0 or unjustified_coverage):
        return {
            "status": "not_ready",
            "reason": "crAPI profile detected but authenticated vulnerability testing was not completed.",
            "coverage": "coverage_incomplete",
            "high_or_critical_findings": len(severe),
            "manual_confirmation_items": len(manual),
            "failed_auth_phases": [item.phase_name for item in failed_auth],
            "ai_review_failed": bool(failed_ai),
            "missing_prerequisite_phases": [item.phase_name for item in missing],
            "not_run": not_run,
            "authenticated_sessions": auth_sessions,
            "unjustified_coverage_items": [case.case_id for case in unjustified_coverage],
        }
    if authenticated_api and auth_sessions == 0:
        return {
            "status": "not_ready",
            "reason": "Authenticated API behavior was discovered but no authenticated session was captured.",
            "high_or_critical_findings": len(severe),
            "manual_confirmation_items": len(manual),
            "failed_auth_phases": [item.phase_name for item in failed_auth],
            "ai_review_failed": bool(failed_ai),
            "missing_prerequisite_phases": [item.phase_name for item in missing],
            "not_run": not_run,
            "authenticated_sessions": auth_sessions,
        }
    if scan.status in {ScanStatus.FAILED.value, ScanStatus.FAILED_AI.value, ScanStatus.FAILED_PRECHECK.value, ScanStatus.FAILED_SYSTEM.value}:
        status = "manual_review_required"
        reason = "Scan did not complete successfully."
    elif severe or failed_auth or failed_ai:
        status = "not_ready"
        reason = "High-impact findings, failed authenticated phases, or AI review errors require remediation or review."
    elif not_run or unjustified_coverage:
        status = "manual_review_required"
        reason = "One or more vulnerability validation phases were not executed or justified."
    elif manual or missing:
        status = "manual_review_required"
        reason = "Manual confirmation or missing prerequisites remain."
    else:
        status = "ready"
        reason = "No high/critical findings or failed required stages recorded."
    return {
        "status": status,
        "reason": reason,
        "high_or_critical_findings": len(severe),
        "manual_confirmation_items": len(manual),
        "failed_auth_phases": [item.phase_name for item in failed_auth],
        "ai_review_failed": bool(failed_ai),
        "missing_prerequisite_phases": [item.phase_name for item in missing],
        "not_run": not_run,
        "authenticated_sessions": auth_sessions,
        "unjustified_coverage_items": [case.case_id for case in unjustified_coverage],
    }


def scan_target(session: Session, scan: Scan) -> str | None:
    project = session.get(Project, scan.project_id)
    target = session.scalar(select(Target).where(Target.project_id == scan.project_id).order_by(Target.id.desc()).limit(1))
    return target.url if target else None


def scan_summary(session: Session, scan: Scan) -> dict:
    project = session.get(Project, scan.project_id)
    target = scan_target(session, scan)
    findings_count = session.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan.id)) or 0
    return {
        "scan_id": scan.id,
        "project": project.name if project else None,
        "target": target,
        "status": scan.status,
        "profile": scan.profile,
        "engagement_mode": scan.engagement_mode,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "findings_count": findings_count,
        "production_readiness": production_readiness_for_scan(session, scan),
    }


def completed_tools(session: Session, scan_id: int) -> set[str]:
    return {
        item.tool_name
        for item in session.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id)).all()
        if item.status in {RunStatus.COMPLETED.value, RunStatus.FINDING_CREATED.value, RunStatus.NOT_APPLICABLE.value, RunStatus.ALTERNATE_TOOL_USED.value}
    }


def tools_for_phase(phase: str) -> list[str]:
    return PHASE_TOOLS.get(phase, [])
