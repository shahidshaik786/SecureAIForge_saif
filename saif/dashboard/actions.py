from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saif.db.models import AuthenticatedSession, DiscoveredAuthFlow, Finding, Scan, ScanPhase, ScanProcess, ToolRun, Evidence
from saif.services.case_management import production_readiness_for_scan
from saif.services.progress import status_snapshot


@dataclass(frozen=True)
class ButtonState:
    enabled: bool
    reason: str | None = None
    label: str | None = None
    css_class: str = "btn-secondary"
    confirm_required: bool = False

    def as_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "reason": self.reason,
            "label": self.label,
            "css_class": self.css_class,
            "confirm_required": self.confirm_required,
        }


RUNNING = {"running"}
STARTING = {"created", "planning", "resuming"}
RESUMABLE = {"paused", "stopped", "worker_stale", "running_stale", "failed_system", "failed_ai", "failed_precheck", "failed"}
FINISHED = {"completed", "stopped", "failed", "failed_system", "failed_ai", "failed_precheck"}
CONTINUABLE = {"stopped", "paused", "ready", "completed", "worker_stale", "running_stale", "failed", "failed_system", "failed_ai", "failed_precheck", "manual_review_required"}


def scan_actions(session: Session, scan: Scan) -> dict[str, dict]:
    status = _effective_status(session, scan)
    active_process = _active_process(session, scan.id)
    resumable = status in RESUMABLE and not active_process
    reportable = _has_reportable_data(session, scan.id)
    auth_context = _has_auth_context(session, scan.id, scan)
    account_context = _has_account_context(session, scan.id, scan)
    authz_context = _authz_context(session, scan.id, scan)
    pending_destructive = _pending_destructive_confirmation(scan)
    actions = {
        "live_monitor": ButtonState(True, label="Live Monitor", css_class="btn-secondary"),
        "pause": ButtonState(status in RUNNING, None if status in RUNNING else "Pause is available only for running scans.", "Pause", "btn-warning"),
        "resume": ButtonState(resumable, None if resumable else "Resume is available only for recoverable scans with no active tracked worker. Stop or Force Stop the current worker first.", "Resume", "btn-success"),
        "stop": ButtonState(status in RUNNING | STARTING, None if status in RUNNING | STARTING else "Stop is available only while a scan is running, planning, or resuming.", "Stop", "btn-danger", True),
        "force_stop": ButtonState(bool(active_process), None if active_process else "Force Stop requires an active tracked worker process.", "Force Stop", "btn-danger", True),
        "continue_phase": ButtonState(status in CONTINUABLE, None if status != "running" else "Cannot continue phase while scan is running.", "Continue Phase", "btn-secondary"),
        "generate_report": ButtonState(reportable, None if reportable else "Generate Report requires completed phases, findings, tool runs, or evidence.", "Generate Report", "btn-secondary"),
        "generate_html": ButtonState(reportable, None if reportable else "HTML report requires reportable scan data.", "Generate HTML", "btn-secondary"),
        "generate_json": ButtonState(True, label="Generate JSON", css_class="btn-secondary"),
        "generate_docx": ButtonState(False, "DOCX reports are coming soon.", "Generate DOCX", "btn-disabled"),
        "generate_pdf": ButtonState(False, "PDF reports are coming soon.", "Generate PDF", "btn-disabled"),
        "validate_auth": ButtonState(auth_context, None if auth_context else "No credentials, generated accounts, auth endpoints, or sessions available.", "Validate Auth", "btn-secondary"),
        "relogin": ButtonState(account_context, None if account_context else "No stored credentials or generated accounts are available.", "Re-login", "btn-secondary"),
        "create_accounts": ButtonState(_can_create_accounts(session, scan), None if _can_create_accounts(session, scan) else "Account generation requires operator approval and a registration endpoint or lab profile.", "Create Test Accounts", "btn-secondary"),
        "authorization_testing": ButtonState(authz_context, None if authz_context else "Authorization testing requires two valid sessions or account generation approval.", "Run Authorization Testing", "btn-secondary"),
        "destructive_approval": ButtonState(pending_destructive, None if pending_destructive else "No destructive confirmation is pending.", "Approve Destructive Tests", "btn-warning", True),
    }
    return {name: state.as_dict() for name, state in actions.items()}


def get_button_state(session: Session, scan: Scan, action: str, context: dict | None = None) -> dict:
    return scan_actions(session, scan).get(action, ButtonState(False, f"Unknown action: {action}", action).as_dict())


def validate_scan_action(session: Session, scan: Scan, action: str) -> tuple[bool, str | None]:
    mapping = {
        "pause": "pause",
        "resume": "resume",
        "stop": "stop",
        "stop-force": "force_stop",
        "continue": "continue_phase",
        "run-phase": "continue_phase",
        "report": "generate_report",
    }
    state = get_button_state(session, scan, mapping.get(action, action))
    return bool(state["enabled"]), state.get("reason")


def finding_actions(finding: Finding) -> dict[str, dict]:
    status = (finding.status or "").lower()
    open_status = status not in {"closed", "fixed", "false_positive", "accepted_risk"}
    can_retest = status in {"finding_created", "reported", "retest_required", "reopened"}
    can_close = status in {"fixed", "false_positive", "accepted_risk", "reported"}
    return {
        "retest": ButtonState(can_retest, None if can_retest else "Retest is available for open or retest-required findings.", "Retest", "btn-secondary").as_dict(),
        "close": ButtonState(can_close, None if can_close else "Close requires fixed, false positive, accepted risk, or reported status.", "Close", "btn-secondary").as_dict(),
        "mark-false-positive": ButtonState(status != "closed", None if status != "closed" else "Closed findings must be reopened first.", "False Positive", "btn-warning", True).as_dict(),
        "mark-accepted-risk": ButtonState(status != "closed", None if status != "closed" else "Closed findings must be reopened first.", "Accept Risk", "btn-warning", True).as_dict(),
        "reopen": ButtonState(status in {"closed", "fixed", "false_positive", "accepted_risk"}, None if status in {"closed", "fixed", "false_positive", "accepted_risk"} else "Only closed/fixed/accepted findings can be reopened.", "Reopen", "btn-secondary").as_dict(),
        "update-severity": ButtonState(open_status, None if open_status else "Reopen the finding before changing severity.", "Update Severity", "btn-secondary").as_dict(),
    }


def validate_finding_action(finding: Finding, action: str) -> tuple[bool, str | None]:
    state = finding_actions(finding).get(action, ButtonState(False, f"Unsupported finding action: {action}").as_dict())
    return bool(state["enabled"]), state.get("reason")


def _status(scan: Scan) -> str:
    return str(scan.status or "").lower()


def _effective_status(session: Session, scan: Scan) -> str:
    try:
        return str(status_snapshot(session, scan.id).get("status") or scan.status or "").lower()
    except Exception:
        return _status(scan)


def _active_process(session: Session, scan_id: int) -> ScanProcess | None:
    process = session.scalar(select(ScanProcess).where(ScanProcess.scan_id == scan_id).order_by(ScanProcess.id.desc()).limit(1))
    return process if process and process.status in {"started", "running"} and process.pid else None


def _has_reportable_data(session: Session, scan_id: int) -> bool:
    phase_count = session.scalar(select(func.count(ScanPhase.id)).where(ScanPhase.scan_id == scan_id, ScanPhase.status.in_(["completed", "finding_created"]))) or 0
    tool_count = session.scalar(select(func.count(ToolRun.id)).where(ToolRun.scan_id == scan_id)) or 0
    evidence_count = session.scalar(select(func.count(Evidence.id)).where(Evidence.scan_id == scan_id)) or 0
    finding_count = session.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan_id)) or 0
    return bool(phase_count or tool_count or evidence_count or finding_count)


def _has_auth_context(session: Session, scan_id: int, scan: Scan) -> bool:
    sessions = session.scalar(select(func.count(AuthenticatedSession.id)).where(AuthenticatedSession.scan_id == scan_id)) or 0
    flows = session.scalar(select(func.count(DiscoveredAuthFlow.id)).where(DiscoveredAuthFlow.scan_id == scan_id)) or 0
    return bool(sessions or flows or scan.credentials_path or scan.allow_account_generation)


def _has_account_context(session: Session, scan_id: int, scan: Scan) -> bool:
    sessions = session.scalar(select(func.count(AuthenticatedSession.id)).where(AuthenticatedSession.scan_id == scan_id)) or 0
    return bool(sessions or scan.credentials_path or scan.allow_account_generation)


def _authz_context(session: Session, scan_id: int, scan: Scan) -> bool:
    sessions = session.scalar(select(func.count(AuthenticatedSession.id)).where(AuthenticatedSession.scan_id == scan_id)) or 0
    return bool(sessions >= 2 or scan.allow_account_generation)


def _can_create_accounts(session: Session, scan: Scan) -> bool:
    if not scan.allow_account_generation:
        return False
    if scan.profile in {"crapi", "api-security-authenticated-test"}:
        return True
    flows = session.scalar(select(func.count(DiscoveredAuthFlow.id)).where(DiscoveredAuthFlow.scan_id == scan.id, DiscoveredAuthFlow.flow_type.ilike("%registration%"))) or 0
    return bool(flows)


def _pending_destructive_confirmation(scan: Scan) -> bool:
    return bool(scan.enable_destructive_tests and not scan.confirm_destructive_testing)
