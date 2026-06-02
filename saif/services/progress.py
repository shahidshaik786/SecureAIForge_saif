from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from saif.config import get_settings
from saif.db import session_scope
from saif.db.models import AgentJob, AiCallRun, Evidence, Log, Scan, ScanEvent, ScanPhase, ScanProcess, ToolRun


def emit_progress(
    session: Session,
    scan: Scan,
    message: str,
    *,
    level: str = "INFO",
    phase: str | None = None,
    agent: str | None = None,
    tool: str | None = None,
    event_type: str = "progress",
    context: dict | None = None,
    console: Console | None = None,
    live: bool = False,
) -> None:
    now = datetime.now(timezone.utc)
    scan.last_activity_at = now
    if phase is not None:
        scan.current_phase = phase
    if agent is not None:
        scan.current_agent = agent
    if tool is not None:
        scan.current_tool = tool
    scan.progress_message = message
    session.add(
        ScanEvent(
            scan_id=scan.id,
            timestamp=now,
            level=level,
            phase=phase or scan.current_phase,
            agent_name=agent or scan.current_agent,
            tool_name=tool or scan.current_tool,
            event_type=event_type,
            message=message,
            context_json=context or {},
        )
    )
    session.add(Log(scan_id=scan.id, level=level.lower(), message=message, context={"event_type": event_type, **(context or {})}))
    _write_runtime_log(scan.id, now, level, phase or scan.current_phase, agent or scan.current_agent, tool or scan.current_tool, message, context or {})
    session.flush()
    session.commit()
    if live and console:
        console.print(_format_live_line(scan.id, message, phase or scan.current_phase, agent or scan.current_agent, tool or scan.current_tool), highlight=False)


def _format_live_line(scan_id: int, message: str, phase: str | None, agent: str | None, tool: str | None) -> str:
    bits = [f"[scan {scan_id}]"]
    if phase:
        bits.append(f"phase={phase}")
    if agent:
        bits.append(f"agent={agent}")
    if tool:
        bits.append(f"tool={tool}")
    bits.append(message)
    return " ".join(bits)


def _write_runtime_log(scan_id: int, timestamp: datetime, level: str, phase: str | None, agent: str | None, tool: str | None, message: str, context: dict) -> Path:
    log_dir = get_settings().log_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"scan-{scan_id}.log"
    line = (
        f"{timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')} {level.upper()} scan={scan_id} "
        f"phase={phase or '-'} agent={agent or '-'} tool={tool or '-'} "
        f"{message} context={json.dumps(context, default=str, sort_keys=True)}\n"
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
    return path


@contextmanager
def heartbeat(scan_id: int, *, phase: str | None, agent: str | None, tool: str | None, console: Console | None = None, live: bool = False):
    stop = threading.Event()
    interval = max(1, get_settings().scan_heartbeat_seconds)

    def run() -> None:
        start = time.monotonic()
        while not stop.wait(interval):
            duration = int(time.monotonic() - start)
            try:
                with session_scope() as session:
                    scan = session.get(Scan, scan_id)
                    if not scan:
                        continue
                    emit_progress(
                        session,
                        scan,
                        f"still running duration={duration}s",
                        phase=phase,
                        agent=agent,
                        tool=tool,
                        event_type="heartbeat",
                        context={"duration_seconds": duration, "latest_evidence": latest_evidence_path(session, scan_id)},
                        console=console,
                        live=live,
                    )
            except Exception:
                continue

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1)


def latest_evidence_path(session: Session, scan_id: int) -> str | None:
    item = session.scalar(select(Evidence).where(Evidence.scan_id == scan_id).order_by(desc(Evidence.id)).limit(1))
    return item.path if item else None


def status_snapshot(session: Session, scan_id: int) -> dict:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise ValueError(f"scan {scan_id} not found")
    last_event = session.scalar(select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(desc(ScanEvent.id)).limit(1))
    phases = session.scalars(select(ScanPhase).where(ScanPhase.scan_id == scan_id).order_by(ScanPhase.id)).all()
    findings_count = 0
    try:
        from saif.db.models import Finding
        from sqlalchemy import func

        findings_count = session.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan_id)) or 0
    except Exception:
        findings_count = 0
    stale_after = get_settings().scan_stale_after_seconds
    now = datetime.now(timezone.utc)
    active_statuses = {"created", "planning", "ready", "running", "resuming"}
    seconds_since_activity = (now - scan.last_activity_at).total_seconds() if scan.last_activity_at else None
    stale = bool(seconds_since_activity is not None and scan.status in active_statuses and seconds_since_activity > stale_after)
    process = session.scalar(select(ScanProcess).where(ScanProcess.scan_id == scan_id).order_by(desc(ScanProcess.id)).limit(1))
    worker_status = process.status if process else None
    if stale and process and worker_status == "started":
        process.status = "stale"
        worker_status = "stale"
        session.flush()
        session.commit()
    display_status = "worker_stale" if stale and worker_status in {"started", "stale"} else "running_stale" if stale else scan.status
    return {
        "scan_id": scan.id,
        "status": display_status,
        "worker_status": worker_status,
        "seconds_since_activity": int(seconds_since_activity) if seconds_since_activity is not None else None,
        "current_phase": scan.current_phase,
        "current_agent": scan.current_agent,
        "current_tool": scan.current_tool,
        "progress_message": scan.progress_message,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "last_activity": scan.last_activity_at.isoformat() if scan.last_activity_at else None,
        "last_event": last_event.message if last_event else None,
        "last_evidence_file": latest_evidence_path(session, scan_id),
        "completed_phases": [item.phase_name for item in phases if item.status in {"completed", "finding_created"}],
        "pending_phases": [item.phase_name for item in phases if item.status in {"planned", "running"}],
        "failed_phases": [item.phase_name for item in phases if item.status in {"execution_error", "missing_prerequisite", "missing_credentials", "missing_tool", "tool_install_failed"}],
        "findings": findings_count,
        "next_recommended_action": _next_recommended_action(scan_id, phases),
    }


def _next_recommended_action(scan_id: int, phases: list[ScanPhase]) -> str:
    phase_status = {item.phase_name: item.status for item in phases}
    for phase in ["account_provisioning", "login_session", "token_analysis", "authenticated_crawling", "authorization_testing", "input_validation_testing", "business_logic_testing", "reporting"]:
        if phase_status.get(phase) not in {"completed", "finding_created"}:
            return f"./saif.sh scan continue --scan-id {scan_id} --phase {phase} --full"
    return f"./saif.sh scan report --scan-id {scan_id} --format html"


def watch_snapshot(session: Session, scan_id: int) -> dict:
    return {
        "status": status_snapshot(session, scan_id),
        "agent_jobs": [_row(item) for item in session.scalars(select(AgentJob).where(AgentJob.scan_id == scan_id).order_by(desc(AgentJob.id)).limit(10)).all()],
        "tool_runs": [_row(item) for item in session.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id).order_by(desc(ToolRun.id)).limit(10)).all()],
        "evidence": [_row(item) for item in session.scalars(select(Evidence).where(Evidence.scan_id == scan_id).order_by(desc(Evidence.id)).limit(10)).all()],
        "errors": [_row(item) for item in session.scalars(select(ScanEvent).where(ScanEvent.scan_id == scan_id, ScanEvent.level.in_(["ERROR", "WARN"])).order_by(desc(ScanEvent.id)).limit(10)).all()],
        "ai_calls": [_row(item) for item in session.scalars(select(AiCallRun).where(AiCallRun.scan_id == scan_id).order_by(desc(AiCallRun.id)).limit(10)).all()],
        "events": [_row(item) for item in session.scalars(select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(desc(ScanEvent.id)).limit(10)).all()],
    }


def _row(item) -> dict:
    data = {}
    for column in item.__table__.columns:
        value = getattr(item, column.name)
        data[column.name] = value.isoformat() if hasattr(value, "isoformat") else value
    return data
