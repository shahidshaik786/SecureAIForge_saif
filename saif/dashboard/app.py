from __future__ import annotations

import secrets
import subprocess
import sys
import logging
import os
import importlib.metadata
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from saif.config import get_settings
from saif.dashboard import services
from saif.db import session_scope
from saif.db.models import Finding, Scan, ScanProcess, ScanStatus
from saif.services.progress import emit_progress
from saif.services.scan_config import normalize_scan_config
from saif.services.credentials import load_credentials
from saif.services.debug_export import generate_full_ai_debug_export
from saif.services.targets import upsert_project_target
from sqlalchemy import select, text
from sqlalchemy.exc import ProgrammingError


logger = logging.getLogger(__name__)
security = HTTPBasic(auto_error=False)
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def validate_dashboard_assets() -> None:
    if not TEMPLATES_DIR.exists():
        raise RuntimeError(f"Dashboard template directory not found: {TEMPLATES_DIR}")
    if not (TEMPLATES_DIR / "index.html").exists():
        raise RuntimeError(f"Dashboard template not found: {TEMPLATES_DIR / 'index.html'}")


def _template_response(request: Request, context: dict):
    page_titles = {
        "overview": "SAIF - Secure AI Forge",
        "control": "Scan Control",
        "live": "Live Monitor",
        "scans": "Scans",
        "scan_detail": "Scan Detail",
        "findings": "Findings",
        "finding_detail": "Finding Detail",
        "auth_sessions": "Auth Sessions",
        "payload_attempts": "Payload Attempts",
        "agent_activity": "Agent Activity",
        "tool_runs": "Tool Runs",
        "ai_activity": "AI Activity",
        "evidence": "Evidence",
        "reports": "Reports",
        "settings": "Settings",
    }
    context = dict(context)
    context.setdefault("page_title", page_titles.get(context.get("page"), "SAIF - Secure AI Forge"))
    context.setdefault("page_subtitle", "AI-assisted authorized Web/API security testing, evidence, and reporting forge.")
    context.setdefault("ollama_model", get_settings().ollama_model)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context=context,
    )


def _dashboard_context(session) -> dict:
    return {
        "latest_scan_id": services.latest_scan_id(session),
        "latest_active_scan_id": services.latest_active_scan_id(session),
    }


def _migration_required_context(exc: Exception) -> dict:
    return {
        "page": "overview",
        "overview": {},
        "scans": [],
        "dashboard_error": "Database migration required. Run ./saif.sh init-db",
        "dashboard_error_detail": str(exc),
    }


def _dashboard_page(request: Request, builder):
    try:
        with session_scope() as session:
            return _template_response(request, builder(session))
    except ProgrammingError as exc:
        logger.exception("Dashboard database schema is not current")
        return _template_response(request, _migration_required_context(exc))


def api_response(data, status_code: int = 200) -> JSONResponse:
    try:
        return JSONResponse(content=services.safe_json(data), status_code=status_code)
    except Exception as exc:
        logger.exception("Dashboard API serialization failed for type=%s", type(data).__name__)
        return JSONResponse(
            content={"ok": False, "error": "serialization_failed", "message": str(exc), "response_type": type(data).__name__},
            status_code=500,
        )


def api_not_found(message: str) -> JSONResponse:
    return api_response({"ok": False, "error": "not_found", "message": message}, status_code=404)


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def _active_worker_for_scan(session, scan_id: int) -> ScanProcess | None:
    processes = session.scalars(select(ScanProcess).where(ScanProcess.scan_id == scan_id).order_by(ScanProcess.id.desc()).limit(5)).all()
    for process in processes:
        if process.status in {"started", "running", "planning", "stopping"} and _pid_alive(process.pid):
            return process
    try:
        from saif.services.progress import status_snapshot

        snapshot = status_snapshot(session, scan_id)
        if snapshot.get("worker_status") == "active":
            return processes[0] if processes else None
    except Exception:
        pass
    return None


def _record_process(session, *, scan_id: int, process, command: list[str], log_path: str | None = None) -> dict:
    record = ScanProcess(
        scan_id=scan_id,
        pid=getattr(process, "pid", None),
        command=" ".join(command),
        status="started",
        started_at=datetime.now(timezone.utc),
        log_path=log_path,
    )
    session.add(record)
    session.flush()
    return services.serialize_scan_process(record)


def _start_background_command(command: list[str], *, scan_id: int | None = None, log_path: str | None = None) -> dict:
    if scan_id is None:
        raise ValueError("Cannot start scan worker without scan_id")
    with session_scope() as session:
        active = _active_worker_for_scan(session, scan_id)
        if active:
            scan = session.get(Scan, scan_id)
            if scan:
                emit_progress(session, scan, f"Scan already has active worker PID {active.pid}", event_type="scan_worker_already_running", context={"pid": active.pid})
            return {"pid": active.pid, "status": "already_running", "message": f"Scan already has active worker PID {active.pid}"}
    log_handle = None
    if log_path:
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        log_handle = path.open("ab")
    process = subprocess.Popen(command, cwd=Path.cwd(), stdout=log_handle or subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if log_handle:
        log_handle.close()
        log_handle = None
    process_id = None
    try:
        with session_scope() as session:
            if hasattr(session, "add") and hasattr(session, "flush"):
                process_record = _record_process(session, scan_id=scan_id, process=process, command=command, log_path=log_path)
                process_id = process_record.get("id")
                scan = session.get(Scan, scan_id)
                if scan:
                    emit_progress(
                        session,
                        scan,
                        "Scan worker process started",
                        phase=scan.current_phase or "precheck",
                        event_type="scan_worker_started",
                        context={"pid": getattr(process, "pid", None), "process_id": process_id},
                    )
    except Exception as exc:
        logger.warning(
            "Scan process started but process tracking failed scan_id=%s pid=%s reason=%s",
            scan_id,
            getattr(process, "pid", None),
            exc,
        )
        try:
            process.terminate()
        except Exception:
            pass
        if log_handle:
            log_handle.close()
        raise RuntimeError("Could not start scan because scan process tracking failed.") from exc
    if process_id is None:
        try:
            process.terminate()
        except Exception:
            pass
        if log_handle:
            log_handle.close()
        raise RuntimeError("Could not start scan because scan ID was not created.")
    return {
        "ok": True,
        "scan_id": scan_id,
        "pid": process.pid,
        "process_id": process_id,
        "tracking_status": "recorded" if process_id else "tracking_failed",
        "status": "started",
        "message": "Background command started",
        "command": " ".join(command),
    }


def _dashboard_project_name(target: str, profile: str) -> str:
    parsed = urlparse(target)
    host = (parsed.hostname or "target").replace(".", "-")
    port = f"-{parsed.port}" if parsed.port else ""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"saif-dashboard-{profile}-{host}{port}-{stamp}"[:255]


def _scan_worker_command(scan_id: int, debug: bool = True) -> list[str]:
    cmd = [sys.executable, "-m", "saif.cli", "scan", "run-existing", "--scan-id", str(scan_id)]
    if debug:
        cmd.append("--debug")
    return cmd


def _create_dashboard_scan(payload: dict) -> dict:
    target = str(payload.get("target") or "").strip().rstrip("/")
    if not target:
        raise ValueError("target is required")
    profile = str(payload.get("profile") or "auto")
    engagement_mode = str(payload.get("engagement_mode") or payload.get("mode") or "black-box").replace("-", "_")
    destructive_policy = str(payload.get("destructive_test_policy") or payload.get("destructive_policy") or "detect_only")
    account_source = str(payload.get("account_source") or payload.get("auth_mode") or "auto")
    if account_source == "username_password":
        account_source = "credentials_file"
    required_user_count = int(payload.get("required_user_count") or 2)
    scan_options = normalize_scan_config(
        {
            "target": target,
            "profile": profile,
            "application_profile": profile,
            "engagement_mode": engagement_mode,
            "full": bool(payload.get("full")),
            "enumeration_only": bool(payload.get("enumeration_only")),
            "debug": bool(payload.get("debug", True)),
            "execution_profile": payload.get("execution_profile"),
            "account_source": account_source,
            "auth_mode": account_source,
            "credentials_path": payload.get("credentials_path"),
            "required_user_count": required_user_count,
            "source_path": payload.get("source_path"),
            "allow_account_generation": bool(payload.get("allow_account_generation")),
            "allow_authenticated_testing": bool(payload.get("allow_authenticated_testing")),
            "allow_authorization_testing": bool(payload.get("allow_authorization_testing")),
            "allow_payload_testing": bool(payload.get("allow_payload_testing")),
            "allow_rate_limit_testing": bool(payload.get("allow_rate_limit_testing")),
            "allow_test_owned_object_creation": bool(payload.get("allow_test_owned_object_creation")),
            "enable_destructive_tests": bool(payload.get("enable_destructive_tests")),
            "destructive_method_policy": payload.get("destructive_method_policy"),
            "destructive_test_policy": destructive_policy,
            "confirm_authorized": bool(payload.get("confirm_authorized")),
            "confirm_destructive_testing": bool(payload.get("confirm_destructive_testing")),
            "selected_test_categories": payload.get("selected_test_categories") or [],
            "known_protected_endpoints": payload.get("known_protected_endpoints") or [],
            "har_file": payload.get("har_file"),
            "known_authenticated_requests": payload.get("known_authenticated_requests") or [],
            "login_workflow_hints": payload.get("login_workflow_hints") or {},
        }
    )
    if scan_options.get("execution_profile") == "auth-authorization-debug":
        engagement_mode = "gray_box"
        scan_options.update(
            {
                "engagement_mode": engagement_mode,
                "account_source": "generated_test_accounts",
                "auth_mode": "generated_test_accounts",
                "allow_account_generation": True,
                "allow_authenticated_testing": True,
                "allow_authorization_testing": True,
                "allow_test_owned_object_creation": True,
                "allow_payload_testing": False,
                "allow_rate_limit_testing": False,
                "enable_destructive_tests": False,
                "destructive_test_policy": "test_owned_only",
                "destructive_method_policy": scan_options.get("destructive_method_policy") or "test_owned_only",
                "required_user_count": 2,
            }
        )
    if scan_options.get("execution_profile") == "destructive-full-scan":
        if not scan_options.get("confirm_authorized"):
            raise ValueError("Target authorization confirmation is required for Destructive Test Cases - Full Authorized Scan.")
        if not scan_options.get("confirm_destructive_testing"):
            raise ValueError("Destructive testing confirmation is required for Destructive Test Cases - Full Authorized Scan.")
        engagement_mode = "gray_box"
        scan_options["engagement_mode"] = engagement_mode
        scan_options["full"] = True
        scan_options["enumeration_only"] = False
        scan_options["allow_account_generation"] = True
        scan_options["allow_authenticated_testing"] = True
        scan_options["allow_authorization_testing"] = True
        scan_options["allow_payload_testing"] = True
        scan_options["allow_rate_limit_testing"] = True
        scan_options["allow_test_owned_object_creation"] = True
        scan_options["enable_destructive_tests"] = True
        scan_options["account_source"] = scan_options.get("account_source") or "generated_test_accounts"
        scan_options["auth_mode"] = scan_options["account_source"]
    if scan_options.get("destructive_test_policy") == "authenticated_full" and profile == "crapi" and account_source == "auto":
        scan_options["account_source"] = "generated_test_accounts"
        scan_options["auth_mode"] = "generated_test_accounts"
        scan_options["allow_account_generation"] = True
    if scan_options.get("account_source") == "credentials_file":
        credentials_path = payload.get("credentials_path")
        if not credentials_path or not load_credentials(Path(credentials_path)):
            raise ValueError("Credentials file selected, but no valid credentials were found. Choose generated test accounts or provide a valid credentials file.")
    now = datetime.now(timezone.utc)
    with session_scope() as session:
        project_name = str(payload.get("project") or _dashboard_project_name(target, profile))
        project, _ = upsert_project_target(session, project_name, target)
        scan = Scan(
            project_id=project.id,
            profile=profile,
            ai_provider="Ollama",
            authorized_testing_mode=True,
            engagement_mode=engagement_mode,
            credentials_path=payload.get("credentials_path"),
            source_path=payload.get("source_path"),
            scan_config=scan_options,
            auth_mode=scan_options.get("auth_mode") or "auto",
            destructive_method_policy=scan_options.get("destructive_method_policy"),
            enable_destructive_tests=bool(scan_options.get("enable_destructive_tests")),
            destructive_test_policy=scan_options.get("destructive_test_policy") or destructive_policy,
            allow_test_owned_object_creation=bool(scan_options.get("allow_test_owned_object_creation")),
            confirm_destructive_testing=bool(scan_options.get("confirm_destructive_testing")),
            allow_account_generation=bool(scan_options.get("allow_account_generation")),
            allow_authenticated_testing=bool(scan_options.get("allow_authenticated_testing")),
            allow_authorization_testing=bool(scan_options.get("allow_authorization_testing")),
            allow_payload_testing=bool(scan_options.get("allow_payload_testing")),
            allow_rate_limit_testing=bool(scan_options.get("allow_rate_limit_testing")),
            status=ScanStatus.CREATED.value,
            started_at=now,
            current_phase="precheck",
            progress_message="Dashboard scan created",
            progress_percent=0,
            last_activity_at=now,
        )
        session.add(scan)
        session.flush()
        emit_progress(
            session,
            scan,
            "Scan created from dashboard",
            phase="precheck",
            event_type="scan_created_from_dashboard",
            context={
                "target": target,
                "profile": profile,
                "engagement_mode": engagement_mode,
                "full": bool(scan_options.get("full")),
                "enumeration_only": bool(scan_options.get("enumeration_only")),
                "execution_profile": scan_options["execution_profile"],
                "destructive_test_policy": scan_options.get("destructive_test_policy"),
                "enable_destructive_tests": bool(scan_options.get("enable_destructive_tests")),
                "allow_account_generation": bool(scan_options.get("allow_account_generation")),
                "allow_authenticated_testing": bool(scan_options.get("allow_authenticated_testing")),
                "allow_authorization_testing": bool(scan_options.get("allow_authorization_testing")),
                "allow_payload_testing": bool(scan_options.get("allow_payload_testing")),
                "allow_rate_limit_testing": bool(scan_options.get("allow_rate_limit_testing")),
                "account_source": scan_options.get("account_source"),
                "required_user_count": scan_options.get("required_user_count"),
                "selected_test_categories": scan_options.get("selected_test_categories") or [],
            },
        )
        return {"scan_id": scan.id, "project": project.name, "target": target}


def create_app() -> FastAPI:
    validate_dashboard_assets()
    app = FastAPI(title="SAIF Dashboard", version=_version(), dependencies=[Depends(require_auth)])
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        return _dashboard_page(request, lambda session: _dashboard_context(session) | {"page": "overview", "overview": services.overview(session), "scans": services.scans(session)})

    @app.get("/control", response_class=HTMLResponse)
    def control(request: Request):
        return _dashboard_page(request, lambda session: _dashboard_context(session) | {"page": "control", "scans": services.scans(session)})

    @app.get("/live", response_class=HTMLResponse)
    def live_latest(request: Request):
        with session_scope() as session:
            scan_id = services.latest_active_scan_id(session)
            if scan_id:
                return RedirectResponse(url=f"/scans/{scan_id}/live", status_code=307)
            scans = services.scans(session)
            return _template_response(request, _dashboard_context(session) | {"page": "live", "scan_id": None, "watch": {}, "scans": scans})

    @app.get("/scans", response_class=HTMLResponse)
    def scan_list(request: Request):
        with session_scope() as session:
            return _template_response(request, _dashboard_context(session) | {"page": "scans", "scans": services.scans(session)})

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    def scan_page(request: Request, scan_id: int):
        with session_scope() as session:
            return _template_response(request, _dashboard_context(session) | {"page": "scan_detail", "scan_id": scan_id, "detail": services.scan_detail(session, scan_id), "watch": services.watch(session, scan_id)})

    @app.get("/scans/{scan_id}/live", response_class=HTMLResponse)
    def live_page(request: Request, scan_id: int):
        with session_scope() as session:
            return _template_response(request, _dashboard_context(session) | {"page": "live", "scan_id": scan_id, "watch": services.watch(session, scan_id)})

    @app.get("/scans/{scan_id}/control", response_class=HTMLResponse)
    def scan_control_page(request: Request, scan_id: int):
        with session_scope() as session:
            return _template_response(request, _dashboard_context(session) | {"page": "control", "scan_id": scan_id, "scans": services.scans(session), "detail": services.scan_detail(session, scan_id)})

    @app.get("/scans/{scan_id}/auth", response_class=HTMLResponse)
    def scan_auth_page(request: Request, scan_id: int):
        with session_scope() as session:
            from saif.db.models import AuthenticatedSession

            return _template_response(request, {"page": "auth_sessions", "scan_id": scan_id, "auth_sessions": services.table(session, scan_id, AuthenticatedSession)})

    @app.get("/findings", response_class=HTMLResponse)
    def findings_page(request: Request):
        with session_scope() as session:
            findings = [services.row(item) for item in session.query(Finding).order_by(Finding.id.desc()).all()]
            return _template_response(request, {"page": "findings", "findings": findings})

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    def finding_detail(request: Request, finding_id: int):
        with session_scope() as session:
            finding = session.get(Finding, finding_id)
            if not finding:
                raise HTTPException(404)
            return _template_response(request, {"page": "finding_detail", "finding": services.row(finding)})

    @app.get("/payload-attempts", response_class=HTMLResponse)
    def payload_attempts(request: Request):
        with session_scope() as session:
            from saif.db.models import PayloadAttempt

            return _template_response(request, {"page": "payload_attempts", "payload_attempts": [services.row(item) for item in session.query(PayloadAttempt).order_by(PayloadAttempt.id.desc()).limit(300).all()]})

    @app.get("/auth-sessions", response_class=HTMLResponse)
    def auth_sessions(request: Request):
        with session_scope() as session:
            from saif.db.models import AuthenticatedSession

            return _template_response(request, {"page": "auth_sessions", "auth_sessions": [services.row(item) for item in session.query(AuthenticatedSession).order_by(AuthenticatedSession.id.desc()).limit(300).all()]})

    @app.get("/ai-activity", response_class=HTMLResponse)
    def ai_activity(request: Request):
        with session_scope() as session:
            from saif.db.models import AiCallRun

            return _template_response(request, {"page": "ai_activity", "ai_calls": [services.row(item) for item in session.query(AiCallRun).order_by(AiCallRun.id.desc()).limit(200).all()]})

    @app.get("/agent-activity", response_class=HTMLResponse)
    def agent_activity(request: Request):
        with session_scope() as session:
            from saif.db.models import AgentJob

            return _template_response(request, {"page": "agent_activity", "agent_jobs": [services.row(item) for item in session.query(AgentJob).order_by(AgentJob.id.desc()).limit(300).all()]})

    @app.get("/tool-runs", response_class=HTMLResponse)
    def tool_runs(request: Request):
        with session_scope() as session:
            from saif.db.models import ToolRun

            return _template_response(request, {"page": "tool_runs", "tool_runs": [services.row(item) for item in session.query(ToolRun).order_by(ToolRun.id.desc()).limit(300).all()]})

    @app.get("/evidence", response_class=HTMLResponse)
    def evidence(request: Request):
        with session_scope() as session:
            from saif.db.models import Evidence

            return _template_response(request, {"page": "evidence", "evidence_items": [services.row(item) for item in session.query(Evidence).order_by(Evidence.id.desc()).limit(300).all()]})

    @app.get("/reports", response_class=HTMLResponse)
    def reports(request: Request):
        with session_scope() as session:
            from saif.db.models import Report

            return _template_response(request, {"page": "reports", "reports": [services.row(item) for item in session.query(Report).order_by(Report.id.desc()).limit(300).all()]})

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request):
        with session_scope() as session:
            return _template_response(request, {"page": "settings", "settings": services.settings_payload(session)})

    add_api_routes(app)
    return app


def require_auth(credentials: HTTPBasicCredentials | None = Depends(security)) -> None:
    settings = get_settings()
    if not settings.dashboard_password:
        return
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, headers={"WWW-Authenticate": "Basic"})
    expected_user = settings.dashboard_username or "saif"
    if not (secrets.compare_digest(credentials.username, expected_user) and secrets.compare_digest(credentials.password, settings.dashboard_password)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, headers={"WWW-Authenticate": "Basic"})


def _version() -> str:
    try:
        return importlib.metadata.version("saif")
    except Exception:
        return "0.1.0"


def _health_payload() -> dict:
    db_status = "ok"
    try:
        with session_scope() as session:
            session.execute(text("select 1"))
    except Exception as exc:
        db_status = "failed"
        logger.exception("Dashboard health DB check failed")
        try:
            from saif.services.dashboard import _log_dashboard

            _log_dashboard("health_check_failed", {"db": "failed", "error": str(exc)})
        except Exception:
            pass
    payload = {
        "status": "ok",
        "dashboard": "running",
        "db": db_status,
        "version": _version(),
        "time": datetime.now(timezone.utc).isoformat(),
    }
    try:
        from saif.services.dashboard import _log_dashboard

        _log_dashboard("health_check", payload)
    except Exception:
        pass
    return payload


def add_api_routes(app: FastAPI) -> None:
    @app.get("/health")
    def root_health():
        return api_response(_health_payload())

    @app.get("/api/health")
    def health():
        return api_response(_health_payload())

    @app.get("/api/scans")
    def api_scans():
        with session_scope() as session:
            return api_response(services.scans(session))

    @app.get("/api/scans/{scan_id}")
    @app.get("/api/scans/{scan_id}/summary")
    def api_scan(scan_id: int):
        with session_scope() as session:
            try:
                return api_response(services.scan_detail(session, scan_id))
            except ValueError:
                return api_not_found(f"scan {scan_id} not found")

    @app.get("/api/scans/{scan_id}/production-readiness")
    def api_readiness(scan_id: int):
        with session_scope() as session:
            try:
                return api_response(services.scan_detail(session, scan_id)["production_readiness"])
            except ValueError:
                return api_not_found(f"scan {scan_id} not found")

    @app.get("/api/scans/{scan_id}/coverage")
    def api_coverage(scan_id: int):
        with session_scope() as session:
            try:
                return api_response(services.scan_detail(session, scan_id)["coverage"])
            except ValueError:
                return api_not_found(f"scan {scan_id} not found")

    @app.get("/api/scans/{scan_id}/request-map")
    def api_request_map(scan_id: int):
        return api_response(services.request_map(scan_id).get("requests", []))

    @app.get("/api/scans/{scan_id}/ai-trace-index")
    def api_ai_trace_index(scan_id: int):
        return api_response(services.ai_trace_index(scan_id).get("calls", []))

    @app.get("/api/scans/{scan_id}/agent-reactions")
    def api_agent_reactions(scan_id: int):
        return api_response(services.agent_reactions(scan_id))

    @app.get("/api/scans/{scan_id}/discovery-sources")
    def api_discovery_sources(scan_id: int):
        return api_response(services.discovery_sources(scan_id))

    @app.get("/api/scans/{scan_id}/tool-install-events")
    def api_tool_install_events(scan_id: int):
        return api_response(services.tool_install_events(scan_id))

    @app.get("/api/scans/{scan_id}/debug-export")
    def api_debug_export(scan_id: int, format: str = "json"):
        with session_scope() as session:
            try:
                json_path, html_path = generate_full_ai_debug_export(session, scan_id)
            except ValueError:
                return api_not_found(f"scan {scan_id} not found")
        selected = html_path if format == "html" else json_path
        media_type = "text/html" if format == "html" else "application/json"
        return FileResponse(selected, media_type=media_type, filename=selected.name)

    @app.get("/api/scans/{scan_id}/logs/tail")
    def api_logs_tail(scan_id: int, lines: int = 100):
        log_path = get_settings().log_dir / f"scan-{scan_id}.log"
        if not log_path.exists():
            return api_response([])
        content = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return api_response([{"line": line} for line in content[-max(1, min(lines, 1000)):]])

    @app.get("/api/scans/{scan_id}/live-state")
    def api_live_state(scan_id: int):
        with session_scope() as session:
            try:
                return api_response(services.live_state(session, scan_id))
            except ValueError:
                return api_not_found(f"scan {scan_id} not found")

    @app.get("/api/scans/{scan_id}/{resource}")
    def api_scan_resource(scan_id: int, resource: str):
        if resource == "actions":
            with session_scope() as session:
                try:
                    return api_response(services.actions_for_scan(session, scan_id))
                except ValueError:
                    return api_not_found(f"scan {scan_id} not found")
        if resource == "reports":
            with session_scope() as session:
                try:
                    return api_response(services.reports(session, scan_id))
                except ValueError:
                    return api_not_found(f"scan {scan_id} not found")
        if resource not in services.MODELS:
            raise HTTPException(404)
        with session_scope() as session:
            return api_response(services.table(session, scan_id, services.MODELS[resource]))

    @app.post("/api/scans/start")
    async def api_start(request: Request):
        payload = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
        payload = dict(payload)
        payload["confirm_authorized"] = bool(payload.get("confirm_authorized") or payload.get("confirm"))
        payload["confirm_destructive_testing"] = bool(payload.get("confirm_destructive_testing") or payload.get("confirm_destructive"))
        target = payload.get("target")
        if not target:
            return api_response({"ok": False, "status": "missing_target", "message": "target is required"}, status_code=400)
        if not payload.get("confirm_authorized"):
            return api_response({"ok": False, "error": "Authorization confirmation is required before starting a scan."}, status_code=400)
        if payload.get("enable_destructive_tests") and not payload.get("confirm_destructive_testing"):
            return api_response({"ok": False, "error": "Destructive testing acknowledgement is required before enabling destructive tests."}, status_code=400)
        destructive_test_policy = payload.get("destructive_test_policy") or payload.get("destructive_policy") or "detect_only"
        destructive_method_policy = payload.get("destructive_method_policy") or "no_destructive_methods"
        if destructive_test_policy == "lab_full_allowed" and destructive_method_policy not in {"lab_full_allowed", "test_owned_only", "manual_confirmation"}:
            return api_response(
                {
                    "ok": False,
                    "status": "invalid_scan_config",
                    "message": "Invalid scan configuration: Destructive Test Cases - Full Authorized Scan requires destructive policy lab_full_allowed, test_owned_only, or manual_confirmation.",
                },
                status_code=400,
            )
        try:
            normalize_scan_config(
                {
                    **payload,
                    "engagement_mode": payload.get("engagement_mode") or payload.get("mode") or "black-box",
                    "destructive_test_policy": destructive_test_policy,
                }
            )
        except ValueError as exc:
            return api_response({"ok": False, "status": "invalid_scan_config", "message": str(exc)}, status_code=400)
        try:
            created = _create_dashboard_scan(payload)
        except ValueError as exc:
            return api_response({"ok": False, "status": "invalid_request", "message": str(exc)}, status_code=400)
        scan_id = int(created["scan_id"])
        cmd = _scan_worker_command(scan_id, debug=bool(payload.get("debug", True)))
        try:
            result = _start_background_command(cmd, scan_id=scan_id, log_path=str(get_settings().log_dir / f"scan-{scan_id}.log"))
        except Exception as exc:
            with session_scope() as session:
                scan = session.get(Scan, scan_id)
                if scan:
                    scan.status = ScanStatus.FAILED_SYSTEM.value
                    scan.progress_message = "Scan worker start failed"
                    emit_progress(
                        session,
                        scan,
                        "Scan worker start failed",
                        level="ERROR",
                        phase="precheck",
                        event_type="worker_start_failed",
                        context={"error": str(exc)},
                    )
            return api_response({"ok": False, "status": "worker_start_failed", "error": str(exc), "message": "Could not start scan because scan ID was not created."}, status_code=500)
        result.update({"scan_id": scan_id, "target": created["target"], "project": created["project"], "live_url": f"/scans/{scan_id}/live"})
        return api_response(result, status_code=202)

    @app.get("/api/scans/{scan_id}/actions")
    def api_scan_actions(scan_id: int):
        with session_scope() as session:
            try:
                return api_response(services.actions_for_scan(session, scan_id))
            except ValueError:
                return api_not_found(f"scan {scan_id} not found")

    @app.post("/api/scans/{scan_id}/{action}")
    def api_scan_action(scan_id: int, action: str, phase: str | None = None):
        if action not in {"pause", "resume", "stop", "stop-force", "continue", "run-phase", "resolve-prerequisites", "restart-worker", "report"}:
            raise HTTPException(404)
        if action == "restart-worker":
            with session_scope() as session:
                scan = session.get(Scan, scan_id)
                if not scan:
                    return api_not_found(f"scan {scan_id} not found")
                ok, reason = services.validate_scan_action(session, scan, action)
                if not ok:
                    return api_response({"ok": False, "error": reason, "scan_status": scan.status}, status_code=409)
                scan.status = ScanStatus.RESUMING.value
                emit_progress(session, scan, "worker restart requested", event_type="worker_restart_requested", context={"requested_by": "dashboard"})
            worker = _start_background_command(_scan_worker_command(scan_id, debug=True), scan_id=scan_id, log_path=str(get_settings().log_dir / f"scan-{scan_id}.log"))
            return api_response(worker | {"scan_id": scan_id, "live_url": f"/scans/{scan_id}/live"}, status_code=202)
        if action == "resolve-prerequisites":
            selected_phase = "authenticated_crawling"
            with session_scope() as session:
                scan = session.get(Scan, scan_id)
                if not scan:
                    return api_not_found(f"scan {scan_id} not found")
                ok, reason = services.validate_scan_action(session, scan, action)
                if not ok:
                    return api_response({"ok": False, "error": reason, "scan_status": scan.status}, status_code=409)
                scan.progress_message = "Resolve prerequisites requested"
                emit_progress(session, scan, scan.progress_message, event_type="resolve_prerequisites_requested", context={"requested_by": "dashboard"})
            cmd = [sys.executable, "-m", "saif.cli", "scan", "continue", "--scan-id", str(scan_id), "--phase", selected_phase, "--full", "--debug"]
            return api_response(_start_background_command(cmd, scan_id=scan_id, log_path=str(get_settings().log_dir / f"scan-{scan_id}.log")) | {"phase": selected_phase}, status_code=202)
        if action in {"continue", "run-phase"}:
            selected_phase = phase or "account_provisioning"
            with session_scope() as session:
                if hasattr(session, "get"):
                    try:
                        scan = session.get(Scan, scan_id)
                        if not scan:
                            return api_not_found(f"scan {scan_id} not found")
                        ok, reason = services.validate_scan_action(session, scan, action)
                        if not ok:
                            return api_response({"ok": False, "error": reason, "scan_status": scan.status}, status_code=409)
                    except ValueError:
                        return api_not_found(f"scan {scan_id} not found")
            cmd = [sys.executable, "-m", "saif.cli", "scan", "continue", "--scan-id", str(scan_id), "--phase", selected_phase, "--full", "--debug"]
            return api_response(_start_background_command(cmd, scan_id=scan_id, log_path=str(get_settings().log_dir / f"scan-{scan_id}.log")) | {"phase": selected_phase}, status_code=202)
        if action == "stop-force":
            with session_scope() as session:
                if hasattr(session, "get"):
                    scan = session.get(Scan, scan_id)
                    if not scan:
                        return api_not_found(f"scan {scan_id} not found")
                    ok, reason = services.validate_scan_action(session, scan, action)
                    if not ok:
                        return api_response({"ok": False, "error": reason, "scan_status": scan.status}, status_code=409)
            cmd = [sys.executable, "-m", "saif.cli", "scan", "stop", "--scan-id", str(scan_id), "--force"]
            return api_response(_start_background_command(cmd, scan_id=scan_id, log_path=str(get_settings().log_dir / f"scan-{scan_id}.log")), status_code=202)
        with session_scope() as session:
            try:
                result = services.scan_action(session, scan_id, action, phase=phase)
            except ValueError:
                return api_not_found(f"scan {scan_id} not found")
            except PermissionError as exc:
                scan = session.get(Scan, scan_id)
                return api_response({"ok": False, "error": str(exc), "scan_status": scan.status if scan else None}, status_code=409)
        if action == "resume":
            try:
                worker = _start_background_command(_scan_worker_command(scan_id), scan_id=scan_id, log_path=str(get_settings().log_dir / f"scan-{scan_id}.log"))
                result["worker"] = {"pid": worker["pid"], "status": worker["status"], "live_url": f"/scans/{scan_id}/live"}
            except Exception as exc:
                result["worker"] = {"status": "worker_start_failed", "error": str(exc)}
        return api_response(result)

    @app.post("/api/findings/{finding_id}/{action}")
    def api_finding_action(finding_id: int, action: str, value: str | None = None):
        with session_scope() as session:
            try:
                return api_response(services.finding_action(session, finding_id, action, value))
            except ValueError as exc:
                return api_response({"ok": False, "error": "invalid_finding_action", "message": str(exc)}, status_code=404)
            except PermissionError as exc:
                return api_response({"ok": False, "error": str(exc)}, status_code=409)

    @app.get("/api/evidence/{evidence_id}/preview")
    def api_evidence_preview(evidence_id: int, show_secure_evidence: bool = False):
        if show_secure_evidence and not get_settings().allow_secret_view:
            raise HTTPException(403, "Set SAIF_ALLOW_SECRET_VIEW=true to view secure evidence")
        with session_scope() as session:
            try:
                return api_response(services.evidence_preview(session, evidence_id, allow_secret=show_secure_evidence))
            except ValueError:
                return api_not_found(f"evidence {evidence_id} not found")

    @app.post("/api/scans/{scan_id}/auth/{action}")
    def api_auth_action(scan_id: int, action: str):
        if action not in {"validate", "relogin", "create-accounts"}:
            raise HTTPException(404)
        phase_by_action = {
            "validate": "session_validation",
            "relogin": "login_session",
            "create-accounts": "account_provisioning",
        }
        phase = phase_by_action[action]
        cmd = [sys.executable, "-m", "saif.cli", "scan", "continue", "--scan-id", str(scan_id), "--phase", phase, "--full", "--debug"]
        return api_response(
            _start_background_command(cmd, scan_id=scan_id, log_path=str(get_settings().log_dir / f"scan-{scan_id}.log"))
            | {"action": action, "phase": phase},
            status_code=202,
        )

    @app.get("/api/reports/download")
    def api_report_download(path: str):
        report_path = Path(path)
        if not report_path.exists() or get_settings().report_dir.resolve() not in report_path.resolve().parents:
            raise HTTPException(404)
        return FileResponse(str(report_path), filename=report_path.name)
