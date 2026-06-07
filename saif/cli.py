from pathlib import Path
import os
import time
import traceback
from datetime import datetime, timezone

import typer
from alembic import command
from alembic.config import Config
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select
from sqlalchemy.exc import ProgrammingError, SQLAlchemyError

from saif.ai.gate import (
    AIContext,
    AIPrecheckError,
    OllamaModelMissingError,
    ai_error_message,
    build_ai_scan_plan,
    record_failed_precheck,
)
from saif.config import get_settings
from saif.db.models import AgentJob, AiCallRun, AuthenticatedSession, Credential, Evidence, Finding, PayloadAttempt, Project, Report, RunStatus, Scan, ScanEvent, ScanPhase, ScanProcess, ScanStatus, Target, TestCase, ToolRun
from saif.db import session_scope
from saif.registry.testcases import load_testcases
from saif.registry.tools import check_tool, load_tools
from saif.services.bootstrap import initialize_workspace, seed_foundation
from saif.services.doctor import run_doctor
from saif.services.prompt_runner import extract_target, parse_prompt, run_prompt_scan, select_tools
from saif.services.progress import emit_progress, latest_evidence_path, status_snapshot, watch_snapshot
from saif.services.reporting import generate_report
from saif.services.scan_config import normalize_scan_config
from saif.services.case_management import completed_tools, ensure_scan_phases, production_readiness_for_scan, scan_summary, scan_target, sync_scan_phases, tools_for_phase, mark_phase
from saif.services.dashboard import dashboard_status as dashboard_status_payload, run_dashboard, stop_dashboard
from saif.services.targets import resolve_target, upsert_project_target
from saif.services.tool_manager import install_missing_supported_tools, print_tool_summary, refresh_tool_registry, tool_registry_snapshot
import saif.services.prompt_runner as prompt_runner

app = typer.Typer(help="SAIF - Secure AI Forge")
db_app = typer.Typer(help="Database commands")
tools_app = typer.Typer(help="Tool registry commands")
project_app = typer.Typer(help="Project management commands")
testcases_app = typer.Typer(help="Test case registry commands")
scan_app = typer.Typer(help="Scan management commands")
report_app = typer.Typer(help="Reporting commands")
dashboard_app = typer.Typer(help="Local dashboard")
logs_app = typer.Typer(help="Runtime logs")
auth_app = typer.Typer(help="Authentication and session diagnostics")
finding_app = typer.Typer(help="Finding retest and closure workflow")
fix_app = typer.Typer(help="Source-assisted remediation guidance")

app.add_typer(db_app, name="db")
app.add_typer(tools_app, name="tools")
app.add_typer(project_app, name="project")
app.add_typer(testcases_app, name="testcases")
app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")
app.add_typer(dashboard_app, name="dashboard")
app.add_typer(logs_app, name="logs")
app.add_typer(auth_app, name="auth")
app.add_typer(finding_app, name="finding")
app.add_typer(fix_app, name="fix")

console = Console(width=180)


DETERMINISTIC_EXECUTION_PROFILES = {
    "destructive-full-scan",
    "authenticated-full-scan",
    "auth-authorization-debug",
    "standard-non-destructive",
    "safe-enumeration",
}


def _source_from_cli_arg(value: str | None) -> str:
    return "cli-arg" if value else "env"


def _upgrade_database_or_exit() -> None:
    try:
        command.upgrade(Config("alembic.ini"), "head")
    except Exception as exc:
        console.print("ERROR: database migration failed.")
        console.print(f"Reason: {exc}")
        console.print("Fix:")
        console.print("- check DATABASE_URL in .env")
        console.print("- run: ./saif.sh init-db")
        console.print("- if this happened during an upgrade, review the Alembic migration output above")
        raise typer.Exit(code=1) from exc


def _handle_db_programming_error(exc: ProgrammingError) -> None:
    message = str(exc)
    if "UndefinedColumn" in message or "does not exist" in message:
        missing = _extract_missing_column(message)
        console.print("ERROR: Database schema mismatch.")
        if missing:
            console.print(f"Missing column: {missing}")
        console.print("Run: ./saif.sh init-db")
        raise typer.Exit(code=1) from exc
    raise exc


def _extract_missing_column(message: str) -> str | None:
    import re

    match = re.search(r'column "([^"]+)" of relation "([^"]+)" does not exist', message)
    if match:
        column, table = match.groups()
        return f"{table}.{column}"
    match = re.search(r'column [^.\s]+\.([A-Za-z_][A-Za-z0-9_]*) does not exist', message)
    if match:
        return match.group(1)
    return None


def _build_ai_or_record_failed(session, project_name: str, prompt: str, target: str, parsed: dict, tools: list[str], debug: bool = False):
    try:
        settings = get_settings()
        console.print("AI planning:")
        console.print(f"Model: {settings.ollama_model}")
        console.print(f"Timeout: {settings.ollama_timeout_seconds}s")
        ai_context = build_ai_scan_plan(prompt=prompt, target_url=target, parsed_intent=parsed, selected_tools=tools, debug=debug)
        for attempt in ai_context.ai_call_attempts or []:
            console.print(
                "AI call: "
                f"stage=initial_planning model={attempt.get('model')} timeout={settings.ollama_timeout_seconds}s "
                f"attempt={attempt.get('attempt')}/{settings.ollama_max_retries + 1} "
                f"duration={round(int(attempt.get('duration_ms') or 0) / 1000, 2)}s "
                f"result={attempt.get('response_status')}"
            )
        console.print("Status: approved")
        return ai_context
    except AIPrecheckError as exc:
        context = {"code": getattr(exc, "code", "AI_PRECHECK_ERROR")}
        for key in ["prompt", "target", "model", "timeout_seconds", "base_url", "error"]:
            if hasattr(exc, key):
                context[key] = getattr(exc, key)
        if hasattr(exc, "ai_call_attempts"):
            context["ai_call_attempts"] = exc.ai_call_attempts
        if hasattr(exc, "raw_response"):
            context["raw_ai_response"] = exc.raw_response
        if hasattr(exc, "raw_plan"):
            context["raw_ai_plan"] = exc.raw_plan
        record_failed_precheck(session, project_name, str(exc), context=context)
        console.print(ai_error_message(exc))
        if getattr(exc, "code", "") == "AI_PLAN_NOT_APPROVED":
            console.print("Ollama: reachable")
            console.print(f"AI model: {get_settings().ollama_model}")
            console.print("AI planning: failed")
            console.print(f"Reason: {exc}")
        return None


def _print_run_summary(
    project: str,
    target: str,
    target_source: str,
    mode: str,
    tools: list[str],
    scan_id: int,
    parsed_intent: dict | None = None,
    unavailable_tools: list[dict] | None = None,
    json_path: Path | None = None,
    html_path: Path | None = None,
) -> None:
    console.print(f"Selected target: {target}")
    console.print(f"Source: {target_source}")
    console.print(f"Selected mode: {mode}")
    if parsed_intent is not None:
        enabled = [key for key, value in parsed_intent.items() if value]
        console.print(f"Parsed intent: {enabled}")
    console.print(f"Selected tools: {tools}")
    console.print(f"Unavailable tools/prerequisites: {unavailable_tools or []}")
    console.print(f"Selected project: {project}")
    console.print(f"Scan ID: {scan_id}")
    console.print(f"Evidence directory: .saif/evidence/scan-{scan_id}")
    if json_path or html_path:
        console.print("Reports:")
        if json_path:
            console.print(f"  JSON: {json_path}")
        if html_path:
            console.print(f"  HTML: {html_path}")


@app.command()
def init() -> None:
    """Create local SAIF workspace directories."""
    paths = initialize_workspace()
    for path in paths:
        console.print(f"[green]created[/green] {path}")


@db_app.command("init")
def db_init() -> None:
    """Run PostgreSQL migrations and seed foundation data."""
    _upgrade_database_or_exit()
    try:
        with session_scope() as session:
            seed_foundation(session)
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)
    console.print("[green]database initialized and seeded[/green]")


@app.command("doctor")
def doctor(target: str | None = typer.Option(None, "--target")) -> None:
    """Check the local SAIF runtime and optional target reachability."""
    try:
        selected_target = resolve_target(cli_target=target) if target or os.getenv("TARGET_URL") else None
    except ValueError as exc:
        console.print(f"[yellow]target not applicable[/yellow] {exc}")
        selected_target = None
    ok = run_doctor(selected_target.url if selected_target else None, console=console)
    raise typer.Exit(code=0 if ok else 1)


@tools_app.command("list")
def tools_list() -> None:
    """List SAIF tool categories and registered tools."""
    table = Table(title="SAIF Tool Registry")
    table.add_column("category")
    table.add_column("tool")
    table.add_column("kind")
    table.add_column("required")
    for category in load_tools():
        for tool in category.tools:
            table.add_row(category.name, tool.name, tool.kind, str(tool.required))
    console.print(table)


@tools_app.command("check")
def tools_check() -> None:
    """Check local availability of external CLI tools and Python tools."""
    table = Table(title="SAIF Tool Checks")
    table.add_column("category")
    table.add_column("tool")
    table.add_column("kind")
    table.add_column("status")
    for category in load_tools():
        for tool in category.tools:
            table.add_row(category.name, tool.name, tool.kind, check_tool(tool))
    console.print(table)


@tools_app.command("status")
def tools_status() -> None:
    """Refresh and show persistent tool registry status."""
    try:
        with session_scope() as session:
            refresh_tool_registry(session, install_missing=False, console=console)
            rows = tool_registry_snapshot(session)
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)
    table = Table(title="SAIF Tool Registry Status")
    table.add_column("tool")
    table.add_column("status")
    table.add_column("path")
    table.add_column("version")
    table.add_column("install attempts")
    for row in rows:
        table.add_row(
            row["tool_name"],
            row["status"],
            row.get("command_path") or "",
            row.get("version") or "",
            str(row.get("install_attempt_count") or 0),
        )
    console.print(table)


@tools_app.command("refresh")
def tools_refresh(install_missing: bool = typer.Option(False, "--install-missing"), browser: bool = typer.Option(False, "--browser")) -> None:
    """Refresh tool registry and optionally install missing supported tools."""
    try:
        with session_scope() as session:
            preparation = refresh_tool_registry(session, install_missing=install_missing, console=console, browser=browser)
            rows = tool_registry_snapshot(session)
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)
    console.print("Tool summary:")
    console.print(f"Installed tools ({len(preparation.installed_tools)}): {', '.join(preparation.installed_tools) if preparation.installed_tools else 'none'}")
    console.print(f"Missing tools ({len(preparation.missing_tools)}): {', '.join(preparation.missing_tools) if preparation.missing_tools else 'none'}")
    if preparation.attempts:
        table = Table(title="Tool install attempts")
        table.add_column("tool")
        table.add_column("status")
        table.add_column("reason")
        for attempt in preparation.attempts:
            table.add_row(attempt.tool, attempt.status, attempt.reason or "")
        console.print(table)
    table = Table(title="SAIF Tool Registry")
    table.add_column("tool")
    table.add_column("status")
    table.add_column("path")
    for row in rows:
        table.add_row(row["tool_name"], row["status"], row.get("command_path") or "")
    console.print(table)


@app.command("install-tools")
def install_tools(browser: bool = typer.Option(False, "--browser")) -> None:
    """Install missing supported external tools for WSL/Linux."""
    print_tool_summary(console)
    preparation = install_missing_supported_tools(console, browser=browser)
    if preparation.attempts:
        table = Table(title="SAIF Tool Installation")
        table.add_column("tool")
        table.add_column("attempted")
        table.add_column("status")
        table.add_column("reason")
        for attempt in preparation.attempts:
            table.add_row(attempt.tool, str(attempt.attempted), attempt.status, attempt.reason or "")
        console.print(table)
    try:
        with session_scope() as session:
            refresh_tool_registry(session, install_missing=False, console=console)
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@project_app.command("create")
def project_create(
    name: str | None = typer.Option(None, "--name"),
    target: str | None = typer.Option(None, "--target"),
    target_source: str | None = typer.Option(None, "--target-source", hidden=True),
) -> None:
    """Create a project with its first target."""
    settings = get_settings()
    name = name or settings.demo_project_name
    try:
        resolved = resolve_target(cli_target=target)
        source = target_source or _source_from_cli_arg(target)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    try:
        with session_scope() as session:
            upsert_project_target(session, name, resolved.url, console=console)
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)
    console.print(f"Source: {source}")


@testcases_app.command("list")
def testcases_list(profile: str = typer.Option("web-api", "--profile")) -> None:
    """List test cases for a profile."""
    registry = load_testcases(profile)
    table = Table(title=f"SAIF Test Cases: {profile}")
    table.add_column("phase")
    table.add_column("id")
    table.add_column("agent")
    table.add_column("tool")
    table.add_column("name")
    table.add_column("enabled")
    for test_case in registry.test_cases:
        table.add_row(
            test_case.phase,
            test_case.id,
            test_case.agent,
            test_case.tool,
            test_case.name,
            str(test_case.enabled),
        )
    console.print(table)


@scan_app.command("start")
def scan_start(
    project: str | None = typer.Option(None, "--project"),
    target: str | None = typer.Option(None, "--target"),
    target_source: str | None = typer.Option(None, "--target-source", hidden=True),
    profile: str = typer.Option("auto", "--profile"),
    mode: str | None = typer.Option(None, "--mode"),
    credentials: str | None = typer.Option(None, "--credentials"),
    source_path: str | None = typer.Option(None, "--source-path"),
    ai: str = typer.Option("ollama", "--ai"),
    enumeration_only: bool = typer.Option(False, "--enumeration-only"),
    full: bool = typer.Option(False, "--full"),
    auth: bool = typer.Option(False, "--auth"),
    vuln_test: bool = typer.Option(False, "--vuln-test"),
    no_destructive_methods: bool = typer.Option(False, "--no-destructive-methods"),
    destructive_method_policy: str | None = typer.Option(None, "--destructive-method-policy"),
    enable_destructive_tests: bool = typer.Option(False, "--enable-destructive-tests"),
    destructive_policy: str = typer.Option("detect_only", "--destructive-policy"),
    allow_test_owned_object_creation: bool = typer.Option(False, "--allow-test-owned-object-creation"),
    confirm_destructive_testing: bool = typer.Option(False, "--confirm-destructive-testing"),
    auth_mode: str = typer.Option("auto", "--auth-mode"),
    allow_account_generation: bool = typer.Option(False, "--allow-account-generation"),
    allow_authenticated_testing: bool = typer.Option(False, "--allow-authenticated-testing"),
    allow_authorization_testing: bool = typer.Option(False, "--allow-authorization-testing"),
    allow_payload_testing: bool = typer.Option(False, "--allow-payload-testing"),
    allow_rate_limit_testing: bool = typer.Option(False, "--allow-rate-limit-testing"),
    selected_test_categories: str | None = typer.Option(None, "--selected-test-categories"),
    protected_endpoint: list[str] | None = typer.Option(None, "--protected-endpoint"),
    har_file: str | None = typer.Option(None, "--har-file"),
    known_authenticated_request: list[str] | None = typer.Option(None, "--known-authenticated-request"),
    login_url: str | None = typer.Option(None, "--login-url"),
    username_field: str | None = typer.Option(None, "--username-field"),
    password_field: str | None = typer.Option(None, "--password-field"),
    submit_selector: str | None = typer.Option(None, "--submit-selector"),
    post_login_action: str | None = typer.Option(None, "--post-login-action"),
    cookie_file: str | None = typer.Option(None, "--cookie-file"),
    workflow_script: str | None = typer.Option(None, "--workflow-script"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Start an AI-planned scan for a project."""
    settings = get_settings()
    project = project or settings.demo_project_name
    try:
        resolved = resolve_target(cli_target=target)
        source = target_source or _source_from_cli_arg(target)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    run_doctor(resolved.url, console=console)
    engagement_mode = _resolve_engagement_mode(mode, credentials, source_path)
    destructive_method_policy = destructive_method_policy or ("no_destructive_methods" if no_destructive_methods else "test_owned_only" if full else "no_destructive_methods")
    if no_destructive_methods and destructive_policy == "detect_only":
        destructive_policy = "disabled"
    if credentials:
        os.environ["SAIF_CREDENTIALS_PATH"] = credentials
    prompt = _scan_start_prompt(resolved.url, profile, enumeration_only, full, auth, vuln_test, no_destructive_methods, engagement_mode)
    parsed_intent = parse_prompt(prompt)
    selected_tools = select_tools(parsed_intent, resolved.url)
    try:
        with session_scope() as session:
            seed_foundation(session, "api-security" if profile == "auto" else profile)
            db_project, _ = upsert_project_target(session, project, resolved.url, console=console)
            ai_context = _build_ai_or_record_failed(session, project, prompt, resolved.url, parsed_intent, selected_tools, debug=debug)
            if ai_context is None:
                ai_failed = True
                scan_id = 0
                tool_results = []
                json_path = None
                html_path = None
            else:
                ai_failed = False
                scan, selected_tools, tool_results, parsed_intent, _ = run_prompt_scan(
                    session,
                    db_project,
                    resolved.url,
                    prompt,
                    ai_context,
                    console=console,
                    target_source=source,
                    debug_live=debug,
                    engagement_mode=engagement_mode,
                    credentials_path=credentials,
                    source_path=source_path,
                    auth_mode=auth_mode,
                    destructive_method_policy=destructive_method_policy,
                    enable_destructive_tests=enable_destructive_tests,
                    destructive_test_policy=destructive_policy,
                    allow_test_owned_object_creation=allow_test_owned_object_creation,
                    confirm_destructive_testing=confirm_destructive_testing,
                    allow_account_generation=allow_account_generation,
                    allow_authenticated_testing=allow_authenticated_testing,
                    allow_authorization_testing=allow_authorization_testing,
                    allow_payload_testing=allow_payload_testing,
                    allow_rate_limit_testing=allow_rate_limit_testing,
                    selected_test_categories=_split_csv(selected_test_categories),
                    known_protected_endpoints=_parse_known_protected_endpoints(protected_endpoint or []),
                    har_file=har_file,
                    known_authenticated_requests=known_authenticated_request or [],
                    login_workflow_hints={
                        "login_url": login_url,
                        "username_field": username_field,
                        "password_field": password_field,
                        "submit_selector": submit_selector,
                        "post_login_action": post_login_action,
                        "cookie_file": cookie_file,
                        "workflow_script": workflow_script,
                    },
                )
                scan_id = scan.id
                json_path = generate_report(session, project, "json")
                html_path = generate_report(session, project, "html")
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)
    if ai_failed:
        raise typer.Exit(code=1)
    unavailable_tools = [{"tool": item["tool"], "status": item.get("status"), "reason": item.get("reason")} for item in tool_results if item.get("reason")]
    _print_run_summary(
        project=project,
        target=resolved.url,
        target_source=source,
        mode="default",
        tools=selected_tools,
        scan_id=scan_id,
        parsed_intent=parsed_intent,
        unavailable_tools=unavailable_tools,
        json_path=json_path,
        html_path=html_path,
    )


@scan_app.command("run-existing")
def scan_run_existing(
    scan_id: int = typer.Option(..., "--scan-id"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Run the normal scan workflow against an existing dashboard-created scan row."""
    try:
        with session_scope() as session:
            scan = _load_scan_or_exit(session, scan_id)
            active_pid = _active_worker_pid(session, scan_id)
            if active_pid:
                message = f"Scan already has active worker PID {active_pid}"
                _append_worker_log(scan_id, message, level="WARNING")
                emit_progress(session, scan, message, level="WARNING", phase=scan.current_phase or "worker", agent="orchestrator_agent", event_type="worker_already_running", context={"pid": active_pid}, console=console, live=True)
                raise typer.Exit(code=0)
            target = scan_target(session, scan)
            if not target:
                console.print(f"ERROR: scan {scan_id} has no target attached through its project.")
                scan.status = ScanStatus.FAILED.value
                emit_progress(session, scan, "scan has no attached target", level="ERROR", phase="precheck", event_type="error", console=console, live=True)
                raise typer.Exit(code=1)
            project = session.get(Project, scan.project_id)
            if not project:
                console.print(f"ERROR: scan {scan_id} project was not found.")
                scan.status = ScanStatus.FAILED.value
                emit_progress(session, scan, "scan project was not found", level="ERROR", phase="precheck", event_type="error", console=console, live=True)
                raise typer.Exit(code=1)

            emit_progress(
                session,
                scan,
                "Scan worker process started",
                phase=scan.current_phase or "precheck",
                agent="orchestrator_agent",
                event_type="scan_worker_started",
                context={"pid": os.getpid(), "source": "run-existing"},
                console=console,
                live=True,
            )
            _append_worker_log(scan.id, f"worker process started pid={os.getpid()} args=scan run-existing --scan-id {scan.id}", level="INFO")
            created_event = session.scalar(
                select(ScanEvent)
                .where(ScanEvent.scan_id == scan.id, ScanEvent.event_type == "scan_created_from_dashboard")
                .order_by(ScanEvent.id.desc())
            )
            dashboard_options = {**(scan.scan_config or {}), **(dict(created_event.context_json or {}) if created_event else {})}
            dashboard_options.update(
                {
                    "application_profile": dashboard_options.get("application_profile") or scan.profile,
                    "profile": dashboard_options.get("profile") or scan.profile,
                    "engagement_mode": scan.engagement_mode or dashboard_options.get("engagement_mode"),
                    "allow_authenticated_testing": bool(scan.allow_authenticated_testing),
                    "allow_authorization_testing": bool(scan.allow_authorization_testing),
                    "allow_payload_testing": bool(scan.allow_payload_testing),
                    "allow_rate_limit_testing": bool(scan.allow_rate_limit_testing),
                    "enable_destructive_tests": bool(scan.enable_destructive_tests),
                    "destructive_test_policy": scan.destructive_test_policy or dashboard_options.get("destructive_test_policy"),
                    "destructive_method_policy": scan.destructive_method_policy or dashboard_options.get("destructive_method_policy"),
                    "account_source": dashboard_options.get("account_source") or scan.auth_mode,
                    "auth_mode": scan.auth_mode or dashboard_options.get("auth_mode"),
                    "credentials_path": scan.credentials_path or dashboard_options.get("credentials_path"),
                    "required_user_count": dashboard_options.get("required_user_count") or 2,
                }
            )
            try:
                dashboard_options = normalize_scan_config(dashboard_options)
            except ValueError as exc:
                scan.status = ScanStatus.FAILED_PRECHECK.value
                scan.completed_at = datetime.now(timezone.utc)
                emit_progress(
                    session,
                    scan,
                    str(exc),
                    level="ERROR",
                    phase="precheck",
                    agent="orchestrator_agent",
                    event_type="invalid_scan_config",
                    context={"scan_config": dashboard_options},
                    console=console,
                    live=True,
                )
                emit_progress(
                    session,
                    scan,
                    "scan start failed",
                    level="ERROR",
                    phase="precheck",
                    agent="orchestrator_agent",
                    event_type="scan_start_failed",
                    context={"reason": str(exc)},
                    console=console,
                    live=True,
                )
                _mark_scan_worker_completed(scan.id, status="failed", exit_code=1)
                raise typer.Exit(code=1)
            scan.scan_config = dashboard_options
            _append_worker_log(scan.id, f"loaded scan config execution_profile={dashboard_options.get('execution_profile')} profile={dashboard_options.get('profile')} account_source={dashboard_options.get('account_source')}", level="INFO")
            seed_foundation(session, "api-security" if scan.profile == "auto" else scan.profile)
            emit_progress(session, scan, "precheck started", phase="precheck", agent="orchestrator_agent", event_type="precheck_started", console=console, live=True)
            run_doctor(target, console=console)
            emit_progress(session, scan, "precheck completed", phase="precheck", agent="orchestrator_agent", event_type="precheck_completed", console=console, live=True)
            workflow_phases = _expanded_workflow_phases(dashboard_options)
            emit_progress(
                session,
                scan,
                "workflow expanded",
                phase="precheck",
                agent="orchestrator_agent",
                event_type="workflow_expanded",
                context={"execution_profile": dashboard_options.get("execution_profile"), "phases": workflow_phases},
                console=console,
                live=True,
            )
            if workflow_phases:
                emit_progress(
                    session,
                    scan,
                    f"first phase queued: {workflow_phases[0]}",
                    phase=workflow_phases[0],
                    agent="orchestrator_agent",
                    event_type="phase_started",
                    context={"phase": workflow_phases[0]},
                    console=console,
                    live=True,
                )
            prompt = _scan_start_prompt(
                target,
                scan.profile or "auto",
                bool(dashboard_options.get("enumeration_only")),
                bool(dashboard_options.get("full") or scan.profile == "api-security-authenticated-test"),
                bool(scan.allow_authenticated_testing),
                bool(scan.allow_payload_testing),
                (scan.destructive_test_policy or "") == "disabled",
                scan.engagement_mode,
            )
            parsed_intent = parse_prompt(prompt)
            selected_tools = select_tools(parsed_intent, target)
            deterministic_workflow = _has_deterministic_workflow(dashboard_options, workflow_phases)
            emit_progress(
                session,
                scan,
                "AI planning attempted",
                phase="ai_planning",
                agent="ai_planner_agent",
                tool="ollama",
                event_type="ai_planning_attempted",
                context={"execution_profile": dashboard_options.get("execution_profile"), "deterministic_workflow": deterministic_workflow},
                console=console,
                live=True,
            )
            try:
                ai_context = build_ai_scan_plan(prompt=prompt, target_url=target, parsed_intent=parsed_intent, selected_tools=selected_tools, debug=debug)
            except AIPrecheckError as exc:
                if deterministic_workflow:
                    ai_context = _advisory_ai_context(
                        prompt=prompt,
                        target=target,
                        selected_tools=selected_tools,
                        execution_profile=str(dashboard_options.get("execution_profile") or ""),
                        workflow_phases=workflow_phases,
                        exc=exc,
                    )
                    _append_worker_log(scan.id, f"AI planning failed/warned code={getattr(exc, 'code', 'AI_PRECHECK_ERROR')} reason={exc}", level="WARNING")
                    emit_progress(
                        session,
                        scan,
                        "AI planning unavailable; continuing deterministic workflow",
                        level="WARNING",
                        phase="ai_planning",
                        agent="ai_planner_agent",
                        tool="ollama",
                        event_type="ai_planning_not_used",
                        context={
                            "code": getattr(exc, "code", "AI_PRECHECK_ERROR"),
                            "message": str(exc),
                            "ai_planning_status": "warning",
                            "ai_planning_error": str(exc),
                            "ai_planning_warning": "Ollama did not return valid executable test plan; deterministic workflow was used.",
                            "ai_available": False,
                            "deterministic_mode": True,
                            "execution_profile": dashboard_options.get("execution_profile"),
                            "workflow_phases": workflow_phases,
                        },
                        console=console,
                        live=True,
                    )
                    emit_progress(
                        session,
                        scan,
                        "deterministic workflow continued",
                        phase="precheck",
                        agent="orchestrator_agent",
                        event_type="deterministic_workflow_continued",
                        context={"execution_profile": dashboard_options.get("execution_profile"), "phases": workflow_phases},
                        console=console,
                        live=True,
                    )
                    if workflow_phases:
                        emit_progress(
                            session,
                            scan,
                            f"first deterministic phase started: {workflow_phases[0]}",
                            phase=workflow_phases[0],
                            agent="orchestrator_agent",
                            event_type="phase_started",
                            context={"phase": workflow_phases[0], "deterministic_mode": True},
                            console=console,
                            live=True,
                        )
                else:
                    scan.status = ScanStatus.FAILED_AI_TIMEOUT.value if getattr(exc, "code", "") == "AI_PLANNING_TIMEOUT" else ScanStatus.FAILED_PRECHECK.value
                    scan.completed_at = datetime.now(timezone.utc)
                    emit_progress(
                        session,
                        scan,
                        f"AI planning failed: {exc}",
                        level="ERROR",
                        phase="ai_planning",
                        agent="ai_planner_agent",
                        tool="ollama",
                        event_type="error",
                        context={"code": getattr(exc, "code", "AI_PRECHECK_ERROR"), "message": str(exc)},
                        console=console,
                        live=True,
                    )
                    console.print(ai_error_message(exc))
                    raise typer.Exit(code=1)
            else:
                emit_progress(
                    session,
                    scan,
                    "AI planning completed",
                    phase="ai_planning",
                    agent="ai_planner_agent",
                    tool="ollama",
                    event_type="ai_planning_completed",
                    context={"deterministic_workflow": deterministic_workflow},
                    console=console,
                    live=True,
                )
                if deterministic_workflow:
                    emit_progress(
                        session,
                        scan,
                        "deterministic workflow continued",
                        phase="precheck",
                        agent="orchestrator_agent",
                        event_type="deterministic_workflow_continued",
                        context={"execution_profile": dashboard_options.get("execution_profile"), "phases": workflow_phases},
                        console=console,
                        live=True,
                    )
                    if workflow_phases:
                        emit_progress(
                            session,
                            scan,
                            f"first deterministic phase started: {workflow_phases[0]}",
                            phase=workflow_phases[0],
                            agent="orchestrator_agent",
                            event_type="phase_started",
                            context={"phase": workflow_phases[0], "deterministic_mode": True},
                            console=console,
                            live=True,
                        )

            scan, selected_tools, tool_results, parsed_intent, _ = run_prompt_scan(
                session,
                project,
                target,
                prompt,
                ai_context,
                console=console,
                target_source="dashboard",
                debug_live=debug,
                engagement_mode=scan.engagement_mode,
                credentials_path=scan.credentials_path,
                source_path=scan.source_path,
                auth_mode=scan.auth_mode,
                destructive_method_policy=scan.destructive_method_policy,
                enable_destructive_tests=bool(scan.enable_destructive_tests),
                destructive_test_policy=scan.destructive_test_policy or "detect_only",
                allow_test_owned_object_creation=bool(scan.allow_test_owned_object_creation),
                confirm_destructive_testing=bool(scan.confirm_destructive_testing),
                allow_account_generation=bool(scan.allow_account_generation),
                allow_authenticated_testing=bool(scan.allow_authenticated_testing),
                allow_authorization_testing=bool(scan.allow_authorization_testing),
                allow_payload_testing=bool(scan.allow_payload_testing),
                allow_rate_limit_testing=bool(scan.allow_rate_limit_testing),
                selected_test_categories=list(dashboard_options.get("selected_test_categories") or []),
                existing_scan=scan,
            )
            _append_worker_log(scan.id, f"selected tools={','.join(selected_tools)}", level="INFO")
            json_path = generate_report(session, None, "json", scan_id=scan.id)
            html_path = generate_report(session, None, "html", scan_id=scan.id)
            _print_run_summary(
                project=project.name,
                target=target,
                target_source="dashboard",
                mode=scan.engagement_mode or "dashboard",
                tools=selected_tools,
                scan_id=scan.id,
                parsed_intent=parsed_intent,
                unavailable_tools=[{"tool": item["tool"], "status": item.get("status"), "reason": item.get("reason")} for item in tool_results if item.get("reason")],
                json_path=json_path,
                html_path=html_path,
            )
            _mark_scan_worker_completed(scan.id)
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)
    except SQLAlchemyError as exc:
        _append_worker_log(scan_id, "database error\n" + traceback.format_exc())
        _mark_scan_worker_failed(scan_id, f"Database error: {exc}", traceback_text=traceback.format_exc())
        console.print(f"ERROR: scan {scan_id} failed with a database error. Check .saif/logs/scan-{scan_id}.log")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        _append_worker_log(scan_id, "worker crashed\n" + traceback.format_exc())
        _mark_scan_worker_failed(scan_id, f"Worker error: {exc}", traceback_text=traceback.format_exc())
        console.print(f"ERROR: scan {scan_id} worker failed. Check .saif/logs/scan-{scan_id}.log")
        raise typer.Exit(code=1) from exc


def _append_worker_log(scan_id: int, message: str, *, level: str = "ERROR") -> None:
    try:
        path = get_settings().log_dir / f"scan-{scan_id}.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {level.upper()} scan={scan_id} {message}\n")
    except Exception:
        pass


def _mark_scan_worker_failed(scan_id: int, message: str, traceback_text: str | None = None) -> None:
    try:
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.EXECUTION_ERROR.value
                scan.completed_at = datetime.now(timezone.utc)
                scan.current_phase = "failed"
                scan.progress_message = f"worker crashed: {message[:160]}"
                phase = scan.current_phase or "worker"
                emit_progress(
                    session,
                    scan,
                    message[:900],
                    level="ERROR",
                    phase=phase,
                    agent=scan.current_agent or "orchestrator_agent",
                    tool=scan.current_tool,
                    event_type="worker_crashed",
                    context={"error": message[:2000], "traceback": (traceback_text or "")[-6000:]},
                    console=console,
                    live=True,
                )
                if phase in {"created", "precheck", "ai_planning", "worker"}:
                    emit_progress(
                        session,
                        scan,
                        message[:900],
                        level="ERROR",
                        phase=phase,
                        agent=scan.current_agent or "orchestrator_agent",
                        tool=scan.current_tool,
                        event_type="workflow_build_failed",
                        context={"error": message[:2000]},
                        console=console,
                        live=True,
                    )
                    emit_progress(
                        session,
                        scan,
                        "scan start failed",
                        level="ERROR",
                        phase=phase,
                        agent=scan.current_agent or "orchestrator_agent",
                        tool=scan.current_tool,
                        event_type="scan_start_failed",
                        context={"reason": message[:2000]},
                        console=console,
                        live=True,
                    )
                emit_progress(
                    session,
                    scan,
                    message[:900],
                    level="ERROR",
                    phase=phase,
                    agent=scan.current_agent,
                    tool=scan.current_tool,
                    event_type="scan_failed",
                    context={"error": message[:2000]},
                    console=console,
                    live=True,
                )
            process = session.scalar(
                select(ScanProcess)
                .where(ScanProcess.scan_id == scan_id, ScanProcess.pid == os.getpid())
                .order_by(ScanProcess.id.desc())
            )
            if process:
                process.status = "crashed"
                process.ended_at = datetime.now(timezone.utc)
                process.exit_code = 1
    except Exception:
        pass


def _mark_scan_worker_completed(scan_id: int, *, status: str = "completed", exit_code: int = 0) -> None:
    try:
        with session_scope() as session:
            process = session.scalar(
                select(ScanProcess)
                .where(ScanProcess.scan_id == scan_id, ScanProcess.pid == os.getpid())
                .order_by(ScanProcess.id.desc())
            )
            if process:
                process.status = status
                process.ended_at = datetime.now(timezone.utc)
                process.exit_code = exit_code
    except Exception:
        pass


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def _active_worker_pid(session, scan_id: int) -> int | None:
    processes = session.scalars(select(ScanProcess).where(ScanProcess.scan_id == scan_id).order_by(ScanProcess.id.desc()).limit(5)).all()
    current_pid = os.getpid()
    for process in processes:
        if process.pid != current_pid and process.status in {"started", "running"} and _pid_alive(process.pid):
            return process.pid
    return None


def _load_scan_or_exit(session, scan_id: int) -> Scan:
    scan = session.get(Scan, scan_id)
    if not scan:
        console.print(f"ERROR: scan {scan_id} was not found.")
        raise typer.Exit(code=1)
    return scan


def _expanded_workflow_phases(scan_config: dict) -> list[str]:
    if scan_config.get("execution_profile") == "destructive-full-scan":
        return [
            "enumeration",
            "endpoint_inventory",
            "request_templates",
            "auth_endpoint_classification",
            "account_provisioning",
            "login_session_user1",
            "login_session_user2",
            "session_validation",
            "authenticated_crawling",
            "authorization_matrix",
            "bola_idor_testing",
            "bfla_testing",
            "xss_testing",
            "sqli_testing",
            "command_injection_testing",
            "rate_limit_testing",
            "business_logic_testing",
            "report_generation",
        ]
    if scan_config.get("full") or scan_config.get("allow_authenticated_testing"):
        return [
            "api_discovery",
            "auth_mapping",
            "login_session",
            "session_validation",
            "authenticated_crawling",
            "authorization_testing",
            "input_validation_testing",
            "business_logic_testing",
            "report_generation",
        ]
    return ["enumeration", "api_discovery", "report_generation"]


def _has_deterministic_workflow(scan_config: dict, workflow_phases: list[str]) -> bool:
    execution_profile = str(scan_config.get("execution_profile") or "").strip()
    return bool(workflow_phases) and execution_profile in DETERMINISTIC_EXECUTION_PROFILES


def _advisory_ai_context(
    *,
    prompt: str,
    target: str,
    selected_tools: list[str],
    execution_profile: str,
    workflow_phases: list[str],
    exc: AIPrecheckError,
) -> AIContext:
    return AIContext(
        provider="Ollama",
        model=get_settings().ollama_model,
        base_url=get_settings().ollama_base_url,
        prompt=prompt,
        scan_plan={
            "approved": True,
            "mode": execution_profile,
            "target": target,
            "tools": selected_tools,
            "test_cases": [],
            "not_applicable": [],
            "missing_prerequisites": [],
            "ai_planning_status": "warning",
            "ai_planning_error": str(exc),
            "ai_planning_warning": "Ollama did not return valid executable test plan; deterministic workflow was used.",
            "ai_available": False,
            "deterministic_mode": True,
            "deterministic_workflow_phases": workflow_phases,
            "warning": "Ollama did not return valid executable test plan; deterministic workflow was used.",
        },
        ai_call_attempts=getattr(exc, "ai_call_attempts", []),
    )


def _scan_start_prompt(
    target: str,
    profile: str,
    enumeration_only: bool,
    full: bool,
    auth: bool,
    vuln_test: bool,
    no_destructive_methods: bool,
    engagement_mode: str | None = None,
) -> str:
    parts = ["default enumeration"]
    if full:
        parts.append("SAIF:full Destructive Test Cases - Full Authorized Scan")
    if profile == "crapi":
        parts.append("SAIF:application_profile=crapi")
    elif auth:
        parts.append("SAIF:auth authenticated API security testing")
    elif vuln_test:
        parts.append("SAIF:vuln_test vulnerability validation")
    if enumeration_only:
        parts.append("SAIF:enumeration_only")
    if no_destructive_methods:
        parts.append("SAIF:no_destructive_methods no destructive methods")
    if engagement_mode:
        parts.append(f"SAIF:mode={engagement_mode}")
    parts.append(f"profile {profile}")
    parts.append(f"target: {target}")
    return ". ".join(parts)


def _resolve_engagement_mode(mode: str | None, credentials: str | None, source_path: str | None) -> str:
    normalized = (mode or "").replace("-", "_").lower() or None
    if normalized and normalized not in {"black_box", "gray_box", "white_box"}:
        raise typer.BadParameter("--mode must be black-box, gray-box, or white-box")
    if normalized:
        return normalized
    if source_path:
        return "white_box"
    if credentials:
        return "gray_box"
    return "black_box"


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_known_protected_endpoints(values: list[str]) -> list[dict]:
    parsed = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        parts = text.split(None, 1)
        if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            parsed.append({"method": parts[0].upper(), "path": parts[1].strip()})
        else:
            parsed.append({"method": "GET", "path": text})
    return parsed


@scan_app.command("pause")
def scan_pause(scan_id: int = typer.Option(..., "--scan-id")) -> None:
    """Request a running scan to pause between tool steps."""
    try:
        with session_scope() as session:
            scan = _load_scan_or_exit(session, scan_id)
            scan.status = ScanStatus.PAUSED.value
            emit_progress(session, scan, "scan paused", event_type="scan_paused", console=console, live=True)
            console.print(f"Scan {scan_id}: paused")
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@scan_app.command("resume")
def scan_resume(scan_id: int = typer.Option(..., "--scan-id")) -> None:
    """Mark a paused scan as ready to resume."""
    try:
        with session_scope() as session:
            scan = _load_scan_or_exit(session, scan_id)
            scan.status = ScanStatus.RESUMING.value
            emit_progress(session, scan, "scan resumed", event_type="scan_resumed", console=console, live=True)
            console.print(f"Scan {scan_id}: resuming")
            console.print("Resume execution will continue from incomplete planned records in the worker-enabled flow.")
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@scan_app.command("stop")
def scan_stop(scan_id: int = typer.Option(..., "--scan-id"), force: bool = typer.Option(False, "--force")) -> None:
    """Request a running scan to stop between tool steps."""
    try:
        with session_scope() as session:
            scan = _load_scan_or_exit(session, scan_id)
            scan.status = ScanStatus.STOPPED.value if force else ScanStatus.STOPPING.value
            emit_progress(session, scan, "scan stopped" if force else "scan stopping", event_type="scan_stopped", console=console, live=True)
            console.print(f"Scan {scan_id}: {'stopped' if force else 'stopping'}")
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@scan_app.command("status")
def scan_status(scan_id: int = typer.Option(..., "--scan-id")) -> None:
    """Show scan lifecycle and execution counters."""
    try:
        with session_scope() as session:
            scan = _load_scan_or_exit(session, scan_id)
            sync_scan_phases(session, scan)
            readiness = production_readiness_for_scan(session, scan)
            snapshot = status_snapshot(session, scan_id)
            target = scan_target(session, scan)
            table = Table(title=f"SAIF Scan {scan_id}")
            table.add_column("field")
            table.add_column("value")
            table.add_row("Scan ID", str(scan_id))
            table.add_row("Target", target or "")
            table.add_row("Status", snapshot["status"])
            table.add_row("Current phase", snapshot.get("current_phase") or "")
            table.add_row("Current agent", snapshot.get("current_agent") or "")
            table.add_row("Current tool", snapshot.get("current_tool") or "")
            table.add_row("Progress", snapshot.get("progress_message") or "")
            table.add_row("profile", scan.profile)
            table.add_row("engagement_mode", scan.engagement_mode or "")
            table.add_row("ai_provider", scan.ai_provider or "")
            table.add_row("Started at", snapshot.get("started_at") or "")
            table.add_row("Last activity", snapshot.get("last_activity") or "")
            table.add_row("Last evidence file", snapshot.get("last_evidence_file") or "")
            table.add_row("Completed phases", ", ".join(snapshot.get("completed_phases") or []))
            table.add_row("Pending phases", ", ".join(snapshot.get("pending_phases") or []))
            table.add_row("Failed phases", ", ".join(snapshot.get("failed_phases") or []))
            table.add_row("Findings", str(snapshot.get("findings") or 0))
            table.add_row("Production readiness", readiness["status"])
            table.add_row("Readiness reason", readiness.get("reason") or "")
            table.add_row("Next recommended action", snapshot.get("next_recommended_action") or "")
            console.print(table)
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@scan_app.command("debug")
def scan_debug(scan_id: int = typer.Option(..., "--scan-id")) -> None:
    """Print scan row, process row, recent events/tool runs, and runtime log tail."""
    with session_scope() as session:
        scan = _load_scan_or_exit(session, scan_id)
        console.print(f"Scan #{scan_id}")
        console.print(
            {
                "status": scan.status,
                "current_phase": scan.current_phase,
                "current_agent": scan.current_agent,
                "current_tool": scan.current_tool,
                "progress_message": scan.progress_message,
                "last_activity_at": scan.last_activity_at,
                "scan_config": scan.scan_config,
            }
        )
        process = session.scalar(select(ScanProcess).where(ScanProcess.scan_id == scan_id).order_by(ScanProcess.id.desc()).limit(1))
        pid_alive = False
        if process and process.pid:
            try:
                os.kill(process.pid, 0)
                pid_alive = True
            except OSError:
                pid_alive = False
        console.print(f"Process: {process.status if process else 'none'} pid={process.pid if process else None} alive={pid_alive}")
        events = session.scalars(select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.id.desc()).limit(50)).all()
        console.print("Last 50 events:")
        for event in reversed(events):
            console.print(f"{event.id} {event.timestamp} {event.level} {event.event_type} phase={event.phase} tool={event.tool_name} {event.message}")
        runs = session.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id).order_by(ToolRun.id.desc()).limit(50)).all()
        console.print("Last 50 tool runs:")
        for run in reversed(runs):
            console.print(f"{run.id} {run.tool_name} {run.status} started={run.started_at} completed={run.completed_at} output={run.output}")
        log_path = get_settings().log_dir / f"scan-{scan_id}.log"
        evidence_count = session.scalar(select(func.count(Evidence.id)).where(Evidence.scan_id == scan_id)) or 0
        console.print(f"Evidence files count: {evidence_count}")
        console.print(f"Runtime log path: {log_path}")
        if log_path.exists():
            console.print("Last 100 runtime log lines:")
            for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-100:]:
                console.print(line)
        else:
            console.print("Runtime log does not exist yet.")


@auth_app.command("debug")
def auth_debug(scan_id: int = typer.Option(..., "--scan-id")) -> None:
    """Print deterministic authentication/session validation diagnostics."""
    with session_scope() as session:
        scan = _load_scan_or_exit(session, scan_id)
        console.print(f"SAIF Auth Debug - scan #{scan_id}")
        console.print(
            {
                "scan_status": scan.status,
                "current_phase": scan.current_phase,
                "execution_profile": (scan.scan_config or {}).get("execution_profile"),
                "account_source": (scan.scan_config or {}).get("account_source") or scan.auth_mode,
                "allow_account_generation": scan.allow_account_generation,
                "allow_authenticated_testing": scan.allow_authenticated_testing,
                "allow_authorization_testing": scan.allow_authorization_testing,
            }
        )
        credentials = session.scalars(select(Credential).where(Credential.project_id == scan.project_id).order_by(Credential.id)).all()
        console.print("Generated/configured users:")
        for credential in credentials:
            metadata = credential.metadata_json or {}
            if metadata.get("scan_id") == scan.id or str(credential.label).startswith("generated-"):
                console.print(
                    {
                        "label": credential.label,
                        "username": credential.username,
                        "role": credential.role,
                        "signup_status": metadata.get("status"),
                        "login_status": metadata.get("login_status"),
                    }
                )
        sessions = session.scalars(select(AuthenticatedSession).where(AuthenticatedSession.scan_id == scan_id).order_by(AuthenticatedSession.id)).all()
        console.print("Authenticated sessions:")
        for auth_session in sessions:
            metadata = auth_session.metadata_json or {}
            token_validation = metadata.get("token_validation") or {}
            token_metadata = metadata.get("token_metadata") or token_validation.get("token_metadata") or {}
            console.print(
                {
                    "label": auth_session.credential_label,
                    "username": auth_session.username,
                    "login_status": auth_session.login_status,
                    "session_status": auth_session.session_status,
                    "token_field_detected": metadata.get("token_field_name"),
                    "token_length": token_metadata.get("token_length"),
                    "jwt_shape_valid": token_metadata.get("jwt_shape_valid"),
                    "auth_header_mode": token_metadata.get("header_mode_used"),
                    "token_source": token_validation.get("token_source") or ("db_secret" if auth_session.access_token_secret else "masked_or_missing"),
                    "validation_url": token_validation.get("validation_url"),
                    "validation_status": token_validation.get("status_code"),
                    "final_reason": token_validation.get("reason"),
                    "evidence_path": token_validation.get("evidence_path"),
                }
            )
            for attempt in token_validation.get("candidates_tried") or []:
                console.print(
                    "  tried "
                    + str(
                        {
                            "endpoint": attempt.get("endpoint"),
                            "status_code": attempt.get("status_code"),
                            "body_preview": str(attempt.get("body_preview") or "")[:220],
                        }
                    )
                )
        tool_runs = session.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id, ToolRun.tool_name.in_(["account_provisioning", "login_session", "session_validation", "authenticated_crawling", "authorization_matrix", "idor_bola_bfla_planner"])).order_by(ToolRun.id.desc()).limit(30)).all()
        console.print("Recent auth tool runs:")
        for run in reversed(tool_runs):
            output = run.output or {}
            console.print(f"{run.id} {run.tool_name} status={run.status} reason={output.get('reason')}")
        log_path = get_settings().log_dir / f"scan-{scan_id}.log"
        console.print(f"Runtime log path: {log_path}")
        if log_path.exists():
            for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-80:]:
                console.print(line)


@scan_app.command("watch")
def scan_watch(scan_id: int = typer.Option(..., "--scan-id"), interval: int = typer.Option(2, "--interval")) -> None:
    """Watch scan progress, latest tool runs, evidence, events, and AI calls."""
    try:
        while True:
            with session_scope() as session:
                snapshot = watch_snapshot(session, scan_id)
            console.clear()
            console.print_json(data=snapshot)
            time.sleep(max(1, interval))
    except KeyboardInterrupt:
        console.print("watch stopped")
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@scan_app.command("list")
def scan_list() -> None:
    """List historical pentest scans."""
    try:
        with session_scope() as session:
            scans = session.scalars(select(Scan).order_by(Scan.id.desc())).all()
            table = Table(title="SAIF Scans")
            for column in ["scan id", "project", "target", "status", "profile", "started", "completed", "findings", "production readiness"]:
                table.add_column(column)
            for scan in scans:
                summary = scan_summary(session, scan)
                table.add_row(
                    str(summary["scan_id"]),
                    str(summary.get("project") or ""),
                    str(summary.get("target") or ""),
                    str(summary.get("status") or ""),
                    str(summary.get("profile") or ""),
                    str(summary.get("started_at") or ""),
                    str(summary.get("completed_at") or ""),
                    str(summary.get("findings_count") or 0),
                    str((summary.get("production_readiness") or {}).get("status") or ""),
                )
            console.print(table)
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@scan_app.command("show")
def scan_show(scan_id: int = typer.Option(..., "--scan-id")) -> None:
    """Show scan details, phases, findings, and resume options."""
    try:
        with session_scope() as session:
            scan = _load_scan_or_exit(session, scan_id)
            phases = sync_scan_phases(session, scan)
            summary = scan_summary(session, scan)
            console.print_json(data=summary)
            phase_table = Table(title=f"Scan {scan_id} Phases")
            for column in ["phase", "status", "started", "completed", "agent", "reason"]:
                phase_table.add_column(column)
            for phase in phases:
                phase_table.add_row(
                    phase.phase_name,
                    phase.status,
                    phase.started_at.isoformat() if phase.started_at else "",
                    phase.completed_at.isoformat() if phase.completed_at else "",
                    phase.agent_name or "",
                    phase.error_message or "",
                )
            console.print(phase_table)
            findings = session.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)).all()
            finding_table = Table(title="Finding Index")
            for column in ["id", "title", "severity", "status", "confidence", "endpoint"]:
                finding_table.add_column(column)
            for finding in findings:
                finding_table.add_row(finding.finding_uid or str(finding.id), finding.title, finding.severity, finding.status, finding.confidence or "", finding.affected_endpoint or "")
            console.print(finding_table)
            incomplete = [phase.phase_name for phase in phases if phase.status not in {RunStatus.COMPLETED.value, RunStatus.FINDING_CREATED.value, RunStatus.NOT_APPLICABLE.value}]
            console.print(f"Resume options: {', '.join(incomplete[:8]) if incomplete else 'none'}")
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@scan_app.command("continue")
def scan_continue(
    scan_id: int = typer.Option(..., "--scan-id"),
    phase: str = typer.Option(..., "--phase"),
    rerun: bool = typer.Option(False, "--rerun"),
    full: bool = typer.Option(False, "--full"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Continue a previous scan from a selected phase without rerunning completed tools by default."""
    try:
        with session_scope() as session:
            scan = _load_scan_or_exit(session, scan_id)
            target = scan_target(session, scan)
            if not target:
                console.print("ERROR: no target found for scan project.")
                raise typer.Exit(code=1)
            tools = tools_for_phase(phase)
            if full and phase == "account_provisioning":
                tools = [
                    "account_provisioning",
                    "login_session",
                    "token_analysis",
                    "authenticated_crawling",
                    "authorization_matrix",
                    "idor_bola_bfla_planner",
                    "jwt_adaptive",
                    "input_validation_planner",
                    "xss_adaptive",
                    "sqli_adaptive",
                    "ssrf_adaptive",
                    "business_logic_planner",
                ]
            if not tools and phase == "reporting":
                mark_phase(session, scan, "reporting", RunStatus.RUNNING.value)
                json_path = generate_report(session, None, "json", scan_id=scan.id)
                html_path = generate_report(session, None, "html", scan_id=scan.id)
                mark_phase(session, scan, "reporting", RunStatus.COMPLETED.value, {"json": str(json_path), "html": str(html_path)})
                console.print(f"JSON: {json_path}")
                console.print(f"HTML: {html_path}")
                return
            if not tools:
                console.print(f"ERROR: phase {phase!r} is not executable yet.")
                raise typer.Exit(code=1)
            scan.status = ScanStatus.RUNNING.value
            scan.current_phase = phase
            mark_phase(session, scan, phase, RunStatus.RUNNING.value)
            emit_progress(session, scan, f"status=running phase={phase}", phase=phase, agent=prompt_runner._agent_for_tool(tools[0]) if tools else None, tool=tools[0] if tools else None, event_type="phase_started", console=console, live=True)
            done = completed_tools(session, scan_id)
            prompt = f"continue {phase}. target: {target}"
            parsed = parse_prompt(prompt)
            runner = _phase_runner_map()
            executed = []
            for tool in tools:
                if tool in done and not rerun:
                    executed.append({"tool": tool, "status": "already_completed"})
                    continue
                if tool not in runner:
                    executed.append({"tool": tool, "status": RunStatus.NOT_APPLICABLE.value, "reason": "no executor registered"})
                    continue
                agent_name = prompt_runner._agent_for_tool(tool)
                emit_progress(session, scan, "agent started", phase=prompt_runner._phase_for_tool(tool), agent=agent_name, tool=tool, event_type="agent_started", console=console, live=debug)
                emit_progress(session, scan, "started", phase=prompt_runner._phase_for_tool(tool), agent=agent_name, tool=tool, event_type="tool_started", console=console, live=True)
                with prompt_runner.heartbeat(scan.id, phase=prompt_runner._phase_for_tool(tool), agent=agent_name, tool=tool, console=console, live=debug):
                    result = runner[tool](session, scan, target, prompt, parsed)
                emit_progress(session, scan, f"completed status={result.get('status')} evidence={result.get('evidence_path')}", phase=prompt_runner._phase_for_tool(tool), agent=agent_name, tool=tool, event_type="tool_completed", context={"status": result.get("status"), "evidence_path": result.get("evidence_path")}, console=console, live=True)
                emit_progress(session, scan, "agent completed", phase=prompt_runner._phase_for_tool(tool), agent=agent_name, tool=tool, event_type="agent_completed", context={"status": result.get("status")}, console=console, live=debug)
                executed.append(result)
            status = RunStatus.FINDING_CREATED.value if any(item.get("status") == RunStatus.FINDING_CREATED.value for item in executed) else RunStatus.EXECUTION_ERROR.value if any(item.get("status") == RunStatus.EXECUTION_ERROR.value for item in executed) else RunStatus.COMPLETED.value
            mark_phase(session, scan, phase, status, {"executed": executed, "rerun": rerun})
            sync_scan_phases(session, scan)
            scan.status = ScanStatus.READY.value
            emit_progress(session, scan, f"phase={phase} completed status={status}", phase=phase, event_type="phase_completed", console=console, live=True)
            console.print_json(data={"scan_id": scan_id, "phase": phase, "status": status, "executed": executed})
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@scan_app.command("report")
def scan_report(scan_id: int = typer.Option(..., "--scan-id"), format_: str = typer.Option("html", "--format")) -> None:
    """Generate a report for a specific scan."""
    if format_ not in {"json", "html"}:
        raise typer.BadParameter("Report format must be json or html")
    try:
        with session_scope() as session:
            path = generate_report(session, None, format_, scan_id=scan_id)
            console.print(f"[green]report generated[/green] {Path(path)}")
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@scan_app.command("retest")
def scan_retest(scan_id: int = typer.Option(..., "--scan-id"), only_open_findings: bool = typer.Option(False, "--only-open-findings")) -> None:
    """Queue retest workflow for scan findings."""
    try:
        with session_scope() as session:
            scan = _load_scan_or_exit(session, scan_id)
            stmt = select(Finding).where(Finding.scan_id == scan_id)
            findings = session.scalars(stmt).all()
            if only_open_findings:
                findings = [finding for finding in findings if finding.status not in {"closed", "fixed", "false_positive", "accepted_risk"}]
            for finding in findings:
                finding.status = "retest_required"
                finding.retest_status = "queued"
            emit_progress(
                session,
                scan,
                f"retest queued for {len(findings)} finding(s)",
                event_type="scan_retest_queued",
                context={"finding_ids": [finding.id for finding in findings], "only_open_findings": only_open_findings},
                console=console,
                live=True,
            )
            console.print_json(data={"scan_id": scan_id, "retest_queued": len(findings), "finding_ids": [finding.id for finding in findings]})
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@finding_app.command("retest")
def finding_retest(finding_id: int = typer.Option(..., "--finding-id")) -> None:
    """Queue a single finding for retest."""
    try:
        with session_scope() as session:
            finding = session.get(Finding, finding_id)
            if not finding:
                console.print(f"ERROR: finding {finding_id} was not found.")
                raise typer.Exit(code=1)
            finding.status = "retest_required"
            finding.retest_status = "queued"
            scan = session.get(Scan, finding.scan_id)
            if scan:
                emit_progress(
                    session,
                    scan,
                    f"finding {finding_id} retest queued",
                    event_type="finding_retest_queued",
                    context={"finding_id": finding_id, "finding_uid": finding.finding_uid},
                    console=console,
                    live=True,
                )
            console.print_json(data={"finding_id": finding_id, "status": finding.status, "retest_status": finding.retest_status})
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@finding_app.command("close")
def finding_close(
    finding_id: int = typer.Option(..., "--finding-id"),
    closure_evidence: str | None = typer.Option(None, "--closure-evidence"),
) -> None:
    """Close a finding after retest or accepted workflow evidence is recorded."""
    try:
        with session_scope() as session:
            finding = session.get(Finding, finding_id)
            if not finding:
                console.print(f"ERROR: finding {finding_id} was not found.")
                raise typer.Exit(code=1)
            finding.status = "closed"
            finding.retest_status = finding.retest_status or "closed_by_tester"
            finding.closure_evidence_path = closure_evidence or finding.closure_evidence_path
            finding.fixed_at = datetime.now(timezone.utc)
            scan = session.get(Scan, finding.scan_id)
            if scan:
                emit_progress(
                    session,
                    scan,
                    f"finding {finding_id} closed",
                    event_type="finding_closed",
                    context={"finding_id": finding_id, "closure_evidence": closure_evidence},
                    console=console,
                    live=True,
                )
            console.print_json(data={"finding_id": finding_id, "status": finding.status, "closure_evidence_path": finding.closure_evidence_path})
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


@fix_app.command("suggest")
def fix_suggest(finding_id: int = typer.Option(..., "--finding-id"), source_path: str = typer.Option(..., "--source-path")) -> None:
    """Generate source-assisted remediation guidance without modifying code."""
    suggestion = _source_fix_suggestion(finding_id, source_path, apply_patch=False)
    console.print_json(data=suggestion)


@fix_app.command("patch")
def fix_patch(
    finding_id: int = typer.Option(..., "--finding-id"),
    source_path: str = typer.Option(..., "--source-path"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    apply: bool = typer.Option(False, "--apply"),
) -> None:
    """Prepare a remediation patch workflow. Source modification requires --apply and a concrete patch."""
    if dry_run and apply:
        raise typer.BadParameter("Use either --dry-run or --apply, not both.")
    suggestion = _source_fix_suggestion(finding_id, source_path, apply_patch=apply)
    console.print_json(data=suggestion)


def _source_fix_suggestion(finding_id: int, source_path: str, apply_patch: bool) -> dict:
    path = Path(source_path)
    if not path.exists():
        console.print(f"ERROR: source path does not exist: {source_path}")
        raise typer.Exit(code=1)
    try:
        with session_scope() as session:
            finding = session.get(Finding, finding_id)
            if not finding:
                console.print(f"ERROR: finding {finding_id} was not found.")
                raise typer.Exit(code=1)
            payload = {
                "finding_id": finding_id,
                "finding_uid": finding.finding_uid,
                "title": finding.title,
                "source_path": str(path),
                "mode": "white_box_source_assisted",
                "applied": False,
                "status": "manual_review_required",
                "remediation": finding.remediation or _default_remediation_for_finding(finding),
                "secure_code_guidance": finding.secure_code_guidance or _default_secure_code_guidance_for_finding(finding),
                "next_steps": [
                    "Review the affected endpoint and input handling in the source tree.",
                    "Create a small patch with unit/integration tests.",
                    "Run SAIF retest after the application is redeployed.",
                ],
            }
            if apply_patch:
                payload["status"] = "manual_confirmation_required"
                payload["reason"] = "No deterministic patch was generated for this finding. SAIF did not modify source files."
            suggestion_dir = Path(".saif") / "fix-suggestions"
            suggestion_dir.mkdir(parents=True, exist_ok=True)
            suggestion_path = suggestion_dir / f"finding-{finding_id}-suggestion.json"
            suggestion_path.write_text(__import__("json").dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            payload["suggestion_path"] = str(suggestion_path)
            return payload
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)
    raise typer.Exit(code=1)


def _default_remediation_for_finding(finding: Finding) -> str:
    if finding.vulnerability_type:
        return f"Review and remediate the {finding.vulnerability_type} weakness using framework-supported validation, authorization, and logging controls."
    return "Review the affected endpoint, add the missing control, and retest the exact reproduction steps before closure."


def _default_secure_code_guidance_for_finding(finding: Finding) -> str:
    if (finding.vulnerability_type or "").lower() in {"bola", "idor", "authorization"}:
        return "Enforce object-level authorization on the server for every object access using the authenticated subject and role, not client-supplied identifiers."
    if (finding.vulnerability_type or "").lower() in {"xss", "input_validation"}:
        return "Validate inputs by type and context, encode output for the sink, and keep unsafe HTML/JavaScript construction behind reviewed helpers."
    if (finding.vulnerability_type or "").lower() in {"sqli", "sql_injection"}:
        return "Use parameterized queries or ORM-bound values exclusively and avoid constructing SQL with untrusted input."
    return "Use centralized validation, authorization, error handling, and secure defaults so the same control is applied across similar endpoints."


def _phase_runner_map():
    return {
        "auth_session_mapping": prompt_runner._run_auth_session_mapping,
        "account_provisioning": prompt_runner._run_account_provisioning,
        "login_session": prompt_runner._run_login_session,
        "token_analysis": prompt_runner._run_token_analysis,
        "authenticated_crawling": prompt_runner._run_authenticated_crawling,
        "authorization_matrix": prompt_runner._run_authorization_matrix,
        "idor_bola_bfla_planner": prompt_runner._run_idor_bola_bfla_planner,
        "input_validation_planner": prompt_runner._run_input_validation_planner,
        "xss_adaptive": prompt_runner._run_xss_adaptive,
        "sqli_adaptive": prompt_runner._run_sqli_adaptive,
        "ssrf_adaptive": prompt_runner._run_ssrf_adaptive,
        "jwt_adaptive": prompt_runner._run_jwt_adaptive,
        "business_logic_planner": prompt_runner._run_business_logic_planner,
        "openapi_discovery": prompt_runner._run_openapi_discovery,
        "api_profile_probe": prompt_runner._run_api_profile_probe,
        "api_method_probe": prompt_runner._run_api_method_probe,
        "ffuf_api_paths": prompt_runner._run_ffuf_api_paths,
        "gobuster_api_paths": prompt_runner._run_gobuster_api_paths,
    }


@report_app.command("generate")
def report_generate(
    project: str | None = typer.Option(None, "--project"),
    scan_id: int | None = typer.Option(None, "--scan-id"),
    format_: str = typer.Option("json", "--format"),
) -> None:
    """Generate a report for the latest project scan."""
    project = project or get_settings().demo_project_name
    if format_ not in {"json", "html"}:
        raise typer.BadParameter("Report format must be json or html; docx/pdf are planned")
    try:
        with session_scope() as session:
            path = generate_report(session, project if scan_id is None else None, format_, scan_id=scan_id)
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)
    console.print(f"[green]report generated[/green] {Path(path)}")


@dashboard_app.command("start")
def dashboard_start(
    host: str | None = typer.Option(None, "--host"),
    port: int | None = typer.Option(None, "--port"),
    allow_remote: bool | None = typer.Option(None, "--allow-remote/--no-allow-remote"),
    no_auth_explicitly_allowed: bool | None = typer.Option(None, "--no-auth-explicitly-allowed/--require-dashboard-auth"),
) -> None:
    """Start local dashboard and API server."""
    try:
        run_dashboard(host, port, allow_remote=allow_remote, no_auth_explicitly_allowed=no_auth_explicitly_allowed)
    except RuntimeError as exc:
        console.print(f"ERROR: {exc}")
        raise typer.Exit(code=1) from exc


@dashboard_app.command("status")
def dashboard_status() -> None:
    """Show local dashboard process status."""
    console.print_json(data=dashboard_status_payload())


@dashboard_app.command("stop")
def dashboard_stop() -> None:
    """Stop dashboard process started from this workspace."""
    console.print_json(data=stop_dashboard())


@app.command("run-demo")
def run_demo(
    target: str | None = typer.Option(None, "--target"),
    target_source: str | None = typer.Option(None, "--target-source", hidden=True),
    profile: str = typer.Option("auto", "--profile"),
    mode: str | None = typer.Option(None, "--mode"),
    credentials: str | None = typer.Option(None, "--credentials"),
    source_path: str | None = typer.Option(None, "--source-path"),
    ai: str = typer.Option("ollama", "--ai"),
    enumeration_only: bool = typer.Option(False, "--enumeration-only"),
    full: bool = typer.Option(False, "--full"),
    auth: bool = typer.Option(False, "--auth"),
    vuln_test: bool = typer.Option(False, "--vuln-test"),
    no_destructive_methods: bool = typer.Option(False, "--no-destructive-methods"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Run the local demo flow against the configured existing target."""
    settings = get_settings()
    try:
        resolved = resolve_target(cli_target=target)
        source = target_source or _source_from_cli_arg(target)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    run_doctor(resolved.url, console=console)
    initialize_workspace()
    _upgrade_database_or_exit()
    engagement_mode = _resolve_engagement_mode(mode, credentials, source_path)
    if credentials:
        os.environ["SAIF_CREDENTIALS_PATH"] = credentials
    prompt = _scan_start_prompt(resolved.url, profile, enumeration_only, full, auth, vuln_test, no_destructive_methods, engagement_mode)
    parsed_intent = parse_prompt(prompt)
    selected_tools = select_tools(parsed_intent, resolved.url)
    try:
        with session_scope() as session:
            seed_foundation(session, "api-security" if profile == "auto" else profile)
            project, _ = upsert_project_target(session, settings.demo_project_name, resolved.url, console=console)
            ai_context = _build_ai_or_record_failed(session, settings.demo_project_name, prompt, resolved.url, parsed_intent, selected_tools, debug=debug)
            if ai_context is None:
                ai_failed = True
                scan_id = 0
                tool_results = []
                json_path = None
                html_path = None
            else:
                ai_failed = False
                scan, selected_tools, tool_results, parsed_intent, _ = run_prompt_scan(session, project, resolved.url, prompt, ai_context, console=console, target_source=source, debug_live=debug, engagement_mode=engagement_mode, credentials_path=credentials, source_path=source_path)
                scan_id = scan.id
                json_path = generate_report(session, settings.demo_project_name, "json")
                html_path = generate_report(session, settings.demo_project_name, "html")
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)
    if ai_failed:
        raise typer.Exit(code=1)
    unavailable_tools = [{"tool": item["tool"], "status": item.get("status"), "reason": item.get("reason")} for item in tool_results if item.get("reason")]
    _print_run_summary(
        project=settings.demo_project_name,
        target=resolved.url,
        target_source=source,
        mode="default",
        tools=selected_tools,
        scan_id=scan_id,
        parsed_intent=parsed_intent,
        unavailable_tools=unavailable_tools,
        json_path=json_path,
        html_path=html_path,
    )


@app.command("prompt")
def prompt_command(
    prompt: str = typer.Argument(...),
    target: str | None = typer.Option(None, "--target"),
    target_source: str | None = typer.Option(None, "--target-source", hidden=True),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Run a manual prompt flow."""
    settings = get_settings()
    try:
        resolved = resolve_target(cli_target=target, prompt_target=extract_target(prompt))
        source = target_source or ("cli-arg" if target else ("prompt" if extract_target(prompt) else "env"))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    run_doctor(resolved.url, console=console)
    initialize_workspace()
    _upgrade_database_or_exit()
    try:
        with session_scope() as session:
            seed_foundation(session)
            project, _ = upsert_project_target(session, settings.demo_project_name, resolved.url, console=console)
            parsed_intent = parse_prompt(prompt)
            if not any(parsed_intent.values()):
                parsed_intent["default_enumeration"] = True
            selected_tools = select_tools(parsed_intent, resolved.url)
            ai_context = _build_ai_or_record_failed(session, settings.demo_project_name, prompt, resolved.url, parsed_intent, selected_tools, debug=debug)
            if ai_context is None:
                ai_failed = True
                scan_id = 0
                tool_results = []
                json_path = None
                html_path = None
            else:
                ai_failed = False
                scan, selected_tools, tool_results, parsed_intent, _ = run_prompt_scan(session, project, resolved.url, prompt, ai_context, console=console, target_source=source, debug_live=debug)
                scan_id = scan.id
                json_path = generate_report(session, settings.demo_project_name, "json")
                html_path = generate_report(session, settings.demo_project_name, "html")
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)
    if ai_failed:
        raise typer.Exit(code=1)
    unavailable_tools = [
        {"tool": item["tool"], "status": item.get("status"), "reason": item.get("reason")}
        for item in tool_results
        if item.get("reason")
    ]
    _print_run_summary(
        project=settings.demo_project_name,
        target=resolved.url,
        target_source=source,
        mode="default" if parsed_intent.get("default_enumeration") else "manual",
        tools=selected_tools,
        scan_id=scan_id,
        parsed_intent=parsed_intent,
        unavailable_tools=unavailable_tools,
        json_path=json_path,
        html_path=html_path,
    )


@logs_app.command("tail")
def logs_tail(scan_id: int = typer.Option(..., "--scan-id"), follow: bool = typer.Option(False, "--follow"), lines: int = typer.Option(50, "--lines")) -> None:
    """Tail scan events from the database and runtime log file."""
    seen_event_id = 0
    path = get_settings().log_dir / f"scan-{scan_id}.log"
    try:
        while True:
            with session_scope() as session:
                events = (
                    session.scalars(
                        select(ScanEvent)
                        .where(ScanEvent.scan_id == scan_id, ScanEvent.id > seen_event_id)
                        .order_by(ScanEvent.id.desc() if seen_event_id == 0 else ScanEvent.id)
                        .limit(lines if seen_event_id == 0 else 500)
                    )
                    .all()
                )
                if seen_event_id == 0:
                    events = list(reversed(events))
                for event in events:
                    seen_event_id = max(seen_event_id, event.id)
                    console.print(
                        f"{event.timestamp.isoformat()} {event.level} scan={event.scan_id} "
                        f"phase={event.phase or '-'} agent={event.agent_name or '-'} tool={event.tool_name or '-'} "
                        f"{event.event_type}: {event.message}",
                        highlight=False,
                    )
            if not follow:
                if path.exists():
                    console.print(f"Runtime log: {path}")
                return
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("log tail stopped")
    except ProgrammingError as exc:
        _handle_db_programming_error(exc)


if __name__ == "__main__":
    app()
