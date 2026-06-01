import importlib.metadata
import os
import shutil
import sys

import httpx
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from rich.console import Console
from rich.table import Table
from sqlalchemy import create_engine, inspect, text

from saif.config import get_settings
from saif.db.base import Base
from saif.db import models  # noqa: F401
from saif.services.tool_manager import check_runtime_tools
from saif.services.payloads import payload_library_status


def _status(ok: bool) -> str:
    return "ok" if ok else "missing"


CORE_SCHEMA_TABLES = {
    "projects",
    "targets",
    "scans",
    "agents",
    "test_cases",
    "test_runs",
    "tool_runs",
    "requests",
    "responses",
    "evidence",
    "findings",
    "credentials",
    "sessions",
    "authenticated_sessions",
    "reports",
    "logs",
    "discovered_assets",
    "discovered_endpoints",
    "discovered_parameters",
    "discovered_auth_flows",
    "discovered_tokens",
    "discovered_roles",
    "discovered_objects",
    "discovered_tenants",
    "authorization_matrix",
    "pipeline_artifacts",
    "tool_registry",
    "agent_jobs",
    "ai_call_runs",
    "scan_events",
    "scan_phases",
    "scan_processes",
    "scan_test_plan",
    "payload_attempts",
    "application_profiles",
    "discovered_services",
    "discovered_api_specs",
    "discovered_auth_mechanisms",
    "discovered_session_mechanisms",
    "discovered_tenants",
}


def validate_db_schema(engine) -> list[dict]:
    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names())
    mismatches: list[dict] = []
    for table_name, table in Base.metadata.tables.items():
        if table_name not in CORE_SCHEMA_TABLES:
            continue
        expected_columns = set(table.columns.keys())
        if table_name not in actual_tables:
            mismatches.append({"table": table_name, "missing_table": True, "missing_columns": sorted(expected_columns)})
            continue
        actual_columns = {column["name"] for column in inspector.get_columns(table_name)}
        missing_columns = sorted(expected_columns - actual_columns)
        if missing_columns:
            mismatches.append({"table": table_name, "missing_table": False, "missing_columns": missing_columns})
    return mismatches


def run_doctor(target: str | None = None, console: Console | None = None) -> bool:
    console = console or Console()
    settings = get_settings()
    rows: list[tuple[str, str, str]] = []

    rows.append(("Python version", "ok", sys.version.split()[0]))
    rows.append(("virtual environment", _status(sys.prefix != sys.base_prefix), sys.prefix))

    try:
        version = importlib.metadata.version("saif")
        rows.append(("SAIF package installed", "ok", version))
    except importlib.metadata.PackageNotFoundError:
        rows.append(("SAIF package installed", "missing", "run ./saif.sh setup"))

    rows.append((".env loaded", _status(os.path.exists(".env")), ".env" if os.path.exists(".env") else "not found"))
    rows.append(("DATABASE_URL configured", _status(bool(settings.database_url)), settings.database_url or "not set"))

    try:
        engine = create_engine(settings.database_url, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("select 1"))
        rows.append(("PostgreSQL reachable", "ok", "connected"))
    except Exception as exc:
        rows.append(("PostgreSQL reachable", "missing", str(exc)))

    try:
        alembic_cfg = Config("alembic.ini")
        script = ScriptDirectory.from_config(alembic_cfg)
        engine = create_engine(settings.database_url, pool_pre_ping=True)
        with engine.connect() as conn:
            current = MigrationContext.configure(conn).get_current_revision()
        head = script.get_current_head()
        status = "ok" if current == head else "missing"
        rows.append(("Alembic migration status", status, f"current {current or 'none'} / head {head}"))
    except Exception as exc:
        rows.append(("Alembic migration status", "missing", str(exc)))

    schema_mismatches: list[dict] = []
    try:
        engine = create_engine(settings.database_url, pool_pre_ping=True)
        schema_mismatches = validate_db_schema(engine)
        if schema_mismatches:
            missing_column_count = sum(len(item["missing_columns"]) for item in schema_mismatches)
            detail = "; ".join(
                f"table {item['table']} missing columns: {', '.join(item['missing_columns'])}"
                if not item["missing_table"]
                else f"missing table {item['table']}"
                for item in schema_mismatches[:5]
            )
            if len(schema_mismatches) > 5:
                detail = f"{detail}; plus {len(schema_mismatches) - 5} more table(s)"
            detail = f"{missing_column_count} missing column(s): {detail}"
            rows.append(("DB schema validation", "missing", detail))
        else:
            rows.append(("DB schema validation", "ok", "model columns match database"))
    except Exception as exc:
        rows.append(("DB schema validation", "missing", str(exc)))

    try:
        url = f"{settings.ollama_base_url.rstrip('/')}/api/tags"
        response = httpx.get(url, timeout=3)
        reachable = response.status_code < 400
        rows.append(
            (
                "Ollama reachable",
                "ok" if reachable else "missing",
                url if reachable else f"{url} -> HTTP {response.status_code}: {response.text}",
            )
        )
        if response.status_code >= 400:
            installed_models = []
        else:
            installed_models = sorted(item.get("name") for item in response.json().get("models", []) if item.get("name"))
        model_status = "ok" if settings.ollama_model in installed_models else "failed"
        rows.append(("Ollama model available", model_status, ""))
        rows.append(("configured model", "ok", settings.ollama_model))
        rows.append(("installed models", "ok" if installed_models else "missing", ", ".join(installed_models) if installed_models else "(none)"))
    except Exception as exc:
        rows.append(("Ollama reachable", "missing", f"{settings.ollama_base_url.rstrip('/')}/api/tags -> {exc}"))
        rows.append(("Ollama model available", "failed", "could not load /api/tags"))
        rows.append(("configured model", "ok", settings.ollama_model))
        rows.append(("installed models", "missing", "(unknown)"))

    tool_status = check_runtime_tools()
    for tool, installed in sorted(tool_status.items()):
        detail = "Python package installed" if tool == "httpx" and installed else (shutil.which(tool) or "not found")
        rows.append((f"{tool} installed", _status(installed), detail))

    if target:
        try:
            response = httpx.get(target, follow_redirects=True, timeout=5)
            rows.append(("target reachable", "ok", f"{target} -> HTTP {response.status_code}"))
        except Exception as exc:
            rows.append(("target reachable", "missing", str(exc)))
    else:
        rows.append(("target reachable", "not_applicable", "no runtime target provided"))

    table = Table(title="SAIF Doctor")
    table.add_column("check")
    table.add_column("status")
    table.add_column("detail")
    for row in rows:
        table.add_row(*row)
    console.print(table)
    installed = sorted(name for name, ok in tool_status.items() if ok)
    missing = sorted(name for name, ok in tool_status.items() if not ok)
    console.print("Tool summary:")
    console.print(f"Installed tools ({len(installed)}): {', '.join(installed) if installed else 'none'}")
    console.print(f"Missing tools ({len(missing)}): {', '.join(missing) if missing else 'none'}")
    if schema_mismatches:
        console.print("DB schema mismatch:")
        for item in schema_mismatches:
            if item["missing_table"]:
                console.print(f"table {item['table']} missing")
            else:
                console.print(f"table {item['table']} missing columns: {', '.join(item['missing_columns'])}")
        console.print("Fix: ./saif.sh init-db")
    payload_status = payload_library_status()
    console.print("Payload libraries:")
    for category in ["xss", "sqli", "ssrf", "lfi_path_traversal", "open_redirect", "jwt"]:
        item = payload_status.get(category, {})
        console.print(f"- SecLists {category}: {'ok' if item.get('seclists_available') else 'missing'}")
        console.print(f"- SAIF fallback {category}: {'ok' if item.get('fallback_available') else 'missing'}")
        console.print(f"- Active {category} payload source: {item.get('active_path') or 'missing'}")
    return all(status in {"ok", "not_applicable"} for _, status, _ in rows)
