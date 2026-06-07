from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone

from saif.config import get_settings


PID_FILE = Path(".saif/dashboard.pid")
STATE_FILE = Path(".saif/dashboard.json")
LOG_FILE = Path(".saif/logs/dashboard.log")


def run_dashboard(
    host: str | None = None,
    port: int | None = None,
    *,
    allow_remote: bool | None = None,
    no_auth_explicitly_allowed: bool | None = None,
) -> None:
    settings = get_settings()
    host = host or settings.dashboard_host
    port = port or settings.dashboard_port
    allow_remote = settings.dashboard_allow_remote if allow_remote is None else allow_remote
    no_auth_explicitly_allowed = settings.dashboard_no_auth_explicitly_allowed if no_auth_explicitly_allowed is None else no_auth_explicitly_allowed
    if host == "0.0.0.0" and not allow_remote:
        raise RuntimeError("Refusing to bind dashboard to 0.0.0.0 without --allow-remote or SAIF_DASHBOARD_ALLOW_REMOTE=true")
    if host == "0.0.0.0" and not settings.dashboard_password and not no_auth_explicitly_allowed:
        raise RuntimeError("Refusing remote dashboard without SAIF_DASHBOARD_PASSWORD unless --no-auth-explicitly-allowed is set")
    port_owner = _port_owner(port)
    if port_owner.get("listening"):
        status = dashboard_status(host, port)
        if status.get("running") and status.get("pid") == port_owner.get("pid"):
            _log_dashboard("already_running", {"host": host, "port": port, "pid": status.get("pid")})
            print(f"SAIF dashboard already running PID {status.get('pid')}", flush=True)
            _print_dashboard_urls(host, port)
            return
        raise RuntimeError(
            f"Dashboard port {port} is already in use by PID {port_owner.get('pid')} "
            f"command={port_owner.get('command') or 'unknown'}"
        )
    if host == "0.0.0.0":
        print("WARNING: Dashboard is bound to remote interface. Restrict network access.", flush=True)
    try:
        import uvicorn
        from saif.dashboard.app import create_app
    except ImportError as exc:
        _log_dashboard("startup_failed", {"host": host, "port": port, "error": str(exc), "traceback": traceback.format_exc()})
        raise RuntimeError("Dashboard dependencies are missing. Run: ./saif.sh setup") from exc

    try:
        dashboard_app = create_app()
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
        _write_state(host, port, os.getpid(), None)
        _log_dashboard("startup", {"host": host, "port": port, "pid": os.getpid(), "bind_address": f"{host}:{port}", "db": _db_status()})
        print(f"SAIF dashboard PID {os.getpid()}", flush=True)
        _print_dashboard_urls(host, port)
        uvicorn.run(dashboard_app, host=host, port=port, log_level="info", access_log=settings.dashboard_access_log)
    except Exception as exc:
        _write_state(host, port, os.getpid(), str(exc))
        _log_dashboard("startup_failed", {"host": host, "port": port, "pid": os.getpid(), "error": str(exc), "traceback": traceback.format_exc()})
        raise
    finally:
        _log_dashboard("shutdown", {"host": host, "port": port, "pid": os.getpid()})


def dashboard_status(host: str | None = None, port: int | None = None) -> dict:
    settings = get_settings()
    host = host or _state().get("host") or settings.dashboard_host
    port = int(port or _state().get("port") or settings.dashboard_port)
    owner = _port_owner(port)
    state = _state()
    health_url = f"http://127.0.0.1:{port}/health"
    status = {
        "running": False,
        "status": "stopped",
        "host": host,
        "port": port,
        "pid": None,
        "bind_address": f"{host}:{port}",
        "health_url": health_url,
        "last_error": state.get("last_error"),
        "port_listening": bool(owner.get("listening")),
        "port_owner": owner,
    }
    if not PID_FILE.exists():
        if owner.get("listening"):
            status.update({"status": "occupied_by_unknown_process"})
        return status
    pid_text = PID_FILE.read_text(encoding="utf-8").strip()
    try:
        pid = int(pid_text)
    except ValueError:
        status.update({"status": "unknown", "pid": pid_text})
        return status
    if _pid_running(pid):
        status.update({"running": True, "status": "running", "pid": pid})
        return status
    status.update({"status": "stale_pid", "pid": pid})
    return status


def stop_dashboard() -> dict:
    status = dashboard_status()
    pid = status.get("pid")
    if status["status"] != "running" or not isinstance(pid, int):
        if status["status"] == "stale_pid":
            try:
                PID_FILE.unlink()
            except OSError:
                pass
            return {"status": "stale_pid_removed", "pid": pid}
        return status
    import os
    import signal

    os.kill(pid, signal.SIGTERM)
    released = _wait_for_port_release(int(status.get("port") or get_settings().dashboard_port), timeout_seconds=10)
    owner = _port_owner(int(status.get("port") or get_settings().dashboard_port))
    if released:
        try:
            PID_FILE.unlink()
        except OSError:
            pass
        _log_dashboard("shutdown_requested", {"pid": pid, "port_released": True})
        return {"status": "stopped", "pid": pid, "port_released": True}
    _log_dashboard("shutdown_incomplete", {"pid": pid, "port_released": False, "port_owner": owner})
    return {"status": "still_listening", "pid": pid, "port_released": False, "port_owner": owner}


def _pid_running(pid: int) -> bool:
    import os

    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _port_is_occupied(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.25)
        return probe.connect_ex(("127.0.0.1", int(port))) == 0


def _port_owner(port: int) -> dict:
    listening = _port_is_occupied(port)
    result = {"listening": listening, "pid": None, "command": None}
    if not listening:
        return result
    if os.name == "nt":
        try:
            output = subprocess.check_output(["netstat", "-ano", "-p", "tcp"], text=True, errors="ignore")
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
                    local = parts[1]
                    if local.rsplit(":", 1)[-1] == str(port):
                        pid = int(parts[-1])
                        result["pid"] = pid
                        result["command"] = _command_for_pid(pid)
                        return result
        except Exception:
            return result
    return result


def _command_for_pid(pid: int) -> str | None:
    if os.name == "nt":
        try:
            command = [
                "powershell",
                "-NoProfile",
                "-Command",
                f"(Get-CimInstance Win32_Process -Filter \"ProcessId={int(pid)}\").CommandLine",
            ]
            return subprocess.check_output(command, text=True, errors="ignore", timeout=3).strip() or None
        except Exception:
            return None
    try:
        return subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True, timeout=3).strip() or None
    except Exception:
        return None


def _wait_for_port_release(port: int, timeout_seconds: int) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if not _port_is_occupied(port):
            return True
        time.sleep(0.25)
    return not _port_is_occupied(port)


def _write_state(host: str, port: int, pid: int, last_error: str | None) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"host": host, "port": port, "pid": pid, "last_error": last_error, "updated_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")


def _state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8")) if STATE_FILE.exists() else {}
    except Exception:
        return {}


def _log_dashboard(event: str, payload: dict) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    line = {"time": datetime.now(timezone.utc).isoformat(), "event": event, **payload}
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, sort_keys=True, default=str) + "\n")


def _db_status() -> str:
    try:
        from sqlalchemy import text
        from saif.db import session_scope

        with session_scope() as session:
            session.execute(text("select 1"))
        return "ok"
    except Exception as exc:
        _log_dashboard("db_check_failed", {"error": str(exc)})
        return "failed"


def _print_dashboard_urls(host: str, port: int) -> None:
    print("Dashboard URL:", flush=True)
    print(f"- http://127.0.0.1:{port}", flush=True)
    if host == "0.0.0.0":
        wsl_ip = _wsl_ip()
        if wsl_ip:
            print(f"- http://{wsl_ip}:{port}", flush=True)


def _wsl_ip() -> str | None:
    try:
        output = subprocess.check_output(["hostname", "-I"], text=True, timeout=2).strip()
        for item in output.split():
            if item and ":" not in item:
                return item
    except Exception:
        return None
