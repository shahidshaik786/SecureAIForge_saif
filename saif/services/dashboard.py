from __future__ import annotations

from pathlib import Path

from saif.config import get_settings


PID_FILE = Path(".saif/dashboard.pid")


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    allow_remote: bool = False,
    no_auth_explicitly_allowed: bool = False,
) -> None:
    if host == "0.0.0.0" and not allow_remote:
        raise RuntimeError("Refusing to bind dashboard to 0.0.0.0 without --allow-remote")
    settings = get_settings()
    if host == "0.0.0.0" and not settings.dashboard_password and not no_auth_explicitly_allowed:
        raise RuntimeError("Refusing remote dashboard without SAIF_DASHBOARD_PASSWORD unless --no-auth-explicitly-allowed is set")
    if host == "0.0.0.0":
        print("WARNING: Dashboard is bound to remote interface. Restrict network access.", flush=True)
    try:
        import uvicorn
        from saif.dashboard.app import create_app
    except ImportError as exc:
        raise RuntimeError("Dashboard dependencies are missing. Run: ./saif.sh setup") from exc

    dashboard_app = create_app()
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(__import__("os").getpid()), encoding="utf-8")
    print(f"SAIF dashboard: http://{host}:{port}", flush=True)
    uvicorn.run(dashboard_app, host=host, port=port, log_level="info")


def dashboard_status() -> dict:
    if not PID_FILE.exists():
        return {"status": "stopped", "pid": None}
    pid_text = PID_FILE.read_text(encoding="utf-8").strip()
    try:
        pid = int(pid_text)
    except ValueError:
        return {"status": "unknown", "pid": pid_text}
    if _pid_running(pid):
        return {"status": "running", "pid": pid}
    return {"status": "stale_pid", "pid": pid}


def stop_dashboard() -> dict:
    status = dashboard_status()
    pid = status.get("pid")
    if status["status"] != "running" or not isinstance(pid, int):
        return status
    import os
    import signal

    os.kill(pid, signal.SIGTERM)
    return {"status": "stopping", "pid": pid}


def _pid_running(pid: int) -> bool:
    import os

    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
