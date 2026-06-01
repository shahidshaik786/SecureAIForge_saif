from __future__ import annotations

import importlib.metadata
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from sqlalchemy.orm import Session

from saif.config import get_settings
from saif.db.models import ToolRegistry, ToolRegistryStatus


TOOL_DEPENDENCIES = {
    "http_client": "httpx",
    "nmap_top_ports": "nmap",
    "nmap_full_tcp": "nmap",
    "nmap_service_detection": "nmap",
    "katana": "katana",
    "gobuster_dir": "gobuster",
    "ffuf_dir": "ffuf",
    "gobuster_api_paths": "gobuster",
    "ffuf_api_paths": "ffuf",
    "whatweb": "whatweb",
    "technology_fingerprint": "httpx",
}

APT_INSTALL_TOOLS = {
    "nmap": "nmap",
    "gobuster": "gobuster",
    "ffuf": "ffuf",
    "seclists": "seclists",
    "dirb": "dirb",
    "go": "golang-go",
    "whatweb": "whatweb",
    "jq": "jq",
    "curl": "curl",
}

INSTALL_METHODS = {
    "nmap": "apt",
    "gobuster": "apt",
    "ffuf": "apt",
    "seclists": "apt",
    "dirb": "apt",
    "go": "apt",
    "whatweb": "apt",
    "jq": "apt",
    "curl": "apt",
    "katana": "go install",
    "httpx": "python package",
}

_APT_UPDATED = False
_APT_UPGRADED = False
_SESSION_INSTALL_ATTEMPTS: set[str] = set()


@dataclass
class ToolInstallAttempt:
    tool: str
    attempted: bool
    status: str
    reason: str | None = None
    command: str | None = None
    output: str | None = None
    command_path: str | None = None
    version: str | None = None


@dataclass
class ToolPreparation:
    selected_tools: list[str]
    executable_tools: list[str]
    installed_tools: list[str]
    missing_tools: list[str]
    attempts: list[ToolInstallAttempt] = field(default_factory=list)


def check_runtime_tools() -> dict[str, bool]:
    _ensure_go_bin_path()
    return {
        "httpx": _python_package_installed("httpx"),
        "nmap": bool(shutil.which("nmap")),
        "gobuster": bool(shutil.which("gobuster")),
        "ffuf": bool(shutil.which("ffuf")),
        "katana": bool(shutil.which("katana")),
        "whatweb": bool(shutil.which("whatweb")),
        "jq": bool(shutil.which("jq")),
        "curl": bool(shutil.which("curl")),
        "go": bool(shutil.which("go")),
        "seclists": Path("/usr/share/seclists").exists(),
        "dirb": Path("/usr/share/wordlists/dirb").exists() or bool(shutil.which("dirb")),
    }


def print_tool_summary(console: Console | None = None) -> dict[str, bool]:
    console = console or Console()
    status = check_runtime_tools()
    installed = sorted(name for name, ok in status.items() if ok)
    missing = sorted(name for name, ok in status.items() if not ok)
    console.print("Tool summary:")
    console.print(f"Installed tools ({len(installed)}): {', '.join(installed) if installed else 'none'}")
    console.print(f"Missing tools ({len(missing)}): {', '.join(missing) if missing else 'none'}")
    return status


def install_missing_supported_tools(console: Console | None = None) -> ToolPreparation:
    console = console or Console()
    status = check_runtime_tools()
    selected = ["http_client", "nmap_top_ports", "gobuster_dir", "ffuf_dir", "katana"]
    attempts: list[ToolInstallAttempt] = []
    _prepare_apt_batch([dependency for dependency, installed in status.items() if not installed and dependency in APT_INSTALL_TOOLS], console)
    for dependency, installed in status.items():
        if installed:
            continue
        if dependency == "httpx":
            attempts.append(
                ToolInstallAttempt(
                    tool="httpx",
                    attempted=False,
                    status="missing_tool",
                    reason="httpx is installed through ./saif.sh setup, not during tool installation.",
                )
            )
            continue
        console.print(f"Missing tool detected: {dependency}")
        console.print(f"Attempting install: {dependency}")
        attempts.append(_install_dependency(dependency))
    final_status = check_runtime_tools()
    print_tool_summary(console)
    return ToolPreparation(
        selected_tools=selected,
        executable_tools=[tool for tool in selected if _tool_ready(tool, final_status)],
        installed_tools=sorted(name for name, ok in final_status.items() if ok),
        missing_tools=sorted(name for name, ok in final_status.items() if not ok),
        attempts=attempts,
    )


def prepare_selected_tools(selected_tools: list[str], console: Console | None = None, auto_install: bool = True) -> ToolPreparation:
    console = console or Console()
    before = check_runtime_tools()
    attempts: list[ToolInstallAttempt] = []
    executable_tools: list[str] = []
    missing_dependencies = [
        TOOL_DEPENDENCIES[tool]
        for tool in selected_tools
        if TOOL_DEPENDENCIES.get(tool) and not _tool_ready(tool, before) and TOOL_DEPENDENCIES[tool] in APT_INSTALL_TOOLS
    ]
    if auto_install:
        _prepare_apt_batch(missing_dependencies, console)
    for tool in selected_tools:
        dependency = TOOL_DEPENDENCIES.get(tool)
        if not dependency or _tool_ready(tool, before):
            executable_tools.append(tool)
            continue
        console.print(f"Missing tool detected: {dependency}")
        if auto_install and dependency in {*APT_INSTALL_TOOLS, "katana"}:
            console.print(f"Attempting install: {dependency}")
            attempt = _install_dependency(dependency)
        else:
            attempt = ToolInstallAttempt(
                tool=dependency,
                attempted=False,
                status="missing_tool",
                reason=f"{dependency} is not installed",
            )
        attempts.append(attempt)
        after = check_runtime_tools()
        before = after
        if _tool_ready(tool, after):
            executable_tools.append(tool)
    final_status = check_runtime_tools()
    return ToolPreparation(
        selected_tools=selected_tools,
        executable_tools=executable_tools,
        installed_tools=sorted(name for name, ok in final_status.items() if ok),
        missing_tools=sorted(name for name, ok in final_status.items() if not ok),
        attempts=attempts,
    )


def _tool_ready(tool: str, status: dict[str, bool]) -> bool:
    dependency = TOOL_DEPENDENCIES.get(tool)
    return True if not dependency else status.get(dependency, False)


def _python_package_installed(name: str) -> bool:
    try:
        importlib.metadata.version(name)
        return True
    except importlib.metadata.PackageNotFoundError:
        return False


def _install_dependency(tool: str) -> ToolInstallAttempt:
    _ensure_go_bin_path()
    if _dependency_installed(tool):
        return ToolInstallAttempt(
            tool=tool,
            attempted=False,
            status="completed",
            reason=f"{tool} already installed",
            command_path=_dependency_path(tool),
            version=_dependency_version(tool),
        )
    if tool in _SESSION_INSTALL_ATTEMPTS:
        return ToolInstallAttempt(
            tool=tool,
            attempted=False,
            status="tool_install_failed",
            reason=f"{tool} install already attempted in this session",
            command_path=_dependency_path(tool),
        )
    _SESSION_INSTALL_ATTEMPTS.add(tool)
    if tool in APT_INSTALL_TOOLS:
        package = APT_INSTALL_TOOLS[tool]
        install = _run_command(["sudo", "apt-get", "install", "-y", package], timeout=get_settings().tool_timeout_seconds)
        installed = install.returncode == 0 and _dependency_installed(tool)
        return ToolInstallAttempt(
            tool=tool,
            attempted=True,
            status="completed" if installed else "tool_install_failed",
            reason=None if installed else _compact_error(install.stderr or install.stdout or "apt-get install failed"),
            command=f"sudo apt-get install -y {package}",
            output=(install.stdout + install.stderr)[-4000:],
            command_path=_dependency_path(tool),
            version=_dependency_version(tool),
        )
    if tool == "katana":
        if shutil.which("katana"):
            return ToolInstallAttempt(tool="katana", attempted=False, status="completed", reason="katana already installed", command_path=shutil.which("katana"), version=_dependency_version("katana"))
        if not shutil.which("go"):
            return ToolInstallAttempt(
                tool="katana",
                attempted=True,
                status="tool_install_failed",
                reason="Go is required to install katana. Suggested fix: sudo apt-get install -y golang-go",
                command="go install github.com/projectdiscovery/katana/cmd/katana@latest",
            )
        _ensure_go_bin_path()
        install = _run_command(["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"], timeout=max(600, get_settings().tool_timeout_seconds))
        installed = install.returncode == 0 and shutil.which("katana")
        return ToolInstallAttempt(
            tool="katana",
            attempted=True,
            status="completed" if installed else "tool_install_failed",
            reason=None if installed else _compact_error(install.stderr or install.stdout or "katana install failed"),
            command="go install github.com/projectdiscovery/katana/cmd/katana@latest",
            output=(install.stdout + install.stderr)[-4000:],
            command_path=shutil.which("katana"),
            version=_dependency_version("katana"),
        )
    return ToolInstallAttempt(tool=tool, attempted=False, status="missing_tool", reason=f"No installer for {tool}")


def refresh_tool_registry(session: Session, install_missing: bool = False, console: Console | None = None) -> ToolPreparation:
    status = check_runtime_tools()
    attempts: list[ToolInstallAttempt] = []
    if install_missing:
        missing_apt = [tool for tool, installed in status.items() if not installed and tool in APT_INSTALL_TOOLS]
        _prepare_apt_batch(missing_apt, console)
        for tool, installed in status.items():
            if installed or tool == "httpx":
                continue
            if tool in APT_INSTALL_TOOLS or tool == "katana":
                attempts.append(_install_dependency(tool))
        status = check_runtime_tools()
    upsert_tool_registry(session, status, attempts)
    selected = ["http_client", "nmap_top_ports", "gobuster_dir", "ffuf_dir", "katana"]
    return ToolPreparation(
        selected_tools=selected,
        executable_tools=[tool for tool in selected if _tool_ready(tool, status)],
        installed_tools=sorted(name for name, ok in status.items() if ok),
        missing_tools=sorted(name for name, ok in status.items() if not ok),
        attempts=attempts,
    )


def upsert_tool_registry(session: Session, status: dict[str, bool], attempts: list[ToolInstallAttempt] | None = None) -> None:
    now = datetime.now(timezone.utc)
    attempts_by_tool = {attempt.tool: attempt for attempt in attempts or []}
    for tool, installed in status.items():
        row = session.query(ToolRegistry).filter(ToolRegistry.tool_name == tool).one_or_none()
        if not row:
            row = ToolRegistry(tool_name=tool)
            session.add(row)
        attempt = attempts_by_tool.get(tool)
        row.install_method = INSTALL_METHODS.get(tool)
        row.command_path = _dependency_path(tool)
        row.version = _dependency_version(tool)
        row.status = ToolRegistryStatus.INSTALLED.value if installed else ToolRegistryStatus.MISSING.value
        row.last_checked_at = now
        if attempt:
            row.last_install_attempt_at = now
            row.install_attempt_count = (row.install_attempt_count or 0) + (1 if attempt.attempted else 0)
            row.last_error = attempt.reason if attempt.status != "completed" else None
            row.status = ToolRegistryStatus.INSTALLED.value if attempt.status == "completed" else ToolRegistryStatus.INSTALL_FAILED.value
            row.metadata_json = {"last_attempt": attempt.__dict__}


def tool_registry_snapshot(session: Session) -> list[dict]:
    rows = session.query(ToolRegistry).order_by(ToolRegistry.tool_name).all()
    return [
        {
            "tool_name": row.tool_name,
            "install_method": row.install_method,
            "command_path": row.command_path,
            "version": row.version,
            "status": row.status,
            "last_checked_at": row.last_checked_at.isoformat() if row.last_checked_at else None,
            "install_attempt_count": row.install_attempt_count,
            "last_error": row.last_error,
            "metadata": row.metadata_json,
        }
        for row in rows
    ]


def _prepare_apt_batch(tools: list[str], console: Console | None = None) -> None:
    apt_tools = sorted({tool for tool in tools if tool in APT_INSTALL_TOOLS})
    if not apt_tools:
        return
    _apt_update_once(console)
    if get_settings().apt_upgrade:
        _apt_upgrade_once(console)


def _apt_update_once(console: Console | None = None) -> ToolInstallAttempt | None:
    global _APT_UPDATED
    if _APT_UPDATED:
        return None
    if console:
        console.print("apt update: running once for this install session")
    result = _run_command(["sudo", "apt-get", "update"], timeout=get_settings().tool_timeout_seconds)
    _APT_UPDATED = result.returncode == 0
    if result.returncode != 0 and console:
        console.print(f"apt update: failed - {_compact_error(result.stderr or result.stdout)}")
    return ToolInstallAttempt(
        tool="apt",
        attempted=True,
        status="completed" if result.returncode == 0 else "tool_install_failed",
        reason=None if result.returncode == 0 else _compact_error(result.stderr or result.stdout or "apt-get update failed"),
        command="sudo apt-get update",
        output=(result.stdout + result.stderr)[-4000:],
    )


def _apt_upgrade_once(console: Console | None = None) -> ToolInstallAttempt | None:
    global _APT_UPGRADED
    if _APT_UPGRADED:
        return None
    if console:
        console.print("apt upgrade: enabled by SAIF_APT_UPGRADE=true")
    result = _run_command(["sudo", "apt-get", "upgrade", "-y"], timeout=max(600, get_settings().tool_timeout_seconds))
    _APT_UPGRADED = result.returncode == 0
    if result.returncode != 0 and console:
        console.print(f"apt upgrade: failed - {_compact_error(result.stderr or result.stdout)}")
    return ToolInstallAttempt(
        tool="apt-upgrade",
        attempted=True,
        status="completed" if result.returncode == 0 else "tool_install_failed",
        reason=None if result.returncode == 0 else _compact_error(result.stderr or result.stdout or "apt-get upgrade failed"),
        command="sudo apt-get upgrade -y",
        output=(result.stdout + result.stderr)[-4000:],
    )


def _ensure_go_bin_path() -> None:
    go_bin = str(Path.home() / "go" / "bin")
    path = os.environ.get("PATH", "")
    if go_bin not in path.split(os.pathsep):
        os.environ["PATH"] = f"{go_bin}{os.pathsep}{path}" if path else go_bin


def _dependency_installed(tool: str) -> bool:
    if tool == "httpx":
        return _python_package_installed("httpx")
    if tool == "seclists":
        return Path("/usr/share/seclists").exists()
    if tool == "dirb":
        return Path("/usr/share/wordlists/dirb").exists() or bool(shutil.which("dirb"))
    return bool(shutil.which(tool))


def _dependency_path(tool: str) -> str | None:
    if tool == "httpx":
        return "python:httpx" if _python_package_installed("httpx") else None
    if tool == "seclists":
        return "/usr/share/seclists" if Path("/usr/share/seclists").exists() else None
    if tool == "dirb" and Path("/usr/share/wordlists/dirb").exists():
        return "/usr/share/wordlists/dirb"
    return shutil.which(tool)


def _dependency_version(tool: str) -> str | None:
    if tool == "httpx":
        try:
            return importlib.metadata.version("httpx")
        except importlib.metadata.PackageNotFoundError:
            return None
    command_path = shutil.which(tool)
    if not command_path:
        return None
    result = _run_command([command_path, "--version"], timeout=10)
    text = (result.stdout or result.stderr).strip().splitlines()
    return text[0][:255] if text else None


def _run_command(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(command, 124, stdout=exc.stdout or "", stderr=exc.stderr or "command timed out")
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, stdout="", stderr=str(exc))


def _compact_error(value: str) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    return (lines[-1] if lines else value.strip())[:300]
