from __future__ import annotations

import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from saif.config import get_settings
from saif.utils.json_safety import make_json_safe


CommandRunner = Callable[[str, int], subprocess.CompletedProcess[str]]
CorrectionProvider = Callable[[dict, dict], dict | None]


BLOCKED_COMMAND_PATTERNS = [
    r"\brm\s+-rf\s+/",
    r"\brm\s+-rf\s+~",
    r"\brm\s+-rf\s+\$HOME",
    r"\bmkfs(?:\.[a-z0-9]+)?\b",
    r"\bdd\s+.*\bof=/dev/",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bpoweroff\b",
    r":\(\)\s*\{\s*:\|:\s*&\s*\};:",
    r"\bcurl\b.*\|\s*(?:sh|bash|powershell|pwsh)\b",
    r"\bwget\b.*\|\s*(?:sh|bash|powershell|pwsh)\b",
    r"\bscp\b.*(?:/home|~)",
    r"\brsync\b.*(?:/home|~)",
]


def evidence_file(scan_id: int) -> Path:
    return get_settings().evidence_dir / f"scan-{scan_id}" / "tool_install_events.jsonl"


def is_command_safe(command: str, *, workspace: str | Path | None = None) -> tuple[bool, str | None]:
    normalized = " ".join(str(command or "").strip().split())
    lowered = normalized.lower()
    if not normalized:
        return False, "empty command"
    for pattern in BLOCKED_COMMAND_PATTERNS:
        if re.search(pattern, lowered):
            return False, f"blocked destructive command pattern: {pattern}"
    workspace_path = str(Path(workspace or Path.cwd()).resolve()).lower()
    home = str(Path.home().resolve()).lower()
    if re.search(r"\bdel\s+/[sq]\s+", lowered) and (workspace_path in lowered or home in lowered):
        return False, "blocked recursive delete of workspace or home"
    if re.search(r"\bremove-item\b.*\b-recurse\b", lowered) and (workspace_path in lowered or home in lowered):
        return False, "blocked recursive delete of workspace or home"
    return True, None


def run_install_plan(
    *,
    scan_id: int,
    tool: str,
    capability: str,
    required_for: str,
    reason: str,
    install_plan: dict,
    requested_by: str = "tool_manager_agent",
    ollama_status: str = "not_requested",
    fallback_plan_used: bool = False,
    resumed_phase: str | None = None,
    command_runner: CommandRunner | None = None,
    correction_provider: CorrectionProvider | None = None,
    max_retries: int | None = None,
    timeout_seconds: int | None = None,
) -> dict:
    settings = get_settings()
    retries = max(0, int(max_retries if max_retries is not None else settings.tool_install_max_retries))
    timeout = int(timeout_seconds or settings.tool_timeout_seconds)
    command_runner = command_runner or _run_shell_command
    attempt_index = 0
    current_plan = dict(install_plan or {})
    events: list[dict] = []
    while attempt_index <= retries:
        attempt_index += 1
        result = _execute_plan_once(scan_id, tool, capability, required_for, reason, current_plan, attempt_index, command_runner, timeout)
        events.append(result)
        if result.get("status") == "completed":
            summary = _summary_event(scan_id, tool, capability, required_for, requested_by, ollama_status, fallback_plan_used, events, True, resumed_phase, "installed_and_resumed")
            _append_event(scan_id, summary)
            return {"status": "completed", "tool": tool, "attempts": events, "summary_event": summary, "evidence_path": str(evidence_file(scan_id))}
        if attempt_index > retries or correction_provider is None:
            break
        corrected = correction_provider(current_plan, result)
        if not corrected:
            break
        current_plan = dict(corrected)
        _append_event(scan_id, {"event_type": "tool_install_retry_plan_received", "tool": tool, "attempt": attempt_index + 1, "plan": current_plan})
    summary = _summary_event(scan_id, tool, capability, required_for, requested_by, ollama_status, fallback_plan_used, events, False, resumed_phase, "install_failed_skipped")
    _append_event(scan_id, summary)
    return {"status": "coverage_gap", "tool": tool, "reason": "tool installation failed after retries", "attempts": events, "summary_event": summary, "evidence_path": str(evidence_file(scan_id))}


def _execute_plan_once(
    scan_id: int,
    tool: str,
    capability: str,
    required_for: str,
    reason: str,
    install_plan: dict,
    attempt: int,
    command_runner: CommandRunner,
    timeout: int,
) -> dict:
    commands = _commands_from_plan(install_plan)
    verify_commands = _verify_commands_from_plan(install_plan)
    _append_event(scan_id, {"event_type": "tool_install_plan_started", "tool": tool, "capability": capability, "required_for": required_for, "reason": reason, "attempt": attempt, "plan": install_plan})
    command_results = []
    for command in commands:
        safe, block_reason = is_command_safe(command)
        if not safe:
            event = {"event_type": "tool_install_command_blocked", "tool": tool, "attempt": attempt, "command": command, "reason": block_reason, "status": "blocked"}
            _append_event(scan_id, event)
            return {"status": "blocked", "reason": block_reason, "commands": command_results + [event]}
        started = time.perf_counter()
        completed = command_runner(command, timeout)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        row = {
            "event_type": "tool_install_command_completed",
            "tool": tool,
            "attempt": attempt,
            "command": command,
            "exit_code": completed.returncode,
            "duration_ms": elapsed_ms,
            "stdout": (completed.stdout or "")[-4000:],
            "stderr": (completed.stderr or "")[-4000:],
        }
        command_results.append(row)
        _append_event(scan_id, row)
        if completed.returncode != 0:
            return {"status": "tool_install_failed", "reason": completed.stderr or completed.stdout or "install command failed", "commands": command_results}
    verify_results = [_run_verify(scan_id, tool, attempt, command, command_runner, timeout) for command in verify_commands]
    verified = bool(verify_results) and all(item.get("exit_code") == 0 for item in verify_results)
    status = "completed" if verified or (not verify_commands and all(item.get("exit_code") == 0 for item in command_results)) else "tool_install_failed"
    final = {"event_type": "tool_install_plan_completed", "tool": tool, "attempt": attempt, "status": status, "verified": verified, "commands": command_results, "verify": verify_results}
    _append_event(scan_id, final)
    return final


def _run_verify(scan_id: int, tool: str, attempt: int, command: str, command_runner: CommandRunner, timeout: int) -> dict:
    safe, block_reason = is_command_safe(command)
    if not safe:
        row = {"event_type": "tool_install_verify_blocked", "tool": tool, "attempt": attempt, "command": command, "reason": block_reason, "exit_code": 126}
        _append_event(scan_id, row)
        return row
    completed = command_runner(command, min(timeout, 60))
    row = {"event_type": "tool_install_verify_completed", "tool": tool, "attempt": attempt, "command": command, "exit_code": completed.returncode, "stdout": (completed.stdout or "")[-1000:], "stderr": (completed.stderr or "")[-1000:]}
    _append_event(scan_id, row)
    return row


def _commands_from_plan(plan: dict) -> list[str]:
    value = plan.get("commands") or plan.get("install_commands") or []
    return [str(item).strip() for item in value if str(item).strip()]


def _verify_commands_from_plan(plan: dict) -> list[str]:
    value = plan.get("verify_commands") or plan.get("verification_commands") or []
    return [str(item).strip() for item in value if str(item).strip()]


def _run_shell_command(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(command, 124, stdout=exc.stdout or "", stderr=exc.stderr or "command timed out")
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, stdout="", stderr=str(exc))


def _summary_event(
    scan_id: int,
    tool: str,
    capability: str,
    required_for: str,
    requested_by: str,
    ollama_status: str,
    fallback_plan_used: bool,
    events: list[dict],
    success: bool,
    resumed_phase: str | None,
    final_status: str,
) -> dict:
    command_rows = [row for event in events for row in event.get("commands", []) if isinstance(row, dict)]
    verify_rows = [row for event in events for row in event.get("verify", []) if isinstance(row, dict)]
    return {
        "event_type": "tool_install_summary",
        "scan_id": scan_id,
        "tool": tool,
        "capability": capability,
        "required_for": required_for,
        "requested_by": requested_by,
        "ollama_install_plan_requested": ollama_status != "not_requested",
        "ollama_status": ollama_status,
        "fallback_plan_used": bool(fallback_plan_used),
        "commands_run": command_rows,
        "verify_commands_run": verify_rows,
        "install_success": bool(success),
        "verify_success": bool(success) and (not verify_rows or all(row.get("exit_code") == 0 for row in verify_rows)),
        "resumed_phase": resumed_phase or required_for,
        "final_status": final_status,
    }


def _append_event(scan_id: int, event: dict) -> None:
    path = evidence_file(scan_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = make_json_safe({"time": datetime.now(timezone.utc).isoformat(), "scan_id": scan_id, **event})
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, default=str) + "\n")


def basic_install_plan(tool: str) -> dict:
    return deterministic_install_plan(tool)


def deterministic_install_plan(tool: str) -> dict:
    tool = str(tool or "").strip().lower()
    plans = {
        "playwright": {
            "commands": [".venv/bin/python -m pip install playwright", ".venv/bin/python -m playwright install chromium"],
            "verify_commands": [".venv/bin/python -c \"import playwright; print('ok')\""],
        },
        "chromium": {
            "commands": [".venv/bin/python -m playwright install chromium"],
            "verify_commands": [".venv/bin/python -c \"from playwright.sync_api import sync_playwright; print('ok')\""],
        },
        "ffuf": {"commands": ["sudo apt-get update", "sudo apt-get install -y ffuf"], "verify_commands": ["ffuf -V"]},
        "gobuster": {"commands": ["sudo apt-get update", "sudo apt-get install -y gobuster"], "verify_commands": ["gobuster version"]},
        "nmap": {"commands": ["sudo apt-get update", "sudo apt-get install -y nmap"], "verify_commands": ["nmap --version"]},
        "katana": {"commands": ["go install github.com/projectdiscovery/katana/cmd/katana@latest"], "verify_commands": ["katana -version"]},
    }
    plan = plans.get(tool, {"commands": [f"{tool} --version"], "verify_commands": [f"{tool} --version"]})
    return {"tool": tool, **plan, "notes": "Deterministic fallback install plan used when AI install advice is unavailable."}
