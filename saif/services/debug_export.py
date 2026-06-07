from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from saif.config import get_settings
from saif.db.models import Evidence, Finding, PipelineArtifact, PayloadAttempt, Scan, ToolRun
from saif.services.case_management import scan_target


def generate_full_ai_debug_export(session: Session, scan_id: int) -> tuple[Path, Path]:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise ValueError(f"scan {scan_id} not found")
    base = get_settings().evidence_dir / f"scan-{scan_id}"
    debug_dir = base / "debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    ai_trace_index = _read_json(base / "ai" / "ai_trace_index.json", {"scan_id": scan_id, "total_ai_calls": 0, "calls": []})
    all_ai_traces = []
    for call in ai_trace_index.get("calls") or []:
        path = Path(str(call.get("trace_path") or ""))
        if path.exists():
            all_ai_traces.append(_read_json(path, {"trace_path": str(path), "error": "unreadable"}))
    agent_reactions = _read_jsonl(base / "agent_reactions.jsonl")
    request_map = _read_json(base / "request_map.json", {"scan_id": scan_id, "total_requests": 0, "requests": []})
    artifacts = session.scalars(select(PipelineArtifact).where(PipelineArtifact.scan_id == scan_id)).all()
    tool_runs = [_row_tool(item) for item in session.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id)).all()]
    payload_attempts = [_row_payload(item) for item in session.scalars(select(PayloadAttempt).where(PayloadAttempt.scan_id == scan_id)).all()]
    findings = [_row_finding(item) for item in session.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()]
    coverage_gaps = [_row_evidence(item) for item in session.scalars(select(Evidence).where(Evidence.scan_id == scan_id, Evidence.kind == "coverage_gap")).all()]
    errors = [item for item in tool_runs if str(item.get("status") or "").lower() in {"execution_error", "failed", "tool_install_failed"}]
    auth_gate = (scan.scan_config or {}).get("auth_gate") or {}
    workflow_inventory = _artifact_data(artifacts, "workflow_request_inventory")
    behavior_proof = _artifact_data(artifacts, "authenticated_behavior_proof")
    selected_tool_plan = _artifact_data(artifacts, "selected_tool_plan")
    summary = {
        "total_ai_calls": len(ai_trace_index.get("calls") or []),
        "ai_timeouts": len([call for call in ai_trace_index.get("calls") or [] if call.get("status") == "timeout"]),
        "ai_completed": len([call for call in ai_trace_index.get("calls") or [] if call.get("status") == "completed"]),
        "agent_fallbacks": len([row for row in agent_reactions if row.get("action_taken") == "fallback"]),
        "request_count": request_map.get("total_requests") or len(request_map.get("requests") or []),
        "authorization_candidates": int(auth_gate.get("authorization_candidate_count") or 0),
    }
    payload = {
        "scan_id": scan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": scan_target(session, scan),
        "ollama_profile": get_settings().ollama_profile,
        "ai_trace_index": ai_trace_index,
        "all_ai_traces": all_ai_traces,
        "agent_reactions": agent_reactions,
        "request_map": request_map,
        "workflow_request_inventory": workflow_inventory,
        "authenticated_behavior_proof": behavior_proof,
        "auth_gate": auth_gate,
        "selected_tool_plan": selected_tool_plan,
        "payload_attempts": payload_attempts,
        "tool_runs": tool_runs,
        "findings": findings,
        "coverage_gaps": coverage_gaps,
        "errors": errors,
        "summary": summary,
    }
    json_path = debug_dir / f"scan-{scan_id}-full-ai-debug.json"
    html_path = debug_dir / f"scan-{scan_id}-full-ai-debug.html"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    html_path.write_text(_html(payload), encoding="utf-8")
    return json_path, html_path


def _html(payload: dict) -> str:
    sections = [
        ("AI Calls", payload.get("ai_trace_index")),
        ("Ollama Prompts", [{"ai_call_id": item.get("ai_call_id"), "request_to_ollama": item.get("request_to_ollama")} for item in payload.get("all_ai_traces") or []]),
        ("Ollama Raw Responses", [{"ai_call_id": item.get("ai_call_id"), "raw_ollama_response": item.get("raw_ollama_response")} for item in payload.get("all_ai_traces") or []]),
        ("Parsed Decisions", [{"ai_call_id": item.get("ai_call_id"), "parsed_ollama_response": item.get("parsed_ollama_response"), "guardrail_validation": item.get("guardrail_validation")} for item in payload.get("all_ai_traces") or []]),
        ("Agent Reactions", payload.get("agent_reactions")),
        ("Request Map", payload.get("request_map")),
        ("Auth Gate", payload.get("auth_gate")),
        ("Coverage Gaps", payload.get("coverage_gaps")),
        ("Tool Runs", payload.get("tool_runs")),
        ("Errors", payload.get("errors")),
    ]
    body = "\n".join(f"<h2>{escape(title)}</h2><pre>{escape(json.dumps(value, indent=2, sort_keys=True, default=str))}</pre>" for title, value in sections)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>SAIF AI Debug Scan {payload.get('scan_id')}</title>
<style>body{{font-family:Arial,sans-serif;margin:24px;background:#f8fafc;color:#111827}}pre{{background:#111827;color:#e5e7eb;padding:14px;border-radius:6px;overflow:auto}}h1,h2{{color:#0f172a}}</style></head>
<body><h1>SAIF Full AI Debug Export - Scan {payload.get('scan_id')}</h1>
<p>Target: <code>{escape(str(payload.get('target') or ''))}</code></p>
<p>Ollama profile: <strong>{escape(str(payload.get('ollama_profile') or ''))}</strong></p>
<h2>Summary</h2><pre>{escape(json.dumps(payload.get('summary'), indent=2, sort_keys=True, default=str))}</pre>
{body}</body></html>"""


def _artifact_data(artifacts, name: str) -> dict:
    for item in reversed(list(artifacts)):
        if item.name == name and item.data:
            return item.data
    return {}


def _read_json(path: Path, fallback: dict) -> dict:
    if not path.exists():
        return fallback
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return {"path": str(path), "error": str(exc), **fallback}
    return value if isinstance(value, dict) else fallback


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except Exception:
            value = {"raw": line[:2000]}
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _row_tool(item: ToolRun) -> dict:
    return {"tool_name": item.tool_name, "status": item.status, "command": item.command, "evidence_path": item.evidence_path, "output": item.output, "error": item.error}


def _row_payload(item: PayloadAttempt) -> dict:
    return {"endpoint": item.endpoint, "method": item.method, "parameter_name": item.parameter_name, "vulnerability_type": item.vulnerability_type, "status": item.status, "evidence_path": item.evidence_path}


def _row_finding(item: Finding) -> dict:
    return {"title": item.title, "severity": item.severity, "status": item.status, "endpoint": item.affected_endpoint, "confidence": item.confidence}


def _row_evidence(item: Evidence) -> dict:
    return {"kind": item.kind, "path": item.path, "summary": item.summary, "metadata": item.metadata_json}
