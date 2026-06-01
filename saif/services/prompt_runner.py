import os
import re
import shutil
import subprocess
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse
from xml.etree import ElementTree

import httpx
import yaml
from rich.console import Console
from sqlalchemy.orm import Session

from saif.ai.gate import AIContext, ai_review_evidence, log_ai_context, log_ai_review
from saif.config import get_settings
from saif.db.models import (
    AgentJob,
    AgentJobStatus,
    AiCallRun,
    ApplicationProfile,
    AuthenticatedSession,
    AuthorizationMatrix,
    Credential,
    DiscoveredAsset,
    DiscoveredApiSpec,
    DiscoveredAuthFlow,
    DiscoveredAuthMechanism,
    DiscoveredEndpoint,
    DiscoveredObject,
    DiscoveredParameter,
    DiscoveredService,
    DiscoveredSessionMechanism,
    DiscoveredTenant,
    DiscoveredToken,
    Evidence,
    Finding,
    Log,
    PipelineArtifact,
    PayloadAttempt,
    Project,
    Request,
    Response,
    RunStatus,
    Scan,
    ScanTestPlan,
    ScanStatus,
    SessionRecord,
    TestCase,
    TestRun,
    ToolRun,
)
from saif.services.case_management import ensure_scan_phases, mark_phase, sync_scan_phases
from saif.services.credentials import load_credentials
from saif.services.evidence import write_evidence
from saif.services.payloads import active_payload_source, load_payloads, payload_library_status
from saif.services.progress import emit_progress, heartbeat
from saif.services.profiles import auth_endpoint_candidates, detect_profile, load_profile, login_payloads, profile_from_scan_artifacts, protected_endpoint_candidates, registration_payloads
from saif.services.tool_manager import TOOL_DEPENDENCIES, ToolInstallAttempt, check_runtime_tools, prepare_selected_tools, upsert_tool_registry


TARGET_RE = re.compile(r"(?:https?://[^\s,;'\"<>]+)|(?:\b(?:\d{1,3}\.){3}\d{1,3}\b)", re.IGNORECASE)
OPENAPI_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/api-docs",
    "/swagger-ui.html",
    "/swagger/",
    "/api/swagger.json",
]
API_BASE_CANDIDATES = [
    "/",
    "/api",
    "/api/v1",
    "/api/v2",
    "/identity",
    "/identity/api",
    "/identity/api/auth",
    "/identity/api/v1",
    "/identity/api/v2",
    "/workshop",
    "/workshop/api",
    "/workshop/api/v1",
    "/workshop/api/v2",
    "/community",
    "/community/api",
    "/community/api/v1",
    "/community/api/v2",
    "/user",
    "/users",
    "/auth",
    "/oauth",
    "/saml",
]
API_WORDS = [
    "auth",
    "login",
    "signup",
    "register",
    "logout",
    "verify",
    "token",
    "refresh",
    "forgot-password",
    "reset-password",
    "user",
    "users",
    "profile",
    "vehicle",
    "vehicles",
    "shop",
    "shops",
    "mechanic",
    "mechanics",
    "community",
    "posts",
    "videos",
    "coupon",
    "validate-coupon",
    "orders",
    "health",
    "status",
    "graphql",
    "swagger.json",
    "openapi.json",
    "v2/api-docs",
    "v3/api-docs",
]
TOOL_ALIASES = {
    "robots_check": "robots_txt",
    "sitemap_check": "sitemap_xml",
    "nmap_enumeration": "nmap_top_ports",
    "nmap": "nmap_top_ports",
    "port_scan": "nmap_top_ports",
    "service_enumeration": "nmap_top_ports",
    "web_crawler": "katana",
    "crawler": "katana",
    "crawler_internal": "crawler",
    "web_discovery": "crawler",
    "directory_discovery": "gobuster_dir",
    "gobuster": "gobuster_dir",
    "ffuf": "ffuf_dir",
    "auth_mapping": "auth_session_mapping",
    "session_mapping": "auth_session_mapping",
    "token_analysis": "token_analysis",
    "authorization_matrix": "authorization_matrix",
    "idor_bola_bfla_planning": "idor_bola_bfla_planner",
    "input_validation_testing": "input_validation_planner",
    "business_logic_testing": "business_logic_planner",
    "api_profile": "api_profile_probe",
    "api_profile_detection": "api_profile_probe",
    "method_probe": "api_method_probe",
    "api_method_probing": "api_method_probe",
    "ffuf_api": "ffuf_api_paths",
    "gobuster_api": "gobuster_api_paths",
}


def extract_target(prompt: str) -> str | None:
    match = TARGET_RE.search(prompt)
    return match.group(0).rstrip(".,)") if match else None


def parse_prompt(prompt: str) -> dict:
    lowered = prompt.lower()
    return {
        "default_enumeration": "default enumeration" in lowered,
        "full_enumeration": "full enumeration" in lowered,
        "full_web_api_enumeration": any(phrase in lowered for phrase in ["full web and api enumeration", "full web/api enumeration", "web and api enumeration"]),
        "search_shodan": "search shodan" in lowered or "shodan" in lowered,
        "technology_fingerprint": any(
            phrase in lowered for phrase in ["find technology", "build technology", "find build technology", "technology fingerprint"]
        ),
        "crawler": any(phrase in lowered for phrase in ["crawler", "crawl", "katana"]),
        "directory_discovery": any(phrase in lowered for phrase in ["gobuster", "ffuf", "directory discovery", "content discovery"]),
        "nmap_enumeration": any(phrase in lowered for phrase in ["nmap enumeration", "port scan", "service enumeration", "nmap"]),
        "api_enumeration": any(phrase in lowered for phrase in ["api enumeration", "swagger", "openapi"]),
        "strong_api_discovery": any(phrase in lowered for phrase in ["strong crapi", "crapi", "nested api", "api discovery", "probe methods", "method probe"]),
        "crapi_full_test": any(phrase in lowered for phrase in ["crapi full test", "register two test users", "account provisioning", "capture tokens", "authenticated apis", "jwt issues"]),
        "adaptive_payload_testing": any(phrase in lowered for phrase in ["payload", "xss", "sqli", "sql injection", "ssrf", "jwt", "input validation"]),
        "auth_testing": any(phrase in lowered for phrase in ["login", "auth", "authorization", "idor", "bola", "bfla", "authenticated", "cross-account"]),
        "cross_account": any(phrase in lowered for phrase in ["cross-account", "cross account", "user1 and user2"]),
        "single_ip_target": bool(re.search(r"target:\s*(?:\d{1,3}\.){3}\d{1,3}\b", lowered)),
        "enumeration_only": any(phrase in lowered for phrase in ["enumeration only", "enumeration-only", "saif:enumeration_only"]),
        "full_scan": any(phrase in lowered for phrase in ["full test", "full scan", "full api security", "saif:full"]),
        "auth_scan": any(phrase in lowered for phrase in ["authenticated test", "auth scan", "saif:auth"]),
        "vuln_test": any(phrase in lowered for phrase in ["vulnerability test", "vuln test", "saif:vuln_test"]),
        "no_destructive_methods": any(phrase in lowered for phrase in ["no destructive methods", "saif:no_destructive_methods"]),
        "mode_black_box": any(phrase in lowered for phrase in ["saif:mode=black_box", "saif:mode=black-box", "black-box", "black box"]),
        "mode_gray_box": any(phrase in lowered for phrase in ["saif:mode=gray_box", "saif:mode=gray-box", "gray-box", "gray box"]),
        "mode_white_box": any(phrase in lowered for phrase in ["saif:mode=white_box", "saif:mode=white-box", "white-box", "white box"]),
    }


def select_tools(parsed: dict, target_url: str) -> list[str]:
    tools = ["http_client"]
    if parsed["single_ip_target"]:
        return ["nmap_top_ports", "nmap_full_tcp", "nmap_service_detection", "http_service_detection"]
    if parsed["default_enumeration"] or parsed["full_enumeration"] or parsed["full_web_api_enumeration"]:
        tools.extend(
            [
                "technology_fingerprint",
                "root_link_inventory",
                "robots_txt",
                "sitemap_xml",
                "openapi_discovery",
                "static_asset_inventory",
                "api_path_hints",
                "api_profile_probe",
                "api_method_probe",
            ]
        )
        if parsed["full_enumeration"] or parsed["full_web_api_enumeration"] or parsed.get("full_scan"):
            tools.extend(["crawler", "gobuster_dir", "ffuf_dir", "ffuf_api_paths", "gobuster_api_paths", "auth_session_mapping", "token_analysis", "authorization_matrix"])
        if parsed.get("full_scan"):
            tools.extend(["account_provisioning", "login_session", "authenticated_crawling", "idor_bola_bfla_planner", "jwt_adaptive", "input_validation_planner", "xss_adaptive", "sqli_adaptive", "ssrf_adaptive", "business_logic_planner"])
        if _host_allowed_for_nmap(target_url):
            tools.append("nmap_top_ports")
    else:
        if parsed["search_shodan"]:
            tools.append("shodan_search")
        if parsed["technology_fingerprint"]:
            tools.append("technology_fingerprint")
        if parsed["nmap_enumeration"]:
            tools.append("nmap_top_ports")
        if parsed["api_enumeration"] or parsed.get("strong_api_discovery"):
            tools.extend(["openapi_discovery", "api_path_hints", "api_profile_probe", "api_method_probe"])
        if parsed.get("strong_api_discovery"):
            tools.extend(["static_asset_inventory", "ffuf_api_paths", "gobuster_api_paths", "auth_session_mapping", "token_analysis"])
        if parsed.get("crapi_full_test") or parsed.get("full_scan"):
            tools.extend(["account_provisioning", "login_session", "authenticated_crawling", "authorization_matrix", "idor_bola_bfla_planner", "token_analysis"])
        if parsed.get("adaptive_payload_testing") or parsed.get("crapi_full_test") or parsed.get("vuln_test") or parsed.get("full_scan"):
            tools.extend(["xss_adaptive", "sqli_adaptive", "ssrf_adaptive", "jwt_adaptive"])
        if parsed["crawler"]:
            tools.append("crawler")
        if parsed["directory_discovery"]:
            tools.extend(["gobuster_dir", "ffuf_dir"])
        if parsed["auth_testing"] or parsed.get("auth_scan") or parsed.get("full_scan"):
            tools.extend(
                [
                    "technology_fingerprint",
                    "root_link_inventory",
                    "openapi_discovery",
                    "static_asset_inventory",
                    "api_path_hints",
                    "crawler",
                    "auth_session_mapping",
                    "token_analysis",
                    "authorization_matrix",
                    "idor_bola_bfla_planner",
                    "input_validation_planner",
                    "business_logic_planner",
                ]
            )
    return _ordered_tools(list(dict.fromkeys(tools)))


def _ordered_tools(tools: list[str]) -> list[str]:
    priority = [
        "http_client",
        "technology_fingerprint",
        "root_link_inventory",
        "robots_txt",
        "sitemap_xml",
        "openapi_discovery",
        "static_asset_inventory",
        "api_path_hints",
        "api_profile_probe",
        "api_method_probe",
        "crawler",
        "katana",
        "gobuster_dir",
        "ffuf_dir",
        "ffuf_api_paths",
        "gobuster_api_paths",
        "auth_session_mapping",
        "account_provisioning",
        "login_session",
        "token_analysis",
        "authenticated_crawling",
        "authorization_matrix",
        "idor_bola_bfla_planner",
        "xss_adaptive",
        "sqli_adaptive",
        "ssrf_adaptive",
        "jwt_adaptive",
        "input_validation_planner",
        "business_logic_planner",
        "nmap_top_ports",
    ]
    rank = {tool: index for index, tool in enumerate(priority)}
    return sorted(tools, key=lambda tool: rank.get(tool, len(priority)))


def run_prompt_scan(
    session: Session,
    project: Project,
    target_url: str,
    prompt: str,
    ai_context: AIContext,
    console: Console | None = None,
    target_source: str | None = None,
    debug_live: bool = False,
    engagement_mode: str | None = None,
    credentials_path: str | None = None,
    source_path: str | None = None,
    auth_mode: str | None = None,
    destructive_method_policy: str | None = None,
    enable_destructive_tests: bool = False,
    destructive_test_policy: str = "detect_only",
    allow_test_owned_object_creation: bool = False,
    confirm_destructive_testing: bool = False,
    allow_account_generation: bool = False,
    allow_authenticated_testing: bool = False,
    allow_authorization_testing: bool = False,
    allow_payload_testing: bool = False,
    allow_rate_limit_testing: bool = False,
    selected_test_categories: list[str] | None = None,
    existing_scan: Scan | None = None,
) -> tuple[Scan, list[str], list[dict], dict, dict]:
    parsed = parse_prompt(prompt)
    if not any(parsed.values()):
        parsed["default_enumeration"] = True
    parser_selected_tools = select_tools(parsed, target_url)

    runner = {
        "http_client": _run_http_baseline,
        "shodan_search": _run_shodan_search,
        "technology_fingerprint": _run_technology_fingerprint,
        "root_link_inventory": _run_root_link_inventory,
        "robots_txt": _run_robots_txt,
        "sitemap_xml": _run_sitemap_xml,
        "openapi_discovery": _run_openapi_discovery,
        "static_asset_inventory": _run_static_asset_inventory,
        "api_path_hints": _run_api_path_hints,
        "api_profile_probe": _run_api_profile_probe,
        "api_method_probe": _run_api_method_probe,
        "ffuf_api_paths": _run_ffuf_api_paths,
        "gobuster_api_paths": _run_gobuster_api_paths,
        "account_provisioning": _run_account_provisioning,
        "login_session": _run_login_session,
        "authenticated_crawling": _run_authenticated_crawling,
        "xss_adaptive": _run_xss_adaptive,
        "sqli_adaptive": _run_sqli_adaptive,
        "ssrf_adaptive": _run_ssrf_adaptive,
        "jwt_adaptive": _run_jwt_adaptive,
        "nmap_top_ports": _run_nmap,
        "nmap_full_tcp": _run_nmap_full_tcp,
        "nmap_service_detection": _run_nmap_service_detection,
        "http_service_detection": _run_http_service_detection,
        "katana": _run_katana,
        "crawler": _run_crawler,
        "gobuster_dir": _run_gobuster_dir,
        "ffuf_dir": _run_ffuf_dir,
        "auth_session_mapping": _run_auth_session_mapping,
        "token_analysis": _run_token_analysis,
        "authorization_matrix": _run_authorization_matrix,
        "idor_bola_bfla_planner": _run_idor_bola_bfla_planner,
        "input_validation_planner": _run_input_validation_planner,
        "business_logic_planner": _run_business_logic_planner,
        "auth_authorization_planner": _run_auth_authorization_planner,
    }
    ai_selected_tools = _normalize_ai_tools(ai_context.scan_plan.get("tools", []), runner.keys())
    selected_tools = _ordered_tools(list(dict.fromkeys((ai_selected_tools or []) + parser_selected_tools)))
    ai_context.scan_plan["mode"] = _mode_from_prompt(parsed)

    scan = existing_scan or Scan(project_id=project.id)
    scan.project_id = project.id
    scan.profile = _mode_from_prompt(parsed)
    scan.ai_provider = "Ollama"
    scan.authorized_testing_mode = True
    scan.engagement_mode = engagement_mode or _engagement_mode_from_prompt(parsed, credentials_path, source_path)
    scan.credentials_path = credentials_path
    scan.source_path = source_path
    scan.auth_mode = auth_mode
    scan.destructive_method_policy = destructive_method_policy
    scan.enable_destructive_tests = enable_destructive_tests
    scan.destructive_test_policy = destructive_test_policy
    scan.allow_test_owned_object_creation = allow_test_owned_object_creation
    scan.confirm_destructive_testing = confirm_destructive_testing
    scan.allow_account_generation = allow_account_generation
    scan.allow_authenticated_testing = allow_authenticated_testing
    scan.allow_authorization_testing = allow_authorization_testing
    scan.allow_payload_testing = allow_payload_testing
    scan.allow_rate_limit_testing = allow_rate_limit_testing
    scan.status = ScanStatus.PLANNING.value
    scan.started_at = scan.started_at or datetime.now(timezone.utc)
    session.add(scan)
    session.flush()
    _create_scan_test_plan(session, scan, selected_test_categories or [])
    emit_progress(session, scan, f"status=planning target={target_url}", phase="precheck", agent="orchestrator_agent", event_type="scan_started", console=console, live=True)
    emit_progress(
        session,
        scan,
        "Destructive testing policy selected",
        phase="precheck",
        agent="orchestrator_agent",
        event_type="destructive_policy_selected",
        context={
            "enabled": enable_destructive_tests,
            "policy": destructive_test_policy,
            "destructive_method_policy": destructive_method_policy,
            "allow_test_owned_object_creation": allow_test_owned_object_creation,
            "confirm_destructive_testing": confirm_destructive_testing,
        },
        console=console if enable_destructive_tests else None,
        live=enable_destructive_tests,
    )
    ensure_scan_phases(session, scan)
    mark_phase(session, scan, "precheck", RunStatus.COMPLETED.value, {"target": target_url})
    mark_phase(session, scan, "ai_planning", RunStatus.COMPLETED.value, {"selected_tools": selected_tools})
    log_ai_context(session, scan, ai_context, parsed, target_url, selected_tools)
    session.add(
        Log(
            scan_id=scan.id,
            level="info",
            message="Prompt received",
            context={
                "prompt": prompt,
                "parsed_intent": parsed,
                "selected_target": target_url,
                "target_source": target_source,
                "selected_tools": selected_tools,
                "parser_selected_tools": parser_selected_tools,
                "engagement_mode": scan.engagement_mode,
                "credentials_path": credentials_path,
                "source_path": source_path,
                "auth_mode": auth_mode,
                "destructive_method_policy": destructive_method_policy,
                "enable_destructive_tests": enable_destructive_tests,
                "destructive_test_policy": destructive_test_policy,
                "allow_test_owned_object_creation": allow_test_owned_object_creation,
                "confirm_destructive_testing": confirm_destructive_testing,
                "allow_account_generation": allow_account_generation,
                "allow_authenticated_testing": allow_authenticated_testing,
                "allow_authorization_testing": allow_authorization_testing,
                "allow_payload_testing": allow_payload_testing,
                "allow_rate_limit_testing": allow_rate_limit_testing,
                "selected_test_categories": selected_test_categories or [],
            },
        )
    )
    _create_agent_job(session, scan, "orchestrator_agent", "scan_start", AgentJobStatus.COMPLETED.value, {"target": target_url, "tools": selected_tools})
    _create_agent_job(session, scan, "ai_planner_agent", "plan", AgentJobStatus.COMPLETED.value, {"prompt": prompt}, {"plan": ai_context.scan_plan})
    planned_cases = _create_planned_test_cases(session, scan, selected_tools, target_url)
    scan.status = ScanStatus.READY.value
    session.flush()
    preparation = prepare_selected_tools(selected_tools, console=console)
    executable_tools = list(preparation.executable_tools)
    upsert_tool_registry(session, check_runtime_tools(), preparation.attempts)
    session.add(
        Log(
            scan_id=scan.id,
            level="info",
            message="Tool preparation",
            context={
                "selected_tools": preparation.selected_tools,
                "executable_tools": preparation.executable_tools,
                "installed_tools": preparation.installed_tools,
                "missing_tools": preparation.missing_tools,
                "auto_install_attempts": [attempt.__dict__ for attempt in preparation.attempts],
            },
        )
    )
    _print_tool_preparation(preparation, console)

    tool_results: list[dict] = []
    try:
        scan.status = ScanStatus.RUNNING.value
        emit_progress(session, scan, "status=running", phase="enumeration", agent="orchestrator_agent", event_type="scan_started", console=console, live=True)
        for attempt in preparation.attempts:
            if attempt.status != "completed":
                tool_results.append(_record_install_attempt(session, scan, attempt))
        tool_index = 0
        while tool_index < len(executable_tools):
            tool = executable_tools[tool_index]
            tool_index += 1
            control_status = _scan_control_status(session, scan)
            if control_status in {ScanStatus.PAUSED.value, ScanStatus.STOPPING.value, ScanStatus.STOPPED.value}:
                scan.status = ScanStatus.STOPPED.value if control_status in {ScanStatus.STOPPING.value, ScanStatus.STOPPED.value} else ScanStatus.PAUSED.value
                if scan.status == ScanStatus.STOPPED.value:
                    scan.completed_at = datetime.now(timezone.utc)
                break
            agent_name = _agent_for_tool(tool)
            phase_name = _phase_for_tool(tool)
            emit_progress(session, scan, "agent started", phase=phase_name, agent=agent_name, tool=tool, event_type="agent_started", console=console, live=debug_live)
            emit_progress(session, scan, "started", phase=phase_name, agent=agent_name, tool=tool, event_type="tool_started", console=console, live=True)
            job = _create_agent_job(session, scan, agent_name, tool, AgentJobStatus.RUNNING.value, {"tool": tool, "target": target_url})
            try:
                if tool == "katana" and any(item.get("tool") in {"katana", "crawler"} and str(item.get("command", "")).startswith("katana ") for item in tool_results):
                    _finish_agent_job(job, AgentJobStatus.COMPLETED.value, {"status": "deduplicated", "reason": "katana already executed for crawler capability"})
                    continue
                with heartbeat(scan.id, phase=phase_name, agent=agent_name, tool=tool, console=console, live=debug_live):
                    result = runner[tool](session, scan, target_url, prompt, parsed)
                tool_results.append(result)
                _finish_agent_job(job, AgentJobStatus.COMPLETED.value, {"status": result.get("status"), "evidence_path": result.get("evidence_path")})
                emit_progress(session, scan, "agent completed", phase=phase_name, agent=agent_name, tool=tool, event_type="agent_completed", context={"status": result.get("status")}, console=console, live=debug_live)
                emit_progress(
                    session,
                    scan,
                    f"completed status={result.get('status')} evidence={result.get('evidence_path')}",
                    phase=phase_name,
                    agent=agent_name,
                    tool=tool,
                    event_type="tool_completed",
                    context={"status": result.get("status"), "evidence_path": result.get("evidence_path")},
                    console=console,
                    live=True,
                )
                if tool in planned_cases:
                    planned_cases[tool].status = result.get("status") or RunStatus.EXECUTION_ERROR.value
                added_tools = _maybe_escalate_after_profile_probe(session, scan, tool, result, parsed, selected_tools, executable_tools, runner.keys(), target_url)
                if added_tools:
                    for added_tool in added_tools:
                        if added_tool not in planned_cases:
                            planned_cases.update(_create_planned_test_cases(session, scan, [added_tool], target_url))
                    scan.profile = "crapi-full-test" if _latest_application_profile(session, scan.id).get("lab_profile") == "crapi" else "api-security-authenticated-test"
                    ai_context.scan_plan["mode"] = scan.profile
                    ai_context.scan_plan["tools"] = selected_tools
                    session.add(
                        Log(
                            scan_id=scan.id,
                            level="info",
                            message="Scan mode escalated",
                            context={
                                "mode": scan.profile,
                                "added_tools": added_tools,
                                "reason": "Application profile and auth endpoints support authenticated API security workflow.",
                                "selected_tools": selected_tools,
                            },
                        )
                    )
                    if console:
                        console.print(f"Scan mode escalated: {scan.profile}")
                        console.print(f"Added tools: {', '.join(added_tools)}")
            except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.HTTPStatusError, ValueError, OSError, subprocess.SubprocessError) as exc:
                result = _record_tool(
                    session,
                    scan,
                    tool,
                    f"execute {tool}",
                    RunStatus.EXECUTION_ERROR.value,
                    {"error": str(exc), "reason": f"{tool} execution error"},
                    "tooling",
                    f"{tool} execution error",
                    f"execution_error_{tool}",
                )
                tool_results.append(result)
                _finish_agent_job(job, AgentJobStatus.FAILED.value, {"status": result.get("status")}, str(exc))
                emit_progress(session, scan, "agent failed", level="ERROR", phase=phase_name, agent=agent_name, tool=tool, event_type="agent_completed", context={"error": str(exc)}, console=console, live=debug_live)
                emit_progress(session, scan, f"error {exc}", level="ERROR", phase=phase_name, agent=agent_name, tool=tool, event_type="error", console=console, live=True)
                if tool in planned_cases:
                    planned_cases[tool].status = RunStatus.EXECUTION_ERROR.value
        if scan.status in {ScanStatus.PAUSED.value, ScanStatus.STOPPED.value}:
            session.flush()
            return scan, selected_tools, tool_results, parsed, {}
        discovery_for_review = _discovery_summary(session, scan.id)
        auth_for_review = _auth_testing_status(session, scan.id)
        try:
            emit_progress(session, scan, f"AI call started stage=evidence_review model={ai_context.model} timeout={get_settings().ollama_timeout_seconds}s", phase="ai_evidence_review", agent="ai_reviewer_agent", tool="ollama", event_type="ai_call_started", console=console, live=True)
            with heartbeat(scan.id, phase="ai_evidence_review", agent="ai_reviewer_agent", tool="ollama", console=console, live=debug_live):
                ai_review = ai_review_evidence(session, scan, ai_context)
        except Exception as exc:
            ai_review = {
                "evidence_review": "AI evidence review did not complete. A local rule-engine summary was used so the scan report can still be generated.",
                "finding_summary": [],
                "risk_notes": [],
                "ai_evidence_review_status": "failed_ai_chat",
                "ai_evidence_review_error": str(exc),
                "local_fallback_summary_used": True,
            }
        ai_review = _ground_ai_review(ai_review, discovery_for_review, auth_for_review)
        log_ai_review(session, scan, ai_context, ai_review)
        emit_progress(session, scan, f"AI call completed stage=evidence_review status={ai_review.get('ai_evidence_review_status', 'completed')}", phase="ai_evidence_review", agent="ai_reviewer_agent", tool="ollama", event_type="ai_call_completed", console=console, live=True)
        mark_phase(
            session,
            scan,
            "ai_evidence_review",
            RunStatus.COMPLETED.value if ai_review.get("ai_evidence_review_status", "completed") in {"completed", "completed_with_consistency_warning"} else RunStatus.EXECUTION_ERROR.value,
            {"status": ai_review.get("ai_evidence_review_status", "completed"), "local_fallback_summary_used": ai_review.get("local_fallback_summary_used", False)},
            ai_review.get("ai_evidence_review_error"),
        )
        sync_scan_phases(session, scan)
        session.flush()
        if console:
            status = ai_review.get("ai_evidence_review_status", "completed")
            for attempt in ai_review.get("ai_call_attempts") or []:
                console.print(
                    "AI call: "
                    f"stage=evidence_review model={attempt.get('model')} timeout={get_settings().ollama_timeout_seconds}s "
                    f"attempt={attempt.get('attempt')}/{get_settings().ollama_max_retries + 1} "
                    f"duration={round(int(attempt.get('duration_ms') or 0) / 1000, 2)}s "
                    f"result={attempt.get('response_status')}"
                )
            console.print(f"AI evidence review: {status}")
            if status != "completed" and ai_review.get("ai_evidence_review_error"):
                console.print(f"AI evidence review error: {ai_review.get('ai_evidence_review_error')}")
        execution_context = {
            "execution_summary": _execution_summary(selected_tools, tool_results),
            "discovery_summary": _discovery_summary(session, scan.id),
            "auth_testing_status": _auth_testing_status(session, scan.id),
            "pipeline": _pipeline_status(tool_results, ai_review),
        }
        _finalize_test_case_lifecycle(session, scan, execution_context)
        execution_context["coverage_matrix"] = _deterministic_coverage_matrix(session, scan, execution_context)
        session.add(
            Log(
                scan_id=scan.id,
                level="info",
                message="Execution summary",
                context=execution_context,
            )
        )
        _print_execution_summary(selected_tools, tool_results, console)
        _print_pipeline_summary(session, scan.id, tool_results, ai_review, console)
        scan.status = ScanStatus.COMPLETED.value
        scan.completed_at = datetime.now(timezone.utc)
        emit_progress(session, scan, "scan completed", phase="reporting", agent="reporting_agent", event_type="scan_completed", console=console, live=True)
    except Exception:
        scan.status = ScanStatus.FAILED.value
        scan.completed_at = datetime.now(timezone.utc)
        raise

    return scan, selected_tools, tool_results, parsed, ai_review


AGENT_BY_TOOL = {
    "http_client": "recon_agent",
    "technology_fingerprint": "recon_agent",
    "nmap_top_ports": "recon_agent",
    "nmap_full_tcp": "recon_agent",
    "nmap_service_detection": "recon_agent",
    "http_service_detection": "recon_agent",
    "root_link_inventory": "web_discovery_agent",
    "robots_txt": "web_discovery_agent",
    "sitemap_xml": "web_discovery_agent",
    "static_asset_inventory": "web_discovery_agent",
    "api_path_hints": "api_discovery_agent",
    "openapi_discovery": "api_discovery_agent",
    "api_profile_probe": "api_discovery_agent",
    "api_method_probe": "api_discovery_agent",
    "ffuf_api_paths": "api_discovery_agent",
    "gobuster_api_paths": "api_discovery_agent",
    "katana": "web_discovery_agent",
    "crawler": "web_discovery_agent",
    "gobuster_dir": "web_discovery_agent",
    "ffuf_dir": "web_discovery_agent",
    "auth_session_mapping": "auth_agent",
    "account_provisioning": "auth_agent",
    "login_session": "auth_agent",
    "authenticated_crawling": "auth_agent",
    "token_analysis": "token_agent",
    "authorization_matrix": "authorization_agent",
    "idor_bola_bfla_planner": "authorization_agent",
    "xss_adaptive": "input_validation_agent",
    "sqli_adaptive": "input_validation_agent",
    "ssrf_adaptive": "input_validation_agent",
    "jwt_adaptive": "token_agent",
    "input_validation_planner": "input_validation_agent",
    "business_logic_planner": "business_logic_agent",
    "shodan_search": "recon_agent",
}


def _agent_for_tool(tool: str) -> str:
    return AGENT_BY_TOOL.get(tool, "orchestrator_agent")


def _create_agent_job(
    session: Session,
    scan: Scan,
    agent_name: str,
    job_type: str,
    status: str,
    input_payload: dict | None = None,
    output_payload: dict | None = None,
) -> AgentJob:
    now = datetime.now(timezone.utc)
    job = AgentJob(
        scan_id=scan.id,
        agent_name=agent_name,
        job_type=job_type,
        status=status,
        priority=50,
        input=input_payload or {},
        output=output_payload,
        started_at=now if status != AgentJobStatus.QUEUED.value else None,
        completed_at=now if status in {AgentJobStatus.COMPLETED.value, AgentJobStatus.FAILED.value, AgentJobStatus.CANCELLED.value} else None,
    )
    session.add(job)
    session.flush()
    return job


def _finish_agent_job(job: AgentJob, status: str, output: dict | None = None, error: str | None = None) -> None:
    job.status = status
    job.output = output or {}
    job.error = error
    job.completed_at = datetime.now(timezone.utc)


def _create_planned_test_cases(session: Session, scan: Scan, selected_tools: list[str], target_url: str) -> dict[str, TestCase]:
    cases: dict[str, TestCase] = {}
    for index, tool in enumerate(selected_tools, start=1):
        agent_name = _agent_for_tool(tool)
        case = TestCase(
            scan_id=scan.id,
            case_id=f"scan-{scan.id}.{tool}",
            test_id=f"{agent_name}.{tool}",
            profile=scan.profile,
            phase=_phase_for_tool(tool),
            agent=agent_name,
            agent_name=agent_name,
            name=_name_for_tool(tool),
            category=_category_for_tool(tool),
            target=target_url,
            applicability="applicable",
            prerequisites=_prerequisites_for_tool(tool),
            tool=tool,
            selected_tool=tool,
            alternate_tools=_alternate_tools_for_tool(tool),
            status=RunStatus.PLANNED.value,
            priority=10 + index,
            enabled=True,
            definition={"source": "ai_planned_scan", "tool": tool},
        )
        session.add(case)
        cases[tool] = case
    session.flush()
    return cases


def _phase_for_tool(tool: str) -> str:
    if tool in {"openapi_discovery", "api_path_hints", "api_profile_probe", "api_method_probe", "ffuf_api_paths", "gobuster_api_paths"}:
        return "api_discovery"
    if tool in {"auth_session_mapping", "token_analysis", "account_provisioning", "login_session", "authenticated_crawling"}:
        return "authentication_discovery"
    if tool in {"authorization_matrix", "idor_bola_bfla_planner"}:
        return "authorization_testing"
    if tool in {"input_validation_planner", "xss_adaptive", "sqli_adaptive", "ssrf_adaptive"}:
        return "input_validation"
    if tool in {"jwt_adaptive"}:
        return "token_analysis"
    if tool in {"root_link_inventory", "robots_txt", "sitemap_xml", "static_asset_inventory", "katana", "crawler", "gobuster_dir", "ffuf_dir"}:
        return "web_enumeration"
    return "recon"


def _category_for_tool(tool: str) -> str:
    if "nmap" in tool:
        return "port_scan"
    if tool in {"gobuster_dir", "ffuf_dir"}:
        return "directory_discovery"
    if tool in {"katana", "crawler"}:
        return "web_crawling"
    if tool in {"openapi_discovery", "api_path_hints", "api_profile_probe", "api_method_probe", "ffuf_api_paths", "gobuster_api_paths"}:
        return "api_discovery"
    if tool in {"auth_session_mapping", "token_analysis", "account_provisioning", "login_session", "authenticated_crawling"}:
        return "authentication"
    if tool in {"authorization_matrix", "idor_bola_bfla_planner"}:
        return "authorization"
    if tool in {"xss_adaptive", "sqli_adaptive", "ssrf_adaptive"}:
        return "input_validation"
    if tool == "jwt_adaptive":
        return "jwt"
    return tool


def _name_for_tool(tool: str) -> str:
    return tool.replace("_", " ").title()


def _prerequisites_for_tool(tool: str) -> list[str]:
    dependency = TOOL_DEPENDENCIES.get(tool)
    return [dependency] if dependency else []


def _alternate_tools_for_tool(tool: str) -> list[str]:
    return {
        "crawler": ["katana", "internal_crawler", "wget_spider"],
        "katana": ["internal_crawler", "wget_spider"],
        "ffuf_dir": ["gobuster_dir", "internal_wordlist_discovery"],
        "gobuster_dir": ["ffuf_dir", "internal_wordlist_discovery"],
        "technology_fingerprint": ["whatweb", "internal_fingerprint", "httpx_fingerprint"],
        "nmap_top_ports": ["internal_socket_connect_scan"],
        "openapi_discovery": ["js_endpoint_extractor", "crawler_route_extraction", "options_probing"],
        "api_method_probe": ["profile_endpoint_probe", "js_endpoint_extractor"],
        "ffuf_api_paths": ["gobuster_api_paths", "internal_api_method_probe"],
        "gobuster_api_paths": ["ffuf_api_paths", "internal_api_method_probe"],
    }.get(tool, [])


def _scan_control_status(session: Session, scan: Scan) -> str:
    session.refresh(scan)
    if getattr(scan, "stop_requested", False):
        return ScanStatus.STOPPING.value
    if getattr(scan, "pause_requested", False):
        return ScanStatus.PAUSED.value
    return scan.status


def _execution_summary(selected_tools: list[str], tool_results: list[dict]) -> list[dict]:
    by_tool = {item.get("tool"): item for item in tool_results}
    summary = []
    for tool in selected_tools:
        result = by_tool.get(tool)
        if result:
            summary.append({"tool": tool, "status": result.get("status"), "evidence_path": result.get("evidence_path"), "reason": result.get("reason")})
        else:
            summary.append({"tool": tool, "status": RunStatus.EXECUTION_ERROR.value, "reason": "tool selected but no result was recorded"})
    return summary


def _discovery_summary(session: Session, scan_id: int) -> dict:
    endpoints = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan_id).all()
    auth_flows = session.query(DiscoveredAuthFlow).filter(DiscoveredAuthFlow.scan_id == scan_id).all()
    artifacts = session.query(PipelineArtifact).filter(PipelineArtifact.scan_id == scan_id).all()
    api_artifacts = [item for item in artifacts if item.artifact_type in {"api_method_probe", "api_profile_probe", "ffuf_api_paths", "gobuster_api_paths", "discovered_api_paths"}]
    api_candidates_tested = sum((item.data or {}).get("tested_count", 0) for item in api_artifacts)
    profile_tested = sum((item.data or {}).get("profile_endpoints_tested", 0) for item in api_artifacts)
    external_refs = sum((item.data or {}).get("external_reference_count", 0) for item in artifacts)
    return {
        "urls_discovered": len(endpoints),
        "directory_paths_discovered": len([item for item in endpoints if item.endpoint_type == "web" and item.source in {"gobuster_dir", "ffuf_dir", "internal_wordlist_discovery"}]),
        "api_candidates_tested": api_candidates_tested,
        "valid_api_endpoints_discovered": len([item for item in endpoints if item.endpoint_type in {"api", "api_auth", "api_spec"}]),
        "client_side_routes_discovered": len([item for item in endpoints if item.endpoint_type == "client_route"]),
        "external_references_discovered": len([item for item in endpoints if item.endpoint_type == "external"]) + external_refs,
        "profile_detected_endpoints_tested": profile_tested,
        "api_paths_discovered": len([item for item in endpoints if item.endpoint_type == "api"]),
        "forms_discovered": session.query(DiscoveredParameter).filter(DiscoveredParameter.scan_id == scan_id, DiscoveredParameter.location == "form").count(),
        "auth_endpoints_discovered": len(auth_flows),
        "confirmed_auth_endpoints": len([flow for flow in auth_flows if (flow.evidence or {}).get("endpoint_confidence") in {"high", "medium"} or not (flow.evidence or {}).get("endpoint_confidence")]),
        "candidate_auth_endpoints": len([endpoint for endpoint in endpoints if any(token in endpoint.url.lower() for token in ["/auth", "/login", "/signup", "/register", "/token", "/verify", "/otp"])]),
        "invalid_auth_candidates": max(0, len([endpoint for endpoint in endpoints if any(token in endpoint.url.lower() for token in ["/auth", "/login", "/signup", "/register", "/token", "/verify", "/otp"])]) - len(auth_flows)),
        "static_assets_discovered": session.query(DiscoveredAsset).filter(DiscoveredAsset.scan_id == scan_id).count(),
        "open_ports_discovered": len([item for item in endpoints if item.endpoint_type == "port"]),
    }


def _auth_testing_status(session: Session, scan_id: int) -> dict:
    credentials = load_credentials()
    scan = session.get(Scan, scan_id)
    auth_sessions = _authenticated_sessions_for_scan(session, scan) if scan else []
    flows = session.query(DiscoveredAuthFlow).filter(DiscoveredAuthFlow.scan_id == scan_id).all()
    flow_types = {flow.flow_type for flow in flows}
    token_count = session.query(DiscoveredToken).filter(DiscoveredToken.scan_id == scan_id).count()
    roles = {item.get("role") for item in credentials if item.get("role")}
    tenants = {item.get("tenant") for item in credentials if item.get("tenant")}
    return {
        "login_endpoint": "found" if "login" in flow_types else "not_found",
        "registration_endpoint": "found" if "registration" in flow_types else "not_found",
        "sso_oidc_saml": "found" if flow_types.intersection({"sso", "oauth", "oidc", "saml"}) else "not_found",
        "jwt_bearer_token": "found" if token_count else "not_found",
        "credentials": "configured" if credentials or auth_sessions else "missing",
        "authenticated_sessions": len(auth_sessions),
        "cross_account_testing": "configured" if len(auth_sessions) >= 2 or (len(credentials) >= 2 and (len(roles) >= 2 or len(tenants) >= 2)) else "missing_credentials",
    }


def _print_execution_summary(selected_tools: list[str], tool_results: list[dict], console: Console | None) -> None:
    if not console:
        return
    console.print("Execution summary:")
    by_tool = {item.get("tool"): item for item in tool_results}
    for tool in selected_tools:
        result = by_tool.get(tool)
        status = result.get("status") if result else RunStatus.EXECUTION_ERROR.value
        console.print(f"{tool}: {status}")


def _pipeline_status(tool_results: list[dict], ai_review: dict) -> list[dict]:
    statuses = {item.get("tool"): item.get("status") for item in tool_results}
    discovery_tools = ["crawler", "katana", "gobuster_dir", "ffuf_dir", "api_path_hints", "static_asset_inventory"]
    auth_status = statuses.get("auth_session_mapping") or RunStatus.NOT_APPLICABLE.value
    authz_status = statuses.get("authorization_matrix") or RunStatus.NOT_APPLICABLE.value
    return [
        {"stage": "AI planning", "status": RunStatus.COMPLETED.value},
        {"stage": "Baseline enumeration", "status": _combined_status([statuses.get("http_client"), statuses.get("technology_fingerprint")])},
        {"stage": "Discovery expansion", "status": _combined_status([statuses.get(tool) for tool in discovery_tools])},
        {"stage": "Auth mapping", "status": auth_status},
        {"stage": "Authorization matrix", "status": authz_status},
        {"stage": "AI evidence review", "status": RunStatus.COMPLETED.value if ai_review else RunStatus.EXECUTION_ERROR.value},
        {"stage": "Report", "status": "generated"},
    ]


def _finalize_test_case_lifecycle(session: Session, scan: Scan, execution_context: dict) -> None:
    coverage = _deterministic_coverage_matrix(session, scan, execution_context)
    existing = {item.case_id: item for item in session.query(TestCase).filter(TestCase.scan_id == scan.id).all()}
    for item in coverage:
        case_id = f"coverage.{_slug(item['category'])}"
        status = item["status"]
        if status == "not_run":
            status = RunStatus.MISSING_PREREQUISITE.value if item.get("applicable") else RunStatus.NOT_APPLICABLE.value
        definition = {
            "source": "deterministic_coverage_rules",
            "reason": item.get("reason"),
            "required_artifact": item.get("required_artifact"),
            "how_to_make_testable": item.get("how_to_make_testable"),
            "client_action_required": item.get("client_action_required", False),
            "next_action": item.get("next_action"),
        }
        if case_id in existing:
            if existing[case_id].status == RunStatus.PLANNED.value:
                existing[case_id].status = status
            existing[case_id].definition = {**(existing[case_id].definition or {}), **definition}
            existing[case_id].applicability = "applicable" if item.get("applicable") else "not_applicable"
            existing[case_id].prerequisites = [item.get("required_artifact")] if item.get("required_artifact") else []
            continue
        test_case = TestCase(
            scan_id=scan.id,
            case_id=case_id,
            test_id=case_id,
            profile=scan.profile,
            phase=item.get("phase") or "coverage",
            agent=item.get("agent") or "orchestrator_agent",
            agent_name=item.get("agent") or "orchestrator_agent",
            name=item["category"],
            category=item["category"],
            target=None,
            applicability="applicable" if item.get("applicable") else "not_applicable",
            prerequisites=[item.get("required_artifact")] if item.get("required_artifact") else [],
            tool=item.get("tool") or "coverage_rule",
            selected_tool=item.get("tool") or "coverage_rule",
            alternate_tools=[],
            status=status,
            priority=200,
            enabled=True,
            definition=definition,
        )
        session.add(test_case)
    for case in session.query(TestCase).filter(TestCase.scan_id == scan.id, TestCase.status == RunStatus.PLANNED.value).all():
        case.status = RunStatus.MISSING_PREREQUISITE.value
        case.definition = {**(case.definition or {}), "reason": "Test case was planned but no executor result was recorded.", "how_to_make_testable": "Rerun the applicable scan phase or inspect tool execution logs."}
    session.flush()


def _create_scan_test_plan(session: Session, scan: Scan, categories: list[str]) -> None:
    now = datetime.now(timezone.utc)
    existing = {
        item.category: item
        for item in session.query(ScanTestPlan).filter(ScanTestPlan.scan_id == scan.id).all()
    }
    for category in dict.fromkeys(item.strip() for item in categories if item and item.strip()):
        if category in existing:
            existing[category].enabled = True
            existing[category].status = existing[category].status or RunStatus.PLANNED.value
            existing[category].reason = "Selected from dashboard/CLI scan control."
            existing[category].updated_at = now
        else:
            session.add(
                ScanTestPlan(
                scan_id=scan.id,
                category=category,
                enabled=True,
                status=RunStatus.PLANNED.value,
                reason="Selected from dashboard/CLI scan control.",
                created_at=now,
                updated_at=now,
                )
            )


def _deterministic_coverage_matrix(session: Session, scan: Scan, execution_context: dict) -> list[dict]:
    tool_runs = session.query(ToolRun).filter(ToolRun.scan_id == scan.id).all()
    status_by_tool = {item.tool_name: item.status for item in tool_runs}
    findings = session.query(Finding).filter(Finding.scan_id == scan.id).all()
    auth = execution_context.get("auth_testing_status") or _auth_testing_status(session, scan.id)
    discovery = execution_context.get("discovery_summary") or _discovery_summary(session, scan.id)
    parameters = session.query(DiscoveredParameter).filter(DiscoveredParameter.scan_id == scan.id).all()
    tokens = session.query(DiscoveredToken).filter(DiscoveredToken.scan_id == scan.id).count()
    objects = session.query(DiscoveredObject).filter(DiscoveredObject.scan_id == scan.id).count()
    credentials = load_credentials()
    mode = scan.engagement_mode or "black_box"

    def entry(category, tools, applicable=True, reason=None, required=None, next_action=None, phase=None, agent=None):
        statuses = [status_by_tool.get(tool) for tool in tools if status_by_tool.get(tool)]
        status = _coverage_status_local(statuses)
        if not statuses:
            status = RunStatus.MISSING_PREREQUISITE.value if applicable and required else RunStatus.NOT_APPLICABLE.value if not applicable else "not_run"
        category_findings = [finding for finding in findings if category.lower().split("/")[0] in (finding.vulnerability_type or finding.title or "").lower()]
        return {
            "category": category,
            "applicable": applicable,
            "status": status,
            "test_cases_planned": len(tools),
            "test_cases_executed": len(statuses),
            "findings": len(category_findings),
            "missing_prerequisites": required if status in {RunStatus.MISSING_PREREQUISITE.value, "not_run"} else None,
            "not_applicable_reason": reason if not applicable else None,
            "reason": reason,
            "required_artifact": required,
            "how_to_make_testable": _how_to_make_testable(required),
            "client_action_required": bool(required and mode != "black_box"),
            "evidence_path": _latest_tool_evidence(tool_runs, tools),
            "next_action": next_action or f"./saif.sh scan continue --scan-id {scan.id} --phase {phase or 'account_provisioning'} --full",
            "phase": phase,
            "agent": agent,
            "tool": tools[0] if tools else None,
        }

    has_url_param = any((param.name or "").lower() in {"url", "uri", "callback", "webhook", "redirect", "next", "returnurl"} for param in parameters)
    has_params = bool(parameters)
    auth_required = auth.get("login_endpoint") == "found" or auth.get("registration_endpoint") == "found"
    two_sessions = auth.get("authenticated_sessions", 0) >= 2
    matrix = [
        entry("Authentication", ["auth_session_mapping", "account_provisioning", "login_session"], auth_required, "No login or registration endpoint discovered." if not auth_required else ("Credentials/account provisioning required." if mode == "black_box" and not credentials else None), "valid credentials or registration flow" if auth_required and mode == "black_box" and not credentials else None, phase="login_session", agent="auth_agent"),
        entry("Session management", ["login_session", "token_analysis"], auth_required, required="authenticated session" if auth_required and auth.get("authenticated_sessions", 0) == 0 else None, phase="token_analysis", agent="token_agent"),
        entry("JWT/token security", ["jwt_adaptive", "token_analysis"], bool(tokens or auth_required), required="captured JWT/bearer token" if not tokens else None, phase="token_analysis", agent="token_agent"),
        entry("Authorization", ["authorization_matrix"], auth_required, required="authenticated session" if auth.get("authenticated_sessions", 0) == 0 else None, phase="authorization_testing", agent="authorization_agent"),
        entry("BOLA/IDOR", ["authorization_matrix", "idor_bola_bfla_planner"], auth_required, required="two user sessions and at least one object ID" if not two_sessions or not objects else None, phase="authorization_testing", agent="authorization_agent"),
        entry("BFLA", ["authorization_matrix", "idor_bola_bfla_planner"], auth_required, required="authenticated sessions with role/function coverage" if auth.get("authenticated_sessions", 0) == 0 else None, phase="authorization_testing", agent="authorization_agent"),
        entry("Mass assignment", ["input_validation_planner"], has_params, "No writable JSON/body fields discovered." if not has_params else None, "writable JSON/body fields" if not has_params else None, phase="input_validation_testing", agent="input_validation_agent"),
        entry("Input validation", ["input_validation_planner"], has_params, "No parameters/forms/JSON fields discovered." if not has_params else None, "parameters/forms/JSON fields" if not has_params else None, phase="input_validation_testing", agent="input_validation_agent"),
        entry("XSS", ["xss_adaptive"], has_params, "No reflected form/query parameters discovered." if not has_params else None, "form/query parameter" if not has_params else None, phase="input_validation_testing", agent="input_validation_agent"),
        entry("SQL injection", ["sqli_adaptive"], has_params, "No parameters/forms/JSON fields discovered." if not has_params else None, "parameter or JSON field" if not has_params else None, phase="input_validation_testing", agent="input_validation_agent"),
        entry("SSRF", ["ssrf_adaptive"], has_url_param, "No URL/callback/webhook/fetch parameter discovered and no callback listener configured." if not has_url_param else None, "URL-like parameter or collaborator callback endpoint" if not has_url_param else None, phase="input_validation_testing", agent="input_validation_agent"),
        entry("Open redirect", ["input_validation_planner"], has_url_param, "No redirect/next/return URL parameter discovered." if not has_url_param else None, "redirect-like parameter" if not has_url_param else None, phase="input_validation_testing", agent="input_validation_agent"),
        entry("Path traversal", ["input_validation_planner"], has_params, required="path/file parameter" if not has_params else None, phase="input_validation_testing", agent="input_validation_agent"),
        entry("File upload if detected", ["input_validation_planner"], False, "No file upload flow detected.", "file upload endpoint", phase="input_validation_testing", agent="input_validation_agent"),
        entry("Rate limiting", ["business_logic_planner"], auth_required, required="login/OTP/password reset endpoint" if not auth_required else None, phase="business_logic_testing", agent="business_logic_agent"),
        entry("OTP/password reset abuse", ["business_logic_planner"], auth_required, required="OTP/password reset endpoint" if not auth_required else None, phase="business_logic_testing", agent="business_logic_agent"),
        entry("Business logic", ["business_logic_planner"], bool(discovery.get("valid_api_endpoints_discovered")), required="identified business workflow" if not discovery.get("valid_api_endpoints_discovered") else None, phase="business_logic_testing", agent="business_logic_agent"),
        entry("Security misconfiguration", ["technology_fingerprint", "openapi_discovery"], True, phase="enumeration", agent="recon_agent"),
        entry("CORS", ["technology_fingerprint"], True, phase="enumeration", agent="recon_agent"),
        entry("HTTP methods", ["api_method_probe"], True, phase="api_discovery", agent="api_discovery_agent"),
        entry("Sensitive information exposure", ["http_client", "static_asset_inventory"], True, phase="enumeration", agent="recon_agent"),
        entry("Error handling", ["api_method_probe", "input_validation_planner"], True, phase="api_discovery", agent="api_discovery_agent"),
        entry("API inventory/versioning", ["openapi_discovery", "api_profile_probe", "api_method_probe"], True, phase="api_discovery", agent="api_discovery_agent"),
        entry("GraphQL if detected", ["api_profile_probe"], False, "GraphQL endpoint not detected.", "GraphQL endpoint", phase="api_discovery", agent="api_discovery_agent"),
        entry("WebSocket if detected", ["api_path_hints"], False, "WebSocket endpoint not detected.", "WebSocket endpoint", phase="api_discovery", agent="api_discovery_agent"),
    ]
    if mode == "white_box" and not scan.source_path:
        matrix.append(entry("White-box source review", ["source_assisted_review"], True, "Source code path was not provided.", "source-path", phase="source_review", agent="source_review_agent"))
    return matrix


def _coverage_status_local(statuses: list[str]) -> str:
    if not statuses:
        return "not_run"
    if any(status == RunStatus.FINDING_CREATED.value for status in statuses):
        return RunStatus.FINDING_CREATED.value
    if any(status in {RunStatus.EXECUTION_ERROR.value, RunStatus.MISSING_CREDENTIALS.value, RunStatus.MISSING_PREREQUISITE.value} for status in statuses):
        return next(status for status in statuses if status in {RunStatus.EXECUTION_ERROR.value, RunStatus.MISSING_CREDENTIALS.value, RunStatus.MISSING_PREREQUISITE.value})
    if any(status == RunStatus.MANUAL_CONFIRMATION_REQUIRED.value for status in statuses):
        return RunStatus.MANUAL_CONFIRMATION_REQUIRED.value
    if any(status == RunStatus.COMPLETED.value for status in statuses):
        return RunStatus.COMPLETED.value
    return statuses[0]


def _latest_tool_evidence(tool_runs: list[ToolRun], tools: list[str]) -> str | None:
    for run in sorted(tool_runs, key=lambda item: item.id, reverse=True):
        if run.tool_name in tools and run.evidence_path:
            return run.evidence_path
    return None


def _how_to_make_testable(required: str | None) -> str | None:
    if not required:
        return None
    return f"Provide {required} and rerun the applicable scan phase."


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _ground_ai_review(ai_review: dict, discovery: dict, auth: dict) -> dict:
    text = " ".join(
        str(value)
        for value in [
            ai_review.get("evidence_review"),
            ai_review.get("risk_notes"),
            ai_review.get("finding_summary"),
        ]
    ).lower()
    contradictions = []
    if discovery.get("valid_api_endpoints_discovered", 0) > 0 and any(
        phrase in text for phrase in ["no valid api endpoints", "no api endpoints were found", "no valid endpoints were found"]
    ):
        contradictions.append("AI review said no valid API endpoints while structured discovery recorded valid API endpoints.")
    if auth.get("login_endpoint") == "found" and any(phrase in text for phrase in ["no login endpoint", "login endpoint was not found"]):
        contradictions.append("AI review said no login endpoint while structured discovery recorded a login endpoint.")
    if not contradictions:
        ai_review.setdefault("ai_review_consistency", "passed")
        return ai_review
    local_summary = (
        f"Structured evidence recorded {discovery.get('valid_api_endpoints_discovered', 0)} valid API endpoints, "
        f"{discovery.get('auth_endpoints_discovered', 0)} auth endpoints, login_endpoint={auth.get('login_endpoint')}, "
        f"registration_endpoint={auth.get('registration_endpoint')}, authenticated_sessions={auth.get('authenticated_sessions')}."
    )
    grounded = dict(ai_review)
    grounded["ai_review_consistency"] = "failed"
    grounded["ai_review_consistency_warnings"] = contradictions
    grounded["ai_evidence_review_status"] = "completed_with_consistency_warning"
    grounded["ai_evidence_review_error"] = "; ".join(contradictions)
    grounded["evidence_review"] = local_summary
    grounded["local_fallback_summary_used"] = True
    grounded["finding_summary"] = [
        {
            "title": "Evidence review consistency warning",
            "description": local_summary,
            "severity": "info",
        }
    ]
    return grounded


def _combined_status(values: list[str | None]) -> str:
    present = [value for value in values if value]
    if not present:
        return RunStatus.NOT_APPLICABLE.value
    if any(value == RunStatus.COMPLETED.value for value in present):
        return RunStatus.COMPLETED.value
    if any(value == RunStatus.EXECUTION_ERROR.value for value in present):
        return RunStatus.EXECUTION_ERROR.value
    return present[0]


def _print_pipeline_summary(session: Session, scan_id: int, tool_results: list[dict], ai_review: dict, console: Console | None) -> None:
    if not console:
        return
    pipeline = _pipeline_status(tool_results, ai_review)
    console.print("Pipeline:")
    for idx, item in enumerate(pipeline, start=1):
        console.print(f"{idx}. {item['stage']}: {item['status']}")
    discovery = _discovery_summary(session, scan_id)
    console.print("Discovery summary:")
    console.print(f"URLs discovered: {discovery['urls_discovered']}")
    console.print(f"Directory paths discovered: {discovery['directory_paths_discovered']}")
    console.print(f"API candidates tested: {discovery['api_candidates_tested']}")
    console.print(f"Valid API endpoints discovered: {discovery['valid_api_endpoints_discovered']}")
    console.print(f"Client-side routes discovered: {discovery['client_side_routes_discovered']}")
    console.print(f"External references discovered: {discovery['external_references_discovered']}")
    console.print(f"API paths discovered: {discovery['api_paths_discovered']}")
    console.print(f"Forms discovered: {discovery['forms_discovered']}")
    console.print(f"Auth endpoints discovered: {discovery['auth_endpoints_discovered']}")
    console.print(f"Confirmed auth endpoints: {discovery['confirmed_auth_endpoints']}")
    console.print(f"Candidate auth endpoints: {discovery['candidate_auth_endpoints']}")
    console.print(f"Static assets discovered: {discovery['static_assets_discovered']}")
    console.print(f"Open ports discovered: {discovery['open_ports_discovered']}")
    auth = _auth_testing_status(session, scan_id)
    console.print("Auth testing status:")
    console.print(f"Login endpoint: {auth['login_endpoint']}")
    console.print(f"Registration endpoint: {auth.get('registration_endpoint')}")
    console.print(f"SSO/OIDC/SAML: {auth['sso_oidc_saml']}")
    console.print(f"JWT/Bearer token: {auth['jwt_bearer_token']}")
    console.print(f"Credentials: {auth['credentials']}")
    console.print(f"Authenticated sessions: {auth.get('authenticated_sessions', 0)}")
    console.print(f"Cross-account testing: {auth['cross_account_testing']}")
    api = _api_discovery_console_summary(session, scan_id)
    console.print("API discovery:")
    console.print(f"JS extraction: {api['js_status']}, {api['js_strings_found']} candidate strings found")
    console.print(f"Application profile: {api['profile_status']}")
    console.print(f"Profile endpoints tested: {api['profile_endpoints_tested']}")
    console.print(f"Valid API endpoints: {api['valid_api_endpoints']}")
    console.print(f"Auth endpoints: {api['auth_endpoints']}")
    console.print(f"Next stage: {api['next_stage']}")
    account = _latest_tool_output(session, scan_id, "account_provisioning")
    if account:
        console.print("Account provisioning:")
        for item in (account.get("users") or []):
            console.print(f"{item.get('label')}: {item.get('status')}")
    login = _latest_tool_output(session, scan_id, "login_session")
    if login:
        console.print("Login:")
        for item in (login.get("users") or []):
            console.print(f"{item.get('label')}: {item.get('status')}")
    if login:
        console.print("Token:")
        for item in (login.get("users") or []):
            token = item.get("token") or {}
            if token.get("masked_sample"):
                console.print(f"{item.get('label')}: bearer captured, jwt {'decoded' if token.get('alg') or token.get('sub') else 'not_decoded'}")
    crawl = _latest_tool_output(session, scan_id, "authenticated_crawling")
    if crawl:
        console.print("Authenticated crawling:")
        for label, status in (crawl.get("session_statuses") or {}).items():
            console.print(f"{label}: {status}")
    authz = _latest_tool_output(session, scan_id, "authorization_matrix")
    if authz:
        console.print("Authorization matrix:")
        console.print(authz.get("status") or ("finding_created" if authz.get("findings_created") else RunStatus.COMPLETED.value if authz.get("checks") else authz.get("reason", RunStatus.NOT_APPLICABLE.value)))
    idor = _latest_tool_output(session, scan_id, "idor_bola_bfla_planner")
    if idor:
        console.print("IDOR/BOLA/BFLA:")
        console.print(idor.get("status") or idor.get("reason") or RunStatus.COMPLETED.value)
    payload_sources = payload_library_status()
    console.print("Payload sources:")
    console.print(f"XSS: {payload_sources.get('xss', {}).get('active_source')} {payload_sources.get('xss', {}).get('active_path')}")
    console.print(f"SQLi: {payload_sources.get('sqli', {}).get('active_source')} {payload_sources.get('sqli', {}).get('active_path')}")
    console.print(f"JWT: {payload_sources.get('jwt', {}).get('active_source')} {payload_sources.get('jwt', {}).get('active_path')}")
    console.print("Adaptive testing:")
    for tool, label in [("xss_adaptive", "xss_agent"), ("sqli_adaptive", "sqli_agent"), ("jwt_adaptive", "jwt_agent"), ("authorization_matrix", "authorization_agent")]:
        output = _latest_tool_output(session, scan_id, tool)
        if output:
            console.print(f"{label}: {output.get('status') or 'completed'}")


def _latest_tool_output(session: Session, scan_id: int, tool_name: str) -> dict | None:
    run = (
        session.query(ToolRun)
        .filter(ToolRun.scan_id == scan_id, ToolRun.tool_name == tool_name)
        .order_by(ToolRun.id.desc())
        .first()
    )
    return run.output if run else None


def _api_discovery_console_summary(session: Session, scan_id: int) -> dict:
    artifacts = session.query(PipelineArtifact).filter(PipelineArtifact.scan_id == scan_id).all()
    profile_artifact = next((item.data for item in artifacts if item.artifact_type == "api_profile_probe"), {}) or {}
    method_artifact = next((item.data for item in artifacts if item.artifact_type == "api_method_probe"), {}) or {}
    js_artifact = next((item.data for item in artifacts if item.artifact_type == "discovered_js_strings"), {}) or {}
    auth_count = session.query(DiscoveredAuthFlow).filter(DiscoveredAuthFlow.scan_id == scan_id).count()
    valid_count = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan_id, DiscoveredEndpoint.endpoint_type.in_(["api", "api_auth", "api_spec"])).count()
    return {
        "js_status": RunStatus.COMPLETED.value if js_artifact or method_artifact else RunStatus.NOT_APPLICABLE.value,
        "js_strings_found": js_artifact.get("count") or method_artifact.get("js_strings_found") or 0,
        "profile_status": profile_artifact.get("primary_profile") or profile_artifact.get("app_profile") or method_artifact.get("primary_profile") or method_artifact.get("app_profile") or "not_detected",
        "profile_endpoints_tested": profile_artifact.get("profile_endpoints_tested") or 0,
        "valid_api_endpoints": valid_count,
        "auth_endpoints": auth_count,
        "next_stage": "account provisioning" if auth_count else "continue API route discovery",
    }


def _print_tool_preparation(preparation, console: Console | None) -> None:
    if not console:
        return
    console.print("Tool preparation:")
    for attempt in preparation.attempts:
        display_status = "failed" if attempt.status == RunStatus.TOOL_INSTALL_FAILED.value else attempt.status
        console.print(f"{attempt.tool}: missing")
        if attempt.attempted:
            console.print(f"{attempt.tool} install: attempted")
        console.print(f"{attempt.tool} install: {display_status}" + (f" - {attempt.reason}" if attempt.reason else ""))
        console.print(f"{attempt.tool} status: {attempt.status}")
    console.print(f"Continuing with remaining tools: {', '.join(preparation.executable_tools) if preparation.executable_tools else 'none'}")


def _record_install_attempt(session: Session, scan: Scan, attempt: ToolInstallAttempt) -> dict:
    tool_name = _tool_for_dependency(attempt.tool)
    return _record_tool(
        session,
        scan,
        tool_name,
        attempt.command or f"install {attempt.tool}",
        attempt.status,
        {
            "reason": attempt.reason or f"{attempt.tool} is not installed",
            "attempted": attempt.attempted,
            "dependency": attempt.tool,
            "installer_output": attempt.output,
        },
        "tooling",
        f"{attempt.tool} tool preparation",
        f"tool_prepare_{attempt.tool}",
    )


def _tool_for_dependency(dependency: str) -> str:
    for tool, required in TOOL_DEPENDENCIES.items():
        if required == dependency:
            return tool
    return dependency


def _normalize_ai_tools(raw_tools: list | tuple, supported_tools) -> list[str]:
    if not raw_tools:
        return []
    supported = set(supported_tools)
    normalized: list[str] = []
    for item in raw_tools or []:
        tool = TOOL_ALIASES.get(str(item), str(item))
        if tool in supported and tool not in normalized:
            normalized.append(tool)
    if "http_client" not in normalized:
        normalized.insert(0, "http_client")
    return normalized


FULL_API_SECURITY_TOOLS = [
    "auth_session_mapping",
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


def _maybe_escalate_after_profile_probe(
    session: Session,
    scan: Scan,
    tool: str,
    result: dict,
    parsed: dict,
    selected_tools: list[str],
    executable_tools: list[str],
    supported_tools,
    target_url: str,
) -> list[str]:
    if tool not in {"api_profile_probe", "api_method_probe", "auth_session_mapping"}:
        return []
    profile = _latest_application_profile(session, scan.id)
    if not profile:
        return []
    auth = _auth_testing_status(session, scan.id)
    crapi_detected = profile.get("primary_profile") == "crapi" or profile.get("lab_profile") == "crapi"
    full_requested = parsed.get("full_scan") or parsed.get("auth_scan") or parsed.get("vuln_test")
    auth_ready = auth.get("login_endpoint") == "found" and auth.get("registration_endpoint") == "found"
    if not (full_requested or (crapi_detected and auth_ready and scan.authorized_testing_mode)):
        return []
    next_command = f"./saif.sh scan continue --scan-id {scan.id} --phase account_provisioning --full"
    if parsed.get("enumeration_only"):
        _artifact(
            session,
            scan,
            "scan_mode_recommendation",
            "next_full_api_security_workflow",
            {
                "recommended_command": next_command,
                "reason": "Application profile and auth endpoints support authenticated API security workflow.",
                "profile": profile,
                "auth_testing_status": auth,
                "auto_continue": False,
            },
        )
        return []
    supported = set(supported_tools)
    added = []
    for candidate in FULL_API_SECURITY_TOOLS:
        if candidate not in supported or candidate in selected_tools:
            continue
        selected_tools.append(candidate)
        executable_tools.append(candidate)
        added.append(candidate)
    if added:
        _artifact(
            session,
            scan,
            "scan_mode_escalation",
            "auto_profile_escalation",
            {
                "from_mode": scan.profile,
                "to_mode": "crapi-full-test" if crapi_detected else "api-security-authenticated-test",
                "profile": profile,
                "auth_testing_status": auth,
                "added_tools": added,
                "next_recommended_command": next_command,
                "target": target_url,
            },
        )
    return added


def _latest_application_profile(session: Session, scan_id: int) -> dict:
    profile = (
        session.query(ApplicationProfile)
        .filter(ApplicationProfile.scan_id == scan_id)
        .order_by(ApplicationProfile.id.desc())
        .first()
    )
    if not profile:
        return {}
    return {
        "primary_profile": profile.primary_profile,
        "secondary_profiles": profile.secondary_profiles or [],
        "lab_profile": profile.lab_profile,
        "confidence": profile.confidence,
        "observed": profile.observed or {},
    }


def _mode_from_prompt(parsed: dict) -> str:
    if parsed.get("crapi_full_test") or parsed.get("full_scan"):
        return "crapi-full-test"
    if parsed.get("strong_api_discovery"):
        return "strong-crapi-api-discovery"
    if parsed.get("default_enumeration"):
        return "default-enumeration"
    return "manual-prompt"


def _engagement_mode_from_prompt(parsed: dict, credentials_path: str | None = None, source_path: str | None = None) -> str:
    if parsed.get("mode_white_box") or source_path:
        return "white_box"
    if parsed.get("mode_gray_box") or credentials_path:
        return "gray_box"
    if parsed.get("mode_black_box"):
        return "black_box"
    return "black_box"


def _host_allowed_for_nmap(target_url: str) -> bool:
    return bool(_target_host(target_url))


def _target_host(target_url: str) -> str | None:
    parsed = urlparse(target_url)
    if parsed.hostname:
        return parsed.hostname
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", target_url):
        return target_url
    return None


def _http_get(url: str) -> tuple[str, dict]:
    try:
        response = httpx.get(url, follow_redirects=True, timeout=10)
        return RunStatus.COMPLETED.value, {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body_preview": response.text[:4000],
            "_text": response.text,
            "final_url": str(response.url),
        }
    except Exception as exc:
        return RunStatus.TARGET_UNREACHABLE.value, {"error": str(exc)}


def _record_tool(
    session: Session,
    scan: Scan,
    tool: str,
    command: str,
    status: str,
    output: dict,
    evidence_kind: str,
    summary: str,
    evidence_id: str,
) -> dict:
    stored_output = {key: value for key, value in output.items() if not key.startswith("_")}
    now = datetime.now(timezone.utc)
    agent_name = _agent_for_tool(tool)
    test_case = (
        session.query(TestCase)
        .filter(TestCase.scan_id == scan.id, TestCase.selected_tool == tool)
        .order_by(TestCase.id.desc())
        .first()
    )
    test_run = TestRun(
        scan_id=scan.id,
        test_case_id=test_case.id if test_case else None,
        agent_name=agent_name,
        tool_name=tool,
        command=command,
        status=status,
        started_at=now,
        completed_at=now,
        duration_ms=0,
        output_summary=summary,
        error_message=output.get("error"),
        output=stored_output,
    )
    session.add(test_run)
    session.flush()
    tool_run = ToolRun(
        scan_id=scan.id,
        test_run_id=test_run.id,
        test_case_id=test_case.id if test_case else None,
        agent_name=agent_name,
        tool_name=tool,
        command=command,
        status=status,
        started_at=now,
        completed_at=now,
        duration_ms=0,
        output=stored_output,
    )
    session.add(tool_run)
    session.flush()
    payload = {"tool": tool, "command": command, "status": status, "output": stored_output}
    if "error" in output:
        payload["error"] = output["error"]
    if output.get("reason"):
        payload["reason"] = output.get("reason")
    path = write_evidence(scan.id, evidence_id, payload)
    evidence = Evidence(
        scan_id=scan.id,
        test_run_id=test_run.id,
        kind=evidence_kind,
        path=str(path),
        summary=summary,
        metadata_json={"tool_run_id": tool_run.id, "tool": tool, "status": status},
    )
    session.add(evidence)
    session.flush()
    emit_progress(
        session,
        scan,
        f"evidence={path}",
        phase=_phase_for_tool(tool),
        agent=agent_name,
        tool=tool,
        event_type="evidence_written",
        context={"evidence_path": str(path), "status": status},
    )
    test_run.evidence_id = evidence.id
    tool_run.evidence_path = str(path)
    if test_case:
        test_case.status = RunStatus.ALTERNATE_TOOL_USED.value if output.get("alternate_tool") and status == RunStatus.COMPLETED.value else status
    result = {"tool": tool, "status": status, "command": command, "evidence_path": str(path), "reason": output.get("reason")}
    return result


def _finding(session: Session, scan: Scan, title: str, description: str, evidence_id: int | None = None) -> None:
    finding = Finding(
        scan_id=scan.id,
        title=title,
        severity="info",
        description=description,
        evidence_id=evidence_id,
        status="informational",
        confidence="medium",
        business_impact="Informational observation to support tester review, coverage tracking, and follow-up validation.",
        technical_impact=description,
        remediation="Review this observation during triage and document whether it affects scope, attack surface, or follow-up testing.",
        ai_reasoning_summary=description,
        retest_status="not_retested",
    )
    session.add(finding)
    session.flush()
    emit_progress(session, scan, f"finding created: {title}", phase=scan.current_phase, agent=scan.current_agent, tool=scan.current_tool, event_type="finding_created", context={"finding_id": finding.id, "title": title, "severity": finding.severity})


def _adaptive_finding(
    session: Session,
    scan: Scan,
    title: str,
    severity: str,
    description: str,
    endpoint: str,
    parameter: str | None,
    payload: str | None,
    confidence: str,
    evidence_id: int | None = None,
    status: str = RunStatus.FINDING_CREATED.value,
) -> None:
    dedupe_key = {
        "scan_id": scan.id,
        "title": title[:255],
        "endpoint": endpoint,
        "parameter": parameter,
        "payload": payload,
    }
    existing = (
        session.query(Finding)
        .filter(
            Finding.scan_id == dedupe_key["scan_id"],
            Finding.title == dedupe_key["title"],
            Finding.affected_endpoint == dedupe_key["endpoint"],
            Finding.parameter == dedupe_key["parameter"],
            Finding.payload == dedupe_key["payload"],
        )
        .one_or_none()
    )
    if existing:
        return
    finding = Finding(
        scan_id=scan.id,
        title=title[:255],
        severity=severity,
        description=description,
        evidence_id=evidence_id,
        status=status,
        affected_endpoint=endpoint,
        http_method="GET",
        parameter=parameter,
        payload=payload,
        payload_source="payload library",
        payload_type=payload,
        vulnerability_type=(title.split()[1].lower() if title.lower().startswith("potential ") and len(title.split()) > 1 else title.split()[0].lower()),
        agent_name="input_validation_agent",
        test_case_id=f"adaptive.{title.lower().replace(' ', '_')[:80]}",
        confidence=confidence,
        business_impact="Potential exposure of application data or integrity impact depending on affected endpoint and exploitability.",
        technical_impact=description,
        reproduction_steps=f"Send payload {payload!r} to {parameter or 'target'} at {endpoint}. Compare with baseline response and attached evidence.",
        remediation="Validate input server-side, enforce output encoding, and add authorization/session checks appropriate to the affected endpoint.",
        secure_code_guidance="Apply allow-list validation, contextual output encoding, least-privilege authorization checks, and regression tests for the affected route.",
        references_json=[],
        ai_reasoning_summary=description,
        retest_status="not_retested",
    )
    session.add(finding)
    session.flush()
    emit_progress(session, scan, f"finding created: {title}", phase=scan.current_phase, agent=scan.current_agent, tool=scan.current_tool, event_type="finding_created", context={"finding_id": finding.id, "title": title, "severity": severity, "endpoint": endpoint, "parameter": parameter})


def _artifact(session: Session, scan: Scan, artifact_type: str, name: str, data: dict) -> None:
    session.add(PipelineArtifact(scan_id=scan.id, artifact_type=artifact_type, name=name, data=data))


def _endpoint(session: Session, scan: Scan, url: str, endpoint_type: str, source: str, method: str | None = None, metadata: dict | None = None) -> None:
    session.add(DiscoveredEndpoint(scan_id=scan.id, url=url, method=method, endpoint_type=endpoint_type, source=source, metadata_json=metadata or {}))


def _asset(session: Session, scan: Scan, url: str, asset_type: str, source: str, metadata: dict | None = None) -> None:
    session.add(DiscoveredAsset(scan_id=scan.id, url=url, asset_type=asset_type, source=source, metadata_json=metadata or {}))


def _application_profile(session: Session, scan: Scan, selection: dict) -> None:
    session.add(
        ApplicationProfile(
            scan_id=scan.id,
            primary_profile=selection.get("primary_profile") or selection.get("app_profile") or "generic_web",
            secondary_profiles=selection.get("secondary_profiles", []),
            lab_profile=selection.get("lab_profile"),
            confidence=selection.get("confidence"),
            detection_rules={"matched_rules": selection.get("matched_rules", [])},
            observed=selection.get("observed", {}),
        )
    )


def _auth_mechanism(session: Session, scan: Scan, mechanism_type: str, endpoint: str | None, confidence: str, evidence: dict | None = None) -> None:
    session.add(DiscoveredAuthMechanism(scan_id=scan.id, mechanism_type=mechanism_type, endpoint=endpoint, confidence=confidence, evidence=evidence or {}))


def _session_mechanism(session: Session, scan: Scan, mechanism_type: str, location: str | None, token_type: str | None, confidence: str, metadata: dict | None = None) -> None:
    session.add(DiscoveredSessionMechanism(scan_id=scan.id, mechanism_type=mechanism_type, location=location, token_type=token_type, confidence=confidence, metadata_json=metadata or {}))


def _parameter(session: Session, scan: Scan, name: str, location: str, endpoint: str | None, source: str, metadata: dict | None = None) -> None:
    session.add(DiscoveredParameter(scan_id=scan.id, name=name, location=location, endpoint=endpoint, source=source, metadata_json=metadata or {}))


def _record_validation_parameters(session: Session, scan: Scan, endpoint: str, body: str, source: str) -> None:
    lowered = body.lower()
    known = ["email", "password", "name", "number", "url", "uri", "callback", "redirect", "image", "avatar", "webhook", "next", "returnUrl", "token"]
    for name in known:
        if name.lower() in lowered:
            _parameter(session, scan, name, "json", endpoint, source, {"source_hint": "validation_error"})


def _auth_flow(session: Session, scan: Scan, flow_type: str, url: str | None, evidence: dict | None = None) -> None:
    session.add(DiscoveredAuthFlow(scan_id=scan.id, flow_type=flow_type, url=url, evidence=evidence or {}))


def _token(session: Session, scan: Scan, token_type: str, location: str, sample: str | None, metadata: dict | None = None) -> None:
    session.add(DiscoveredToken(scan_id=scan.id, token_type=token_type, location=location, sample=sample, metadata_json=metadata or {}))
    _session_mechanism(session, scan, "bearer" if token_type in {"jwt", "bearer"} else token_type, location, token_type, "medium", metadata or {})


def _run_http_baseline(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, output = _http_get(target_url)
    if status == RunStatus.COMPLETED.value:
        html = output.get("_text", "")
        title = _extract_title(html)
        output["title"] = title
        _artifact(session, scan, "discovered_headers", "http_response_headers", {"headers": output.get("headers", {}), "status_code": output.get("status_code")})
        selection = detect_profile(target_url, html=html, headers=output.get("headers", {}))
        _application_profile(
            session,
            scan,
            {
                "app_profile": selection.primary_profile,
                "primary_profile": selection.primary_profile,
                "secondary_profiles": selection.secondary_profiles,
                "lab_profile": selection.lab_profile,
                "confidence": selection.confidence,
                "matched_rules": selection.matched_rules,
                "observed": selection.observed,
            },
        )
        for token in _detect_tokens_and_cookies(output.get("headers", {}), html):
            _token(session, scan, token["token_type"], token["location"], token.get("sample"), token)
    result = _record_tool(session, scan, "http_client", f"GET {target_url}", status, output, "http", "HTTP baseline", "prompt_http_baseline")
    if status == RunStatus.COMPLETED.value:
        headers = output.get("headers", {})
        server = headers.get("server") or headers.get("Server")
        if server:
            _finding(session, scan, "HTTP server header detected", f"Server header: {server}")
    return result


def _run_shodan_search(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    api_key = os.getenv("SHODAN_API_KEY")
    host = _target_host(target_url)
    if not api_key:
        output = {"reason": "SHODAN_API_KEY not configured", "host": host}
        status = RunStatus.MISSING_PREREQUISITE.value
        command = "shodan host lookup"
    else:
        command = f"GET https://api.shodan.io/shodan/host/{host}"
        try:
            response = httpx.get(f"https://api.shodan.io/shodan/host/{host}", params={"key": api_key}, timeout=15)
            output = {"status_code": response.status_code, "body_preview": response.text[:4000]}
            status = RunStatus.COMPLETED.value if response.status_code < 500 else RunStatus.EXECUTION_ERROR.value
            if response.status_code == 200:
                _finding(session, scan, "Shodan data found", f"Shodan returned data for {host}.")
        except Exception as exc:
            output = {"error": str(exc)}
            status = RunStatus.EXECUTION_ERROR.value
    return _record_tool(session, scan, "shodan_search", command, status, output, "osint", "Shodan search", "prompt_shodan_search")


def _fetch_root_html(target_url: str) -> tuple[str, str, dict]:
    status, output = _http_get(target_url)
    return status, output.get("_text", ""), output


def _extract_static_assets(html: str) -> list[str]:
    return re.findall(r"""(?:src|href)=["']([^"']+\.(?:js|css|png|jpg|jpeg|svg|ico|map)(?:\?[^"']*)?)["']""", html, re.IGNORECASE)[:200]


def _extract_js_assets(html: str, target_url: str) -> list[str]:
    return [asset for asset in _normalize_url_list(target_url, _extract_static_assets(html)) if asset.lower().split("?", 1)[0].endswith(".js")]


def _extract_links(html: str) -> list[str]:
    return re.findall(r"""href=["']([^"'#]+)["']""", html, re.IGNORECASE)[:200]


def _normalize_url_list(target_url: str, values: list[str]) -> list[str]:
    urls = []
    for value in values:
        if not value or value.startswith(("mailto:", "tel:", "javascript:")):
            continue
        urls.append(urljoin(target_url + "/", value))
    return sorted(set(urls))[:500]


def _extract_title(html: str) -> str | None:
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", title.group(1)).strip() if title else None


def _extract_meta_generator(html: str) -> str | None:
    match = re.search(r"""<meta\s+[^>]*name=["']?generator["']?[^>]*content=["']([^"']+)["']""", html, re.IGNORECASE)
    return match.group(1).strip() if match else None


def _classify_links(target_url: str, links: list[str]) -> dict:
    target_host = urlparse(target_url).netloc
    internal: list[str] = []
    external: list[str] = []
    for link in links:
        absolute = urljoin(target_url + "/", link)
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        if parsed.netloc == target_host:
            internal.append(absolute)
        else:
            external.append(absolute)
    return {"internal": sorted(set(internal))[:300], "external": sorted(set(external))[:300]}


def _same_target(target_url: str, candidate: str) -> bool:
    parsed_target = urlparse(target_url)
    parsed_candidate = urlparse(candidate)
    return not parsed_candidate.netloc or parsed_candidate.netloc == parsed_target.netloc


def _extract_all_links(html: str) -> list[str]:
    return re.findall(r"""(?:href|src|action)=["']([^"']+)["']""", html, re.IGNORECASE)[:500]


def _framework_hints(headers: dict, html: str, assets: list[str]) -> list[str]:
    text = " ".join([str(headers), html[:12000], " ".join(assets)]).lower()
    hints = []
    patterns = {
        "nginx": ["nginx"],
        "openresty": ["openresty"],
        "apache": ["apache"],
        "express": ["x-powered-by': 'express", '"x-powered-by": "express"', "express"],
        "asp.net": ["asp.net", "x-aspnet"],
        "php": ["php", "x-powered-by': 'php", '"x-powered-by": "php"'],
        "react": ["react", "__react", "react-dom"],
        "angular": ["angular", "ng-version"],
        "vue": ["vue", "__vue__"],
        "bootstrap": ["bootstrap"],
        "jquery": ["jquery"],
        "swagger-ui": ["swagger-ui", "swaggerui"],
    }
    for name, tokens in patterns.items():
        if any(token in text for token in tokens):
            hints.append(name)
    return sorted(set(hints))


def _parse_sitemap_urls(xml_text: str) -> list[str]:
    if not xml_text.strip():
        return []
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return sorted(set(re.findall(r"<loc>(.*?)</loc>", xml_text, re.IGNORECASE | re.DOTALL)))[:500]
    urls = []
    for element in root.iter():
        if element.tag.lower().endswith("loc") and element.text:
            urls.append(element.text.strip())
    return sorted(set(urls))[:500]


def _detect_tokens_and_cookies(headers: dict, body: str) -> list[dict]:
    results: list[dict] = []
    for name, value in headers.items():
        lower_name = str(name).lower()
        lower_value = str(value).lower()
        if lower_name == "set-cookie":
            results.append(
                {
                    "token_type": "cookie",
                    "location": "set-cookie",
                    "sample": str(value)[:160],
                    "httponly": "httponly" in lower_value,
                    "secure": "secure" in lower_value,
                    "samesite": "samesite" in lower_value,
                }
            )
        if lower_name == "authorization" or "bearer " in lower_value:
            results.append({"token_type": "bearer", "location": lower_name, "sample": str(value)[:160]})
        if lower_name.startswith("access-control-"):
            results.append({"token_type": "cors_header", "location": lower_name, "sample": str(value)[:160]})
    jwt_re = r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"
    for match in re.findall(jwt_re, body):
        results.append({"token_type": "jwt", "location": "body", "sample": match[:160]})
    csrf_re = r"""(?:csrf|xsrf)[^"'=:\s]{0,40}["']?\s*[:=]\s*["']([^"']{8,})["']"""
    for match in re.findall(csrf_re, body, re.IGNORECASE):
        results.append({"token_type": "csrf", "location": "body", "sample": match[:160]})
    return results


def _extract_forms(target_url: str, html: str) -> list[dict]:
    forms = []
    for form_match in re.finditer(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", html, re.IGNORECASE | re.DOTALL):
        attrs = form_match.group("attrs")
        body = form_match.group("body")
        action = _html_attr(attrs, "action") or target_url
        method = (_html_attr(attrs, "method") or "GET").upper()
        inputs = re.findall(r"""<input\b[^>]*name=["']?([^"'>\s]+)""", body, re.IGNORECASE)
        forms.append({"action": urljoin(target_url + "/", action), "method": method, "inputs": sorted(set(inputs))})
    return forms


def _html_attr(attrs: str, name: str) -> str | None:
    match = re.search(rf"""{name}=["']?([^"'\s>]+)""", attrs, re.IGNORECASE)
    return match.group(1) if match else None


def _load_profile(profile_name: str) -> dict:
    return load_profile(profile_name)


def _detect_app_profile(html: str) -> dict:
    selection = detect_profile("", html=html)
    return {
        "app_profile": selection.primary_profile,
        "primary_profile": selection.primary_profile,
        "secondary_profiles": selection.secondary_profiles,
        "lab_profile": selection.lab_profile,
        "confidence": selection.confidence,
        "profile": selection.profile,
        "matched_rules": selection.matched_rules,
        "observed": selection.observed,
    }


def _api_wordlist_path() -> str:
    return "configs/wordlists/api_common.txt"


def _read_api_words() -> list[str]:
    path = Path(_api_wordlist_path())
    if not path.exists():
        return API_WORDS
    words = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            value = raw.strip().lstrip("/")
            if value and not value.startswith("#"):
                words.append(value)
    return list(dict.fromkeys(words + API_WORDS))


def _extract_js_api_strings(js_body: str) -> dict:
    strings: set[str] = set()
    external_refs: set[str] = set()
    patterns = [
        r"""fetch\(\s*["'`]([^"'`]+)["'`]""",
        r"""axios\.(?:get|post|put|delete|patch)\(\s*["'`]([^"'`]+)["'`]""",
        r"""axios\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`]""",
        r"""XMLHttpRequest\.open\(\s*["'`][A-Z]+["'`]\s*,\s*["'`]([^"'`]+)["'`]""",
        r"""(?:baseURL|apiUrl|authUrl|REACT_APP_API_URL)\s*[:=]\s*["'`]([^"'`]+)["'`]""",
        r"""["'`]((?:/api/|/identity/|/workshop/|/community/|/auth/|/login|/signup|/register|/token|/refresh)[^"'`]{0,180})["'`]""",
    ]
    keyword_re = re.compile(r"""["'`]([^"'`]*(?:identity|workshop|community|vehicle|coupon|token|refresh|login|signup|register)[^"'`]*)["'`]""", re.IGNORECASE)
    for pattern in patterns:
        for match in re.findall(pattern, js_body, re.IGNORECASE | re.DOTALL):
            strings.add(str(match).strip())
    for match in keyword_re.findall(js_body):
        value = str(match).strip()
        if "/" in value or value.startswith("http"):
            strings.add(value)
    for value in list(strings):
        if value.startswith("http"):
            external_refs.add(value)
    return {"strings": sorted(strings)[:1000], "external_references": sorted(external_refs)[:300]}


def _collect_js_discovery(target_url: str, html: str) -> dict:
    js_files = _extract_js_assets(html, target_url)
    js_strings: set[str] = set()
    external_refs: set[str] = set()
    previews = {}
    max_bytes = 250_000
    for asset in js_files[:50]:
        try:
            response = httpx.get(asset, follow_redirects=True, timeout=10)
            body = response.text[:max_bytes]
            previews[asset] = {"status_code": response.status_code, "bytes_analyzed": len(body)}
        except Exception as exc:
            previews[asset] = {"error": str(exc)}
            continue
        extracted = _extract_js_api_strings(body)
        js_strings.update(extracted["strings"])
        external_refs.update(extracted["external_references"])
    return {
        "js_files": js_files,
        "previews": previews,
        "discovered_js_strings": sorted(js_strings)[:1000],
        "discovered_external_references": sorted(external_refs)[:300],
    }


def _api_candidate_paths(html: str, target_url: str) -> dict:
    detection = _detect_app_profile(html)
    profile = detection["profile"]
    bases = list(API_BASE_CANDIDATES)
    endpoint_candidates = []
    if profile:
        bases.extend(profile.get("api_base_candidates", []))
        endpoint_candidates.extend(profile.get("endpoint_candidates", []))
    js = _collect_js_discovery(target_url, html)
    for value in js["discovered_js_strings"]:
        if value.startswith("http") and _same_target(target_url, value):
            endpoint_candidates.append(urlparse(value).path)
        elif value.startswith("/"):
            endpoint_candidates.append(value)
    words = _read_api_words()
    candidates: set[str] = set()
    for endpoint in endpoint_candidates:
        if endpoint:
            candidates.add("/" + endpoint.lstrip("/"))
    for base in bases:
        clean_base = "/" + base.strip("/")
        if clean_base == "/":
            clean_base = ""
        for word in words:
            candidates.add(f"{clean_base}/{word.lstrip('/')}")
    return {
        "app_profile": detection["app_profile"],
        "primary_profile": detection.get("primary_profile"),
        "secondary_profiles": detection.get("secondary_profiles", []),
        "lab_profile": detection.get("lab_profile"),
        "confidence": detection.get("confidence"),
        "matched_rules": detection.get("matched_rules", []),
        "observed": detection.get("observed", {}),
        "profile": profile,
        "bases": sorted(set(bases)),
        "js": js,
        "candidate_paths": sorted(candidates)[:1500],
    }


def _json_keys(body: str) -> list[str]:
    try:
        parsed = __import__("json").loads(body)
    except Exception:
        return []
    if isinstance(parsed, dict):
        return sorted(str(key) for key in parsed.keys())[:50]
    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
        return sorted(str(key) for key in parsed[0].keys())[:50]
    return []


def _auth_flow_from_path(path: str) -> str | None:
    lowered = path.lower()
    if any(token in lowered for token in ["signup", "register"]):
        return "registration"
    if "login" in lowered:
        return "login"
    if "logout" in lowered:
        return "logout"
    if "refresh" in lowered:
        return "refresh_token"
    if "token" in lowered:
        return "token"
    if "verify" in lowered or "otp" in lowered:
        return "verification"
    if "forgot" in lowered or "forget" in lowered or "reset-password" in lowered:
        return "password_reset"
    if "oauth" in lowered:
        return "oauth"
    if "saml" in lowered:
        return "saml"
    return None


def _record_exchange(session: Session, scan: Scan, method: str, url: str, request_headers: dict | None, request_body: dict | str | None, response: httpx.Response | None, tool_run_id: int | None = None, error: str | None = None) -> None:
    parsed_url = urlparse(url)
    path_only = parsed_url.path or "/"
    emit_progress(
        session,
        scan,
        f"request={method} {path_only} status={response.status_code if response is not None else 'error'}",
        event_type="http_request",
        context={
            "method": method,
            "path": path_only,
            "status_code": response.status_code if response is not None else None,
            "duration_ms": int(response.elapsed.total_seconds() * 1000) if response is not None and response.elapsed else None,
            "auth_attached": bool((request_headers or {}).get("Authorization") or (request_headers or {}).get("Cookie")),
            "error": error,
        },
    )
    request = Request(
        scan_id=scan.id,
        tool_run_id=tool_run_id,
        method=method,
        url=url,
        headers=request_headers or {},
        body=__import__("json").dumps(request_body) if isinstance(request_body, dict) else request_body,
    )
    session.add(request)
    session.flush()
    session.add(
        Response(
            request_id=request.id,
            status_code=response.status_code if response is not None else None,
            headers=dict(response.headers) if response is not None else {},
            body_preview=(response.text[:4000] if response is not None else error),
            elapsed_ms=int(response.elapsed.total_seconds() * 1000) if response is not None and response.elapsed else None,
        )
    )


def _masked_headers(headers: dict | None) -> dict:
    masked = dict(headers or {})
    for key in list(masked.keys()):
        lowered = key.lower()
        if lowered == "authorization":
            value = str(masked[key])
            masked[key] = "Bearer <masked>" if value.lower().startswith("bearer ") else "<masked>"
        if lowered in {"cookie", "set-cookie"}:
            masked[key] = "<masked>"
    return masked


def _json_value_recursive(value, keys: set[str]) -> str | None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in keys and item:
                return str(item)
        for item in value.values():
            found = _json_value_recursive(item, keys)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = _json_value_recursive(item, keys)
            if found:
                return found
    return None


def _mask_token(token: str | None) -> str | None:
    if not token:
        return None
    value = str(token)
    if len(value) <= 20:
        return value[:6] + "...<masked>"
    return f"{value[:10]}...<masked>...{value[-8:]}"


def _decode_jwt_unverified(token: str | None) -> dict:
    if not token or token.count(".") != 2:
        return {}
    try:
        header_b64, payload_b64, _ = token.split(".", 2)

        def decode_part(part: str) -> dict:
            padded = part + "=" * (-len(part) % 4)
            return __import__("json").loads(base64.urlsafe_b64decode(padded.encode()).decode("utf-8"))

        header = decode_part(header_b64)
        payload = decode_part(payload_b64)
        return {
            "alg": header.get("alg"),
            "sub": payload.get("sub") or payload.get("email") or payload.get("username"),
            "email": payload.get("email"),
            "iat": payload.get("iat"),
            "exp": payload.get("exp"),
            "role": payload.get("role") or payload.get("roles"),
        }
    except Exception:
        return {}


def _token_hash(token: str | None) -> str | None:
    if not token:
        return None
    return hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()


def _is_masked_token(token: str | None) -> bool:
    return bool(token and "...<masked>..." in token)


def _session_secret_path(scan: Scan) -> Path:
    directory = get_settings().evidence_dir / f"scan-{scan.id}" / "secrets"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "authenticated_sessions.json"


def _store_session_secret(scan: Scan, label: str, access_token: str | None, refresh_token: str | None, authorization_header: str | None) -> str | None:
    if not access_token and not refresh_token and not authorization_header:
        return None
    path = _session_secret_path(scan)
    try:
        payload = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"sessions": {}}
    except Exception:
        payload = {"sessions": {}}
    payload.setdefault("sessions", {})[label] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "authorization_header": authorization_header,
        "authorization_header_type": "bearer" if authorization_header else None,
        "token_type": "jwt" if access_token and access_token.count(".") == 2 else "bearer" if access_token else None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def _load_session_secret(auth_session: AuthenticatedSession) -> dict:
    token = auth_session.access_token_secret or auth_session.access_token
    header = auth_session.authorization_header
    source = "db_secret" if auth_session.access_token_secret else "legacy_db"
    if (not token or _is_masked_token(token)) and auth_session.secret_ref:
        try:
            payload = json.loads(Path(auth_session.secret_ref).read_text(encoding="utf-8"))
            data = (payload.get("sessions") or {}).get(auth_session.credential_label) or {}
            token = data.get("access_token") or token
            header = data.get("authorization_header") or header
            source = "secret_ref"
        except Exception:
            pass
    token_was_masked = _is_masked_token(token) or _is_masked_token(header)
    if token_was_masked:
        return {"token": None, "authorization_header": None, "source": source, "token_was_masked": True, "reason": "masked token cannot be used for authenticated crawling"}
    if not header and token:
        header = f"Bearer {token}"
    return {"token": token, "authorization_header": header, "source": source, "token_was_masked": False, "reason": None}


def _parse_json_body(body: str):
    try:
        return __import__("json").loads(body)
    except Exception:
        return None


def _extract_auth_tokens(response: httpx.Response) -> list[dict]:
    tokens = _detect_tokens_and_cookies(dict(response.headers), response.text)
    parsed = _parse_json_body(response.text)
    access = _json_value_recursive(parsed, {"token", "access_token", "access", "jwt", "bearer"}) if parsed is not None else None
    refresh = _json_value_recursive(parsed, {"refresh_token", "refresh"}) if parsed is not None else None
    if access:
        tokens.append({"token_type": "bearer", "location": "json", "sample": access})
        if access.count(".") == 2:
            tokens.append({"token_type": "jwt", "location": "json", "sample": access})
    if refresh:
        tokens.append({"token_type": "refresh", "location": "json", "sample": refresh})
    return tokens


def _authenticated_sessions_for_scan(session: Session, scan: Scan) -> list[AuthenticatedSession]:
    return (
        session.query(AuthenticatedSession)
        .filter(
            AuthenticatedSession.scan_id == scan.id,
            AuthenticatedSession.login_status == "login_success",
        )
        .all()
    )


def _auth_headers_for_session(auth_session: AuthenticatedSession) -> tuple[dict, dict]:
    headers = {}
    cookies = {}
    secret = _load_session_secret(auth_session)
    if secret.get("authorization_header"):
        headers["Authorization"] = secret["authorization_header"]
    if auth_session.cookie:
        for part in auth_session.cookie.split(";"):
            if "=" in part:
                name, value = part.strip().split("=", 1)
                cookies[name] = value
    return headers, cookies


def _looks_valid_api_response(path: str, method: str, status_code: int | None, content_type: str, body: str, allow: str | None) -> bool:
    return _endpoint_confidence(path, method, status_code, content_type, body, allow) in {"high", "medium"}


def _endpoint_confidence(path: str, method: str, status_code: int | None, content_type: str, body: str, allow: str | None) -> str:
    if status_code is None:
        return "low"
    lowered_body = body[:4000].lower()
    lowered_type = content_type.lower()
    generic_openresty = ("openresty" in lowered_body or "nginx" in lowered_body) and "<html" in lowered_body
    no_static_resource = "no static resource" in lowered_body or "not found" in lowered_body and status_code == 404
    jsonish = "application/json" in lowered_type or "application/problem+json" in lowered_type or bool(_json_keys(body))
    validationish = any(token in lowered_body for token in ["validation", "required", "missing", "request model", "field", "email", "password", "number"])
    app_specific_auth = status_code in {401, 403} and any(token in lowered_body for token in ["auth", "token", "jwt", "bearer", "credential", "permission", "forbidden", "unauthorized"])
    if status_code == 404:
        return "low"
    if generic_openresty or no_static_resource:
        return "low"
    if method == "POST" and status_code in {200, 201, 202, 400, 401, 403, 409, 415, 422} and (jsonish or validationish):
        return "high"
    if app_specific_auth and jsonish:
        return "high"
    if status_code in {200, 201, 202, 204, 400, 401, 403, 409, 415, 422} and jsonish:
        return "high"
    if allow and method == "OPTIONS":
        return "medium"
    return "low"


def _probe_api_path(target_url: str, path: str) -> dict:
    url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
    methods = ["OPTIONS", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]
    probes = []
    allowed_methods = []
    destructive_block_reason = "requires_test_owned_object and authenticated_session"
    for method in methods:
        destructive_method = method in {"PUT", "PATCH", "DELETE"}
        if destructive_method:
            probes.append(
                {
                    "method": method,
                    "destructive_method": True,
                    "requires_test_owned_object": True,
                    "requires_authenticated_session": True,
                    "status": "skipped_requires_test_owned_object",
                    "destructive_method_blocked_reason": destructive_block_reason,
                    "tested_safely": False,
                    "looks_valid": False,
                    "endpoint_confidence": "low",
                }
            )
            continue
        try:
            if method == "POST":
                response = httpx.request(method, url, json={}, follow_redirects=False, timeout=8)
            elif method == "HEAD":
                response = httpx.request(method, url, follow_redirects=False, timeout=8)
            else:
                response = httpx.request(method, url, follow_redirects=False, timeout=8)
            content_type = response.headers.get("content-type", "")
            allow = response.headers.get("allow")
            if allow:
                allowed_methods = sorted({item.strip().upper() for item in allow.split(",") if item.strip()})
            preview = response.text[:1200]
            json_keys = _json_keys(response.text)
            confidence = _endpoint_confidence(path, method, response.status_code, content_type, response.text, allow)
            looks_valid = confidence in {"high", "medium"}
            probes.append(
                {
                    "method": method,
                    "status_code": response.status_code,
                    "status": "completed_non_destructive_probe",
                    "content_type": content_type,
                    "allow": allow,
                    "allowed_methods": allowed_methods,
                    "body_preview": preview,
                    "response_preview": preview,
                    "json_keys": json_keys,
                    "looks_valid": looks_valid,
                    "endpoint_confidence": confidence,
                    "requires_test_owned_object": False,
                    "requires_authenticated_session": False,
                    "destructive_method": False,
                    "destructive_method_blocked_reason": None,
                    "tested_safely": True,
                }
            )
        except Exception as exc:
            probes.append({"method": method, "error": str(exc), "status": "execution_error", "looks_valid": False, "tested_safely": method not in {"PUT", "PATCH", "DELETE"}})
    valid = any(probe.get("endpoint_confidence") == "high" for probe in probes) or any(
        probe.get("method") != "OPTIONS" and probe.get("endpoint_confidence") == "medium" for probe in probes
    )
    return {
        "path": path,
        "url": url,
        "auth_flow": _auth_flow_from_path(path),
        "valid": valid,
        "allowed_methods": allowed_methods,
        "observed_status_by_method": {probe["method"]: probe.get("status_code") or probe.get("status") for probe in probes},
        "method_safety_policy": {
            "authorized_testing_mode": True,
            "destructive_method_requires_test_owned_object": True,
            "destructive_methods": ["PUT", "PATCH", "DELETE"],
        },
        "probes": probes,
    }


def _best_confidence(item: dict) -> str:
    order = {"high": 3, "medium": 2, "low": 1}
    best = "low"
    for probe in item.get("probes", []):
        confidence = probe.get("endpoint_confidence") or "low"
        if order.get(confidence, 0) > order.get(best, 0):
            best = confidence
    return best


def _record_api_probe_results(session: Session, scan: Scan, results: list[dict], source: str) -> None:
    for item in results:
        confidence = _best_confidence(item)
        if not item.get("valid") or confidence == "low":
            continue
        endpoint_type = "api_auth" if item.get("auth_flow") else "api"
        methods = [probe.get("method") for probe in item.get("probes", []) if probe.get("looks_valid")]
        _endpoint(session, scan, item["url"], endpoint_type, source, method=",".join(methods) if methods else None, metadata={"path": item["path"], "endpoint_confidence": confidence, "probes": item.get("probes", [])})
        if item.get("auth_flow"):
            _auth_flow(session, scan, item["auth_flow"], item["url"], {"source": source, "endpoint_confidence": confidence, "probes": item.get("probes", [])})
        for probe in item.get("probes", []):
            _record_validation_parameters(session, scan, item["url"], probe.get("body_preview") or "", source)


def _run_technology_fingerprint(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    result: dict = {
        "target": target_url,
        "headers": {},
        "server": None,
        "title": None,
        "meta_generator": None,
        "meta": [],
        "static_assets": [],
        "framework_hints": [],
    }
    status, output = _http_get(target_url)
    html = output.get("_text", "")
    if status == RunStatus.COMPLETED.value:
        result["headers"] = output.get("headers", {})
        result["server"] = result["headers"].get("server") or result["headers"].get("Server")
        result["title"] = _extract_title(html)
        result["meta_generator"] = _extract_meta_generator(html)
        result["meta"] = re.findall(r"<meta\s+[^>]*(?:name|property)=[\"']?([^\"'>\s]+)[^>]*>", html, re.IGNORECASE)[:50]
        result["static_assets"] = _extract_static_assets(html)
        result["framework_hints"] = _framework_hints(result["headers"], html, result["static_assets"])
        _artifact(session, scan, "technology_fingerprint", "technology_hints", result)
    else:
        result.update(output)

    optional = {}
    for tool in ["whatweb", "wappalyzer"]:
        path = shutil.which(tool)
        if not path:
            optional[tool] = {"status": "not installed"}
            continue
        command = [tool, target_url] if tool == "wappalyzer" else [tool, "--no-errors", target_url]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
            optional[tool] = {"status": "executed", "command": " ".join(command), "returncode": completed.returncode, "stdout": completed.stdout[:4000], "stderr": completed.stderr[:1000]}
        except Exception as exc:
            optional[tool] = {"status": "failed", "error": str(exc)}
    result["optional_tools"] = optional
    record = _record_tool(session, scan, "technology_fingerprint", f"fingerprint {target_url}", status, result, "technology", "Technology fingerprinting", "prompt_technology_fingerprint")
    if status == RunStatus.COMPLETED.value:
        _finding(
            session,
            scan,
            "Technology fingerprint",
            f"Server: {result.get('server') or 'unknown'}; title: {result.get('title') or 'unknown'}; hints: {', '.join(result.get('framework_hints') or []) or 'none'}; assets: {len(result.get('static_assets', []))}",
        )
    return record


def _run_root_link_inventory(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, html, root_output = _fetch_root_html(target_url)
    links = _normalize_url_list(target_url, _extract_all_links(html))
    classified = _classify_links(target_url, links)
    output = {
        "links": links,
        "internal_links": classified["internal"],
        "external_links": classified["external"],
        "count": len(links),
        "status_code": root_output.get("status_code"),
        "error": root_output.get("error"),
    }
    for link in classified["internal"]:
        _endpoint(session, scan, link, "web", "root_link_inventory")
    for link in classified["external"]:
        _endpoint(session, scan, link, "external", "root_link_inventory")
    for form in _extract_forms(target_url, html):
        _endpoint(session, scan, form["action"], "form", "root_link_inventory", method=form["method"], metadata={"inputs": form["inputs"]})
        for name in form["inputs"]:
            _parameter(session, scan, name, "form", form["action"], "root_link_inventory")
    _artifact(session, scan, "discovered_urls", "root_link_inventory", output)
    return _record_tool(session, scan, "root_link_inventory", f"GET {target_url} and parse href/src/action links", status, output, "web", "Root link inventory", "prompt_root_link_inventory")


def _run_robots_txt(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    url = urljoin(target_url + "/", "/robots.txt")
    status, output = _http_get(url)
    if output.get("status_code") == 200:
        output["content"] = output.get("_text", "")[:12000]
        for path in re.findall(r"(?im)^(?:allow|disallow|sitemap):\s*(\S+)", output["content"]):
            _endpoint(session, scan, urljoin(target_url + "/", path), "web", "robots_txt")
        _finding(session, scan, "robots.txt found", f"robots.txt is available at {url}.")
    elif output.get("status_code") == 404:
        status = RunStatus.NOT_APPLICABLE.value
        output["reason"] = "robots.txt returned HTTP 404"
    return _record_tool(session, scan, "robots_txt", f"GET {url}", status, output, "web", "robots.txt check", "prompt_robots_txt")


def _run_sitemap_xml(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    url = urljoin(target_url + "/", "/sitemap.xml")
    status, output = _http_get(url)
    if output.get("status_code") == 200:
        output["urls"] = _parse_sitemap_urls(output.get("_text", ""))
        for discovered_url in output["urls"]:
            _endpoint(session, scan, discovered_url, "web", "sitemap_xml")
        _finding(session, scan, "sitemap.xml found", f"sitemap.xml is available at {url}.")
    elif output.get("status_code") == 404:
        status = RunStatus.NOT_APPLICABLE.value
        output["reason"] = "sitemap.xml returned HTTP 404"
    return _record_tool(session, scan, "sitemap_xml", f"GET {url}", status, output, "web", "sitemap.xml check", "prompt_sitemap_xml")


def _run_openapi_discovery(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    results = []
    found = []
    for path in OPENAPI_PATHS:
        url = urljoin(target_url + "/", path)
        status, output = _http_get(url)
        item = {"url": url, "status": status, "status_code": output.get("status_code"), "error": output.get("error")}
        results.append(item)
        if output.get("status_code") == 200:
            found.append(url)
            _endpoint(session, scan, url, "api_spec", "openapi_discovery")
            _api_spec_type = "openapi" if "openapi" in path.lower() or "swagger" in path.lower() else "api"
            session.add(DiscoveredApiSpec(scan_id=scan.id, spec_type=_api_spec_type, url=url, status="found", metadata_json={"status_code": output.get("status_code")}))
            _finding(session, scan, "Exposed OpenAPI document found", f"OpenAPI/Swagger document found at {url}.")
    output = {"checked": results, "found": found, "missing": [item["url"] for item in results if item.get("status_code") == 404]}
    return _record_tool(session, scan, "openapi_discovery", "GET common OpenAPI paths", RunStatus.COMPLETED.value, output, "api", "Common OpenAPI discovery", "prompt_openapi_discovery")


def _run_static_asset_inventory(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, html, root_output = _fetch_root_html(target_url)
    assets = _normalize_url_list(target_url, _extract_static_assets(html))
    js_discovery = _collect_js_discovery(target_url, html)
    js_previews = js_discovery["previews"]
    for asset in assets:
        suffix = asset.lower().split("?", 1)[0].rsplit(".", 1)[-1] if "." in asset else "asset"
        _asset(session, scan, asset, suffix, "static_asset_inventory")
    for asset in assets[:10]:
        if asset.lower().endswith((".js", ".map")):
            _finding(session, scan, "Interesting JS asset found", f"Static asset referenced: {asset}")
    for reference in js_discovery["discovered_external_references"]:
        _endpoint(session, scan, reference, "external", "js_extraction")
    output = {
        "assets": assets,
        "js_previews": js_previews,
        "discovered_js_strings": js_discovery["discovered_js_strings"],
        "discovered_api_candidates": [item for item in js_discovery["discovered_js_strings"] if any(token in item.lower() for token in ["/api", "identity", "workshop", "community", "auth", "token"])],
        "discovered_external_references": js_discovery["discovered_external_references"],
        "external_reference_count": len(js_discovery["discovered_external_references"]),
        "count": len(assets),
        "status_code": root_output.get("status_code"),
        "error": root_output.get("error"),
    }
    _artifact(session, scan, "discovered_assets", "static_asset_inventory", output)
    _artifact(session, scan, "discovered_js_strings", "js_extraction", {"strings": output["discovered_js_strings"], "count": len(output["discovered_js_strings"])})
    _artifact(session, scan, "discovered_external_references", "js_extraction", {"references": output["discovered_external_references"], "external_reference_count": len(output["discovered_external_references"])})
    return _record_tool(session, scan, "static_asset_inventory", f"GET {target_url} and parse static assets", status, output, "web", "Static asset inventory", "prompt_static_asset_inventory")


def _run_api_path_hints(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, html, root_output = _fetch_root_html(target_url)
    hint_pattern = r"""["']((?:/api/|/identity/|/workshop/|/community/|/user/|/login|/auth|/signup|/register|/token|/refresh|/v\d+/|https?://[^"']+/(?:api|identity|workshop|community|user|login|auth)/)[^"']{0,180})["']"""
    js_discovery = _collect_js_discovery(target_url, html)
    sources = {"root_html": sorted(set(re.findall(hint_pattern, html, re.IGNORECASE)))}
    sources["javascript"] = js_discovery["discovered_js_strings"]
    flattened = sorted({hint for hints in sources.values() for hint in hints})[:200]
    output = {
        "api_path_hints": flattened,
        "sources": sources,
        "discovered_external_references": js_discovery["discovered_external_references"],
        "external_reference_count": len(js_discovery["discovered_external_references"]),
        "count": len(flattened),
        "status_code": root_output.get("status_code"),
        "error": root_output.get("error"),
    }
    for hint in flattened:
        if hint.startswith("http") and not _same_target(target_url, hint):
            _endpoint(session, scan, hint, "external", "api_path_hints")
            continue
        endpoint_type = "api" if any(token in hint.lower() for token in ["/api/", "/identity/", "/workshop/", "/community/", "/auth", "/login", "/signup", "/register", "/token"]) else "client_route"
        _endpoint(session, scan, urljoin(target_url + "/", hint), endpoint_type, "api_path_hints")
    _artifact(session, scan, "discovered_api_paths", "api_path_hints", output)
    return _record_tool(session, scan, "api_path_hints", f"GET {target_url} and parse API path hints", status, output, "api", "API path hints from HTML/JS", "prompt_api_path_hints")


def _run_api_profile_probe(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, html, root_output = _fetch_root_html(target_url)
    candidates = _api_candidate_paths(html, target_url)
    profile = candidates["profile"]
    endpoint_paths = list(profile.get("endpoint_candidates", [])) if profile else []
    results = [_probe_api_path(target_url, path) for path in endpoint_paths]
    _record_api_probe_results(session, scan, results, "api_profile_probe")
    valid = [item for item in results if item.get("valid")]
    auth = [item for item in valid if item.get("auth_flow")]
    if candidates["app_profile"]:
        _finding(session, scan, "Application profile detected", f"Detected profile: {candidates['app_profile']}")
    _application_profile(session, scan, candidates)
    if auth:
        _finding(session, scan, "Authentication endpoints discovered", ", ".join(item["url"] for item in auth[:5]))
        for item in auth:
            _auth_mechanism(session, scan, item.get("auth_flow") or "auth_endpoint", item.get("url"), "medium", item)
    output = {
        "app_profile": candidates["app_profile"],
        "primary_profile": candidates.get("primary_profile"),
        "secondary_profiles": candidates.get("secondary_profiles", []),
        "lab_profile": candidates.get("lab_profile"),
        "confidence": candidates.get("confidence"),
        "profile_detected": bool(candidates["app_profile"]),
        "profile_endpoints_tested": len(results),
        "valid_api_endpoints": valid,
        "auth_endpoints": auth,
        "root_status_code": root_output.get("status_code"),
    }
    _artifact(session, scan, "api_profile_probe", "profile_endpoint_probe", output)
    return _record_tool(session, scan, "api_profile_probe", "detect app profile and probe profile endpoints", status, output, "api", "API profile probe", "prompt_api_profile_probe")


def _run_api_method_probe(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, html, root_output = _fetch_root_html(target_url)
    candidates = _api_candidate_paths(html, target_url)
    paths = candidates["candidate_paths"][:300]
    results = [_probe_api_path(target_url, path) for path in paths]
    _record_api_probe_results(session, scan, results, "api_method_probe")
    valid = [item for item in results if item.get("valid")]
    auth = [item for item in valid if item.get("auth_flow")]
    output = {
        "app_profile": candidates["app_profile"],
        "tested_count": len(results),
        "valid_count": len(valid),
        "auth_endpoint_count": len(auth),
        "methods_probed": ["OPTIONS", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
        "method_safety_policy": {
            "authorized_testing_mode": True,
            "destructive_method_requires_test_owned_object": True,
            "destructive_methods": ["PUT", "PATCH", "DELETE"],
            "destructive_probe_status": "skipped_requires_test_owned_object",
        },
        "valid_api_endpoints": valid[:100],
        "auth_endpoints": auth,
        "js_strings_found": len(candidates["js"]["discovered_js_strings"]),
        "external_reference_count": len(candidates["js"]["discovered_external_references"]),
        "root_status_code": root_output.get("status_code"),
    }
    _artifact(session, scan, "api_method_probe", "method_probe", output)
    return _record_tool(session, scan, "api_method_probe", "OPTIONS/GET/POST/PUT/PATCH/DELETE/HEAD probe API candidates", RunStatus.COMPLETED.value, output, "api", "API method probing", "prompt_api_method_probe")


def _run_ffuf_api_paths(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, html, _ = _fetch_root_html(target_url)
    candidates = _api_candidate_paths(html, target_url)
    wordlist = _api_wordlist_path()
    bases = candidates["bases"][:8]
    runs = []
    discovered = []
    if not shutil.which("ffuf"):
        output = {"reason": "ffuf not installed", "alternate_tool": "api_method_probe"}
        return _record_tool(session, scan, "ffuf_api_paths", f"ffuf -u {target_url}/FUZZ -w {wordlist}", RunStatus.MISSING_TOOL.value, output, "api", "ffuf API path discovery", "prompt_ffuf_api_paths")
    for index, base in enumerate(bases, start=1):
        output_path = write_evidence(scan.id, f"ffuf_api_raw_{index}", {"placeholder": True})
        fuzz_url = urljoin(target_url.rstrip("/") + "/", base.strip("/").rstrip("/") + "/FUZZ" if base.strip("/") else "FUZZ")
        command_parts = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-mc", "all", "-fc", "404", "-of", "json", "-o", str(output_path)]
        completed = subprocess.run(command_parts, capture_output=True, text=True, timeout=300, check=False)
        parsed_json = None
        try:
            parsed_json = __import__("json").loads(output_path.read_text(encoding="utf-8"))
        except Exception:
            parsed_json = None
        results = parsed_json.get("results", []) if isinstance(parsed_json, dict) else []
        for item in results:
            if item.get("url"):
                discovered.append({"url": item["url"], "status_code": item.get("status")})
                _endpoint(session, scan, item["url"], "api", "ffuf_api_paths", metadata={"status_code": item.get("status")})
        runs.append({"base": base, "command": " ".join(command_parts), "returncode": completed.returncode, "stdout": completed.stdout[:2000], "stderr": completed.stderr[:1000], "raw_output_path": str(output_path), "result_count": len(results)})
    output = {"wordlist": wordlist, "bases": bases, "runs": runs, "found": discovered[:500], "tested_count": len(bases) * len(_read_api_words()), "valid_count": len(discovered)}
    _artifact(session, scan, "ffuf_api_paths", "ffuf_api_path_discovery", output)
    return _record_tool(session, scan, "ffuf_api_paths", "ffuf API base fuzzing", status, output, "api", "ffuf API path discovery", "prompt_ffuf_api_paths")


def _run_gobuster_api_paths(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, html, _ = _fetch_root_html(target_url)
    candidates = _api_candidate_paths(html, target_url)
    wordlist = _api_wordlist_path()
    bases = candidates["bases"][:8]
    runs = []
    discovered = []
    if not shutil.which("gobuster"):
        output = {"reason": "gobuster not installed", "alternate_tool": "api_method_probe"}
        return _record_tool(session, scan, "gobuster_api_paths", f"gobuster dir -u {target_url} -w {wordlist}", RunStatus.MISSING_TOOL.value, output, "api", "Gobuster API path discovery", "prompt_gobuster_api_paths")
    for base in bases:
        base_url = urljoin(target_url.rstrip("/") + "/", base.strip("/") + "/" if base.strip("/") else "")
        command_parts = ["gobuster", "dir", "-u", base_url, "-w", wordlist, "-k", "--no-error"]
        completed = subprocess.run(command_parts, capture_output=True, text=True, timeout=300, check=False)
        parsed_paths = _parse_gobuster_paths(completed.stdout, base_url)
        for item in parsed_paths:
            discovered.append(item)
            _endpoint(session, scan, item["url"], "api", "gobuster_api_paths", metadata={"status_code": item.get("status_code")})
        runs.append({"base": base, "command": " ".join(command_parts), "returncode": completed.returncode, "stdout": completed.stdout[:4000], "stderr": completed.stderr[:1000], "result_count": len(parsed_paths)})
    output = {"wordlist": wordlist, "bases": bases, "runs": runs, "found": discovered[:500], "tested_count": len(bases) * len(_read_api_words()), "valid_count": len(discovered)}
    _artifact(session, scan, "gobuster_api_paths", "gobuster_api_path_discovery", output)
    return _record_tool(session, scan, "gobuster_api_paths", "gobuster API base fuzzing", status, output, "api", "Gobuster API path discovery", "prompt_gobuster_api_paths")


def _flow_url(session: Session, scan: Scan, flow_types: set[str]) -> str | None:
    flows = session.query(DiscoveredAuthFlow).filter(DiscoveredAuthFlow.scan_id == scan.id).all()
    confident = [
        flow
        for flow in flows
        if flow.flow_type in flow_types and ((flow.evidence or {}).get("endpoint_confidence") in {"high", "medium"} or not (flow.evidence or {}).get("endpoint_confidence"))
    ]
    return confident[0].url if confident else None


def _flow_urls(session: Session, scan: Scan, flow_types: set[str]) -> list[str]:
    flows = session.query(DiscoveredAuthFlow).filter(DiscoveredAuthFlow.scan_id == scan.id).all()
    urls = []
    for flow in flows:
        if flow.flow_type not in flow_types:
            continue
        confidence = (flow.evidence or {}).get("endpoint_confidence")
        if confidence in {"high", "medium"} or not confidence:
            urls.append(flow.url)
    return list(dict.fromkeys(urls))


def _profile_auth_urls(session: Session, scan: Scan, target_url: str, keywords: set[str]) -> list[str]:
    selection = profile_from_scan_artifacts(session, scan, target_url)
    urls = []
    for candidate in auth_endpoint_candidates(selection.profile):
        lowered = candidate.lower()
        if any(keyword in lowered for keyword in keywords):
            urls.append(urljoin(target_url.rstrip("/") + "/", candidate.lstrip("/")))
    return list(dict.fromkeys(urls))


def _generated_users(scan_id: int) -> list[dict]:
    suffix = f"{scan_id:06d}"
    return [
        {"label": "user1", "name": "SAIF User One", "email": f"saif_user1_{scan_id}@example.test", "number": f"900000{suffix}"[-10:], "password": "SaifTest@12345", "role": "user", "tenant": "tenant-a"},
        {"label": "user2", "name": "SAIF User Two", "email": f"saif_user2_{scan_id}@example.test", "number": f"900001{suffix}"[-10:], "password": "SaifTest@12345", "role": "user", "tenant": "tenant-b"},
    ]


def _upsert_generated_credential(session: Session, scan: Scan, user: dict, status: str) -> Credential:
    label = f"generated-{user['label']}-scan-{scan.id}"
    credential = session.query(Credential).filter(Credential.project_id == scan.project_id, Credential.label == label).one_or_none()
    metadata = {"source": "account_provisioning", "scan_id": scan.id, "status": status, "password": user["password"], "tenant": user["tenant"]}
    if credential:
        credential.username = user["email"]
        credential.secret_ref = "generated:SaifTest@12345"
        credential.role = user["role"]
        credential.metadata_json = metadata
    else:
        credential = Credential(project_id=scan.project_id, label=label, username=user["email"], secret_ref="generated:SaifTest@12345", role=user["role"], metadata_json=metadata)
        session.add(credential)
    session.flush()
    return credential


def _run_account_provisioning(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    selection = profile_from_scan_artifacts(session, scan, target_url)
    signup_urls = _flow_urls(session, scan, {"registration"}) or _profile_auth_urls(session, scan, target_url, {"signup", "register"})
    if not signup_urls:
        output = {
            "reason": "registration endpoint not discovered",
            "selected_profile": selection.primary_profile,
            "profile_confidence": selection.confidence,
        }
        return _record_tool(session, scan, "account_provisioning", "POST signup", RunStatus.MISSING_PREREQUISITE.value, output, "auth", "Account provisioning", "prompt_account_provisioning")
    users = _generated_users(scan.id)
    results = []
    for user in users:
        payload_templates = registration_payloads(selection.profile, user) or [
            {"email": user["email"], "username": user["email"], "password": user["password"], "name": user["name"]}
        ]
        user_result = {"label": user["label"], "email": user["email"], "attempts": []}
        status = "registration_failed"
        for signup_url in signup_urls:
            for payload in payload_templates:
                try:
                    response = httpx.post(signup_url, json=payload, follow_redirects=False, timeout=10)
                    _record_exchange(session, scan, "POST", signup_url, {"content-type": "application/json"}, payload, response)
                    body = response.text.lower()
                    if response.status_code in {200, 201, 202}:
                        status = "registered"
                    elif response.status_code in {400, 401, 403, 422} and any(token in body for token in ["verify", "otp", "verification", "mfa"]):
                        status = "verification_required"
                    elif response.status_code in {400, 409} and any(token in body for token in ["exist", "already", "duplicate"]):
                        status = "already_exists"
                    attempt = {
                        "url": signup_url,
                        "status_code": response.status_code,
                        "status": status,
                        "payload_fields": sorted(payload.keys()),
                        "json_keys": _json_keys(response.text),
                        "body_preview": response.text[:1000],
                    }
                    user_result["attempts"].append(attempt)
                    if status in {"registered", "already_exists", "verification_required"}:
                        break
                except Exception as exc:
                    user_result["attempts"].append({"url": signup_url, "status": "registration_failed", "error": str(exc), "payload_fields": sorted(payload.keys())})
            if status in {"registered", "already_exists", "verification_required"}:
                break
        credential = _upsert_generated_credential(session, scan, user, status)
        user_result.update({"status": status, "credential_id": credential.id})
        results.append(user_result)
    output_status = RunStatus.COMPLETED.value if any(item["status"] in {"registered", "already_exists"} for item in results) else RunStatus.MISSING_PREREQUISITE.value if any(item["status"] == "verification_required" for item in results) else RunStatus.EXECUTION_ERROR.value
    output = {"signup_urls": signup_urls, "selected_profile": selection.primary_profile, "profile_confidence": selection.confidence, "users": results}
    _artifact(session, scan, "account_provisioning", "generated_users", output)
    return _record_tool(session, scan, "account_provisioning", "POST discovered registration endpoints", output_status, output, "auth", "Account provisioning", "prompt_account_provisioning")


def _run_login_session(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    login_url = _flow_url(session, scan, {"login"})
    if not login_url:
        output = {"reason": "login endpoint not discovered; run auth_mapping or provide credentials with explicit endpoint metadata"}
        return _record_tool(session, scan, "login_session", "login session creation", RunStatus.MISSING_PREREQUISITE.value, output, "auth", "Login session", "prompt_login_session")
    credentials = session.query(Credential).filter(Credential.project_id == scan.project_id, Credential.label.like(f"generated-%-scan-{scan.id}")).all()
    configured_credentials = load_credentials()
    if not credentials and configured_credentials:
        credentials = [
            Credential(
                project_id=scan.project_id,
                label=str(item.get("label") or item.get("username") or "configured-user"),
                username=item.get("username"),
                role=item.get("role"),
                metadata_json={**item, "password": item.get("password")},
            )
            for item in configured_credentials
            if item.get("auth_type", "form") == "form"
        ]
    if not credentials:
        output = {"reason": "generated credentials not available; configure configs/credentials.yaml if registration requires verification"}
        return _record_tool(session, scan, "login_session", f"POST {login_url}", RunStatus.MISSING_CREDENTIALS.value, output, "auth", "Login session", "prompt_login_session")
    results = []
    for credential in credentials:
        password = (credential.metadata_json or {}).get("password") or "SaifTest@12345"
        profile = profile_from_scan_artifacts(session, scan, target_url).profile
        candidate_payloads = login_payloads(profile, credential.username, password)
        try:
            response = None
            payload = {}
            for candidate in candidate_payloads:
                payload = candidate
                response = httpx.post(login_url, json=payload, follow_redirects=False, timeout=10)
                if response.status_code in {200, 201}:
                    break
            if response is None:
                raise RuntimeError("no login payload templates available")
            _record_exchange(session, scan, "POST", login_url, {"content-type": "application/json"}, payload, response)
            tokens = _extract_auth_tokens(response)
            access_token = next((token["sample"] for token in tokens if token["token_type"] in {"bearer", "jwt"}), None)
            refresh_token = next((token["sample"] for token in tokens if token["token_type"] == "refresh"), None)
            token_meta = _decode_jwt_unverified(access_token)
            for token in tokens:
                _token(
                    session,
                    scan,
                    token["token_type"],
                    token["location"],
                    _mask_token(token.get("sample")),
                    {"credential": credential.label, "login_url": login_url, "masked_sample": _mask_token(token.get("sample")), **(_decode_jwt_unverified(token.get("sample")) if token.get("token_type") in {"bearer", "jwt"} else {})},
                )
            auth_header = None
            if access_token:
                auth_header = f"Bearer {access_token}"
            secret_ref = _store_session_secret(scan, credential.label, access_token, refresh_token, auth_header)
            validation = _validate_authenticated_session_token(session, scan, target_url, credential.label, access_token)
            session_record = SessionRecord(
                project_id=scan.project_id,
                credential_id=credential.id,
                label=credential.label.replace("generated-", "authenticated-"),
                cookies=dict(response.cookies),
                headers={"Authorization": "Bearer <masked>"} if auth_header else {},
            )
            if response.status_code in {200, 201} and (tokens or response.text):
                session.add(session_record)
                existing_auth = (
                    session.query(AuthenticatedSession)
                    .filter(AuthenticatedSession.scan_id == scan.id, AuthenticatedSession.credential_label == credential.label)
                    .one_or_none()
                )
                if not existing_auth:
                    existing_auth = AuthenticatedSession(scan_id=scan.id, credential_label=credential.label, auth_type="bearer")
                    session.add(existing_auth)
                existing_auth.username = credential.username
                existing_auth.role = credential.role or "user"
                existing_auth.tenant = (credential.metadata_json or {}).get("tenant")
                existing_auth.access_token = _mask_token(access_token)
                existing_auth.access_token_secret = access_token
                existing_auth.access_token_hash = _token_hash(access_token)
                existing_auth.access_token_masked = _mask_token(access_token)
                existing_auth.secret_ref = secret_ref
                existing_auth.refresh_token = refresh_token
                existing_auth.cookie = "; ".join(f"{key}={value}" for key, value in dict(response.cookies).items()) or None
                existing_auth.authorization_header = "Bearer <masked>" if auth_header else None
                existing_auth.authorization_header_type = "bearer" if auth_header else None
                existing_auth.token_type = "jwt" if access_token and access_token.count(".") == 2 else "bearer"
                existing_auth.login_status = "login_success"
                existing_auth.session_status = validation["session_status"]
                existing_auth.metadata_json = {"masked_access_token": _mask_token(access_token), "masked_refresh_token": _mask_token(refresh_token), "token_validation": validation, **token_meta}
                status = "login_success"
            else:
                status = "login_failed"
            metadata = dict(credential.metadata_json or {})
            metadata.update({"login_status": status, "login_url": login_url})
            credential.metadata_json = metadata
            results.append({"label": credential.label, "username": credential.username, "status": status, "session_status": validation.get("session_status") if access_token else None, "token_validation": validation if access_token else None, "status_code": response.status_code, "tokens_captured": len(tokens), "token": {"type": "jwt" if access_token and access_token.count(".") == 2 else "bearer" if access_token else None, "masked_sample": _mask_token(access_token), "hash": _token_hash(access_token), **token_meta}, "json_keys": _json_keys(response.text), "body_preview": response.text[:1000]})
        except Exception as exc:
            results.append({"label": credential.label, "username": credential.username, "status": "login_failed", "error": str(exc)})
    output_status = RunStatus.COMPLETED.value if any(item["status"] == "login_success" for item in results) else RunStatus.MISSING_CREDENTIALS.value
    output = {"login_url": login_url, "users": results}
    _artifact(session, scan, "login_session", "authenticated_sessions", output)
    return _record_tool(session, scan, "login_session", f"POST {login_url}", output_status, output, "auth", "Login session", "prompt_login_session")


def _validate_authenticated_session_token(session: Session, scan: Scan, target_url: str, label: str, access_token: str | None) -> dict:
    profile = profile_from_scan_artifacts(session, scan, target_url).profile
    candidates = protected_endpoint_candidates(profile) or ["/api/me", "/api/user", "/api/profile", "/me", "/profile", "/user"]
    validation_url = urljoin(target_url + "/", candidates[0].lstrip("/"))
    if not access_token:
        return {"session_status": "login_success_but_token_unavailable", "reason": "login did not return access token", "validation_url": validation_url}
    if _is_masked_token(access_token):
        return {"session_status": "login_success_but_token_unavailable", "reason": "masked token cannot be used for validation", "validation_url": validation_url}
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        response = None
        selected_url = validation_url
        for candidate in candidates:
            candidate_url = urljoin(target_url + "/", candidate.lstrip("/"))
            response = httpx.get(candidate_url, headers=headers, follow_redirects=False, timeout=10)
            selected_url = candidate_url
            if response.status_code == 200:
                break
        if response is None:
            raise RuntimeError("no validation endpoint candidates available")
        validation_url = selected_url
        _record_exchange(session, scan, "GET", validation_url, {"Authorization": "Bearer <masked>"}, None, response)
        token_meta = _decode_jwt_unverified(access_token)
        evidence = {
            "session_label": label,
            "token_attached": True,
            "auth_header_type": "bearer",
            "token_source": "memory",
            "token_was_masked": False,
            "request_url": validation_url,
            "status_code": response.status_code,
            "body_preview": response.text[:1000],
            "decoded_jwt_sub": token_meta.get("sub") or token_meta.get("email"),
            "decoded_jwt_role": token_meta.get("role"),
        }
        path = write_evidence(scan.id, f"token_validation_{label}", evidence)
        session.add(Evidence(scan_id=scan.id, kind="auth", path=str(path), summary=f"Token validation for {label}: HTTP {response.status_code}", metadata_json={"tool": "token_validation", "session_label": label, "status_code": response.status_code}))
        if response.status_code == 200:
            return {"session_status": "usable", "reason": None, "validation_url": validation_url, "status_code": response.status_code, "evidence_path": str(path)}
        if response.status_code == 401:
            return {"session_status": "login_success_but_token_rejected", "reason": "token rejected by protected endpoint", "validation_url": validation_url, "status_code": response.status_code, "evidence_path": str(path)}
        return {"session_status": "login_success_validation_inconclusive", "reason": f"validation endpoint returned HTTP {response.status_code}", "validation_url": validation_url, "status_code": response.status_code, "evidence_path": str(path)}
    except Exception as exc:
        return {"session_status": "login_success_validation_error", "reason": str(exc), "validation_url": validation_url}


def _collect_ids(value, found: list[dict], path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            if str(key).lower() in {"id", "user_id", "vehicle_id", "post_id", "coupon_id", "uuid"} and isinstance(item, (str, int)):
                found.append({"field": key_path, "value": str(item)})
            _collect_ids(item, found, key_path)
    elif isinstance(value, list):
        for index, item in enumerate(value[:50]):
            _collect_ids(item, found, f"{path}[{index}]")


def _run_authenticated_crawling(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    auth_sessions = _authenticated_sessions_for_scan(session, scan)
    if not auth_sessions:
        output = {"reason": "authenticated sessions not available"}
        return _record_tool(session, scan, "authenticated_crawling", "authenticated API crawl", RunStatus.MISSING_CREDENTIALS.value, output, "auth", "Authenticated crawling", "prompt_authenticated_crawling")
    profile = profile_from_scan_artifacts(session, scan, target_url).profile
    paths = protected_endpoint_candidates(profile)
    if not paths:
        discovered = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id, DiscoveredEndpoint.endpoint_type.in_(["api", "authenticated_api", "api_auth"])).limit(50).all()
        paths = [urlparse(item.url).path or item.url for item in discovered]
    if not paths:
        paths = ["/api/me", "/api/user", "/api/profile", "/me", "/profile", "/user"]
    results = []
    object_count = 0
    session_statuses = {}
    for auth_session in auth_sessions:
        secret = _load_session_secret(auth_session)
        if secret.get("token_was_masked") or (not secret.get("authorization_header") and not auth_session.cookie):
            reason = secret.get("reason") or "execution token unavailable or masked token used"
            session_statuses[auth_session.credential_label] = RunStatus.EXECUTION_ERROR.value
            results.append(
                {
                    "session": auth_session.credential_label,
                    "status": RunStatus.EXECUTION_ERROR.value,
                    "reason": reason,
                    "token_attached": False,
                    "auth_header_type": "bearer",
                    "token_source": secret.get("source"),
                    "token_was_masked": bool(secret.get("token_was_masked")),
                }
            )
            continue
        headers, cookies = _auth_headers_for_session(auth_session)
        token_meta = _decode_jwt_unverified(secret.get("token")) or (auth_session.metadata_json or {})
        session_statuses[auth_session.credential_label] = RunStatus.COMPLETED.value
        for path in paths:
            url = urljoin(target_url + "/", path)
            try:
                response = httpx.get(url, headers=headers, cookies=cookies, follow_redirects=False, timeout=10)
                _record_exchange(session, scan, "GET", url, _masked_headers(headers), None, response)
                if response.status_code == 401:
                    session_statuses[auth_session.credential_label] = RunStatus.EXECUTION_ERROR.value
                parsed_json = _parse_json_body(response.text)
                ids = []
                _collect_ids(parsed_json, ids)
                for item in ids[:100]:
                    object_count += 1
                    session.add(DiscoveredObject(scan_id=scan.id, object_type=item["field"], object_ref=f"{url}#{item['value']}", source="authenticated_crawling", metadata_json={"session": auth_session.credential_label, "url": url, "value": item["value"]}))
                if response.status_code != 404:
                    _endpoint(session, scan, url, "authenticated_api", "authenticated_crawling", method="GET", metadata={"session": auth_session.credential_label, "status_code": response.status_code, "ids_found": len(ids)})
                results.append({"session": auth_session.credential_label, "url": url, "method": "GET", "auth_header_type_used": "bearer" if headers.get("Authorization") else "cookie" if cookies else "none", "token_attached": bool(headers.get("Authorization") or cookies), "auth_header_type": "bearer" if headers.get("Authorization") else None, "token_source": secret.get("source"), "token_was_masked": False, "decoded_jwt_sub": token_meta.get("sub") or token_meta.get("email"), "decoded_jwt_role": token_meta.get("role"), "token_subject": token_meta.get("sub") or token_meta.get("email"), "masked_token": auth_session.access_token_masked or _mask_token(secret.get("token")), "status_code": response.status_code, "body_preview": response.text[:1000], "json_keys": _json_keys(response.text), "ids_found": ids[:20], "reason": "bearer token rejected by protected endpoint" if response.status_code == 401 else None})
            except Exception as exc:
                session_statuses[auth_session.credential_label] = RunStatus.EXECUTION_ERROR.value
                results.append({"session": auth_session.credential_label, "url": url, "error": str(exc)})
    output = {"requests": results, "objects_discovered": object_count, "session_statuses": session_statuses}
    _artifact(session, scan, "authenticated_crawling", "authenticated_api_inventory", output)
    status = RunStatus.COMPLETED.value if any(value == RunStatus.COMPLETED.value for value in session_statuses.values()) else RunStatus.EXECUTION_ERROR.value
    if status == RunStatus.EXECUTION_ERROR.value:
        if any(item.get("token_was_masked") for item in results):
            output["reason"] = "execution token unavailable or masked token used"
        elif any(item.get("status_code") == 401 and item.get("token_attached") for item in results):
            output["reason"] = "bearer token rejected by protected endpoint"
    return _record_tool(session, scan, "authenticated_crawling", "authenticated API crawl", status, output, "auth", "Authenticated crawling", "prompt_authenticated_crawling")


def _run_nmap(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    host = _target_host(target_url)
    command = f"nmap -sT -sV --top-ports 100 --open -T3 {host}"
    if not host:
        output = {"reason": f"Could not extract host from {target_url!r}"}
        status = RunStatus.MISSING_PREREQUISITE.value
    elif not _host_allowed_for_nmap(target_url):
        output = {"reason": "target host is outside configured scope"}
        status = RunStatus.OUT_OF_SCOPE.value
    elif not shutil.which("nmap"):
        output = {"reason": "nmap not installed", "host": host}
        status = RunStatus.MISSING_TOOL.value
    else:
        command_parts = ["nmap", "-sT", "-sV", "--top-ports", "100", "--open", "-T3", host]
        try:
            first = subprocess.run(command_parts, capture_output=True, text=True, timeout=180, check=False)
            retry = None
            retry_reason = None
            if "Host seems down" in first.stdout + first.stderr and _http_probe_reachable(target_url):
                retry_reason = "HTTP target reachable but nmap ping probe reported host down"
                retry_parts = ["nmap", "-Pn", "-sT", "-sV", "--top-ports", "100", "--open", "-T3", host]
                retry = subprocess.run(retry_parts, capture_output=True, text=True, timeout=180, check=False)
            completed = retry or first
            output = {
                "command": " ".join(command_parts),
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "first_attempt": _completed_process_payload(first, command_parts),
                "retry_attempt": _completed_process_payload(retry, ["nmap", "-Pn", "-sT", "-sV", "--top-ports", "100", "--open", "-T3", host]) if retry else None,
                "retry_reason": retry_reason,
            }
            open_lines = [line for line in completed.stdout.splitlines() if re.search(r"\d+/(tcp|udp)\s+open", line)]
            status = RunStatus.COMPLETED.value
            output["open_ports_found"] = bool(open_lines)
            if completed.returncode != 0 and not open_lines:
                status = RunStatus.EXECUTION_ERROR.value
            if open_lines:
                for line in open_lines:
                    _endpoint(session, scan, line, "port", "nmap_top_ports", metadata={"raw": line})
                    parsed_service = _parse_nmap_service_line(line)
                    session.add(DiscoveredService(scan_id=scan.id, host=host, source="nmap_top_ports", metadata_json={"raw": line}, **parsed_service))
                _finding(session, scan, "Open ports found by nmap", "; ".join(open_lines[:10]))
        except subprocess.TimeoutExpired as exc:
            output = {"error": "nmap timed out", "stdout": exc.stdout or "", "stderr": exc.stderr or ""}
            status = RunStatus.EXECUTION_ERROR.value
        except OSError as exc:
            output = {"error": str(exc)}
            status = RunStatus.EXECUTION_ERROR.value
    return _record_tool(session, scan, "nmap_top_ports", command, status, output, "network", "Nmap top ports enumeration", "prompt_nmap_top_ports")


def _run_nmap_full_tcp(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    host = _target_host(target_url)
    if not host:
        return _record_tool(session, scan, "nmap_full_tcp", "nmap -Pn -sT -p- --open -T3 <host>", RunStatus.MISSING_PREREQUISITE.value, {"reason": f"Could not extract host from {target_url!r}"}, "network", "Nmap full TCP enumeration", "prompt_nmap_full_tcp")
    command_parts = ["nmap", "-Pn", "-sT", "-p-", "--open", "-T3", host]
    if not shutil.which("nmap"):
        return _record_tool(session, scan, "nmap_full_tcp", " ".join(command_parts), RunStatus.MISSING_TOOL.value, {"reason": "nmap not installed"}, "network", "Nmap full TCP enumeration", "prompt_nmap_full_tcp")
    completed = subprocess.run(command_parts, capture_output=True, text=True, timeout=900, check=False)
    open_lines = [line for line in completed.stdout.splitlines() if re.search(r"\d+/(tcp|udp)\s+open", line)]
    for line in open_lines:
        _endpoint(session, scan, line, "port", "nmap_full_tcp", metadata={"raw": line})
    output = {"command": " ".join(command_parts), "returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr, "open_ports": open_lines}
    status = RunStatus.COMPLETED.value
    output["open_ports_found"] = bool(open_lines)
    if completed.returncode != 0 and not open_lines:
        status = RunStatus.EXECUTION_ERROR.value
    return _record_tool(session, scan, "nmap_full_tcp", " ".join(command_parts), status, output, "network", "Nmap full TCP enumeration", "prompt_nmap_full_tcp")


def _run_nmap_service_detection(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    host = _target_host(target_url)
    if not host:
        return _record_tool(session, scan, "nmap_service_detection", "nmap -Pn -sT -sV --open <host>", RunStatus.MISSING_PREREQUISITE.value, {"reason": f"Could not extract host from {target_url!r}"}, "network", "Nmap service detection", "prompt_nmap_service_detection")
    command_parts = ["nmap", "-Pn", "-sT", "-sV", "--top-ports", "1000", "--open", "-T3", host]
    if not shutil.which("nmap"):
        return _record_tool(session, scan, "nmap_service_detection", " ".join(command_parts), RunStatus.MISSING_TOOL.value, {"reason": "nmap not installed"}, "network", "Nmap service detection", "prompt_nmap_service_detection")
    completed = subprocess.run(command_parts, capture_output=True, text=True, timeout=300, check=False)
    services = [line for line in completed.stdout.splitlines() if re.search(r"\d+/(tcp|udp)\s+open", line)]
    for line in services:
        _endpoint(session, scan, line, "service", "nmap_service_detection", metadata={"raw": line})
    output = {"command": " ".join(command_parts), "returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr, "services": services}
    return _record_tool(
        session,
        scan,
        "nmap_service_detection",
        " ".join(command_parts),
        RunStatus.COMPLETED.value if completed.returncode == 0 else RunStatus.EXECUTION_ERROR.value,
        output,
        "network",
        "Nmap service detection",
        "prompt_nmap_service_detection",
    )


def _run_http_service_detection(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    host = _target_host(target_url)
    if not host:
        return _record_tool(session, scan, "http_service_detection", "probe HTTP services", RunStatus.MISSING_PREREQUISITE.value, {"reason": f"Could not extract host from {target_url!r}"}, "web", "HTTP service detection", "prompt_http_service_detection")
    ports = [80, 443, 8080, 8443, 8000, 8888]
    found = []
    for port in ports:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{host}:{port}"
        status, output = _http_get(url)
        if status == RunStatus.COMPLETED.value and output.get("status_code", 999) < 500:
            found.append({"url": url, "status_code": output.get("status_code"), "headers": output.get("headers", {})})
            _endpoint(session, scan, url, "web_service", "http_service_detection", metadata={"status_code": output.get("status_code")})
    output = {"checked_ports": ports, "found": found}
    return _record_tool(session, scan, "http_service_detection", "probe common HTTP service ports", RunStatus.COMPLETED.value if found else RunStatus.NOT_APPLICABLE.value, output, "web", "HTTP service detection", "prompt_http_service_detection")


def _completed_process_payload(process: subprocess.CompletedProcess | None, command_parts: list[str]) -> dict | None:
    if process is None:
        return None
    return {"command": " ".join(command_parts), "returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr}


def _parse_nmap_service_line(line: str) -> dict:
    match = re.match(r"(?P<port>\d+)/(?:tcp|udp)\s+open\s+(?P<service>\S+)(?:\s+(?P<product>.*))?", line.strip())
    if not match:
        return {"service_name": None, "port": None, "protocol": None, "product": None, "version": None}
    product = (match.group("product") or "").strip() or None
    return {
        "service_name": match.group("service"),
        "port": int(match.group("port")),
        "protocol": "tcp" if "/tcp" in line else "udp" if "/udp" in line else None,
        "product": product,
        "version": None,
    }


def _http_probe_reachable(target_url: str) -> bool:
    if not target_url.startswith(("http://", "https://")):
        return False
    try:
        httpx.get(target_url, follow_redirects=True, timeout=5)
        return True
    except Exception:
        return False


def _find_wordlist() -> str | None:
    settings = get_settings()
    candidates = []
    if settings.wordlist_web_common:
        candidates.append(str(settings.wordlist_web_common))
    candidates.extend(
        [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "configs/wordlists/web_common_small.txt",
        ]
    )
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def _parse_gobuster_paths(stdout: str, target_url: str) -> list[dict]:
    results = []
    for line in stdout.splitlines():
        match = re.search(r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d+)", line.strip())
        if match:
            results.append({"path": match.group("path"), "url": urljoin(target_url + "/", match.group("path")), "status_code": int(match.group("status"))})
    return results[:500]


def _run_internal_wordlist_discovery(session: Session, scan: Scan, target_url: str, source_tool: str, reason: str) -> dict:
    wordlist = _find_wordlist()
    if not wordlist:
        output = {"reason": reason, "alternate_tool": "internal_wordlist_discovery", "alternate_status": RunStatus.MISSING_PREREQUISITE.value}
        return _record_tool(session, scan, source_tool, "internal wordlist discovery", RunStatus.MISSING_PREREQUISITE.value, output, "web", "Internal wordlist discovery", f"prompt_{source_tool}_internal_wordlist")
    settings = get_settings()
    words: list[str] = []
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            words.append(value.lstrip("/"))
            if len(words) >= settings.dir_discovery_max_words:
                break
    found = []
    checked = 0
    for word in words:
        checked += 1
        url = urljoin(target_url.rstrip("/") + "/", word)
        try:
            response = httpx.get(url, follow_redirects=False, timeout=5)
        except Exception:
            continue
        if response.status_code != 404:
            item = {"path": "/" + word, "url": url, "status_code": response.status_code}
            found.append(item)
            _endpoint(session, scan, url, "web", "internal_wordlist_discovery", metadata={"status_code": response.status_code})
    output = {
        "reason": reason,
        "alternate_tool": "internal_wordlist_discovery",
        "wordlist": wordlist,
        "checked": checked,
        "found": found[:500],
        "count": len(found),
    }
    return _record_tool(session, scan, source_tool, f"internal wordlist discovery -w {wordlist}", RunStatus.ALTERNATE_TOOL_USED.value, output, "web", "Internal wordlist directory discovery", f"prompt_{source_tool}_internal_wordlist")


def _internal_crawl(target_url: str, max_depth: int | None = None, max_requests: int | None = None) -> dict:
    settings = get_settings()
    max_depth = max_depth if max_depth is not None else settings.crawler_max_depth
    max_requests = max_requests if max_requests is not None else settings.crawler_max_urls
    if not target_url.startswith(("http://", "https://")):
        return {"urls": [], "forms": [], "js_files": [], "api_paths": [], "requests": [], "reason": "internal crawler requires HTTP(S) target"}
    target_host = urlparse(target_url).netloc
    queue = [(target_url, 0)]
    seen: set[str] = set()
    urls: set[str] = set()
    forms: list[dict] = []
    js_files: set[str] = set()
    api_paths: set[str] = set()
    requests = []
    while queue and len(seen) < max_requests:
        url, depth = queue.pop(0)
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        try:
            response = httpx.get(url, follow_redirects=True, timeout=8)
        except Exception as exc:
            requests.append({"url": url, "error": str(exc)})
            continue
        body = response.text
        requests.append({"url": url, "status_code": response.status_code})
        for form in _extract_forms(url, body):
            forms.append(form)
        links = _normalize_url_list(url, _extract_all_links(body))
        for link in links:
            parsed = urlparse(link)
            if parsed.netloc != target_host:
                continue
            urls.add(link)
            if link.lower().split("?", 1)[0].endswith(".js"):
                js_files.add(link)
            elif depth + 1 <= max_depth:
                queue.append((link, depth + 1))
        for hint in re.findall(r"""["']((?:/api/|/auth|/login|/logout|/register|/users|/vehicles|/workshop|/community|/identity|wss?://|graphql)[^"']{0,180})["']""", body, re.IGNORECASE):
            api_paths.add(hint)
    return {"urls": sorted(urls), "forms": forms[:100], "js_files": sorted(js_files), "api_paths": sorted(api_paths), "requests": requests}


def _flow_type_from_url(url: str) -> str:
    lowered = url.lower()
    if "logout" in lowered:
        return "logout"
    if "register" in lowered or "signup" in lowered:
        return "registration"
    if "forgot" in lowered or "reset" in lowered:
        return "password_reset"
    if "saml" in lowered:
        return "saml"
    if "oidc" in lowered or "openid" in lowered:
        return "oidc"
    if "oauth" in lowered:
        return "oauth"
    if "token" in lowered:
        return "token"
    if "callback" in lowered or "redirect_uri" in lowered:
        return "callback"
    if "sso" in lowered:
        return "sso"
    if "login" in lowered or "signin" in lowered:
        return "login"
    return "auth"


def _run_katana(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    command_parts = ["katana", "-u", target_url, "-silent", "-d", "1"]
    try:
        completed = subprocess.run(command_parts, capture_output=True, text=True, timeout=180, check=False)
        urls = [line.strip() for line in completed.stdout.splitlines() if line.strip()][:300]
        output = {"returncode": completed.returncode, "stdout": completed.stdout[:12000], "stderr": completed.stderr[:4000], "urls": urls, "count": len(urls)}
        status = RunStatus.COMPLETED.value if completed.returncode == 0 else RunStatus.EXECUTION_ERROR.value
    except subprocess.TimeoutExpired as exc:
        output = {"error": "katana timed out", "stdout": exc.stdout or "", "stderr": exc.stderr or ""}
        status = RunStatus.EXECUTION_ERROR.value
    except OSError as exc:
        output = {"error": str(exc)}
        status = RunStatus.EXECUTION_ERROR.value
    return _record_tool(session, scan, "katana", " ".join(command_parts), status, output, "web", "Katana crawl inventory", "prompt_katana")


def _run_crawler(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    if shutil.which("katana"):
        return _run_katana(session, scan, target_url, prompt, parsed)
    settings = get_settings()
    output = _internal_crawl(target_url, max_depth=settings.crawler_max_depth, max_requests=settings.crawler_max_urls)
    for url in output["urls"]:
        _endpoint(session, scan, url, "web", "internal_crawler")
    for form in output["forms"]:
        _endpoint(session, scan, form["action"], "form", "internal_crawler", method=form["method"], metadata={"inputs": form["inputs"]})
        for name in form["inputs"]:
            _parameter(session, scan, name, "form", form["action"], "internal_crawler")
    for asset in output["js_files"]:
        _asset(session, scan, asset, "js", "internal_crawler")
    for hint in output["api_paths"]:
        _endpoint(session, scan, urljoin(target_url + "/", hint), "api", "internal_crawler")
    _artifact(session, scan, "discovered_urls", "internal_crawler", output)
    return _record_tool(session, scan, "crawler", f"internal crawler depth={settings.crawler_max_depth} max_requests={settings.crawler_max_urls}", RunStatus.COMPLETED.value, output, "web", "Internal crawler fallback", "prompt_internal_crawler")


def _run_gobuster_dir(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    wordlist = _find_wordlist()
    command = f"gobuster dir -u {target_url} -w <wordlist> -x php,js,json,txt,html -k --no-error"
    if not wordlist:
        return _run_internal_wordlist_discovery(session, scan, target_url, "gobuster_dir", "no external wordlist found")
    command_parts = ["gobuster", "dir", "-u", target_url, "-w", str(wordlist), "-x", "php,js,json,txt,html", "-k", "--no-error"]
    if not shutil.which("gobuster"):
        return _run_internal_wordlist_discovery(session, scan, target_url, "gobuster_dir", "gobuster not installed")
    completed = subprocess.run(command_parts, capture_output=True, text=True, timeout=300, check=False)
    discovered = _parse_gobuster_paths(completed.stdout, target_url)
    for item in discovered:
        _endpoint(session, scan, item["url"], "web", "gobuster_dir", metadata={"status_code": item.get("status_code")})
    output = {"command": " ".join(command_parts), "stdout": completed.stdout, "stderr": completed.stderr, "returncode": completed.returncode, "discovered_paths": discovered, "status_codes": sorted({item.get("status_code") for item in discovered if item.get("status_code")})}
    return _record_tool(session, scan, "gobuster_dir", " ".join(command_parts), RunStatus.COMPLETED.value if completed.returncode in {0, 1} else RunStatus.EXECUTION_ERROR.value, output, "web", "Gobuster directory discovery", "prompt_gobuster_dir")


def _run_ffuf_dir(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    wordlist = _find_wordlist()
    evidence_json = write_evidence(scan.id, "ffuf_raw_output_target", {"placeholder": True})
    command = f"ffuf -u {target_url}/FUZZ -w <wordlist> -mc all -fc 404 -of json -o {evidence_json}"
    if not wordlist:
        return _run_internal_wordlist_discovery(session, scan, target_url, "ffuf_dir", "no external wordlist found")
    if not shutil.which("ffuf"):
        return _run_internal_wordlist_discovery(session, scan, target_url, "ffuf_dir", "ffuf not installed")
    command_parts = ["ffuf", "-u", f"{target_url}/FUZZ", "-w", str(wordlist), "-mc", "all", "-fc", "404", "-of", "json", "-o", str(evidence_json)]
    completed = subprocess.run(command_parts, capture_output=True, text=True, timeout=300, check=False)
    parsed_json = None
    try:
        parsed_json = __import__("json").loads(evidence_json.read_text(encoding="utf-8"))
    except Exception:
        parsed_json = None
    results = parsed_json.get("results", []) if isinstance(parsed_json, dict) else []
    for item in results:
        if item.get("url"):
            _endpoint(session, scan, item["url"], "web", "ffuf_dir", metadata={"status_code": item.get("status")})
    output = {"command": " ".join(command_parts), "stdout": completed.stdout, "stderr": completed.stderr, "returncode": completed.returncode, "json_output": parsed_json, "raw_output_path": str(evidence_json)}
    return _record_tool(session, scan, "ffuf_dir", " ".join(command_parts), RunStatus.COMPLETED.value if completed.returncode in {0, 1} else RunStatus.EXECUTION_ERROR.value, output, "web", "ffuf directory discovery", "prompt_ffuf_dir")


def _run_auth_session_mapping(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    urls = [row.url for row in session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id).all()]
    status, html, root_output = _fetch_root_html(target_url) if target_url.startswith(("http://", "https://")) else (RunStatus.NOT_APPLICABLE.value, "", {})
    urls.extend(_normalize_url_list(target_url, _extract_all_links(html)) if html else [])
    common = [
        "/login",
        "/logout",
        "/register",
        "/forgot-password",
        "/reset-password",
        "/identity/api/auth/login",
        "/identity/api/auth/signup",
        "/identity/api/auth/register",
        "/identity/api/auth/verify",
        "/identity/api/auth/forget-password",
        "/identity/api/auth/forgot-password",
        "/identity/api/auth/reset-password",
        "/identity/api/auth/token",
        "/identity/api/auth/refresh",
        "/identity/api/auth/v2/check-otp",
        "/identity/api/auth/v3/check-otp",
        "/oauth",
        "/oidc",
        "/saml",
        "/callback",
        "/token",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ]
    try:
        profile = profile_from_scan_artifacts(session, scan, target_url).profile
        common.extend(auth_endpoint_candidates(profile))
    except Exception:
        pass
    discovered_auth_urls = [
        row.url
        for row in session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id, DiscoveredEndpoint.endpoint_type == "api_auth").all()
    ]
    common.extend(urlparse(url).path for url in discovered_auth_urls)
    checked = []
    for path in sorted(set(common)):
        url = urljoin(target_url + "/", path)
        probe = _probe_api_path(target_url, path)
        checked.append({"url": url, "status": RunStatus.COMPLETED.value, "valid": probe.get("valid"), "probes": probe.get("probes", [])})
        if probe.get("valid") and probe.get("auth_flow"):
            _auth_flow(session, scan, probe["auth_flow"], url, {"probes": probe.get("probes", [])})
            _auth_mechanism(session, scan, probe["auth_flow"], url, "medium", {"probes": probe.get("probes", [])})
    for form in _extract_forms(target_url, html):
        flow_type = _flow_type_from_url(form["action"])
        if flow_type in {"login", "logout", "registration", "password_reset", "oauth", "oidc", "saml", "token"}:
            _auth_flow(session, scan, flow_type, form["action"], {"form": form})
    credentials = load_credentials()
    for item in credentials:
        auth_type = str(item.get("auth_type") or "form")
        _auth_mechanism(session, scan, auth_type, None, "high", {"credential_label": item.get("label"), "source": "configs/credentials.yaml"})
        if auth_type in {"bearer", "api_key", "cookie"}:
            _session_mechanism(session, scan, auth_type, "credentials", "jwt" if auth_type == "bearer" else auth_type, "high", {"credential_label": item.get("label")})
    provisioning = {"status": RunStatus.PLANNED.value, "next_stage": "account_provisioning"}
    output = {"checked": checked, "credentials_configured": bool(credentials), "credential_labels": [item.get("label") for item in credentials], "generated_account_provisioning": provisioning, "root_status_code": root_output.get("status_code")}
    status = RunStatus.COMPLETED.value if checked or html else RunStatus.NOT_APPLICABLE.value
    _artifact(session, scan, "discovered_auth_endpoints", "auth_session_mapping", output)
    return _record_tool(session, scan, "auth_session_mapping", "auth/session discovery", status, output, "auth", "Authentication and session mapping", "prompt_auth_session_mapping")


def _attempt_generated_account_provisioning(session: Session, scan: Scan, target_url: str) -> dict:
    selection = profile_from_scan_artifacts(session, scan, target_url)
    signup_urls = _flow_urls(session, scan, {"registration"}) or _profile_auth_urls(session, scan, target_url, {"signup", "register"})
    login_urls = _flow_urls(session, scan, {"login", "token"}) or _profile_auth_urls(session, scan, target_url, {"login", "signin", "token"})
    signup = signup_urls[0] if signup_urls else None
    login = login_urls[0] if login_urls else None
    if not signup and not login:
        return {
            "status": RunStatus.NOT_APPLICABLE.value,
            "reason": "registration/login endpoints not discovered",
            "selected_profile": selection.primary_profile,
            "profile_confidence": selection.confidence,
        }
    suffix = f"saif{scan.id}"
    email = f"{suffix}@example.com"
    password = "SAIF-Test-Password-123!"
    user_profile = {
        "name": "SAIF Test User",
        "email": email,
        "username": email,
        "number": f"555000{scan.id:04d}"[-10:],
        "password": password,
        "role": "user",
        "tenant": "generated",
    }
    result: dict = {
        "email": email,
        "signup_url": signup,
        "login_url": login,
        "selected_profile": selection.primary_profile,
        "profile_confidence": selection.confidence,
        "status": RunStatus.PLANNED.value,
    }
    if signup:
        try:
            registration_candidates = registration_payloads(selection.profile, user_profile) or [
                {"email": email, "username": email, "password": password, "name": user_profile["name"]}
            ]
            payload = registration_candidates[0]
            response = httpx.post(signup, json=payload, follow_redirects=False, timeout=10)
            result["signup"] = {"status_code": response.status_code, "content_type": response.headers.get("content-type"), "body_preview": response.text[:1000], "json_keys": _json_keys(response.text)}
            if any(token in response.text.lower() for token in ["verify", "otp", "verification"]):
                result["status"] = RunStatus.MISSING_PREREQUISITE.value
                result["reason"] = "verification_required"
        except Exception as exc:
            result["signup"] = {"error": str(exc)}
            result["status"] = RunStatus.EXECUTION_ERROR.value
    if login and result.get("reason") != "verification_required":
        try:
            login_candidates = login_payloads(selection.profile, email, password)
            payload = login_candidates[0] if login_candidates else {"email": email, "password": password}
            login_response = httpx.post(login, json=payload, follow_redirects=False, timeout=10)
            result["login"] = {"status_code": login_response.status_code, "content_type": login_response.headers.get("content-type"), "body_preview": login_response.text[:1000], "json_keys": _json_keys(login_response.text)}
            tokens = _detect_tokens_and_cookies(dict(login_response.headers), login_response.text)
            result["tokens_detected"] = len(tokens)
            for token in tokens:
                _token(session, scan, token["token_type"], token["location"], token.get("sample"), token)
            if tokens or login_response.status_code in {200, 201}:
                credential = Credential(
                    project_id=scan.project_id,
                    label=f"generated-{suffix}",
                    username=email,
                    secret_ref="generated during authorized test run",
                    role="generated_user",
                    metadata_json={"source": "auth_session_mapping", "scan_id": scan.id, "login_url": login},
                )
                session.add(credential)
                session.flush()
                session.add(
                    SessionRecord(
                        project_id=scan.project_id,
                        credential_id=credential.id,
                        label=f"generated-session-{suffix}",
                        cookies=dict(login_response.cookies),
                        headers={},
                    )
                )
                result["status"] = RunStatus.COMPLETED.value
            elif result.get("status") == RunStatus.PLANNED.value:
                result["status"] = RunStatus.MISSING_PREREQUISITE.value
                result["reason"] = "login did not return a usable session/token"
        except Exception as exc:
            result["login"] = {"error": str(exc)}
            result["status"] = RunStatus.EXECUTION_ERROR.value
    return result


def _run_token_analysis(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    tokens = session.query(DiscoveredToken).filter(DiscoveredToken.scan_id == scan.id).all()
    credentials = load_credentials()
    for item in credentials:
        if item.get("auth_type") == "bearer":
            _token(session, scan, "bearer", "credentials", str(item.get("token", ""))[:160], {"label": item.get("label")})
        if item.get("auth_type") == "cookie":
            _token(session, scan, "cookie", "credentials", str(item.get("cookie", ""))[:160], {"label": item.get("label")})
    output = {"tokens_or_cookies_detected": len(tokens), "credential_tokens": [item.get("label") for item in credentials if item.get("auth_type") in {"bearer", "cookie"}]}
    return _record_tool(session, scan, "token_analysis", "token and cookie analysis", RunStatus.COMPLETED.value, output, "auth", "Token/session analysis", "prompt_token_analysis")


def _run_authorization_matrix(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    all_sessions = _authenticated_sessions_for_scan(session, scan)
    sessions = [item for item in all_sessions if item.session_status == "usable"]
    objects = session.query(DiscoveredObject).filter(DiscoveredObject.scan_id == scan.id).limit(100).all()
    if len(all_sessions) >= 2 and len(sessions) < 2:
        output = {
            "reason": "authenticated sessions exist but are not usable against protected endpoints",
            "authenticated_sessions": [
                {"label": item.credential_label, "session_status": item.session_status, "login_status": item.login_status}
                for item in all_sessions
            ],
            "usable_sessions": [item.credential_label for item in sessions],
        }
        return _record_tool(session, scan, "authorization_matrix", "authenticated cross-account object replay", RunStatus.EXECUTION_ERROR.value, output, "authz", "Authorization matrix", "prompt_authorization_matrix")
    if len(sessions) >= 2 and objects:
        checks = []
        findings_created = 0
        subject = sessions[0]
        alternate = sessions[1]
        for obj in objects[:25]:
            url = obj.object_ref.split("#", 1)[0]
            try:
                subject_headers, subject_cookies = _auth_headers_for_session(subject)
                alternate_headers, alternate_cookies = _auth_headers_for_session(alternate)
                owner_response = httpx.get(url, headers=subject_headers, cookies=subject_cookies, follow_redirects=False, timeout=10)
                alternate_response = httpx.get(url, headers=alternate_headers, cookies=alternate_cookies, follow_redirects=False, timeout=10)
                _record_exchange(session, scan, "GET", url, _masked_headers(subject_headers), None, owner_response)
                _record_exchange(session, scan, "GET", url, _masked_headers(alternate_headers), None, alternate_response)
                observed = "same_status" if owner_response.status_code == alternate_response.status_code else "different_status"
                body_same = owner_response.text[:2000] == alternate_response.text[:2000]
                issue = owner_response.status_code in {200, 201} and alternate_response.status_code in {200, 201} and body_same
                matrix_status = RunStatus.FINDING_CREATED.value if issue else RunStatus.COMPLETED.value
                if issue:
                    findings_created += 1
                    _finding(session, scan, "Possible cross-account object access", f"{alternate.credential_label} received the same response for object {obj.object_ref} discovered with {subject.credential_label}.")
                session.add(
                    AuthorizationMatrix(
                        scan_id=scan.id,
                        subject=alternate.credential_label,
                        role="generated_user",
                        endpoint=url,
                        object_ref=obj.object_ref,
                        expected_access="different owner should not receive same object response",
                        observed_access=observed,
                        status=matrix_status,
                        metadata_json={"owner_session": subject.credential_label, "attacker_session": alternate.credential_label, "owner_status": owner_response.status_code, "actual_status_code": alternate_response.status_code, "body_same": body_same, "object_id": obj.object_ref.rsplit("#", 1)[-1]},
                    )
                )
                checks.append({"object_ref": obj.object_ref, "owner_status": owner_response.status_code, "alternate_status": alternate_response.status_code, "body_same": body_same, "status": matrix_status})
            except Exception as exc:
                checks.append({"object_ref": obj.object_ref, "status": RunStatus.EXECUTION_ERROR.value, "error": str(exc)})
        output = {"mode": "authenticated_cross_account", "sessions": [item.credential_label for item in sessions[:2]], "objects_tested": len(checks), "findings_created": findings_created, "checks": checks}
        status = RunStatus.FINDING_CREATED.value if findings_created else RunStatus.COMPLETED.value
        return _record_tool(session, scan, "authorization_matrix", "authenticated cross-account object replay", status, output, "authz", "Authorization matrix", "prompt_authorization_matrix")

    if len(sessions) >= 2 and not objects:
        crawl_run = _latest_tool_output(session, scan.id, "authenticated_crawling") or {}
        had_401 = any(item.get("status_code") == 401 for item in crawl_run.get("requests", []))
        status = RunStatus.EXECUTION_ERROR.value if had_401 else RunStatus.MISSING_PREREQUISITE.value
        reason = "authenticated session exists but target returned 401 during object discovery" if had_401 else "authenticated sessions exist but no object identifiers discovered yet"
        output = {"reason": reason, "authenticated_sessions": [item.credential_label for item in sessions], "objects": 0}
        return _record_tool(session, scan, "authorization_matrix", "authenticated cross-account object replay", status, output, "authz", "Authorization matrix", "prompt_authorization_matrix")

    credentials = load_credentials()
    endpoints = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id).limit(200).all()
    if not credentials:
        output = {"reason": "credentials or authenticated sessions are required for authorization matrix creation", "endpoint_count": len(endpoints), "authenticated_sessions": len(sessions), "objects": len(objects)}
        return _record_tool(session, scan, "authorization_matrix", "build authorization matrix", RunStatus.MISSING_CREDENTIALS.value, output, "authz", "Authorization matrix", "prompt_authorization_matrix")
    for credential in credentials:
        for endpoint in endpoints[:50]:
            session.add(
                AuthorizationMatrix(
                    scan_id=scan.id,
                    subject=str(credential.get("label") or credential.get("username") or "credential"),
                    role=credential.get("role"),
                    endpoint=endpoint.url,
                    expected_access="manual_confirmation_required",
                    observed_access=None,
                    status=RunStatus.PLANNED.value,
                    metadata_json={"tenant": credential.get("tenant"), "auth_type": credential.get("auth_type")},
                )
            )
    output = {"credentials": [item.get("label") for item in credentials], "endpoint_count": len(endpoints), "matrix_entries": len(credentials) * min(len(endpoints), 50)}
    return _record_tool(session, scan, "authorization_matrix", "build authorization matrix", RunStatus.COMPLETED.value, output, "authz", "Authorization matrix", "prompt_authorization_matrix")


def _run_idor_bola_bfla_planner(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    auth_sessions = _authenticated_sessions_for_scan(session, scan)
    objects = session.query(DiscoveredObject).filter(DiscoveredObject.scan_id == scan.id).all()
    authenticated_endpoints = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id, DiscoveredEndpoint.endpoint_type == "authenticated_api").all()
    if len(auth_sessions) >= 2:
        cases = ["IDOR/BOLA", "BFLA", "horizontal privilege escalation", "vertical privilege escalation", "tenant isolation", "forced browsing"]
        if not objects:
            output = {"test_cases": cases, "reason": "authenticated crawling did not discover object identifiers", "authenticated_sessions": [item.credential_label for item in auth_sessions], "authenticated_endpoint_count": len(authenticated_endpoints)}
            return _record_tool(session, scan, "idor_bola_bfla_planner", "plan IDOR/BOLA/BFLA tests", RunStatus.MISSING_PREREQUISITE.value, output, "authz", "IDOR/BOLA/BFLA planning", "prompt_idor_bola_bfla")
        output = {"test_cases": cases, "authenticated_sessions": [item.credential_label for item in auth_sessions], "object_count": len(objects), "authenticated_endpoint_count": len(authenticated_endpoints), "status": "authorization_matrix executed replay checks"}
        return _record_tool(session, scan, "idor_bola_bfla_planner", "plan IDOR/BOLA/BFLA tests", RunStatus.COMPLETED.value, output, "authz", "IDOR/BOLA/BFLA planning", "prompt_idor_bola_bfla")

    credentials = load_credentials()
    status = RunStatus.PLANNED.value if credentials else RunStatus.MISSING_CREDENTIALS.value
    cases = ["IDOR/BOLA", "BFLA", "horizontal privilege escalation", "vertical privilege escalation", "tenant isolation", "forced browsing"]
    output = {"test_cases": cases, "reason": None if credentials else "credentials are required for replay-based authorization testing"}
    return _record_tool(session, scan, "idor_bola_bfla_planner", "plan IDOR/BOLA/BFLA tests", status, output, "authz", "IDOR/BOLA/BFLA planning", "prompt_idor_bola_bfla")


def _run_input_validation_planner(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    params = session.query(DiscoveredParameter).filter(DiscoveredParameter.scan_id == scan.id).all()
    output = {"parameter_count": len(params), "test_families": ["xss", "sqli", "ssrf", "path traversal"], "reason": None if params else "no parameters discovered yet"}
    status = RunStatus.PLANNED.value if params else RunStatus.MISSING_PREREQUISITE.value
    return _record_tool(session, scan, "input_validation_planner", "plan input validation tests", status, output, "input_validation", "Input validation planning", "prompt_input_validation")


def _body_hash(body: str) -> str:
    import hashlib

    return hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _baseline_for_endpoint(url: str) -> dict:
    try:
        response = httpx.get(url, follow_redirects=False, timeout=8)
        return {"status_code": response.status_code, "content_type": response.headers.get("content-type", ""), "body_hash": _body_hash(response.text), "body_length": len(response.text), "interesting_markers": _interesting_markers(response.text), "_body": response.text}
    except Exception as exc:
        return {"error": str(exc), "status_code": None, "content_type": "", "body_hash": "", "body_length": 0, "interesting_markers": [], "_body": ""}


def _interesting_markers(body: str) -> list[str]:
    lowered = body.lower()
    markers = []
    for token in ["sql syntax", "mysql", "postgres", "sqlite", "ora-", "stack trace", "traceback", "exception", "validation", "unauthorized"]:
        if token in lowered:
            markers.append(token)
    return markers


def _record_payload_ai_call(session: Session, scan: Scan, stage: str, client, attempts: list[dict], status: str, error: str | None = None) -> None:
    duration_ms = sum(int(item.get("duration_ms") or 0) for item in attempts) if attempts else None
    final_attempt = attempts[-1] if attempts else {}
    evidence_path = write_evidence(
        scan.id,
        f"ai_call_{stage}_{vuln_type_safe(stage)}_{datetime.now(timezone.utc).strftime('%H%M%S%f')}",
        {"stage": stage, "model": client.model, "status": status, "error": error, "ai_call_attempts": attempts},
    )
    session.add(
        Evidence(
            scan_id=scan.id,
            kind="ai",
            path=str(evidence_path),
            summary=f"AI call {stage}: {status}",
            metadata_json={"stage": stage, "model": client.model, "status": status},
        )
    )
    session.add(
        AiCallRun(
            scan_id=scan.id,
            stage=stage,
            model=client.model,
            prompt_tokens_estimate=int(((final_attempt.get("request_summary") or {}).get("prompt_chars_estimate") or 0) / 4) if final_attempt else None,
            response_status=status,
            http_status=final_attempt.get("http_status"),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            duration_ms=duration_ms,
            retry_count=max(0, len(attempts) - 1),
            error_message=error or final_attempt.get("error_message"),
            request_summary=final_attempt.get("request_summary"),
            response_summary=final_attempt.get("response_summary"),
            evidence_path=str(evidence_path),
        )
    )


def vuln_type_safe(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("_")[:80] or "call"


def _ai_analyze_attempt(session: Session, scan: Scan, vuln_type: str, baseline: dict, attempt: dict) -> dict:
    from saif.ai.ollama import OllamaClient

    client = OllamaClient()
    try:
        decision = client.chat_json(
            [
                {"role": "system", "content": "Return strict JSON only. Analyze one bounded payload test response for authorized testing."},
                {
                    "role": "user",
                    "content": __import__("json").dumps(
                        {
                            "vulnerability_type": vuln_type,
                            "baseline": {k: v for k, v in baseline.items() if not k.startswith("_")},
                            "attempt": attempt,
                            "required_output": {
                                "finding_candidate": False,
                                "vulnerability_type": vuln_type,
                                "confidence": "low",
                                "reason": "",
                                "next_payload_strategy": "",
                                "next_payload": "",
                                "stop_condition": "",
                                "reportable": False,
                                "needs_manual_confirmation": False,
                            },
                        }
                    ),
                },
            ],
            timeout=get_settings().ollama_timeout_seconds,
            stage="payload_decision",
        )
        _record_payload_ai_call(session, scan, "payload_decision", client, client.last_call_attempts, "completed")
        return decision
    except Exception as exc:
        status = getattr(exc, "status", "failed_ai_chat")
        _record_payload_ai_call(session, scan, "payload_decision", client, getattr(client, "last_call_attempts", []), status, str(exc))
        return {"finding_candidate": False, "vulnerability_type": vuln_type, "confidence": "low", "reason": f"AI analyzer unavailable: {exc}", "reportable": False, "needs_manual_confirmation": True}


def _adaptive_payload_loop(session: Session, scan: Scan, vuln_type: str, category: str, target_url: str, parameter_filter=None) -> dict:
    settings = get_settings()
    params = session.query(DiscoveredParameter).filter(DiscoveredParameter.scan_id == scan.id).all()
    if parameter_filter:
        params = [param for param in params if parameter_filter(param.name)]
    if not params:
        return {"status": RunStatus.MISSING_PREREQUISITE.value, "reason": "no parameters discovered for adaptive testing", "payload_source": active_payload_source(category).__dict__, "attempts": []}
    payloads = load_payloads(category, settings.max_payloads_per_parameter)
    if not payloads:
        return {"status": RunStatus.MISSING_PREREQUISITE.value, "reason": f"no payloads available for {category}", "payload_source": active_payload_source(category).__dict__, "attempts": []}
    attempts = []
    decisions = []
    status = RunStatus.COMPLETED.value
    for param in params[:10]:
        endpoint = param.endpoint or target_url
        baseline = _baseline_for_endpoint(endpoint)
        for index, payload in enumerate(payloads[: settings.max_ai_payload_iterations], start=1):
            try:
                response = httpx.get(endpoint, params={param.name: payload}, follow_redirects=False, timeout=8)
                reflection = payload in response.text
                error_marker = bool(_interesting_markers(response.text))
                attempt = {
                    "payload": payload,
                    "location": "query",
                    "endpoint": endpoint,
                    "parameter": param.name,
                    "status_code": response.status_code,
                    "body_hash": _body_hash(response.text),
                    "body_length_delta": len(response.text) - int(baseline.get("body_length") or 0),
                    "reflection": reflection,
                    "error_marker": error_marker,
                    "body_preview": response.text[:1000],
                }
                path = write_evidence(scan.id, f"adaptive_{vuln_type}_{param.name}_{index}", {"baseline": {k: v for k, v in baseline.items() if not k.startswith("_")}, "attempt": attempt})
                attempt["evidence_path"] = str(path)
                decision = _ai_analyze_attempt(session, scan, vuln_type, baseline, attempt)
                attempts.append(attempt)
                decisions.append({"attempt": index, "parameter": param.name, "ai_decision": decision})
                payload_attempt = PayloadAttempt(
                    scan_id=scan.id,
                    test_case_id=f"adaptive.{vuln_type}",
                    agent_name=f"{vuln_type}_agent",
                    vulnerability_type=vuln_type,
                    endpoint=endpoint,
                    method="GET",
                    parameter_location="query",
                    parameter_name=param.name,
                    payload=payload,
                    payload_masked=_mask_token(payload) if "token" in param.name.lower() else payload,
                    payload_source=f"{active_payload_source(category).source_type}:{active_payload_source(category).path or ''}",
                    baseline_status=baseline.get("status_code"),
                    baseline_body_hash=baseline.get("body_hash"),
                    attack_status=response.status_code,
                    attack_body_hash=_body_hash(response.text),
                    body_length_delta=attempt["body_length_delta"],
                    reflection_detected=reflection,
                    error_marker_detected=error_marker,
                    protected_data_detected=False,
                    ai_decision_json=decision,
                    status=RunStatus.FINDING_CREATED.value if decision.get("reportable") else RunStatus.COMPLETED.value,
                    evidence_path=str(path),
                )
                session.add(payload_attempt)
                session.flush()
                emit_progress(session, scan, f"payload attempt {vuln_type} {param.name} status={payload_attempt.status}", phase=_phase_for_tool(f"{vuln_type}_adaptive"), agent=f"{vuln_type}_agent", tool=f"{vuln_type}_adaptive", event_type="payload_attempt_created", context={"payload_attempt_id": payload_attempt.id, "endpoint": endpoint, "parameter": param.name, "status": payload_attempt.status, "evidence_path": str(path)})
                if decision.get("reportable") and decision.get("confidence") in {"medium", "high"}:
                    status = RunStatus.FINDING_CREATED.value
                    _adaptive_finding(session, scan, f"Potential {vuln_type.upper()} finding", "high" if decision.get("confidence") == "high" else "medium", decision.get("reason") or f"{vuln_type} candidate identified", endpoint, param.name, payload, decision.get("confidence") or "medium", status=RunStatus.FINDING_CREATED.value)
                    break
                if decision.get("needs_manual_confirmation") or (reflection and vuln_type == "xss"):
                    status = RunStatus.MANUAL_CONFIRMATION_REQUIRED.value if status != RunStatus.FINDING_CREATED.value else status
            except Exception as exc:
                attempts.append({"payload": payload, "endpoint": endpoint, "parameter": param.name, "error": str(exc)})
    return {"status": status, "payload_source": active_payload_source(category).__dict__, "attempts": attempts, "ai_decisions": decisions}


def _run_xss_adaptive(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    output = _adaptive_payload_loop(session, scan, "xss", "xss", target_url)
    _artifact(session, scan, "adaptive_testing", "xss_adaptive", output)
    return _record_tool(session, scan, "xss_adaptive", "adaptive XSS payload testing", output["status"], output, "input_validation", "Adaptive XSS testing", "prompt_xss_adaptive")


def _run_sqli_adaptive(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    output = _adaptive_payload_loop(session, scan, "sqli", "sqli", target_url)
    _artifact(session, scan, "adaptive_testing", "sqli_adaptive", output)
    return _record_tool(session, scan, "sqli_adaptive", "adaptive SQL injection payload testing", output["status"], output, "input_validation", "Adaptive SQL injection testing", "prompt_sqli_adaptive")


def _run_ssrf_adaptive(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    settings = get_settings()
    if not settings.ssrf_callback_url:
        output = {"status": RunStatus.MISSING_PREREQUISITE.value, "reason": "SSRF confirmation callback endpoint not configured", "payload_source": active_payload_source("ssrf").__dict__}
        return _record_tool(session, scan, "ssrf_adaptive", "adaptive SSRF testing", RunStatus.MISSING_PREREQUISITE.value, output, "input_validation", "Adaptive SSRF testing", "prompt_ssrf_adaptive")
    names = {"url", "uri", "callback", "redirect", "image", "avatar", "webhook", "next", "returnurl"}
    output = _adaptive_payload_loop(session, scan, "ssrf", "ssrf", target_url, lambda name: name.lower() in names)
    _artifact(session, scan, "adaptive_testing", "ssrf_adaptive", output)
    return _record_tool(session, scan, "ssrf_adaptive", "adaptive SSRF testing", output["status"], output, "input_validation", "Adaptive SSRF testing", "prompt_ssrf_adaptive")


def _run_jwt_adaptive(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    tokens = session.query(DiscoveredToken).filter(DiscoveredToken.scan_id == scan.id, DiscoveredToken.token_type.in_(["jwt", "bearer"])).all()
    auth_sessions = _authenticated_sessions_for_scan(session, scan)
    if not tokens and not auth_sessions:
        output = {"reason": "JWT/bearer tokens not captured"}
        return _record_tool(session, scan, "jwt_adaptive", "adaptive JWT testing", RunStatus.MISSING_PREREQUISITE.value, output, "auth", "Adaptive JWT testing", "prompt_jwt_adaptive")
    endpoints = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id, DiscoveredEndpoint.endpoint_type == "authenticated_api").limit(10).all()
    tests = []
    findings_created = 0
    manual_review = False
    for auth_session in auth_sessions:
        secret = _load_session_secret(auth_session)
        access_token = secret.get("token")
        if not access_token:
            tests.append({"session": auth_session.credential_label, "status": RunStatus.EXECUTION_ERROR.value, "reason": secret.get("reason") or "execution token unavailable or masked token used", "token_was_masked": secret.get("token_was_masked")})
            continue
        token_meta = _decode_jwt_unverified(access_token)
        valid_headers = {"Authorization": f"Bearer {access_token}"}
        tampered_headers = {"Authorization": f"Bearer {_tamper_token(access_token)}"}
        for endpoint in endpoints[:5]:
            baseline = _jwt_probe(endpoint.url, valid_headers)
            for label, headers in [("missing_token", {}), ("malformed_token", {"Authorization": "Bearer malformed.token.value"}), ("tampered_token", tampered_headers)]:
                try:
                    result = _jwt_probe(endpoint.url, headers)
                    comparison = _compare_jwt_probe(baseline, result)
                    finding_confirmed = _jwt_finding_confirmed(baseline, result, comparison)
                    if result.get("is_redirect") or result.get("content_type", "").lower().startswith("text/html"):
                        classification = "false_positive_rejected" if result.get("is_redirect") else "manual_confirmation_required"
                        confidence = "low"
                        severity = "info"
                    elif finding_confirmed:
                        classification = RunStatus.FINDING_CREATED.value
                        confidence = "high" if comparison.get("same_body_hash") else "medium"
                        severity = "high" if confidence == "high" else "medium"
                    else:
                        classification = RunStatus.COMPLETED.value
                        confidence = "low"
                        severity = "info"
                    tests.append(
                        {
                            "session": auth_session.credential_label,
                            "test": label,
                            "url": endpoint.url,
                            "baseline_valid_token": baseline,
                            "result": result,
                            "response_comparison": comparison,
                            "protected_data_detected": bool(baseline.get("protected_data_detected")),
                            "finding_confirmed": finding_confirmed,
                            "classification": classification,
                            "confidence": confidence,
                            "severity": severity,
                            "token_metadata": token_meta,
                        }
                    )
                    payload_attempt = PayloadAttempt(
                        scan_id=scan.id,
                        test_case_id="adaptive.jwt",
                        agent_name="jwt_agent",
                        vulnerability_type="jwt",
                        endpoint=endpoint.url,
                        method="GET",
                        parameter_location="header",
                        parameter_name="Authorization",
                        payload=label,
                        payload_masked=label,
                        payload_source="SAIF jwt adaptive",
                        baseline_status=baseline.get("status_code"),
                        baseline_body_hash=baseline.get("body_hash"),
                        attack_status=result.get("status_code"),
                        attack_body_hash=result.get("body_hash"),
                        body_length_delta=(result.get("body_length") or 0) - (baseline.get("body_length") or 0),
                        reflection_detected=False,
                        error_marker_detected=False,
                        protected_data_detected=bool(result.get("protected_data_detected")),
                        ai_decision_json={"classification": classification, "confidence": confidence, "finding_confirmed": finding_confirmed, "response_comparison": comparison},
                        status=classification,
                        evidence_path=None,
                    )
                    session.add(payload_attempt)
                    session.flush()
                    emit_progress(session, scan, f"payload attempt jwt Authorization status={classification}", phase="token_analysis", agent="jwt_agent", tool="jwt_adaptive", event_type="payload_attempt_created", context={"payload_attempt_id": payload_attempt.id, "endpoint": endpoint.url, "status": classification})
                    if finding_confirmed:
                        findings_created += 1
                        _adaptive_finding(session, scan, "JWT authorization control weakness", severity, f"{label} returned protected data equivalent to a valid-token baseline for {endpoint.url}", endpoint.url, "Authorization", label, confidence)
                    elif classification == "manual_confirmation_required":
                        manual_review = True
                except Exception as exc:
                    tests.append({"session": auth_session.credential_label, "test": label, "url": endpoint.url, "error": str(exc), "token_metadata": token_meta})
    status = RunStatus.FINDING_CREATED.value if findings_created else RunStatus.MANUAL_CONFIRMATION_REQUIRED.value if manual_review else RunStatus.COMPLETED.value
    output = {"payload_source": active_payload_source("jwt").__dict__, "tests": tests, "token_count": len(tokens) + len(auth_sessions)}
    _artifact(session, scan, "adaptive_testing", "jwt_adaptive", output)
    return _record_tool(session, scan, "jwt_adaptive", "adaptive JWT testing", status, output, "auth", "Adaptive JWT testing", "prompt_jwt_adaptive")


def _tamper_token(token: str) -> str:
    if not token:
        return "malformed.token.value"
    replacement = "A" if token[-1] != "A" else "B"
    return token[:-1] + replacement


def _jwt_probe(url: str, headers: dict) -> dict:
    response = httpx.get(url, headers=headers, follow_redirects=False, timeout=8)
    content_type = response.headers.get("content-type", "")
    body = response.text
    json_keys = _json_keys(body)
    is_redirect = response.status_code in {301, 302, 307, 308}
    protected_data_detected = response.status_code == 200 and "application/json" in content_type.lower() and bool(json_keys)
    return {
        "status_code": response.status_code,
        "content_type": content_type,
        "is_redirect": is_redirect,
        "location": response.headers.get("location"),
        "body_hash": _body_hash(body),
        "body_length": len(body),
        "json_keys": json_keys,
        "protected_data_detected": protected_data_detected,
        "body_preview": body[:800],
    }


def _compare_jwt_probe(baseline: dict, result: dict) -> dict:
    return {
        "same_status": baseline.get("status_code") == result.get("status_code"),
        "same_body_hash": baseline.get("body_hash") == result.get("body_hash"),
        "baseline_status": baseline.get("status_code"),
        "test_status": result.get("status_code"),
        "baseline_protected_data_detected": baseline.get("protected_data_detected"),
        "test_protected_data_detected": result.get("protected_data_detected"),
    }


def _jwt_finding_confirmed(baseline: dict, result: dict, comparison: dict) -> bool:
    if result.get("status_code") in {301, 302, 307, 308} or result.get("is_redirect"):
        return False
    if str(result.get("content_type") or "").lower().startswith("text/html"):
        return False
    if not baseline.get("protected_data_detected"):
        return False
    if result.get("protected_data_detected") and comparison.get("same_body_hash"):
        return True
    return bool(result.get("status_code") == 200 and result.get("protected_data_detected"))


def _run_business_logic_planner(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    endpoints = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id).all()
    candidates = [
        endpoint.url
        for endpoint in endpoints
        if any(token in endpoint.url.lower() for token in ["order", "cart", "payment", "checkout", "invoice", "billing", "tenant", "account", "object", "vehicle", "user", "profile", "admin"])
    ]
    output = {"candidate_endpoints": candidates[:100], "test_families": ["workflow abuse", "state transition checks", "role/tenant consistency", "rate/sequence checks"]}
    return _record_tool(session, scan, "business_logic_planner", "plan business logic tests", RunStatus.PLANNED.value if candidates else RunStatus.NOT_APPLICABLE.value, output, "business_logic", "Business logic planning", "prompt_business_logic")


def _run_auth_authorization_planner(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    output = {"reason": "Authentication/authorization testing requires configured credentials and sessions."}
    return _record_tool(session, scan, "auth_authorization_planner", "plan auth/authorization checks", RunStatus.MISSING_CREDENTIALS.value, output, "auth", "Auth/authorization planning", "prompt_auth_authorization")
