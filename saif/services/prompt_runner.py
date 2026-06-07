import os
import re
import shutil
import subprocess
import time
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

from saif.analyzers.parameter_miner import mine_parameters
from saif.analyzers.passive_analyzer import analyze_request_response, is_important_for_ai
from saif.agents.ollama_response_advisor import review_important_response
from saif.ai.advisor import ask_ai_for_payload_strategy, ask_ai_for_report_wording
from saif.ai.gate import AIContext, ai_review_evidence, log_ai_context, log_ai_review
from saif.browser_agent.browser_authenticated_capture import capture_authenticated_browser_traffic
from saif.config import get_settings
from saif.core.request_map import body_shape_from_body, load_request_map, upsert_request_response
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
from saif.importers.har_importer import import_har
from saif.importers.manual_request_importer import import_manual_request
from saif.services.case_management import ensure_scan_phases, mark_phase, sync_scan_phases
from saif.services.credentials import load_credentials
from saif.services.debug_export import generate_full_ai_debug_export
from saif.services.evidence import write_evidence
from saif.services.endpoint_sanitizer import rejection_sample, sanitize_candidate_endpoint
from saif.services.api_docs_analyzer import discover_api_documentation
from saif.services.payloads import active_payload_source, load_payloads, payload_library_status
from saif.services.pentest_engine import PENTEST_PHASES, analyze_response, classify_target
from saif.services.progress import emit_progress, heartbeat
from saif.services.profiles import auth_endpoint_candidates, detect_profile, load_profile, login_payloads, profile_from_scan_artifacts, registration_payloads
from saif.services.tool_manager import TOOL_DEPENDENCIES, ToolInstallAttempt, check_runtime_tools, prepare_selected_tools, upsert_tool_registry


TARGET_RE = re.compile(r"(?:https?://[^\s,;'\"<>]+)|(?:\b(?:\d{1,3}\.){3}\d{1,3}\b)", re.IGNORECASE)
DETERMINISTIC_EXECUTION_PROFILES = {
    "destructive-full-scan",
    "authenticated-full-scan",
    "auth-authorization-debug",
    "standard-non-destructive",
    "safe-enumeration",
}
CATEGORY_TO_TOOLS = {
    "recon": ["http_client", "technology_fingerprint", "root_link_inventory", "robots_txt", "sitemap_xml"],
    "network_recon": ["nmap_top_ports"],
    "api_discovery": ["openapi_discovery", "static_asset_inventory", "api_path_hints", "api_profile_probe"],
    "api_discovery_basic": ["openapi_discovery", "static_asset_inventory", "api_path_hints", "api_profile_probe"],
    "api_discovery_aggressive": ["crawler", "katana", "ffuf_dir", "gobuster_dir", "ffuf_api_paths", "gobuster_api_paths"],
    "method_discovery": ["api_method_probe"],
    "security_headers": ["security_headers_check", "csp_headers_check", "cache_control_check", "cors_check"],
    "error_handling": ["error_disclosure_check"],
    "auth_testing": ["auth_session_mapping", "account_provisioning", "login_session"],
    "session_management": ["token_analysis", "session_validation"],
    "jwt_testing": ["jwt_adaptive"],
    "password_reset_otp": ["password_reset_otp_testing"],
    "rate_limiting": ["rate_limit_planner", "rate_limit_executor"],
    "authorization_matrix": ["authenticated_crawling", "authorization_matrix"],
    "bola_idor": ["idor_bola_bfla_planner", "bola_idor_testing"],
    "bfla": ["bfla_testing"],
    "mass_assignment": ["mass_assignment_testing"],
    "cross_account_replay": ["cross_account_replay"],
    "input_validation": ["input_validation_planner", "xss_adaptive", "sqli_adaptive", "ssrf_adaptive", "path_traversal_adaptive", "open_redirect_adaptive"],
    "xss": ["input_validation_planner", "xss_adaptive"],
    "sqli": ["input_validation_planner", "sqli_adaptive"],
    "ssrf": ["input_validation_planner", "ssrf_adaptive"],
    "business_logic": ["business_logic_planner", "business_logic_testing"],
}
TOOL_TO_CATEGORY = {tool: category for category, tools in CATEGORY_TO_TOOLS.items() for tool in tools}
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


def tools_for_execution_profile(scan_config: dict | None) -> list[str]:
    config = scan_config or {}
    execution_profile = str(config.get("execution_profile") or "").strip()
    destructive_policy = str(config.get("destructive_test_policy") or "").strip()
    full_requested = bool(config.get("full")) or bool(config.get("select_all_applicable"))
    authenticated_requested = bool(config.get("allow_authenticated_testing"))
    authorization_requested = bool(config.get("allow_authorization_testing"))
    payload_requested = bool(config.get("allow_payload_testing"))
    rate_limit_requested = bool(config.get("allow_rate_limit_testing"))
    destructive_requested = (
        execution_profile == "destructive-full-scan"
        or destructive_policy == "lab_full_allowed"
        or bool(config.get("enable_destructive_tests"))
    )
    aggressive_discovery_selected = "api_discovery_aggressive" in set(config.get("selected_test_categories") or []) or bool(config.get("enable_fuzzing"))
    tools: list[str] = []
    if execution_profile == "auth-authorization-debug":
        tools.extend(
            [
                "technology_fingerprint",
                "root_link_inventory",
                "robots_txt",
                "sitemap_xml",
                "static_asset_inventory",
                "openapi_discovery",
                "api_path_hints",
                "api_profile_probe",
                "api_method_probe",
                "crawler",
                "auth_session_mapping",
                "account_provisioning",
                "login_session",
                "session_validation",
                "token_analysis",
                "authenticated_crawling",
                "authenticated_resource_discovery",
                "resource_ownership_map",
                "authorization_matrix",
                "idor_bola_bfla_planner",
                "mass_assignment_testing",
                "cross_account_access_testing",
            ]
        )
    elif destructive_requested or full_requested:
        tools.extend(
            [
                "http_client",
                "technology_fingerprint",
                "security_headers_check",
                "csp_headers_check",
                "cors_check",
                "cache_control_check",
                "error_disclosure_check",
                "root_link_inventory",
                "robots_txt",
                "sitemap_xml",
                "openapi_discovery",
                "static_asset_inventory",
                "api_path_hints",
                "api_profile_probe",
                "api_method_probe",
                "crawler",
                "auth_session_mapping",
                "account_provisioning",
                "login_session",
                "session_validation",
                "token_analysis",
                "authenticated_crawling",
                "authorization_matrix",
                "idor_bola_bfla_planner",
                "input_validation_planner",
                "xss_adaptive",
                "sqli_adaptive",
                "ssrf_adaptive",
                "jwt_adaptive",
                "business_logic_planner",
            ]
        )
        if aggressive_discovery_selected:
            tools.extend(["ffuf_api_paths", "gobuster_api_paths"])
        if rate_limit_requested or destructive_requested:
            tools.append("rate_limit_planner")
    elif authenticated_requested or authorization_requested:
        tools.extend(
            [
                "auth_session_mapping",
                "account_provisioning",
                "login_session",
                "session_validation",
                "token_analysis",
                "authenticated_crawling",
            ]
        )
        if authorization_requested:
            tools.extend(["authorization_matrix", "idor_bola_bfla_planner"])
    if payload_requested and not destructive_requested:
        tools.extend(["input_validation_planner", "xss_adaptive", "sqli_adaptive", "ssrf_adaptive", "jwt_adaptive"])
    return _ordered_tools(list(dict.fromkeys(tools)))


def application_profile_for_existing_scan(existing_scan: Scan | None) -> str:
    if not existing_scan:
        return "auto"
    config = existing_scan.scan_config or {}
    return str(config.get("application_profile") or config.get("profile") or existing_scan.profile or "auto")


def _ordered_tools(tools: list[str]) -> list[str]:
    priority = [
        "http_client",
        "technology_fingerprint",
        "security_headers_check",
        "csp_headers_check",
        "cors_check",
        "cache_control_check",
        "error_disclosure_check",
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
        "session_validation",
        "token_analysis",
        "authenticated_crawling",
        "authenticated_resource_discovery",
        "resource_ownership_map",
        "authorization_matrix",
        "idor_bola_bfla_planner",
        "mass_assignment_testing",
        "cross_account_access_testing",
        "xss_adaptive",
        "sqli_adaptive",
        "ssrf_adaptive",
        "jwt_adaptive",
        "input_validation_planner",
        "rate_limit_planner",
        "business_logic_planner",
        "nmap_top_ports",
    ]
    rank = {tool: index for index, tool in enumerate(priority)}
    return sorted(tools, key=lambda tool: rank.get(tool, len(priority)))


def _deterministic_tools_for_execution_profile(execution_profile: str, tools: list[str]) -> list[str]:
    if execution_profile != "destructive-full-scan":
        return tools
    priority = [
        "http_client",
        "technology_fingerprint",
        "security_headers_check",
        "csp_headers_check",
        "cors_check",
        "cache_control_check",
        "error_disclosure_check",
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
        "session_validation",
        "authenticated_crawling",
        "authenticated_resource_discovery",
        "resource_ownership_map",
        "authorization_matrix",
        "idor_bola_bfla_planner",
        "mass_assignment_testing",
        "cross_account_access_testing",
        "input_validation_planner",
        "xss_adaptive",
        "sqli_adaptive",
        "ssrf_adaptive",
        "jwt_adaptive",
        "rate_limit_planner",
        "business_logic_planner",
    ]
    rank = {tool: index for index, tool in enumerate(priority)}
    return sorted(tools, key=lambda tool: rank.get(tool, len(priority)))


def _apply_selected_category_allowlist(tools: list[str], selected_categories: list[str] | None) -> tuple[list[str], dict]:
    categories = [str(item) for item in (selected_categories or []) if str(item)]
    if not categories:
        return tools, {
            "selected_test_categories": [],
            "allowed_tools": tools,
            "skipped_unselected_tools": [],
            "tool_audit": [{"tool": tool, "selected": True, "category": TOOL_TO_CATEGORY.get(tool), "reason": "selected by scan configuration"} for tool in tools],
        }
    allowed = {tool for category in categories for tool in CATEGORY_TO_TOOLS.get(category, [])}
    selected = [tool for tool in tools if tool in allowed]
    skipped = [
        {"tool": tool, "reason": "tool not selected by selected_test_categories", "category": TOOL_TO_CATEGORY.get(tool)}
        for tool in tools
        if tool not in allowed
    ]
    audit = [
        {"tool": tool, "selected": tool in allowed, "category": TOOL_TO_CATEGORY.get(tool), "reason": "selected by selected_test_categories" if tool in allowed else "tool not selected by selected_test_categories"}
        for tool in tools
    ]
    return selected, {"selected_test_categories": categories, "allowed_tools": sorted(allowed), "skipped_unselected_tools": skipped, "tool_audit": audit}


def _selected_tool_plan_payload(scan: Scan | None, execution_profile: str, full: bool, audit: dict, final_executable_tools: list[str] | None = None) -> dict:
    allowed_tools = list(dict.fromkeys(audit.get("allowed_tools", [])))
    payload = {
        "selected_test_categories": audit.get("selected_test_categories", []),
        "allowed_tools": allowed_tools,
        "final_executable_tools": list(final_executable_tools or []),
        "skipped_unselected_tools": audit.get("skipped_unselected_tools", []),
        "policy_blocked_tools": [],
        "auth_gate_blocked_tools": [],
        "actually_executed_tools": [],
        "attempted_but_should_not_have_executed": [],
        "execution_profile": execution_profile,
        "full": bool(full),
        "tools": audit.get("tool_audit", []),
    }
    if scan is not None:
        config = dict(scan.scan_config or {})
        previous = config.get("selected_tool_plan") or {}
        for key in ["policy_blocked_tools", "auth_gate_blocked_tools", "actually_executed_tools", "attempted_but_should_not_have_executed"]:
            if previous.get(key):
                payload[key] = previous.get(key)
    return payload


def _write_selected_tool_plan(session: Session, scan: Scan, execution_profile: str, full: bool, audit: dict, final_executable_tools: list[str] | None = None) -> None:
    payload = _selected_tool_plan_payload(scan, execution_profile, full, audit, final_executable_tools)
    config = dict(scan.scan_config or {})
    config["selected_tool_plan"] = payload
    config["selected_tools"] = list(payload["final_executable_tools"] or [])
    scan.scan_config = config
    path = write_evidence(scan.id, "selected_tool_plan", payload)
    session.add(Evidence(scan_id=scan.id, kind="selected_tool_plan", path=str(path), summary="Selected test category tool plan.", metadata_json={"tool": "orchestrator", "selected_categories": payload["selected_test_categories"]}))
    _artifact(session, scan, "selected_tool_plan", "selected_tool_plan", payload)


def _selected_tool_plan(scan: Scan) -> dict:
    return dict((getattr(scan, "scan_config", None) or {}).get("selected_tool_plan") or {})


def is_tool_selected(scan: Scan, tool_name: str) -> bool:
    plan = _selected_tool_plan(scan)
    if not plan:
        selected = set((scan.scan_config or {}).get("selected_tools") or [])
        return not selected or tool_name in selected
    allowed = set(plan.get("final_executable_tools") or plan.get("allowed_tools") or [])
    return tool_name in allowed


def _mark_tool_skipped_unselected(session: Session, scan: Scan, tool: str, console: Console | None = None) -> None:
    config = dict(scan.scan_config or {})
    plan = dict(config.get("selected_tool_plan") or {})
    skipped = list(plan.get("skipped_unselected_tools") or [])
    if not any(item.get("tool") == tool for item in skipped if isinstance(item, dict)):
        skipped.append({"tool": tool, "reason": "tool not selected by selected_test_categories", "category": TOOL_TO_CATEGORY.get(tool)})
    plan["skipped_unselected_tools"] = skipped
    config["selected_tool_plan"] = plan
    scan.scan_config = config
    emit_progress(session, scan, f"skipped unselected tool: {tool}", phase="orchestration", agent="orchestrator_agent", tool=tool, event_type="tool_skipped_unselected", context={"tool": tool, "reason": "tool not selected by selected_test_categories"}, console=console, live=True)


def _record_tool_executed_in_plan(scan: Scan, tool: str) -> None:
    config = dict(scan.scan_config or {})
    plan = dict(config.get("selected_tool_plan") or {})
    executed = list(plan.get("actually_executed_tools") or [])
    if tool not in executed:
        executed.append(tool)
    plan["actually_executed_tools"] = executed
    allowed = set(plan.get("final_executable_tools") or plan.get("allowed_tools") or [])
    invalid = [item for item in executed if item not in allowed]
    plan["attempted_but_should_not_have_executed"] = invalid
    if invalid:
        config["scan_quality_status"] = "invalid_tool_selection_enforcement"
    config["selected_tool_plan"] = plan
    scan.scan_config = config


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
    known_protected_endpoints: list[dict | str] | None = None,
    har_file: str | None = None,
    known_authenticated_requests: list[dict | str] | None = None,
    login_workflow_hints: dict | None = None,
    existing_scan: Scan | None = None,
) -> tuple[Scan, list[str], list[dict], dict, dict]:
    parsed = parse_prompt(prompt)
    if not any(parsed.values()):
        parsed["default_enumeration"] = True
    parser_selected_tools = select_tools(parsed, target_url)
    profile_selected_tools = tools_for_execution_profile((existing_scan.scan_config if existing_scan else None) or {})

    runner = {
        "http_client": _run_http_baseline,
        "shodan_search": _run_shodan_search,
        "technology_fingerprint": _run_technology_fingerprint,
        "security_headers_check": _run_security_headers_check,
        "csp_headers_check": _run_csp_headers_check,
        "cors_check": _run_cors_check,
        "cache_control_check": _run_cache_control_check,
        "error_disclosure_check": _run_error_disclosure_check,
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
        "session_validation": _run_session_validation,
        "authenticated_crawling": _run_authenticated_crawling,
        "authenticated_resource_discovery": _run_authenticated_resource_discovery,
        "resource_ownership_map": _run_resource_ownership_map,
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
        "mass_assignment_testing": _run_mass_assignment_testing,
        "cross_account_access_testing": _run_cross_account_access_testing,
        "input_validation_planner": _run_input_validation_planner,
        "business_logic_planner": _run_business_logic_planner,
        "rate_limit_planner": _run_rate_limit_planner,
        "rate_limit_executor": _run_rate_limit_executor,
        "auth_authorization_planner": _run_auth_authorization_planner,
    }
    ai_selected_tools = _normalize_ai_tools(ai_context.scan_plan.get("tools", []), runner.keys())
    selected_tools = _ordered_tools(list(dict.fromkeys((ai_selected_tools or []) + parser_selected_tools + profile_selected_tools)))
    execution_profile = str(((existing_scan.scan_config if existing_scan else {}) or {}).get("execution_profile") or "")
    selected_tools = _deterministic_tools_for_execution_profile(execution_profile, selected_tools)
    if execution_profile == "auth-authorization-debug":
        selected_tools = profile_selected_tools
    selected_tools, selected_tool_audit = _apply_selected_category_allowlist(selected_tools, selected_test_categories)
    selected_tools = [tool for tool in selected_tools if tool in runner]
    ai_context.scan_plan["mode"] = execution_profile if execution_profile in DETERMINISTIC_EXECUTION_PROFILES else _mode_from_prompt(parsed)
    ai_context.scan_plan["execution_profile_tools"] = profile_selected_tools
    ai_context.scan_plan["selected_category_allowed_tools"] = selected_tool_audit.get("allowed_tools", [])
    ai_context.scan_plan["skipped_unselected_tools"] = selected_tool_audit.get("skipped_unselected_tools", [])

    scan = existing_scan or Scan(project_id=project.id)
    scan.project_id = project.id
    scan.profile = application_profile_for_existing_scan(existing_scan)
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
    existing_known = (scan.scan_config or {}).get("known_protected_endpoints") or []
    existing_config = scan.scan_config or {}
    scan.scan_config = {
        **existing_config,
        "selected_test_categories": selected_test_categories or [],
        "selected_tools": selected_tools,
        "known_protected_endpoints": known_protected_endpoints or existing_known,
        "har_file": har_file or existing_config.get("har_file"),
        "known_authenticated_requests": known_authenticated_requests or existing_config.get("known_authenticated_requests") or [],
        "login_workflow_hints": login_workflow_hints or existing_config.get("login_workflow_hints") or {},
    }
    scan.status = ScanStatus.PLANNING.value
    scan.started_at = scan.started_at or datetime.now(timezone.utc)
    session.add(scan)
    session.flush()
    _import_initial_workflow_evidence(session, scan, target_url)
    target_classification = classify_target(target_url)
    _artifact(
        session,
        scan,
        "scan_memory",
        "target_classification",
        {
            "phase_order": PENTEST_PHASES,
            "target_classification": target_classification,
            "decision_loop": "OBSERVE_THINK_DECIDE_ACT_VERIFY_LEARN",
        },
    )
    emit_progress(
        session,
        scan,
        f"target classified type={target_classification['target_type']} host={target_classification['host']}",
        phase="target_classification",
        agent="orchestrator_agent",
        event_type="target_classified",
        context=target_classification,
        console=console,
        live=True,
    )
    _create_scan_test_plan(session, scan, selected_test_categories or [])
    _write_selected_tool_plan(session, scan, execution_profile, bool(((existing_scan.scan_config if existing_scan else {}) or {}).get("full")), selected_tool_audit, selected_tools)
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
    mark_phase(
        session,
        scan,
        "ai_planning",
        RunStatus.COMPLETED.value,
        {
            "selected_tools": selected_tools,
            "ai_planning_status": ai_context.scan_plan.get("ai_planning_status") or "approved",
            "ai_planning_error": ai_context.scan_plan.get("ai_planning_error"),
            "ai_planning_warning": ai_context.scan_plan.get("ai_planning_warning") or ai_context.scan_plan.get("warning"),
            "ai_available": ai_context.scan_plan.get("ai_available", True),
            "deterministic_mode": ai_context.scan_plan.get("deterministic_mode", False),
        },
    )
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
    final_selected_tools = [tool for tool in (_selected_tool_plan(scan).get("final_executable_tools") or []) if is_tool_selected(scan, tool) and tool in runner]
    preparation = prepare_selected_tools(final_selected_tools, console=console)
    executable_tools = [tool for tool in preparation.executable_tools if is_tool_selected(scan, tool)]
    config = dict(scan.scan_config or {})
    plan = dict(config.get("selected_tool_plan") or {})
    plan["final_executable_tools"] = executable_tools
    config["selected_tool_plan"] = plan
    config["selected_tools"] = executable_tools
    scan.scan_config = config
    upsert_tool_registry(session, check_runtime_tools(), preparation.attempts)
    session.add(
        Log(
            scan_id=scan.id,
            level="info",
            message="Tool preparation",
            context={
                "selected_tools": final_selected_tools,
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
        emit_progress(session, scan, f"Executable selected tools: {executable_tools}", phase="orchestration", agent="orchestrator_agent", event_type="executable_selected_tools", context={"final_executable_tools": executable_tools, "skipped_unselected_tools": selected_tool_audit.get("skipped_unselected_tools", [])}, console=console, live=True)
        emit_progress(session, scan, "status=running", phase="enumeration", agent="orchestrator_agent", event_type="scan_started", console=console, live=True)
        for attempt in preparation.attempts:
            if attempt.status != "completed":
                tool_results.append(_record_install_attempt(session, scan, attempt))
        tool_index = 0
        while tool_index < len(executable_tools):
            tool = executable_tools[tool_index]
            tool_index += 1
            if not is_tool_selected(scan, tool):
                _mark_tool_skipped_unselected(session, scan, tool, console=console)
                continue
            control_status = _scan_control_status(session, scan)
            if control_status in {ScanStatus.PAUSED.value, ScanStatus.STOPPING.value, ScanStatus.STOPPED.value}:
                scan.status = ScanStatus.STOPPED.value if control_status in {ScanStatus.STOPPING.value, ScanStatus.STOPPED.value} else ScanStatus.PAUSED.value
                if scan.status == ScanStatus.STOPPED.value:
                    scan.completed_at = datetime.now(timezone.utc)
                break
            agent_name = _agent_for_tool(tool)
            phase_name = _phase_for_tool(tool)
            if _auth_gate_blocks_tool(scan, tool):
                _mark_auth_gate_tool_blocked(session, scan, tool)
                continue
            dependency_block = _dependency_block_for_tool(session, scan, tool)
            if dependency_block:
                resolution = _resolve_missing_prerequisite(
                    session,
                    scan,
                    tool,
                    dependency_block,
                    runner,
                    target_url,
                    prompt,
                    parsed,
                    console=console,
                    debug_live=debug_live,
                )
                tool_results.extend(resolution.get("tool_results", []))
                dependency_block = _dependency_block_for_tool(session, scan, tool)
                if dependency_block:
                    dependency_block["resolver"] = {key: value for key, value in resolution.items() if key != "tool_results"}
                    result = _record_dependency_block(session, scan, tool, dependency_block, console=console)
                    tool_results.append(result)
                    if tool in planned_cases:
                        planned_cases[tool].status = result.get("status") or RunStatus.MISSING_PREREQUISITE.value
                    continue
                emit_progress(
                    session,
                    scan,
                    f"retry started after prerequisite resolution: {tool}",
                    phase=phase_name,
                    agent=agent_name,
                    tool=tool,
                    event_type="retry_started",
                    context={"resolved_by": resolution.get("actions_taken", [])},
                    console=console,
                    live=True,
                )
            emit_progress(session, scan, "agent started", phase=phase_name, agent=agent_name, tool=tool, event_type="agent_started", console=console, live=debug_live)
            emit_progress(session, scan, "started", phase=phase_name, agent=agent_name, tool=tool, event_type="tool_started", console=console, live=True)
            _record_tool_executed_in_plan(scan, tool)
            job = _create_agent_job(session, scan, agent_name, tool, AgentJobStatus.RUNNING.value, {"tool": tool, "target": target_url})
            running_tool_run = _start_tool_run_marker(session, scan, tool, agent_name, f"execute {tool}")
            try:
                if tool == "katana" and any(item.get("tool") in {"katana", "crawler"} and str(item.get("command", "")).startswith("katana ") for item in tool_results):
                    _finish_agent_job(job, AgentJobStatus.COMPLETED.value, {"status": "deduplicated", "reason": "katana already executed for crawler capability"})
                    continue
                with heartbeat(scan.id, phase=phase_name, agent=agent_name, tool=tool, console=console, live=debug_live):
                    result = runner[tool](session, scan, target_url, prompt, parsed)
                tool_results.append(result)
                _finish_tool_run_marker(running_tool_run, result.get("status") or RunStatus.EXECUTION_ERROR.value, result)
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
                auth_stop = _auth_failed_stop_reason(scan, tool, result)
                if auth_stop:
                    _write_auth_coverage_blocked(session, scan, result)
                    scan.status = "auth_blocked"
                    scan.current_phase = "session_validation_failed"
                    scan.current_agent = "auth_agent"
                    scan.current_tool = "session_validation"
                    scan.progress_message = auth_stop
                    scan.last_activity_at = datetime.now(timezone.utc)
                    emit_progress(
                        session,
                        scan,
                        auth_stop,
                        level="ERROR",
                        phase="session_validation_failed",
                        agent="auth_agent",
                        tool="session_validation",
                        event_type="auth_failed",
                        context={"valid_sessions_count": (result.get("output") or {}).get("valid_sessions_count"), "reason": (result.get("output") or {}).get("reason")},
                        console=console,
                        live=True,
                    )
                    break
                added_tools = _maybe_escalate_after_profile_probe(session, scan, tool, result, parsed, selected_tools, executable_tools, runner.keys(), target_url)
                if added_tools:
                    if selected_tool_audit.get("selected_test_categories"):
                        allowed_added = set(selected_tool_audit.get("allowed_tools") or [])
                        skipped_added = [item for item in added_tools if item not in allowed_added]
                        added_tools = [item for item in added_tools if item in allowed_added]
                        if skipped_added:
                            emit_progress(session, scan, f"skipped unselected escalation tools: {', '.join(skipped_added)}", phase=phase_name, agent="orchestrator_agent", event_type="tool_skipped_unselected", context={"tools": skipped_added, "reason": "tool not selected by selected_test_categories"}, console=console, live=True)
                    if not added_tools:
                        continue
                    for added_tool in added_tools:
                        if added_tool not in planned_cases:
                            planned_cases.update(_create_planned_test_cases(session, scan, [added_tool], target_url))
                    scan.profile = "api-security-authenticated-test"
                    ai_context.scan_plan["mode"] = scan.profile
                    ai_context.scan_plan["tools"] = selected_tools
                    session.add(
                        Log(
                            scan_id=scan.id,
                            level="info",
                            message="Execution profile escalated",
                            context={
                                "execution_profile": scan.profile,
                                "added_tools": added_tools,
                                "reason": "Application profile and auth endpoints support authenticated API security workflow.",
                                "selected_tools": selected_tools,
                            },
                        )
                    )
                    if console:
                        console.print(f"Execution profile escalated: {scan.profile}")
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
                _finish_tool_run_marker(running_tool_run, RunStatus.EXECUTION_ERROR.value, result, str(exc))
                _finish_agent_job(job, AgentJobStatus.FAILED.value, {"status": result.get("status")}, str(exc))
                emit_progress(session, scan, "agent failed", level="ERROR", phase=phase_name, agent=agent_name, tool=tool, event_type="agent_completed", context={"error": str(exc)}, console=console, live=debug_live)
                emit_progress(session, scan, f"error {exc}", level="ERROR", phase=phase_name, agent=agent_name, tool=tool, event_type="error", console=console, live=True)
                if tool in planned_cases:
                    planned_cases[tool].status = RunStatus.EXECUTION_ERROR.value
        if scan.status in {ScanStatus.PAUSED.value, ScanStatus.STOPPED.value, ScanStatus.AUTH_FAILED.value, "auth_blocked"}:
            _write_selected_tool_plan(session, scan, execution_profile, bool(((existing_scan.scan_config if existing_scan else {}) or {}).get("full")), selected_tool_audit, executable_tools)
            _safe_debug_export(session, scan)
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
        report_wording = ask_ai_for_report_wording(
            session,
            scan,
            current_phase="report_generation",
            scope={"target": target_url, "allowed_hosts": [urlparse(target_url).hostname]},
            evidence={"ai_review": ai_review, "execution_summary": _execution_summary(selected_tools, tool_results)},
            stage="report_wording",
        )
        ai_review["ai_report_wording_memory"] = report_wording
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
        _write_selected_tool_plan(session, scan, execution_profile, bool(((existing_scan.scan_config if existing_scan else {}) or {}).get("full")), selected_tool_audit, executable_tools)
        scan.status = _final_scan_status(session, scan, selected_tools, tool_results)
        if (scan.scan_config or {}).get("scan_quality_status") == "invalid_tool_selection_enforcement":
            scan.status = "execution_error"
        scan.completed_at = datetime.now(timezone.utc)
        _safe_debug_export(session, scan)
        emit_progress(session, scan, f"scan {scan.status}", phase="reporting", agent="reporting_agent", event_type="scan_completed", console=console, live=True)
    except Exception:
        scan.status = ScanStatus.FAILED.value
        scan.completed_at = datetime.now(timezone.utc)
        raise

    return scan, selected_tools, tool_results, parsed, ai_review


def _safe_debug_export(session: Session, scan: Scan) -> None:
    try:
        json_path, html_path = generate_full_ai_debug_export(session, scan.id)
        config = dict(scan.scan_config or {})
        config["full_ai_debug_json"] = str(json_path)
        config["full_ai_debug_html"] = str(html_path)
        scan.scan_config = config
    except Exception as exc:
        _artifact(session, scan, "debug_export_error", "full_ai_debug_export_failed", {"error": str(exc)})


AGENT_BY_TOOL = {
    "http_client": "recon_agent",
    "technology_fingerprint": "recon_agent",
    "security_headers_check": "recon_agent",
    "csp_headers_check": "recon_agent",
    "cors_check": "recon_agent",
    "cache_control_check": "recon_agent",
    "error_disclosure_check": "recon_agent",
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
    "session_validation": "auth_agent",
    "authenticated_crawling": "auth_agent",
    "authenticated_resource_discovery": "auth_agent",
    "resource_ownership_map": "authorization_agent",
    "token_analysis": "token_agent",
    "authorization_matrix": "authorization_agent",
    "idor_bola_bfla_planner": "authorization_agent",
    "mass_assignment_testing": "authorization_agent",
    "cross_account_access_testing": "authorization_agent",
    "xss_adaptive": "input_validation_agent",
    "sqli_adaptive": "input_validation_agent",
    "ssrf_adaptive": "input_validation_agent",
    "jwt_adaptive": "token_agent",
    "input_validation_planner": "input_validation_agent",
    "rate_limit_planner": "business_logic_agent",
    "rate_limit_executor": "business_logic_agent",
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
        case_id = f"scan-{scan.id}.{tool}"
        case = session.query(TestCase).filter(TestCase.scan_id == scan.id, TestCase.case_id == case_id, TestCase.profile == scan.profile).one_or_none()
        if case:
            case.enabled = True
            case.status = case.status or RunStatus.PLANNED.value
            case.priority = min(case.priority or 10 + index, 10 + index)
        else:
            case = TestCase(
                scan_id=scan.id,
                case_id=case_id,
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
    if tool in {"security_headers_check", "csp_headers_check", "cors_check", "cache_control_check", "error_disclosure_check"}:
        return "recon"
    if tool in {"openapi_discovery", "api_path_hints", "api_profile_probe", "api_method_probe", "ffuf_api_paths", "gobuster_api_paths"}:
        return "api_discovery"
    if tool in {"auth_session_mapping", "token_analysis", "account_provisioning", "login_session", "session_validation", "authenticated_crawling", "authenticated_resource_discovery"}:
        return "authentication_discovery"
    if tool in {"authorization_matrix", "idor_bola_bfla_planner", "resource_ownership_map", "mass_assignment_testing", "cross_account_access_testing"}:
        return "authorization_testing"
    if tool in {"input_validation_planner", "xss_adaptive", "sqli_adaptive", "ssrf_adaptive"}:
        return "input_validation"
    if tool in {"rate_limit_planner", "rate_limit_executor"}:
        return "business_logic_testing"
    if tool in {"jwt_adaptive"}:
        return "token_analysis"
    if tool in {"root_link_inventory", "robots_txt", "sitemap_xml", "static_asset_inventory", "katana", "crawler", "gobuster_dir", "ffuf_dir"}:
        return "web_enumeration"
    return "recon"


def _category_for_tool(tool: str) -> str:
    if tool in {"security_headers_check", "csp_headers_check", "cors_check", "cache_control_check", "error_disclosure_check"}:
        return "security_headers"
    if "nmap" in tool:
        return "port_scan"
    if tool in {"gobuster_dir", "ffuf_dir"}:
        return "directory_discovery"
    if tool in {"katana", "crawler"}:
        return "web_crawling"
    if tool in {"openapi_discovery", "api_path_hints", "api_profile_probe", "api_method_probe", "ffuf_api_paths", "gobuster_api_paths"}:
        return "api_discovery"
    if tool in {"auth_session_mapping", "token_analysis", "account_provisioning", "login_session", "session_validation", "authenticated_crawling", "authenticated_resource_discovery"}:
        return "authentication"
    if tool in {"authorization_matrix", "idor_bola_bfla_planner", "resource_ownership_map", "mass_assignment_testing", "cross_account_access_testing"}:
        return "authorization"
    if tool in {"xss_adaptive", "sqli_adaptive", "ssrf_adaptive"}:
        return "input_validation"
    if tool in {"rate_limit_planner", "rate_limit_executor"}:
        return "rate_limiting"
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


def _usable_session_count(session: Session, scan: Scan) -> int:
    return (
        session.query(AuthenticatedSession)
        .filter(
            AuthenticatedSession.scan_id == scan.id,
            AuthenticatedSession.login_status == "login_success",
            AuthenticatedSession.session_status == "usable",
        )
        .count()
    )


def _protected_endpoint_count(session: Session, scan: Scan) -> int:
    return (
        session.query(DiscoveredEndpoint)
        .filter(DiscoveredEndpoint.scan_id == scan.id, DiscoveredEndpoint.endpoint_type == "authenticated_api")
        .count()
    )


def _discovered_object_count(session: Session, scan: Scan) -> int:
    return session.query(DiscoveredObject).filter(DiscoveredObject.scan_id == scan.id).count()


def _request_templates(session: Session, scan: Scan, target_url: str | None = None) -> list[dict]:
    params = session.query(DiscoveredParameter).filter(DiscoveredParameter.scan_id == scan.id).all()
    templates = []
    for param in params:
        template = _request_template_for_parameter(session, scan, param, target_url or "")
        if template:
            templates.append(template)
    return templates


def _request_templates_count(session: Session, scan: Scan) -> int:
    return len(_request_templates(session, scan))


def _confirmed_auth_flow_urls(session: Session, scan: Scan, flow_types: set[str]) -> list[str]:
    urls = []
    for flow in session.query(DiscoveredAuthFlow).filter(DiscoveredAuthFlow.scan_id == scan.id).all():
        if flow.flow_type not in flow_types or not flow.url:
            continue
        evidence = flow.evidence or {}
        confidence = evidence.get("endpoint_confidence")
        source = str(evidence.get("source") or "").lower()
        if confidence in {"high", "medium"} or source in {"form", "crawler", "openapi", "api_method_probe", "api_profile_probe"}:
            urls.append(flow.url)
    return list(dict.fromkeys(urls))


def _method_confirmed_for_url(session: Session, scan: Scan, url: str, preferred_method: str = "POST") -> bool:
    preferred_method = preferred_method.upper()
    endpoints = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id, DiscoveredEndpoint.url == url).all()
    for endpoint in endpoints:
        methods = {item.strip().upper() for item in str(endpoint.method or "").split(",") if item.strip()}
        if preferred_method in methods:
            return True
        metadata = endpoint.metadata_json or {}
        for probe in metadata.get("probes", []) or []:
            if probe.get("method") == preferred_method and probe.get("endpoint_confidence") in {"high", "medium"}:
                return True
    return False


def _request_template_ready_for_url(session: Session, scan: Scan, url: str, target_url: str) -> bool:
    params = session.query(DiscoveredParameter).filter(DiscoveredParameter.scan_id == scan.id, DiscoveredParameter.endpoint == url).all()
    return any(_request_template_for_parameter(session, scan, param, target_url) for param in params)


def _request_templates_for_url(session: Session, scan: Scan, url: str, target_url: str) -> list[dict]:
    params = session.query(DiscoveredParameter).filter(DiscoveredParameter.scan_id == scan.id, DiscoveredParameter.endpoint == url).all()
    return [template for param in params if (template := _request_template_for_parameter(session, scan, param, target_url))]


def _auth_endpoint_gate(session: Session, scan: Scan, target_url: str, flow_types: set[str]) -> dict:
    discovered = _confirmed_auth_flow_urls(session, scan, flow_types)
    ready = []
    blocked = []
    for url in discovered:
        method_confirmed = _method_confirmed_for_url(session, scan, url, "POST")
        template_ready = _request_template_ready_for_url(session, scan, url, target_url)
        item = {
            "url": url,
            "method": "POST" if method_confirmed else None,
            "method_confirmed": method_confirmed,
            "request_template_ready": template_ready,
            "required_parameters_known": template_ready,
        }
        if method_confirmed and template_ready:
            ready.append(item)
        else:
            blocked.append(item)
    return {"ready": ready, "blocked": blocked, "discovered": discovered}


def _endpoint_inventory(session: Session, scan: Scan, target_url: str) -> list[dict]:
    flows_by_url = {
        flow.url: flow
        for flow in session.query(DiscoveredAuthFlow).filter(DiscoveredAuthFlow.scan_id == scan.id).all()
        if flow.url
    }
    rows = []
    for endpoint in session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id).limit(1000).all():
        flow = flows_by_url.get(endpoint.url)
        params = session.query(DiscoveredParameter).filter(DiscoveredParameter.scan_id == scan.id, DiscoveredParameter.endpoint == endpoint.url).all()
        template_ready = any(_request_template_for_parameter(session, scan, param, target_url) for param in params)
        metadata = endpoint.metadata_json or {}
        rows.append(
            {
                "path": urlparse(endpoint.url).path or endpoint.url,
                "method": endpoint.method,
                "type": flow.flow_type if flow else endpoint.endpoint_type,
                "confidence": (flow.evidence or {}).get("endpoint_confidence") if flow else metadata.get("endpoint_confidence"),
                "source": endpoint.source,
                "parameters": sorted({param.name for param in params}),
                "request_template_ready": template_ready,
            }
        )
    return rows


def _latest_tool_status(session: Session, scan: Scan, tool: str) -> str | None:
    run = session.query(ToolRun).filter(ToolRun.scan_id == scan.id, ToolRun.tool_name == tool).order_by(ToolRun.id.desc()).first()
    return run.status if run else None


def _dependency_block_for_tool(session: Session, scan: Scan, tool: str) -> dict | None:
    usable_sessions = _usable_session_count(session, scan)
    protected_endpoints = _protected_endpoint_count(session, scan)
    objects = _discovered_object_count(session, scan)
    templates = _request_templates_count(session, scan)
    execution_profile = str((getattr(scan, "scan_config", None) or {}).get("execution_profile") or "")
    auth_gate = ((getattr(scan, "scan_config", None) or {}).get("auth_gate") or {})
    auth_gate_status = str(auth_gate.get("status") or "")
    failed_session_validation = _latest_tool_status(session, scan, "session_validation") in {RunStatus.MISSING_PREREQUISITE.value, RunStatus.MISSING_CREDENTIALS.value, RunStatus.EXECUTION_ERROR.value}
    auth_debug_allowed = {
        "technology_fingerprint",
        "root_link_inventory",
        "robots_txt",
        "sitemap_xml",
        "static_asset_inventory",
        "openapi_discovery",
        "api_path_hints",
        "api_profile_probe",
        "api_method_probe",
        "crawler",
        "auth_session_mapping",
        "account_provisioning",
        "login_session",
        "session_validation",
        "token_analysis",
        "authenticated_crawling",
        "authenticated_resource_discovery",
        "resource_ownership_map",
        "authorization_matrix",
        "idor_bola_bfla_planner",
        "mass_assignment_testing",
        "cross_account_access_testing",
    }
    if execution_profile == "auth-authorization-debug" and tool not in auth_debug_allowed:
        return {
            "missing_artifact": "execution_profile_scope",
            "reason": f"{tool} is outside the Auth + Authorization Debug execution profile",
            "how_to_make_testable": "choose Authenticated Full Scan or Destructive Test Cases - Full Authorized Scan to run broader payload and discovery tools",
        }
    if tool == "account_provisioning":
        registration_gate = _auth_endpoint_gate(session, scan, "", {"registration"})
        if not registration_gate["ready"]:
            return {
                "missing_artifact": "registration_request_template",
                "reason": "No registration/signup endpoint discovered",
                "how_to_make_testable": "complete endpoint inventory, auth endpoint classification, and request template building before account provisioning",
                "endpoint_gate": registration_gate,
            }
    if tool == "login_session":
        login_gate = _auth_endpoint_gate(session, scan, "", {"login", "token"})
        has_generated_credentials = session.query(Credential).filter(Credential.project_id == scan.project_id, Credential.label.like(f"generated-%-scan-{scan.id}")).count() > 0
        has_configured_credentials = bool(load_credentials())
        if not has_generated_credentials and not has_configured_credentials:
            return {
                "missing_artifact": "login_credentials",
                "reason": "login requires generated accounts or configured credentials",
                "how_to_make_testable": "run account provisioning after a registration endpoint is discovered, or configure credentials",
            }
        if not login_gate["ready"]:
            return {
                "missing_artifact": "login_request_template",
                "reason": "No login endpoint with a ready request template discovered",
                "how_to_make_testable": "complete endpoint inventory, auth endpoint classification, and request template building before login",
                "endpoint_gate": login_gate,
            }
    if tool == "session_validation":
        token_count = session.query(DiscoveredToken).filter(DiscoveredToken.scan_id == scan.id).count()
        auth_session_count = session.query(AuthenticatedSession).filter(AuthenticatedSession.scan_id == scan.id).count()
        if token_count < 1 and auth_session_count < 1:
            return {
                "missing_artifact": "token_or_session",
                "reason": "session validation requires a token, cookie, or authenticated session from login",
                "how_to_make_testable": "complete login_session or import an existing session before session validation",
            }
    if tool in {"authenticated_crawling", "authenticated_resource_discovery"} and auth_gate_status in {"session_material_missing", "authenticated_behavior_not_proven", "login_failed", "no_login_workflow_discovered"}:
        return {
            "missing_artifact": auth_gate_status,
            "reason": auth_gate.get("reason") or "Authenticated behavior has not been proven from workflow evidence",
            "how_to_make_testable": "enable browser capture, provide HAR after login, paste an authenticated request, or provide credentials and post-login action",
        }
    if tool == "resource_ownership_map" and _latest_tool_status(session, scan, "authenticated_crawling") != RunStatus.COMPLETED.value:
        return {
            "missing_artifact": "authenticated_resource_inventory",
            "reason": "resource ownership mapping requires authenticated crawling/resource discovery first",
            "how_to_make_testable": "complete session_validation and authenticated_crawling",
        }
    if tool == "authorization_matrix":
        if auth_gate_status not in {"ready_for_authorization", "ready_for_bola_bfla", "two_user_behavior_proven"}:
            return {
                "missing_artifact": auth_gate_status or "authenticated_behavior_not_proven",
                "reason": auth_gate.get("reason") or "Authorization testing requires confirmed authenticated behavior and testable workflow requests",
                "how_to_make_testable": "provide two user sessions plus HAR/browser workflow inventory or known authenticated requests",
            }
        if objects < 1:
            return {
                "missing_artifact": "no_resource_candidates",
                "reason": "No resource/object candidates were inferred from workflow requests",
                "how_to_make_testable": "provide HAR or authenticated requests containing user/object identifiers",
            }
    if tool in {"idor_bola_bfla_planner", "mass_assignment_testing", "cross_account_access_testing"}:
        if auth_gate_status not in {"ready_for_authorization", "ready_for_bola_bfla", "two_user_behavior_proven"}:
            return {
                "missing_artifact": auth_gate_status or "authenticated_behavior_not_proven",
                "reason": "BOLA/BFLA testing requires authenticated behavior proof, two-user comparison, and testable workflow requests",
                "how_to_make_testable": "provide browser/HAR workflow evidence for two users and object-bearing requests",
            }
        if tool in {"idor_bola_bfla_planner", "cross_account_access_testing"} and objects < 1:
            return {
                "missing_artifact": "object_ownership_map",
                "reason": f"{tool} requires discovered object identifiers and ownership mapping",
                "how_to_make_testable": "run authenticated_crawling/resource discovery to collect user-owned objects",
            }
    if tool in {"xss_adaptive", "sqli_adaptive", "ssrf_adaptive"}:
        if execution_profile == "destructive-full-scan" and failed_session_validation and not get_settings().public_input_validation_allowed:
            return {
                "missing_artifact": "confirmed_protected_session",
                "reason": "input validation is blocked after auth coverage failure; set public_input_validation_allowed=true to test unauthenticated inputs",
                "how_to_make_testable": "validate a protected authenticated session or explicitly allow public input validation",
            }
        if (
            getattr(scan, "enable_destructive_tests", False)
            and getattr(scan, "allow_authenticated_testing", False)
            and usable_sessions > 0
            and _latest_tool_status(session, scan, "authenticated_crawling") != RunStatus.COMPLETED.value
        ):
            return {
                "missing_artifact": "authenticated_endpoint_inventory",
                "reason": f"{tool} waits for authenticated crawling in destructive full scans so authenticated payload tests do not run before session-dependent inventory is built",
                "how_to_make_testable": "complete authenticated_crawling, or run an enumeration-only/public-input scan profile",
            }
        if templates < 1:
            return {
                "missing_artifact": "request_templates",
                "reason": f"{tool} requires request templates built from forms, OpenAPI, JS requests, validation errors, or observed successful requests",
                "how_to_make_testable": "run API discovery, method/schema classification, auth mapping, and request-shape discovery first",
            }
    if tool == "jwt_adaptive" and usable_sessions < 1 and not session.query(DiscoveredToken).filter(DiscoveredToken.scan_id == scan.id).count():
        return {
            "missing_artifact": "jwt_or_bearer_token",
            "reason": "JWT testing requires captured tokens or a valid authenticated session",
            "how_to_make_testable": "run login_session or provide bearer credentials",
        }
    if tool == "business_logic_planner" and protected_endpoints < 1 and usable_sessions > 0:
        return {
            "missing_artifact": "authenticated_endpoint_inventory",
            "reason": "business logic testing requires authenticated endpoint inventory",
            "how_to_make_testable": "run authenticated_crawling successfully first",
        }
    return None


def _auth_failed_stop_reason(scan: Scan, tool: str, result: dict) -> str | None:
    execution_profile = str((scan.scan_config or {}).get("execution_profile") or "")
    selected_categories = set((scan.scan_config or {}).get("selected_test_categories") or [])
    auth_focused = bool(selected_categories & {"authorization_matrix", "bola_idor", "bfla", "mass_assignment", "cross_account_replay"})
    if tool != "session_validation":
        return None
    auth_gate = ((scan.scan_config or {}).get("auth_gate") or {})
    if auth_gate.get("status") == "ready_for_authorization":
        return None
    output = result.get("output") or {}
    valid_count = int(output.get("valid_sessions_count") or output.get("login_sessions_count") or 0)
    if valid_count > 0 and auth_gate.get("status") not in {"authenticated_behavior_not_proven", "two_sessions_no_workflow_requests", "no_authorization_testable_requests"}:
        return None
    if execution_profile == "auth-authorization-debug" or auth_focused:
        return "Login/session material was captured, but authenticated behavior was not proven"
    if execution_profile == "destructive-full-scan" and not get_settings().public_input_validation_allowed:
        return "Authenticated behavior was not proven; auth-dependent destructive workflow stopped"
    return None


AUTH_GATE_BLOCKED_TOOLS = {
    "authenticated_crawling",
    "authenticated_resource_discovery",
    "resource_ownership_map",
    "authorization_matrix",
    "idor_bola_bfla_planner",
    "bola_idor_testing",
    "bfla_testing",
    "mass_assignment_testing",
    "cross_account_access_testing",
    "cross_account_replay",
}


def _auth_gate_blocks_tool(scan: Scan, tool: str) -> bool:
    auth_gate = ((scan.scan_config or {}).get("auth_gate") or {})
    blocking_statuses = {
        "no_login_workflow_discovered",
        "login_failed",
        "session_material_missing",
        "authenticated_behavior_not_proven",
        "one_user_behavior_proven",
        "no_authorization_testable_requests",
        "two_sessions_no_workflow_requests",
        "no_resource_candidates",
    }
    return auth_gate.get("status") in blocking_statuses and tool in set(auth_gate.get("blocks") or AUTH_GATE_BLOCKED_TOOLS)


def _mark_auth_gate_tool_blocked(session: Session, scan: Scan, tool: str) -> None:
    config = dict(scan.scan_config or {})
    plan = dict(config.get("selected_tool_plan") or {})
    blocked = list(plan.get("auth_gate_blocked_tools") or [])
    if tool not in blocked:
        blocked.append(tool)
    plan["auth_gate_blocked_tools"] = blocked
    config["selected_tool_plan"] = plan
    scan.scan_config = config
    case = session.query(TestCase).filter(TestCase.scan_id == scan.id, TestCase.selected_tool == tool).one_or_none()
    if case:
        case.status = "coverage_gap_auth_blocked"
        case.definition = {**(case.definition or {}), "reason": "Authenticated behavior was not proven from workflow evidence"}


def _write_auth_coverage_blocked(session: Session, scan: Scan, result: dict) -> None:
    selected = set((_selected_tool_plan(scan).get("final_executable_tools") or _selected_tool_plan(scan).get("allowed_tools") or []))
    blocked_selected = [tool for tool in AUTH_GATE_BLOCKED_TOOLS if tool in selected]
    auth_gate = ((scan.scan_config or {}).get("auth_gate") or {})
    status = auth_gate.get("status") or (result.get("output") or {}).get("auth_gate_status") or "authenticated_behavior_not_proven"
    reason = auth_gate.get("reason") or "Authorization testing requires confirmed authenticated behavior and testable workflow requests."
    payload = {
        "status": status,
        "reason": reason,
        "login_sessions_count": int(auth_gate.get("login_sessions_count") or ((result.get("output") or {}).get("login_sessions_count")) or ((result.get("output") or {}).get("valid_sessions_count")) or 0),
        "usable_session_material_count": int(auth_gate.get("usable_session_material_count") or 0),
        "authenticated_behavior_count": int(auth_gate.get("authenticated_behavior_count") or 0),
        "confirmed_protected_endpoints": [],
        "workflow_request_inventory_count": auth_gate.get("request_inventory_count", 0),
        "authorization_candidate_count": auth_gate.get("authorization_candidate_count", 0),
        "resource_candidate_count": auth_gate.get("resource_candidate_count", 0),
        "blocked_selected_tools": blocked_selected,
        "how_to_fix": [
            "enable browser authenticated capture",
            "install Playwright",
            "provide HAR after login",
            "paste a known authenticated request",
            "provide manual workflow steps or post-login action",
        ],
    }
    config = dict(scan.scan_config or {})
    config["auth_gate"] = {**auth_gate, "status": status, "reason": payload["reason"], "blocks": list(AUTH_GATE_BLOCKED_TOOLS)}
    plan = dict(config.get("selected_tool_plan") or {})
    plan["auth_gate_blocked_tools"] = blocked_selected
    config["selected_tool_plan"] = plan
    scan.scan_config = config
    path = write_evidence(scan.id, "auth_coverage_blocked", payload)
    session.add(Evidence(scan_id=scan.id, kind="coverage_gap", path=str(path), summary="Authorization testing blocked: authenticated behavior not proven.", metadata_json={"tool": "auth_gate", "status": payload["status"]}))
    _artifact(session, scan, "coverage_gap", "auth_coverage_blocked", payload)
    for tool in blocked_selected:
        _mark_auth_gate_tool_blocked(session, scan, tool)
    emit_progress(session, scan, payload["reason"], level="WARNING", phase="auth_gate", agent="auth_agent", tool="auth_gate", event_type="coverage_gap_auth_blocked", context=payload)


def _record_dependency_block(session: Session, scan: Scan, tool: str, block: dict, console: Console | None = None) -> dict:
    status = RunStatus.MISSING_PREREQUISITE.value
    output = {
        "status": status,
        "reason": block["reason"],
        "required_artifact": block["missing_artifact"],
        "how_to_make_testable": block.get("how_to_make_testable"),
        "client_action_required": bool(block.get("client_action_required")),
        "endpoint_gate": block.get("endpoint_gate"),
    }
    emit_progress(
        session,
        scan,
        f"dependency blocked: {tool} missing {block['missing_artifact']}",
        level="INFO",
        phase=_phase_for_tool(tool),
        agent=_agent_for_tool(tool),
        tool=tool,
        event_type="dependency_blocked",
        context=output,
        console=console,
        live=True,
    )
    return _record_tool(session, scan, tool, f"dependency check for {tool}", status, output, "orchestration", f"{tool} dependency blocked", f"dependency_blocked_{tool}")


def _resolve_missing_prerequisite(
    session: Session,
    scan: Scan,
    tool: str,
    block: dict,
    runner: dict,
    target_url: str,
    prompt: str,
    parsed: dict,
    *,
    console: Console | None = None,
    debug_live: bool = False,
) -> dict:
    missing = block.get("missing_artifact") or "unknown"
    actions = _prerequisite_actions_for(missing, tool)
    output = {"resolved": False, "actions_taken": [], "retry_allowed": False, "final_reason": block.get("reason"), "tool_results": []}
    emit_progress(
        session,
        scan,
        f"prerequisite resolution started tool={tool} missing={missing}",
        phase=_phase_for_tool(tool),
        agent="orchestrator_agent",
        tool=tool,
        event_type="prerequisite_resolution_started",
        context={"tool": tool, "missing_artifact": missing, "reason": block.get("reason"), "actions": actions},
        console=console,
        live=True,
    )
    if not actions:
        emit_progress(
            session,
            scan,
            f"prerequisite resolution failed tool={tool} missing={missing}",
            level="INFO",
            phase=_phase_for_tool(tool),
            agent="orchestrator_agent",
            tool=tool,
            event_type="prerequisite_resolution_failed",
            context={"tool": tool, "missing_artifact": missing, "reason": "no resolver action available"},
            console=console,
            live=True,
        )
        return output
    for action_tool in actions:
        if action_tool == tool or action_tool not in runner:
            continue
        if _latest_tool_status(session, scan, action_tool) in {RunStatus.COMPLETED.value, RunStatus.FINDING_CREATED.value}:
            output["actions_taken"].append({"tool": action_tool, "status": "already_completed"})
            continue
        action_phase = _phase_for_tool(action_tool)
        action_agent = _agent_for_tool(action_tool)
        emit_progress(
            session,
            scan,
            f"prerequisite resolution action {action_tool}",
            phase=action_phase,
            agent=action_agent,
            tool=action_tool,
            event_type="prerequisite_resolution_action",
            context={"blocked_tool": tool, "missing_artifact": missing, "resolver_tool": action_tool},
            console=console,
            live=True,
        )
        try:
            with heartbeat(scan.id, phase=action_phase, agent=action_agent, tool=action_tool, console=console, live=debug_live):
                result = runner[action_tool](session, scan, target_url, prompt, parsed)
            output["tool_results"].append(result)
            output["actions_taken"].append({"tool": action_tool, "status": result.get("status"), "evidence_path": result.get("evidence_path")})
        except Exception as exc:
            output["actions_taken"].append({"tool": action_tool, "status": RunStatus.EXECUTION_ERROR.value, "error": str(exc)})
            emit_progress(
                session,
                scan,
                f"prerequisite resolution action failed {action_tool}: {exc}",
                level="ERROR",
                phase=action_phase,
                agent=action_agent,
                tool=action_tool,
                event_type="prerequisite_resolution_failed",
                context={"blocked_tool": tool, "resolver_tool": action_tool, "error": str(exc)},
                console=console,
                live=True,
            )
    remaining = _dependency_block_for_tool(session, scan, tool)
    output["resolved"] = remaining is None
    output["retry_allowed"] = remaining is None
    output["final_reason"] = None if remaining is None else remaining.get("reason")
    emit_progress(
        session,
        scan,
        f"prerequisite resolution {'completed' if output['resolved'] else 'failed'} tool={tool}",
        level="INFO" if output["resolved"] else "ERROR",
        phase=_phase_for_tool(tool),
        agent="orchestrator_agent",
        tool=tool,
        event_type="prerequisite_resolution_completed" if output["resolved"] else "prerequisite_resolution_failed",
        context={key: value for key, value in output.items() if key != "tool_results"},
        console=console,
        live=True,
    )
    return output


def _prerequisite_actions_for(missing_artifact: str, blocked_tool: str) -> list[str]:
    mapping = {
        "valid_authenticated_session": ["login_session", "token_analysis"],
        "valid_second_session": ["account_provisioning", "login_session", "token_analysis"],
        "protected_endpoint_inventory": ["authenticated_crawling"],
        "authenticated_endpoint_inventory": ["authenticated_crawling"],
        "object_ownership_map": ["authenticated_crawling"],
        "request_templates": ["api_method_probe", "input_validation_planner"],
        "registration_request_template": ["api_method_probe", "crawler", "auth_session_mapping"],
        "login_request_template": ["api_method_probe", "crawler", "auth_session_mapping"],
        "login_credentials": ["account_provisioning"],
        "token_or_session": ["login_session", "token_analysis"],
        "authenticated_behavior_not_proven": ["browser_authenticated_capture", "session_validation"],
        "workflow_request_inventory_built": ["browser_authenticated_capture", "api_method_probe"],
        "jwt_or_bearer_token": ["login_session", "token_analysis"],
        "test_owned_resource": ["authenticated_crawling"],
        "rate_limit_target": ["api_method_probe", "auth_session_mapping"],
        "endpoint_inventory": ["api_profile_probe", "api_method_probe"],
        "method_matrix": ["api_method_probe"],
    }
    actions = mapping.get(missing_artifact, [])
    return [action for action in actions if action != blocked_tool]


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


def _final_scan_status(session: Session, scan: Scan, selected_tools: list[str], tool_results: list[dict]) -> str:
    execution_profile = str((scan.scan_config or {}).get("execution_profile") or "")
    by_tool = {item.get("tool"): item for item in tool_results}
    if execution_profile in {"destructive-full-scan", "authenticated-full-scan", "auth-authorization-debug"}:
        if session.query(AuthenticatedSession).filter(AuthenticatedSession.scan_id == scan.id, AuthenticatedSession.session_status.in_(["token_storage_error"])).count():
            return "auth_failed"
        required = ["authenticated_crawling", "authorization_matrix", "idor_bola_bfla_planner", "xss_adaptive", "sqli_adaptive", "rate_limit_planner"]
        failed = [
            tool
            for tool in required
            if tool in selected_tools and (by_tool.get(tool) or {}).get("status") in {RunStatus.MISSING_PREREQUISITE.value, RunStatus.MISSING_CREDENTIALS.value, RunStatus.EXECUTION_ERROR.value, "not_run_manual_confirmation_required"}
        ]
        if failed:
            return "completed_with_coverage_gaps"
    return ScanStatus.COMPLETED.value


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
    console.print(f"Executable selected tools: {', '.join(preparation.executable_tools) if preparation.executable_tools else 'none'}")


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
            "execution_profile_recommendation",
            "next_full_authorized_api_security_workflow",
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
    allowed = set(_selected_tool_plan(scan).get("final_executable_tools") or _selected_tool_plan(scan).get("allowed_tools") or [])
    added = []
    for candidate in FULL_API_SECURITY_TOOLS:
        if candidate not in supported or candidate in selected_tools or candidate not in allowed:
            continue
        selected_tools.append(candidate)
        executable_tools.append(candidate)
        added.append(candidate)
    if added:
        _artifact(
            session,
            scan,
            "execution_profile_escalation",
            "auto_execution_profile_escalation",
            {
                "from_mode": scan.profile,
                "to_mode": "api-security-authenticated-test",
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
        return "full-authorized-api-security-test"
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


def _record_http_get_output(session: Session, scan: Scan, url: str, output: dict, source: str) -> None:
    if not output:
        return
    try:
        upsert_request_response(
            scan.id,
            {
                "source": source,
                "method": "GET",
                "url": output.get("final_url") or url,
                "headers": {},
                "response": {
                    "status": output.get("status_code"),
                    "headers": output.get("headers") or {},
                    "content_type": (output.get("headers") or {}).get("content-type"),
                    "body_preview": output.get("body_preview") or output.get("_text") or "",
                    "body_length": len(str(output.get("_text") or output.get("body_preview") or "")),
                    "redirect_location": (output.get("headers") or {}).get("location"),
                    "set_cookie": bool((output.get("headers") or {}).get("set-cookie")),
                },
            },
        )
    except Exception as exc:
        _artifact(session, scan, "request_map_error", safe_artifact_name("request_map_error", "GET", url), {"source": source, "error": str(exc)})


def _start_tool_run_marker(session: Session, scan: Scan, tool: str, agent_name: str, command: str) -> ToolRun:
    now = datetime.now(timezone.utc)
    marker = ToolRun(
        scan_id=scan.id,
        agent_name=agent_name,
        tool_name=tool,
        command=command,
        status=RunStatus.RUNNING.value,
        started_at=now,
        output={"lifecycle": "started_before_execution"},
    )
    session.add(marker)
    session.flush()
    return marker


def _finish_tool_run_marker(marker: ToolRun, status: str, result: dict | None = None, error: str | None = None) -> None:
    marker.status = status
    marker.completed_at = datetime.now(timezone.utc)
    marker.output = {"lifecycle": "execution_marker", "result": result or {}, "error": error[:1000] if error else None}
    if error:
        marker.output["error_message"] = error[:1000]


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
    if _selected_tool_plan(scan) and not is_tool_selected(scan, tool):
        _mark_tool_skipped_unselected(session, scan, tool)
        return {"tool": tool, "status": "skipped_unselected", "command": command, "reason": "tool not selected by selected_test_categories"}
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
    existing = session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title == title[:255], Finding.description == description).one_or_none()
    if existing:
        return
    finding = Finding(
        scan_id=scan.id,
        finding_type="observation",
        title=title,
        severity="info",
        description=description,
        evidence_id=evidence_id,
        status="informational",
        confidence="observed",
        business_impact="Informational observation to support tester review, coverage tracking, and follow-up validation.",
        technical_impact=description,
        remediation="Review this observation during triage and document whether it affects scope, attack surface, or follow-up testing.",
        ai_reasoning_summary=description,
        retest_status="not_retested",
    )
    session.add(finding)
    session.flush()
    emit_progress(session, scan, f"observation created: {title}", phase=scan.current_phase, agent=scan.current_agent, tool=scan.current_tool, event_type="observation_created", context={"finding_id": finding.id, "title": title, "severity": finding.severity, "status": finding.status})


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
        finding_type="finding",
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


def safe_artifact_name(prefix: str, method: str | None, url_or_path: str | None, max_len: int = 180) -> str:
    raw = str(url_or_path or "")
    lowered = raw.lower()
    parsed = urlparse(raw if "://" in raw else f"//local{raw if raw.startswith('/') else '/invalid_candidate'}")
    path = parsed.path if parsed.path and not any(token in lowered for token in ["\n", "\r", "/*", "*/", "licensed under", "import {"]) else "/invalid_candidate"
    body = "_".join(part for part in [prefix, method, path.strip("/").replace("/", "_")] if part)
    body = re.sub(r"[^a-zA-Z0-9_.-]+", "_", body).strip("_") or "artifact"
    digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:8]
    limit = max(20, max_len - len(digest) - 1)
    return f"{body[:limit].strip('_')}_{digest}"


def _artifact(session: Session, scan: Scan, artifact_type: str, name: str, data: dict) -> None:
    scan_id = scan.id
    safe_name = safe_artifact_name(str(name or artifact_type), None, str(name or artifact_type), 180)
    try:
        session.add(PipelineArtifact(scan_id=scan_id, artifact_type=artifact_type, name=safe_name, data={**(data or {}), "artifact_display_name": str(name)}))
        session.flush()
    except Exception as exc:
        session.rollback()
        fallback = write_evidence(scan_id, f"artifact_recording_failed_{hashlib.sha256(str(name).encode()).hexdigest()[:8]}", {"artifact_type": artifact_type, "name": str(name), "error": str(exc), "data_preview": str(data)[:1000]})
        try:
            get_settings().log_dir.mkdir(parents=True, exist_ok=True)
            with (get_settings().log_dir / f"scan-{scan_id}.log").open("a", encoding="utf-8") as handle:
                handle.write(f"artifact_recording_failed scan={scan_id} artifact_type={artifact_type} name={str(name)[:120]} evidence={fallback} error={exc}\n")
        except Exception:
            pass


def _import_initial_workflow_evidence(session: Session, scan: Scan, target_url: str) -> None:
    config = scan.scan_config or {}
    imported = {"har_records": 0, "manual_requests": 0, "errors": []}
    har_file = config.get("har_file")
    if har_file:
        try:
            records = import_har(scan.id, har_file, target_url)
            imported["har_records"] = len(records)
        except Exception as exc:
            imported["errors"].append({"source": "har", "path": str(har_file), "error": str(exc)})
    for item in config.get("known_authenticated_requests") or []:
        try:
            import_manual_request(scan.id, str(item), target_url)
            imported["manual_requests"] += 1
        except Exception as exc:
            imported["errors"].append({"source": "manual", "error": str(exc), "preview": str(item)[:200]})
    if imported["har_records"] or imported["manual_requests"] or imported["errors"]:
        _artifact(session, scan, "workflow_import", "initial_workflow_request_import", imported)
        emit_progress(
            session,
            scan,
            f"workflow evidence imported har_records={imported['har_records']} manual_requests={imported['manual_requests']}",
            phase="request_inventory",
            agent="workflow_import_agent",
            event_type="workflow_evidence_imported",
            context=imported,
        )


def _endpoint(session: Session, scan: Scan, url: str, endpoint_type: str, source: str, method: str | None = None, metadata: dict | None = None) -> None:
    base_url = (metadata or {}).get("base_url") or (url if str(url).startswith(("http://", "https://")) else "")
    sanitized = sanitize_candidate_endpoint(url, base_url, source)
    if not sanitized:
        _artifact(session, scan, "rejected_endpoint_candidate", safe_artifact_name("rejected_endpoint", method, url), rejection_sample(url, source))
        return
    session.add(DiscoveredEndpoint(scan_id=scan.id, url=sanitized.url, method=method or sanitized.method, endpoint_type=endpoint_type, source=source, metadata_json={**(metadata or {}), "confidence": sanitized.confidence, "candidate_type": sanitized.candidate_type}))


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
    _record_http_get_output(session, scan, target_url, output, "http_client")
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


def _headers_for_target(target_url: str) -> tuple[str, dict]:
    status, output = _http_get(target_url)
    headers = output.get("headers") or {}
    return status, {str(key).lower(): value for key, value in headers.items()} | {"_status_code": output.get("status_code"), "_body_preview": output.get("body_preview", "")}


def _run_security_headers_check(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, headers = _headers_for_target(target_url)
    required = ["strict-transport-security", "x-content-type-options", "x-frame-options", "content-security-policy"]
    missing = [name for name in required if not headers.get(name)]
    output = {"checked_headers": required, "missing_headers": missing, "present_headers": {name: headers.get(name) for name in required if headers.get(name)}, "status_code": headers.get("_status_code")}
    if missing:
        _finding(session, scan, "Security headers missing", f"Missing security headers: {', '.join(missing)}")
    return _record_tool(session, scan, "security_headers_check", f"GET {target_url} headers", status, output, "http", "Security headers check", "prompt_security_headers")


def _run_csp_headers_check(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, headers = _headers_for_target(target_url)
    csp = headers.get("content-security-policy")
    output = {"content_security_policy": csp, "status_code": headers.get("_status_code"), "reason": None if csp else "Content-Security-Policy header not present"}
    if not csp:
        _finding(session, scan, "Missing Content-Security-Policy header", "The target did not return a Content-Security-Policy header. Add a restrictive CSP to reduce client-side injection impact.")
    return _record_tool(session, scan, "csp_headers_check", f"GET {target_url} CSP header", status, output, "http", "CSP header check", "prompt_csp_headers")


def _run_cors_check(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    try:
        response = httpx.get(target_url, headers={"Origin": "https://saif.example.test"}, follow_redirects=True, timeout=10)
        allow_origin = response.headers.get("access-control-allow-origin")
        output = {"origin_sent": "https://saif.example.test", "access_control_allow_origin": allow_origin, "status_code": response.status_code}
        if allow_origin == "*":
            _finding(session, scan, "Permissive CORS header observed", "Access-Control-Allow-Origin is wildcard for a cross-origin request.")
        return _record_tool(session, scan, "cors_check", f"GET {target_url} with Origin header", RunStatus.COMPLETED.value, output, "http", "CORS header check", "prompt_cors")
    except Exception as exc:
        return _record_tool(session, scan, "cors_check", f"GET {target_url} with Origin header", RunStatus.EXECUTION_ERROR.value, {"error": str(exc)}, "http", "CORS header check", "prompt_cors")


def _run_cache_control_check(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, headers = _headers_for_target(target_url)
    cache_control = headers.get("cache-control")
    output = {"cache_control": cache_control, "status_code": headers.get("_status_code"), "reason": None if cache_control else "Cache-Control header not present"}
    return _record_tool(session, scan, "cache_control_check", f"GET {target_url} Cache-Control header", status, output, "http", "Cache-Control header check", "prompt_cache_control")


def _run_error_disclosure_check(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, output = _http_get(urljoin(target_url.rstrip("/") + "/", "saif-nonexistent-probe"))
    _record_http_get_output(session, scan, urljoin(target_url.rstrip("/") + "/", "saif-nonexistent-probe"), output, "error_disclosure_check")
    preview = (output.get("_text") or output.get("body_preview") or "")[:4000]
    markers = _interesting_markers(preview)
    result = {"status_code": output.get("status_code"), "markers": markers, "body_preview": preview[:1000]}
    if markers:
        _finding(session, scan, "Error disclosure markers observed", f"Error page contained markers: {', '.join(markers)}")
    return _record_tool(session, scan, "error_disclosure_check", f"GET {target_url}/saif-nonexistent-probe", status, result, "http", "Error disclosure check", "prompt_error_disclosure")


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
        results.append({"token_type": "jwt", "location": "body", "sample": match})
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


def _target_wordlist_path(session: Session, scan: Scan, target_url: str) -> str:
    words = set(_read_api_words())
    for endpoint in session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id).limit(2000).all():
        for part in re.split(r"[^A-Za-z0-9_-]+", urlparse(endpoint.url).path):
            if 2 <= len(part) <= 48 and not part.isdigit():
                words.add(part)
    for param in session.query(DiscoveredParameter).filter(DiscoveredParameter.scan_id == scan.id).limit(2000).all():
        if param.name:
            words.add(str(param.name).strip("/"))
    for row in load_request_map(scan.id).get("requests") or []:
        for part in re.split(r"[^A-Za-z0-9_-]+", str(row.get("path") or "")):
            if 2 <= len(part) <= 48 and not part.isdigit():
                words.add(part)
        for key in (row.get("query_params") or {}).keys():
            words.add(str(key))
        for key in ((row.get("body_shape") or {}).get("keys") or []):
            words.add(str(key))
    output_path = get_settings().evidence_dir / f"scan-{scan.id}" / "target_wordlist.txt"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    selected = sorted({word.strip("/") for word in words if word and 1 < len(word.strip("/")) <= 80})[: get_settings().dir_discovery_max_words]
    output_path.write_text("\n".join(selected) + "\n", encoding="utf-8")
    _artifact(session, scan, "target_wordlist", "target_wordlist", {"path": str(output_path), "word_count": len(selected), "source": "html_js_docs_params_errors_request_map"})
    return str(output_path)


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


def _extract_js_api_strings(js_body: str, base_url: str = "") -> dict:
    strings: set[str] = set()
    external_refs: set[str] = set()
    scrubbed = re.sub(r"/\*.*?\*/", "", js_body, flags=re.DOTALL)
    scrubbed = re.sub(r"(^|\s)//.*", "", scrubbed)
    patterns = [
        r"""fetch\(\s*["'`]([^"'`]+)["'`]""",
        r"""axios\.(?:get|post|put|delete|patch)\(\s*["'`]([^"'`]+)["'`]""",
        r"""axios\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`]""",
        r"""XMLHttpRequest\.open\(\s*["'`][A-Z]+["'`]\s*,\s*["'`]([^"'`]+)["'`]""",
        r"""(?:baseURL|apiUrl|authUrl|REACT_APP_API_URL)\s*[:=]\s*["'`]([^"'`]+)["'`]""",
        r"""["'`]((?:/api/|/identity/api/|/workshop/api/|/community/api/|/swagger|/openapi)[A-Za-z0-9_./{}:-]{0,180})["'`]""",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, scrubbed, re.IGNORECASE | re.DOTALL):
            sanitized = sanitize_candidate_endpoint(str(match).strip(), base_url, "js_extraction")
            if sanitized:
                strings.add(sanitized.url)
    for value in list(strings):
        if value.startswith("http"):
            external_refs.add(value)
    return {"strings": sorted(strings)[:1000], "external_references": sorted(external_refs)[:300]}


def _collect_js_discovery(target_url: str, html: str) -> dict:
    js_files = _extract_js_assets(html, target_url)
    js_strings: set[str] = set()
    external_refs: set[str] = set()
    source_maps = {}
    previews = {}
    for asset in js_files[:50]:
        try:
            response = httpx.get(asset, follow_redirects=True, timeout=10)
            body = response.text
            previews[asset] = {"status_code": response.status_code, "bytes_analyzed": len(body), "full_scan": True}
        except Exception as exc:
            previews[asset] = {"error": str(exc)}
            continue
        extracted = _extract_js_api_strings(body, target_url)
        js_strings.update(extracted["strings"])
        external_refs.update(extracted["external_references"])
        map_match = re.search(r"sourceMappingURL=([^\s*]+)", body)
        if map_match:
            map_url = urljoin(asset, map_match.group(1).strip())
            try:
                map_response = httpx.get(map_url, follow_redirects=True, timeout=10)
                source_maps[map_url] = {"status_code": map_response.status_code, "bytes_analyzed": len(map_response.text)}
                map_extracted = _extract_js_api_strings(map_response.text, target_url)
                js_strings.update(map_extracted["strings"])
                external_refs.update(map_extracted["external_references"])
            except Exception as exc:
                source_maps[map_url] = {"error": str(exc)}
    return {
        "js_files": js_files,
        "previews": previews,
        "source_maps": source_maps,
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
    if not sanitize_candidate_endpoint(url, url if str(url).startswith(("http://", "https://")) else "", "record_exchange"):
        _artifact(session, scan, "rejected_exchange_endpoint", safe_artifact_name("rejected_exchange", method, url), rejection_sample(url, "record_exchange"))
        return
    parsed_url = urlparse(url)
    path_only = parsed_url.path or "/"
    elapsed_ms = int(response.elapsed.total_seconds() * 1000) if response is not None and response.elapsed else None
    emit_progress(
        session,
        scan,
        f"request={method} {path_only} status={response.status_code if response is not None else 'error'}",
        event_type="http_request",
        context={
            "method": method,
            "path": path_only,
            "status_code": response.status_code if response is not None else None,
            "duration_ms": elapsed_ms,
            "auth_attached": bool((request_headers or {}).get("Authorization") or (request_headers or {}).get("Cookie")),
            "error": error,
        },
    )
    analysis = analyze_response(
        method,
        url,
        response.status_code if response is not None else None,
        dict(response.headers) if response is not None else {},
        response.text if response is not None else "",
        elapsed_ms,
    )
    _artifact(session, scan, "response_analysis", safe_artifact_name("response_analysis", method, url), analysis)
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
    _record_request_map_analysis(session, scan, method, url, request_headers, request_body, response, source="tool")


def _record_request_map_analysis(session: Session, scan: Scan, method: str, url: str, request_headers: dict | None, request_body: dict | str | None, response: httpx.Response | None, source: str = "tool") -> dict | None:
    try:
        headers = _masked_headers(request_headers or {})
        response_headers = dict(response.headers) if response is not None else {}
        record = upsert_request_response(
            scan.id,
            {
                "source": source,
                "method": method,
                "url": url,
                "headers": headers,
                "content_type": headers.get("content-type") or headers.get("Content-Type"),
                "body": request_body,
                "body_shape": body_shape_from_body(request_body),
                "auth_attached": bool(headers.get("Authorization") or headers.get("authorization") or headers.get("Cookie") or headers.get("cookie")),
                "response": {
                    "status": response.status_code if response is not None else None,
                    "headers": response_headers,
                    "content_type": response_headers.get("content-type") or response_headers.get("Content-Type"),
                    "body_preview": response.text[:4000] if response is not None else "",
                    "body_length": len(response.text) if response is not None else 0,
                    "redirect_location": response_headers.get("location") or response_headers.get("Location"),
                    "set_cookie": bool(response_headers.get("set-cookie") or response_headers.get("Set-Cookie")),
                },
            },
        )
        passive = analyze_request_response(record)
        parameters = mine_parameters(record)
        if passive.get("tags"):
            record["tags"] = sorted(set(record.get("tags") or []) | set(passive.get("tags") or []))
            upsert_request_response(scan.id, record)
        _artifact(
            session,
            scan,
            "passive_analysis",
            safe_artifact_name("passive_analysis", method, url),
            {"request_id": record.get("request_id"), **passive, "parameters": parameters},
        )
        emit_progress(
            session,
            scan,
            f"request map updated method={method} path={urlparse(url).path or '/'} tags={','.join((record.get('tags') or [])[:5])}",
            event_type="request_map_updated",
            context={"request_id": record.get("request_id"), "tags": record.get("tags") or [], "important_for_ai": is_important_for_ai(record)},
        )
        _maybe_review_response_with_ai(session, scan, record, source)
        return record
    except Exception as exc:
        _artifact(session, scan, "request_map_error", safe_artifact_name("request_map_error", method, url), {"error": str(exc), "url": url, "method": method})
        return None


def _maybe_review_response_with_ai(session: Session, scan: Scan, record: dict, source: str) -> None:
    if not is_important_for_ai(record):
        return
    config = dict(scan.scan_config or {})
    if config.get("response_advisor_disabled"):
        return
    count = int(config.get("response_advisor_calls") or 0)
    max_calls = int(config.get("max_response_advisor_calls") or 10)
    if count >= max_calls:
        return
    config["response_advisor_calls"] = count + 1
    scan.scan_config = config
    try:
        result = review_important_response(
            session,
            scan,
            request_record=record,
            phase=str(scan.current_phase or "response_advisor"),
            selected_categories=list((scan.scan_config or {}).get("selected_test_categories") or []),
            source=source,
        )
        trace = result.get("ai_trace") or {}
        trace_path = trace.get("trace_path")
        if trace_path:
            record["ollama_analysis_refs"] = sorted(set(record.get("ollama_analysis_refs") or []) | {trace_path})
            upsert_request_response(scan.id, record)
        _artifact(session, scan, "response_advisor", safe_artifact_name("response_advisor", record.get("method"), record.get("url")), {"request_id": record.get("request_id"), "ai_validation": result})
    except Exception as exc:
        _artifact(session, scan, "response_advisor_error", safe_artifact_name("response_advisor_error", record.get("method"), record.get("url")), {"request_id": record.get("request_id"), "error": str(exc)})


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


TOKEN_JSON_KEYS = {
    "token",
    "access_token",
    "accesstoken",
    "authtoken",
    "jwt",
    "bearer",
}


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


def _json_value_recursive_with_path(value, keys: set[str], path: str = "") -> tuple[str | None, str | None]:
    normalized_keys = {str(key).lower().replace("_", "") for key in keys} | {str(key).lower() for key in keys}
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            normalized = key_text.lower().replace("_", "")
            key_path = f"{path}.{key_text}" if path else key_text
            if (key_text.lower() in normalized_keys or normalized in normalized_keys) and item:
                return str(item), key_path
        for key, item in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            found, found_path = _json_value_recursive_with_path(item, keys, key_path)
            if found:
                return found, found_path
    if isinstance(value, list):
        for index, item in enumerate(value):
            found, found_path = _json_value_recursive_with_path(item, keys, f"{path}[{index}]")
            if found:
                return found, found_path
    return None, None


def normalize_bearer_token(raw_value: str | None) -> dict:
    raw = str(raw_value or "").strip()
    header_prefix_stripped = False
    while raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
        header_prefix_stripped = True
    parts = raw.split(".") if raw else []
    jwt_shape = len(parts) == 3 and all(parts)
    return {
        "token_value": raw or None,
        "token_type": "jwt" if jwt_shape else "bearer" if raw else None,
        "token_format": "jwt" if jwt_shape else "opaque" if raw else None,
        "token_length": len(raw),
        "token_hash": _token_hash(raw) if raw else None,
        "masked_token": _mask_token(raw) if raw else None,
        "jwt_shape_valid": jwt_shape,
        "jwt_part_count": len(parts) if raw else 0,
        "authorization_header": f"Bearer {raw}" if raw else None,
        "authorization_header_type": "bearer" if raw else None,
        "header_mode": "bearer_prefix_stripped" if header_prefix_stripped else "raw_token",
        "header_mode_used": "Authorization: Bearer <token>" if raw else None,
        "token_was_masked": _is_masked_token(raw),
    }


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
    normalized = normalize_bearer_token(access_token)
    payload.setdefault("sessions", {})[label] = {
        "access_token": normalized.get("token_value"),
        "refresh_token": refresh_token,
        "authorization_header": normalized.get("authorization_header") or authorization_header,
        "authorization_header_type": normalized.get("authorization_header_type"),
        "token_type": normalized.get("token_type"),
        "token_metadata": {key: value for key, value in normalized.items() if key != "token_value"},
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def _load_session_secret(auth_session: AuthenticatedSession) -> dict:
    token = None
    header = auth_session.authorization_header
    source = "secret_ref" if auth_session.secret_ref else "legacy_db"
    if auth_session.secret_ref:
        try:
            payload = json.loads(Path(auth_session.secret_ref).read_text(encoding="utf-8"))
            data = (payload.get("sessions") or {}).get(auth_session.credential_label) or {}
            token = data.get("access_token")
            header = data.get("authorization_header") or header
            source = "secret_ref"
        except Exception:
            pass
    if not token:
        token = auth_session.access_token_secret or auth_session.access_token
        source = "legacy_db"
    token_was_masked = _is_masked_token(token) or _is_masked_token(header)
    if token_was_masked:
        return {"token": None, "authorization_header": None, "source": source, "token_was_masked": True, "reason": "masked token cannot be used for authenticated crawling"}
    normalized = normalize_bearer_token(token or header)
    header = normalized.get("authorization_header")
    stored_meta = ((auth_session.metadata_json or {}).get("token_metadata") or {})
    expected_length = stored_meta.get("token_length")
    if expected_length and normalized.get("token_length") != expected_length:
        return {
            "token": None,
            "authorization_header": None,
            "source": source,
            "token_was_masked": False,
            "reason": "runtime token length does not match stored token metadata",
            "token_storage_error": True,
            "token_metadata": {key: value for key, value in normalized.items() if key != "token_value"},
        }
    return {"token": normalized.get("token_value"), "authorization_header": header, "source": source, "token_was_masked": False, "reason": None, "token_storage_error": False, "token_metadata": {key: value for key, value in normalized.items() if key != "token_value"}}


def _parse_json_body(body: str):
    try:
        return __import__("json").loads(body)
    except Exception:
        return None


def _extract_auth_tokens(response: httpx.Response) -> list[dict]:
    tokens: list[dict] = []
    parsed = _parse_json_body(response.text)
    access, access_field = _json_value_recursive_with_path(parsed, TOKEN_JSON_KEYS) if parsed is not None else (None, None)
    refresh = _json_value_recursive(parsed, {"refresh_token", "refresh"}) if parsed is not None else None
    if access:
        normalized = normalize_bearer_token(access)
        sample = normalized.get("token_value")
        tokens.append({"token_type": normalized.get("token_type") or "bearer", "location": "json", "sample": sample, "field_name": access_field, "token_metadata": {key: value for key, value in normalized.items() if key != "token_value"}})
        if normalized.get("jwt_shape_valid"):
            tokens.append({"token_type": "jwt", "location": "json", "sample": sample, "field_name": access_field, "token_metadata": {key: value for key, value in normalized.items() if key != "token_value"}})
    if refresh:
        tokens.append({"token_type": "refresh", "location": "json", "sample": refresh})
    tokens.extend(_detect_tokens_and_cookies(dict(response.headers), response.text))
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
    _record_http_get_output(session, scan, target_url, root_output, "root_link_inventory")
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
    _record_http_get_output(session, scan, url, output, "robots_txt")
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
    _record_http_get_output(session, scan, url, output, "sitemap_xml")
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
    docs_inventory = discover_api_documentation(scan.id, target_url)
    for path in OPENAPI_PATHS:
        url = urljoin(target_url + "/", path)
        status, output = _http_get(url)
        _record_http_get_output(session, scan, url, output, "openapi_discovery")
        item = {"url": url, "status": status, "status_code": output.get("status_code"), "error": output.get("error")}
        results.append(item)
        if output.get("status_code") == 200:
            found.append(url)
            _endpoint(session, scan, url, "api_spec", "openapi_discovery")
            _api_spec_type = "openapi" if "openapi" in path.lower() or "swagger" in path.lower() else "api"
            session.add(DiscoveredApiSpec(scan_id=scan.id, spec_type=_api_spec_type, url=url, status="found", metadata_json={"status_code": output.get("status_code")}))
            _finding(session, scan, "Exposed OpenAPI document found", f"OpenAPI/Swagger document found at {url}.")
    output = {"checked": results, "found": found, "missing": [item["url"] for item in results if item.get("status_code") == 404], "api_documentation_inventory": docs_inventory}
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
    for hint in js_discovery["discovered_js_strings"]:
        if hint.startswith("http") and not _same_target(target_url, hint):
            _endpoint(session, scan, hint, "external", "js_full_scan")
        elif hint.startswith(("http", "/")):
            _endpoint(session, scan, urljoin(target_url + "/", hint), "api", "js_full_scan")
    output = {
        "assets": assets,
        "js_previews": js_previews,
        "discovered_js_strings": js_discovery["discovered_js_strings"],
        "discovered_api_candidates": [item for item in js_discovery["discovered_js_strings"] if any(token in item.lower() for token in ["/api", "identity", "workshop", "community", "auth", "token"])],
        "discovered_external_references": js_discovery["discovered_external_references"],
        "source_maps": js_discovery.get("source_maps", {}),
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
    root_hints = []
    rejected = []
    for raw in sorted(set(re.findall(hint_pattern, html, re.IGNORECASE))):
        sanitized = sanitize_candidate_endpoint(raw, target_url, "root_html")
        if sanitized:
            root_hints.append(sanitized.url)
        else:
            rejected.append(rejection_sample(raw, "root_html"))
    sources = {"root_html": sorted(set(root_hints))}
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
        "rejected_samples": rejected[:20],
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
    endpoint_inventory = _endpoint_inventory(session, scan, target_url)
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
        "endpoint_inventory": endpoint_inventory,
        "js_strings_found": len(candidates["js"]["discovered_js_strings"]),
        "external_reference_count": len(candidates["js"]["discovered_external_references"]),
        "root_status_code": root_output.get("status_code"),
    }
    _artifact(session, scan, "api_method_probe", "method_probe", output)
    _artifact(session, scan, "endpoint_inventory", "endpoint_inventory", {"endpoint_inventory": endpoint_inventory})
    emit_progress(
        session,
        scan,
        f"endpoint inventory built endpoints={len(valid)} auth_endpoints={len(auth)}",
        phase="api_discovery",
        agent="api_discovery_agent",
        tool="api_method_probe",
        event_type="endpoint_inventory_built",
        context={"valid_api_endpoints": len(valid), "auth_endpoints": len(auth), "tested_count": len(results)},
    )
    emit_progress(
        session,
        scan,
        f"method matrix built endpoints={len(valid)} methods={','.join(output['methods_probed'])}",
        phase="api_discovery",
        agent="api_discovery_agent",
        tool="api_method_probe",
        event_type="method_matrix_built",
        context={
            "valid_api_endpoints": len(valid),
            "methods_probed": output["methods_probed"],
            "method_safety_policy": output["method_safety_policy"],
        },
    )
    return _record_tool(session, scan, "api_method_probe", "OPTIONS/GET/POST/PUT/PATCH/DELETE/HEAD probe API candidates", RunStatus.COMPLETED.value, output, "api", "API method probing", "prompt_api_method_probe")


def _run_ffuf_api_paths(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    status, html, _ = _fetch_root_html(target_url)
    candidates = _api_candidate_paths(html, target_url)
    wordlist = _target_wordlist_path(session, scan, target_url)
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
    wordlist = _target_wordlist_path(session, scan, target_url)
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
    registration_gate = _auth_endpoint_gate(session, scan, target_url, {"registration"})
    signup_urls = [item["url"] for item in registration_gate["ready"]]
    if not signup_urls:
        output = {
            "reason": "No registration/signup endpoint discovered",
            "selected_profile": selection.primary_profile,
            "profile_confidence": selection.confidence,
            "endpoint_gate": registration_gate,
        }
        return _record_tool(session, scan, "account_provisioning", "POST signup", RunStatus.MISSING_PREREQUISITE.value, output, "auth", "Account provisioning", "prompt_account_provisioning")
    users = _generated_users(scan.id)
    results = []
    failed_signup_cache: set[tuple[str, str, int]] = set()
    max_attempts_per_user = 2
    max_total_attempts = len(users) * max_attempts_per_user
    total_attempts = 0
    for user in users:
        user_result = {"label": user["label"], "email": user["email"], "attempts": []}
        status = "registration_failed"
        for signup_url in signup_urls:
            if len(user_result["attempts"]) >= max_attempts_per_user or total_attempts >= max_total_attempts:
                break
            request_templates = _request_templates_for_url(session, scan, signup_url, target_url)
            payload_templates = []
            for template in request_templates:
                body = dict(template.get("body_template") or {})
                for key in list(body.keys()):
                    lowered = key.lower()
                    if lowered in {"email", "username", "user"}:
                        body[key] = user["email"]
                    elif lowered in {"password", "pass"}:
                        body[key] = user["password"]
                    elif lowered in {"name", "fullname", "full_name"}:
                        body[key] = user["name"]
                    elif lowered in {"number", "phone", "mobile"}:
                        body[key] = user["number"]
                    elif lowered == "tenant":
                        body[key] = user["tenant"]
                if body:
                    payload_templates.append(body)
            for payload in payload_templates:
                if len(user_result["attempts"]) >= max_attempts_per_user or total_attempts >= max_total_attempts:
                    break
                payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:16]
                if any(item[0] == signup_url and item[1] == payload_hash for item in failed_signup_cache):
                    user_result["attempts"].append({"url": signup_url, "status": "cached_signup_failure", "payload_fields": sorted(payload.keys()), "payload_hash": payload_hash})
                    continue
                try:
                    total_attempts += 1
                    response = httpx.post(signup_url, json=payload, follow_redirects=False, timeout=10)
                    _record_exchange(session, scan, "POST", signup_url, {"content-type": "application/json"}, payload, response)
                    body = response.text.lower()
                    if response.status_code in {200, 201, 202}:
                        status = "registered"
                    elif response.status_code in {400, 401, 403, 422} and any(token in body for token in ["verify", "otp", "verification", "mfa"]):
                        status = "verification_required"
                    elif response.status_code in {400, 409} and any(token in body for token in ["exist", "already", "duplicate"]):
                        status = "already_exists"
                    elif response.status_code == 403:
                        status = _classify_signup_403(response.text)
                        failed_signup_cache.add((signup_url, payload_hash, response.status_code))
                    attempt = {
                        "url": signup_url,
                        "status_code": response.status_code,
                        "status": status,
                        "payload_fields": sorted(payload.keys()),
                        "payload_hash": payload_hash,
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
    output = {"signup_urls": signup_urls, "selected_profile": selection.primary_profile, "profile_confidence": selection.confidence, "users": results, "endpoint_gate": registration_gate, "attempt_budget": {"max_total_signup_attempts": max_total_attempts, "total_attempts": total_attempts, "max_signup_attempts_per_user": max_attempts_per_user}}
    _artifact(session, scan, "account_provisioning", "generated_users", output)
    return _record_tool(session, scan, "account_provisioning", "POST discovered registration endpoints", output_status, output, "auth", "Account provisioning", "prompt_account_provisioning")


def _classify_signup_403(body: str) -> str:
    lowered = (body or "").lower()
    if any(token in lowered for token in ["csrf", "xsrf"]):
        return "csrf_required"
    if any(token in lowered for token in ["rate", "too many", "limit", "waf", "blocked"]):
        return "waf_or_rate_limit"
    if any(token in lowered for token in ["verify", "otp", "verification", "mfa"]):
        return "verification_required"
    if any(token in lowered for token in ["exist", "already", "duplicate"]):
        return "already_exists"
    return "registration_forbidden"


def _run_login_session(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    login_gate = _auth_endpoint_gate(session, scan, target_url, {"login", "token"})
    login_urls = [item["url"] for item in login_gate["ready"]]
    login_url = login_urls[0] if login_urls else None
    if not login_url:
        output = {"reason": "No login endpoint with a ready request template discovered", "endpoint_gate": login_gate}
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
        request_templates = _request_templates_for_url(session, scan, login_url, target_url)
        candidate_payloads = []
        for template in request_templates:
            body = dict(template.get("body_template") or {})
            for key in list(body.keys()):
                lowered = key.lower()
                if lowered in {"email", "username", "user", "login"}:
                    body[key] = credential.username
                elif lowered in {"password", "pass"}:
                    body[key] = password
            if body:
                candidate_payloads.append(body)
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
            token_item = next((token for token in tokens if token["token_type"] in {"bearer", "jwt"}), {})
            token_normalized = normalize_bearer_token(access_token)
            token_meta = _decode_jwt_unverified(access_token)
            for token in tokens:
                token_details = token.get("token_metadata") or {key: value for key, value in normalize_bearer_token(token.get("sample")).items() if key != "token_value"}
                _token(
                    session,
                    scan,
                    token["token_type"],
                    token["location"],
                    _mask_token(token.get("sample")),
                    {"credential": credential.label, "login_url": login_url, "field_name": token.get("field_name"), "masked_sample": _mask_token(token.get("sample")), **token_details, **(_decode_jwt_unverified(token.get("sample")) if token.get("token_type") in {"bearer", "jwt"} else {})},
                )
            auth_header = token_normalized.get("authorization_header")
            emit_progress(
                session,
                scan,
                f"token captured label={credential.label} captured={bool(access_token)}",
                phase="login_session",
                agent="auth_agent",
                tool="login_session",
                event_type="token_captured",
                context={
                    "label": credential.label,
                    "token_captured": bool(access_token),
                    "token_field_name": token_item.get("field_name"),
                    "token_length": token_normalized.get("token_length"),
                    "jwt_shape_valid": token_normalized.get("jwt_shape_valid"),
                    "auth_header_mode": token_normalized.get("header_mode_used"),
                    "token_was_masked": token_normalized.get("token_was_masked"),
                },
                live=True,
            )
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
                existing_auth.access_token_secret = None
                existing_auth.access_token_hash = token_normalized.get("token_hash")
                existing_auth.access_token_masked = _mask_token(access_token)
                existing_auth.secret_ref = secret_ref
                existing_auth.refresh_token = refresh_token
                existing_auth.cookie = "; ".join(f"{key}={value}" for key, value in dict(response.cookies).items()) or None
                existing_auth.authorization_header = "Bearer <masked>" if auth_header else None
                existing_auth.authorization_header_type = token_normalized.get("authorization_header_type")
                existing_auth.token_type = token_normalized.get("token_type")
                existing_auth.login_status = "login_success"
                existing_auth.session_status = validation["session_status"]
                existing_auth.metadata_json = {"masked_access_token": _mask_token(access_token), "masked_refresh_token": _mask_token(refresh_token), "token_field_name": token_item.get("field_name"), "token_validation": validation, "token_metadata": {key: value for key, value in token_normalized.items() if key != "token_value"}, **token_meta}
                status = "login_success"
            else:
                status = "login_failed"
            metadata = dict(credential.metadata_json or {})
            metadata.update({"login_status": status, "login_url": login_url})
            credential.metadata_json = metadata
            results.append({"label": credential.label, "username": credential.username, "status": status, "session_status": validation.get("session_status") if access_token else None, "token_validation": validation if access_token else None, "status_code": response.status_code, "tokens_captured": len(tokens), "token": {"type": token_normalized.get("token_type"), "field_name": token_item.get("field_name"), "masked_sample": _mask_token(access_token), "hash": token_normalized.get("token_hash"), "length": token_normalized.get("token_length"), "jwt_shape_valid": token_normalized.get("jwt_shape_valid"), "header_mode_used": token_normalized.get("header_mode_used"), **token_meta}, "json_keys": _json_keys(response.text), "body_preview": response.text[:1000]})
        except Exception as exc:
            results.append({"label": credential.label, "username": credential.username, "status": "login_failed", "error": str(exc)})
    output_status = RunStatus.COMPLETED.value if any(item["status"] == "login_success" for item in results) else RunStatus.MISSING_CREDENTIALS.value
    output = {"login_url": login_url, "users": results, "endpoint_gate": login_gate}
    output["browser_authenticated_capture"] = _record_browser_authenticated_capture(session, scan, target_url)
    _artifact(session, scan, "login_session", "authenticated_sessions", output)
    return _record_tool(session, scan, "login_session", f"POST {login_url}", output_status, output, "auth", "Login session", "prompt_login_session")


def _record_browser_authenticated_capture(session: Session, scan: Scan, target_url: str) -> dict:
    auth_sessions = _authenticated_sessions_for_scan(session, scan)
    storage_state = None
    usable_session = next((item for item in auth_sessions if item.session_status == "usable" and item.metadata_json), None)
    if usable_session:
        storage_state = (usable_session.metadata_json or {}).get("browser_storage_state_path")
    try:
        capture = capture_authenticated_browser_traffic(scan.id, target_url, storage_state=storage_state)
    except Exception as exc:
        capture = {"status": "skipped_browser_capture_error", "error": str(exc), "observed_endpoints": []}
    observed_endpoints = capture.get("observed_endpoints") or []
    for item in observed_endpoints:
        _endpoint(
            session,
            scan,
            str(item.get("url") or ""),
            "authenticated_api",
            "browser_authenticated_capture",
            method=item.get("method"),
            metadata={"base_url": target_url, "browser_capture_status": capture.get("status"), "candidate_type": item.get("candidate_type")},
        )
    existing_endpoints = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id).limit(500).all()
    capture = {
        **capture,
        "target": target_url,
        "network_requests": observed_endpoints,
        "existing_api_requests": [
            {"url": item.url, "method": item.method, "type": item.endpoint_type, "source": item.source}
            for item in existing_endpoints
            if item.source in {"js_full_scan", "source_map", "openapi", "crawler", "api_method_probe", "api_profile_probe", "authenticated_crawling"}
        ],
        "authenticated_sessions": [
            {"label": item.credential_label, "login_status": item.login_status, "session_status": item.session_status, "auth_header": "Bearer <masked>" if item.authorization_header else None}
            for item in auth_sessions
        ],
        "localStorage": "captured_masked" if capture.get("storage_state") else "not_captured",
        "sessionStorage": "not_captured",
        "note": "Browser authenticated capture attempted; skipped statuses indicate missing local runtime or capture errors.",
    }
    path = write_evidence(scan.id, "browser_authenticated_capture", capture)
    session.add(Evidence(scan_id=scan.id, kind="auth", path=str(path), summary="Browser/authenticated API capture artifact.", metadata_json={"tool": "browser_authenticated_capture"}))
    _artifact(session, scan, "browser_authenticated_capture", "browser_authenticated_capture", capture)
    _build_workflow_request_inventory(session, scan, target_url)
    _build_authenticated_behavior_proof(session, scan, target_url)
    return {"status": capture["status"], "evidence_path": str(path), "network_request_count": len(capture["network_requests"])}


def _request_id(method: str, url: str, body_shape: dict | None = None) -> str:
    digest = hashlib.sha256(json.dumps({"method": method, "url": url, "body_shape": body_shape or {}}, sort_keys=True, default=str).encode()).hexdigest()[:16]
    return f"req-{digest}"


def _body_shape_from_text(text: str | None, content_type: str | None = None) -> dict:
    if not text:
        return {}
    content_type = (content_type or "").lower()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return {"type": "json", "keys": sorted(parsed.keys())}
        if isinstance(parsed, list):
            return {"type": "json_array", "length": len(parsed)}
    except Exception:
        pass
    if "x-www-form-urlencoded" in content_type or "=" in text:
        return {"type": "form_or_query", "keys": sorted(parse_qs(text, keep_blank_values=True).keys())}
    return {"type": "opaque", "length": len(text)}


def _body_markers(text: str | None) -> list[str]:
    lowered = (text or "")[:5000].lower()
    markers = []
    for marker in ["login", "signin", "dashboard", "profile", "account", "user", "email", "order", "cart", "vehicle", "token", "csrf", "unauthorized", "forbidden"]:
        if marker in lowered:
            markers.append(marker)
    return markers


def _auth_attached(headers: dict | None, cookies: object | None = None) -> bool:
    headers = {str(key).lower(): value for key, value in (headers or {}).items()}
    return bool(headers.get("authorization") or headers.get("cookie") or cookies)


def _request_tags(method: str, url: str, headers: dict | None, body_shape: dict | None, response: dict | None, phase: str) -> list[str]:
    tags = []
    parsed = urlparse(url)
    if phase == "login_submit":
        tags.append("login_submit")
    if _auth_attached(headers):
        tags.append("auth_attached")
    if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        tags.append("state_changing")
    if re.search(r"/\d+([/?#]|$)", parsed.path) or re.search(r"(^|&)[A-Za-z_]*(id|uuid|user|account|order|vehicle)[A-Za-z_]*=", parsed.query, re.I):
        tags.append("contains_id")
    if (response or {}).get("set_cookie"):
        tags.append("sets_session_cookie")
    if (response or {}).get("redirect_location"):
        tags.append("redirect")
    if any(marker in ((response or {}).get("body_markers") or []) for marker in ["profile", "account", "user", "email", "order", "cart", "vehicle"]):
        tags.append("user_specific")
    if "xhr" in phase:
        tags.append("xhr")
    return list(dict.fromkeys(tags))


def _inventory_row(method: str, url: str, phase: str, headers: dict | None = None, body: str | None = None, response: dict | None = None, source: str = "observed_workflow") -> dict:
    parsed = urlparse(url)
    content_type = (headers or {}).get("content-type") or (headers or {}).get("Content-Type")
    body_shape = _body_shape_from_text(body, content_type)
    response = response or {}
    row = {
        "request_id": _request_id(method.upper(), url, body_shape),
        "phase": phase,
        "method": method.upper(),
        "url": url,
        "path": parsed.path or "/",
        "headers": _mask_headers(headers or {}),
        "content_type": content_type,
        "body_shape": body_shape,
        "auth_attached": _auth_attached(headers),
        "auth_material_refs": [],
        "response": response,
        "behavior_tags": [],
        "source": source,
    }
    row["behavior_tags"] = _request_tags(row["method"], url, headers, body_shape, response, phase)
    return row


def _mask_headers(headers: dict) -> dict:
    masked = {}
    for key, value in (headers or {}).items():
        lowered = str(key).lower()
        masked[key] = "<masked>" if lowered in {"authorization", "cookie", "set-cookie", "x-api-key"} else value
    return masked


def _har_rows(path: str, target_url: str) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return []
    rows = []
    for entry in ((data.get("log") or {}).get("entries") or []):
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = request.get("url")
        if not url:
            continue
        headers = {item.get("name"): item.get("value") for item in request.get("headers") or [] if item.get("name")}
        response_headers = {item.get("name"): item.get("value") for item in response.get("headers") or [] if item.get("name")}
        body = ((request.get("postData") or {}).get("text"))
        content_type = (request.get("postData") or {}).get("mimeType") or headers.get("content-type") or headers.get("Content-Type")
        if content_type:
            headers.setdefault("content-type", content_type)
        response_payload = {
            "status": response.get("status"),
            "headers": _mask_headers(response_headers),
            "content_type": ((response.get("content") or {}).get("mimeType")),
            "body_hash": hashlib.sha256(str(((response.get("content") or {}).get("text") or "")).encode()).hexdigest()[:16],
            "body_markers": _body_markers((response.get("content") or {}).get("text")),
            "redirect_location": response.get("redirectURL") or response_headers.get("Location") or response_headers.get("location"),
            "set_cookie": any(str(key).lower() == "set-cookie" for key in response_headers),
        }
        phase = "login_submit" if _looks_like_login_request(headers, body, url) else "post_login" if _auth_attached(headers, request.get("cookies")) else "pre_login"
        rows.append(_inventory_row(request.get("method") or "GET", url, phase, headers, body, response_payload, "har_import"))
    return rows


def _looks_like_login_request(headers: dict | None, body: str | None, url: str | None = None) -> bool:
    text = f"{url or ''} {body or ''}".lower()
    return any(token in text for token in ["password", "passwd", "email", "username", "otp"]) and any(token in text for token in ["password", "passwd", "otp"])


def _manual_request_rows(scan: Scan, target_url: str) -> list[dict]:
    rows = []
    for item in (scan.scan_config or {}).get("known_authenticated_requests") or []:
        if isinstance(item, str):
            lines = [line for line in item.splitlines() if line.strip()]
            if not lines:
                continue
            first = lines[0].split()
            method = first[0] if first else "GET"
            url = first[1] if len(first) > 1 else target_url
            headers = {}
            body_lines = []
            in_body = False
            for line in lines[1:]:
                if not line.strip():
                    in_body = True
                    continue
                if not in_body and ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
                else:
                    body_lines.append(line)
            rows.append(_inventory_row(method, urljoin(target_url + "/", url), "user_action", headers, "\n".join(body_lines), {"status": None, "headers": {}, "content_type": None, "body_hash": "", "body_markers": [], "redirect_location": None, "set_cookie": False}, "manual_authenticated_request"))
        elif isinstance(item, dict):
            rows.append(_inventory_row(str(item.get("method") or "GET"), urljoin(target_url + "/", str(item.get("url") or item.get("path") or "")), "user_action", item.get("headers") or {}, item.get("body"), item.get("response") or {}, "manual_authenticated_request"))
    return rows


def _build_workflow_request_inventory(session: Session, scan: Scan, target_url: str) -> dict:
    rows: list[dict] = []
    for row in (load_request_map(scan.id).get("requests") or []):
        response = row.get("response") or {}
        rows.append(
            _inventory_row(
                str(row.get("method") or "GET"),
                str(row.get("url") or ""),
                "post_login" if row.get("auth_attached") else "pre_login",
                row.get("headers") or {},
                row.get("body_shape") or {},
                {
                    "status": response.get("status"),
                    "headers": {},
                    "content_type": response.get("content_type"),
                    "body_hash": response.get("body_hash"),
                    "body_markers": response.get("markers") or [],
                    "redirect_location": response.get("redirect_location"),
                    "set_cookie": response.get("set_cookie"),
                },
                row.get("source") or "request_map",
            )
        )
    for artifact in session.query(PipelineArtifact).filter(PipelineArtifact.scan_id == scan.id, PipelineArtifact.name == "browser_authenticated_capture").all():
        capture = artifact.data or {}
        for item in capture.get("network_requests") or capture.get("observed_endpoints") or []:
            response = {"status": item.get("status"), "headers": {}, "content_type": item.get("content_type"), "body_hash": "", "body_markers": [], "redirect_location": item.get("redirect_location"), "set_cookie": False}
            rows.append(_inventory_row(str(item.get("method") or "GET"), str(item.get("url") or ""), "post_login_xhr", item.get("headers") or {}, item.get("body"), response, "browser_capture"))
    har_file = (scan.scan_config or {}).get("har_file") or ((scan.source_path or "") if str(scan.source_path or "").lower().endswith(".har") else None)
    if har_file:
        rows.extend(_har_rows(str(har_file), target_url))
    rows.extend(_manual_request_rows(scan, target_url))
    for request in session.query(Request).filter(Request.scan_id == scan.id).limit(1000).all():
        response = session.query(Response).filter(Response.request_id == request.id).order_by(Response.id.desc()).first()
        response_payload = {
            "status": response.status_code if response else None,
            "headers": _mask_headers(response.headers or {}) if response else {},
            "content_type": (response.headers or {}).get("content-type") if response else None,
            "body_hash": hashlib.sha256(str(response.body_preview or "").encode()).hexdigest()[:16] if response else "",
            "body_markers": _body_markers(response.body_preview if response else ""),
            "redirect_location": ((response.headers or {}).get("location") if response else None),
            "set_cookie": bool((response.headers or {}).get("set-cookie")) if response else False,
        }
        phase = "login_submit" if _looks_like_login_request(request.headers, request.body, request.url) else "post_login" if _auth_attached(request.headers) else "pre_login"
        rows.append(_inventory_row(request.method, request.url, phase, request.headers or {}, request.body, response_payload, "recorded_exchange"))
    deduped = {row["request_id"]: row for row in rows if row.get("url")}
    inventory = {"requests": list(deduped.values()), "request_count": len(deduped), "source": "workflow_request_inventory"}
    path = write_evidence(scan.id, "workflow_request_inventory", inventory)
    session.add(Evidence(scan_id=scan.id, kind="workflow_request_inventory", path=str(path), summary="Observed workflow request inventory.", metadata_json={"tool": "browser_workflow_agent", "request_count": inventory["request_count"]}))
    _artifact(session, scan, "workflow_request_inventory", "workflow_request_inventory", inventory)
    return inventory


def _latest_workflow_inventory(session: Session, scan: Scan, target_url: str = "") -> dict:
    artifact = session.query(PipelineArtifact).filter(PipelineArtifact.scan_id == scan.id, PipelineArtifact.name == "workflow_request_inventory").order_by(PipelineArtifact.id.desc()).first()
    if artifact and artifact.data:
        return artifact.data
    return _build_workflow_request_inventory(session, scan, target_url)


def _authorization_candidate_requests(inventory: dict) -> list[dict]:
    candidates = []
    for row in inventory.get("requests") or []:
        tags = set(row.get("behavior_tags") or [])
        method = str(row.get("method") or "GET").upper()
        if tags & {"contains_id", "user_specific", "state_changing"} or method not in {"GET", "HEAD", "OPTIONS"}:
            candidate = dict(row)
            candidate["candidate_tags"] = sorted(tags | ({"authorization_testable"} if tags else {"authorization_testable"}))
            candidates.append(candidate)
    return candidates


def _infer_resources_from_inventory(session: Session, scan: Scan, inventory: dict) -> list[dict]:
    resources = []
    for row in inventory.get("requests") or []:
        text = " ".join([row.get("url") or "", json.dumps(row.get("body_shape") or {}, sort_keys=True), json.dumps((row.get("response") or {}).get("body_markers") or [])])
        for match in re.finditer(r"(?<![A-Za-z0-9])([0-9]{2,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{13,})(?![A-Za-z0-9])", text):
            ref = match.group(1)
            resource = {"resource_id": ref, "resource_type_guess": "unknown", "owner_user": None, "source_request_id": row.get("request_id"), "evidence": row.get("url"), "confidence": "medium"}
            resources.append(resource)
            if not session.query(DiscoveredObject).filter(DiscoveredObject.scan_id == scan.id, DiscoveredObject.object_ref == ref).first():
                session.add(DiscoveredObject(scan_id=scan.id, object_type="unknown", object_ref=ref, source="workflow_request_inventory", metadata_json=resource))
    return resources


def _build_authenticated_behavior_proof(session: Session, scan: Scan, target_url: str) -> dict:
    inventory = _latest_workflow_inventory(session, scan, target_url)
    sessions = _authenticated_sessions_for_scan(session, scan)
    token_count = session.query(DiscoveredToken).filter(DiscoveredToken.scan_id == scan.id).count()
    inventory_material = any(row.get("auth_attached") or "sets_session_cookie" in set(row.get("behavior_tags") or []) for row in inventory.get("requests") or [])
    login_sessions = [item for item in sessions if item.login_status == "login_success"]
    material_sessions = [item for item in sessions if item.cookie or item.authorization_header or item.access_token_masked or item.secret_ref]
    session_material = bool(token_count or inventory_material or material_sessions)
    candidates = _authorization_candidate_requests(inventory)
    resources = _infer_resources_from_inventory(session, scan, inventory)
    proof_types = []
    evidence = []
    if session_material:
        proof_types.append("session_material")
    for row in inventory.get("requests") or []:
        tags = set(row.get("behavior_tags") or [])
        response = row.get("response") or {}
        if "sets_session_cookie" in tags:
            proof_types.append("session_material")
            evidence.append({"request_id": row.get("request_id"), "difference": "response set session cookie", "confidence": "high"})
        if "redirect" in tags and row.get("phase") in {"login_submit", "post_login", "post_login_xhr"}:
            proof_types.append("redirect_diff")
            evidence.append({"request_id": row.get("request_id"), "difference": "post-login redirect observed", "confidence": "medium"})
        if "user_specific" in tags:
            proof_types.append("xhr_user_specific" if "xhr" in tags else "body_diff")
            evidence.append({"request_id": row.get("request_id"), "difference": "user/account markers observed in workflow response", "confidence": "medium"})
        if "auth_attached" in tags and row.get("phase") in {"post_login", "post_login_xhr", "user_action"}:
            proof_types.append("session_material")
            evidence.append({"request_id": row.get("request_id"), "difference": "post-login request carried session material", "confidence": "medium"})
        if "state_changing" in tags and response.get("status") in {200, 201, 202, 204, 302, None}:
            proof_types.append("state_change")
    unique_types = list(dict.fromkeys(proof_types))
    proven = bool(session_material and (evidence or candidates))
    authenticated_behavior_count = len({item.credential_label for item in material_sessions}) if proven else 0
    two_login_sessions = len({item.credential_label for item in login_sessions}) >= 2
    two_user = two_login_sessions and proven
    if two_user and candidates:
        gate_status = "ready_for_authorization"
        gate_reason = None
    elif two_login_sessions and not inventory.get("request_count"):
        gate_status = "two_sessions_no_workflow_requests"
        gate_reason = "Two login sessions exist, but no workflow requests were captured for authorization comparison."
    elif two_user and not candidates:
        gate_status = "no_authorization_testable_requests"
        gate_reason = "Two authenticated sessions exist, but no authorization-testable workflow requests were identified."
    elif proven:
        gate_status = "one_user_behavior_proven"
        gate_reason = "Authenticated behavior was proven, but two-user authorization comparison is not ready."
    elif session_material:
        gate_status = "authenticated_behavior_not_proven"
        gate_reason = "Login/session material exists but no post-login workflow behavior could be confirmed."
    else:
        gate_status = "session_material_missing"
        gate_reason = "No session material was captured."
    proof = {
        "authenticated_behavior_proven": proven,
        "proof_type": unique_types,
        "evidence": evidence,
        "confidence": "high" if any(item.get("confidence") == "high" for item in evidence) else "medium" if proven else "low",
        "auth_gate": {
            "status": gate_status,
            "reason": gate_reason,
            "login_sessions_count": len(login_sessions),
            "usable_session_material_count": len(material_sessions) or (1 if inventory_material or token_count else 0),
            "authenticated_behavior_count": authenticated_behavior_count,
            "request_inventory_count": inventory.get("request_count") or 0,
            "authorization_candidate_count": len(candidates),
            "resource_candidate_count": len(resources),
        },
        "authorization_testable_requests": candidates,
        "resource_candidates": resources,
    }
    path = write_evidence(scan.id, "authenticated_behavior_proof", proof)
    session.add(Evidence(scan_id=scan.id, kind="authenticated_behavior_proof", path=str(path), summary=f"Authenticated behavior proof: {proof['auth_gate']['status']}", metadata_json={"tool": "auth_gate", "status": proof["auth_gate"]["status"]}))
    _artifact(session, scan, "authenticated_behavior_proof", "authenticated_behavior_proof", proof)
    config = dict(scan.scan_config or {})
    config["auth_gate"] = proof["auth_gate"]
    scan.scan_config = config
    return proof


def _mark_endpoint_candidate_status(session: Session, scan: Scan, candidate_url: str, status: str, reason: str) -> None:
    candidate_path = urlparse(candidate_url).path or candidate_url
    for endpoint in session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id).limit(1000).all():
        endpoint_path = urlparse(endpoint.url).path or endpoint.url
        if endpoint.url != candidate_url and endpoint_path != candidate_path:
            continue
        metadata = dict(endpoint.metadata_json or {})
        metadata["candidate_status"] = status
        metadata["candidate_reject_reason"] = reason
        endpoint.metadata_json = metadata
        return


def _validate_authenticated_session_token(session: Session, scan: Scan, target_url: str, label: str, access_token: str | None) -> dict:
    profile = profile_from_scan_artifacts(session, scan, target_url).profile
    inventory = _build_workflow_request_inventory(session, scan, target_url)
    behavior_proof = _build_authenticated_behavior_proof(session, scan, target_url)
    if behavior_proof.get("authenticated_behavior_proven"):
        result = {
            "session_status": "usable",
            "reason": "authenticated behavior proven by workflow evidence",
            "validation_url": None,
            "final_selected_validation_endpoint": None,
            "valid_sessions_count": _usable_session_count(session, scan) + 1,
            "workflow_request_inventory_count": inventory.get("request_count") or 0,
            "authenticated_behavior_proof": behavior_proof,
            "candidates_tried": [],
        }
        emit_progress(session, scan, f"session validation completed label={label} status={result['session_status']}", phase="session_validation", agent="auth_agent", tool="login_session", event_type="session_validation_completed", context=result)
        return result
    candidates = _session_validation_candidates(session, scan, target_url, profile)
    validation_url = None
    emit_progress(session, scan, f"session validation started label={label}", phase="session_validation", agent="auth_agent", tool="login_session", event_type="session_validation_started", context={"session_label": label, "candidate_count": len(candidates)})
    if not access_token:
        result = {"session_status": "token_unavailable", "reason": "login did not return access token", "validation_url": validation_url, "final_selected_validation_endpoint": None, "candidates_tried": []}
        emit_progress(session, scan, f"session validation completed label={label} status={result['session_status']}", phase="session_validation", agent="auth_agent", tool="login_session", event_type="session_validation_completed", context=result)
        return result
    if _is_masked_token(access_token):
        result = {"session_status": "token_unavailable", "reason": "masked token cannot be used for validation", "validation_url": validation_url, "final_selected_validation_endpoint": None, "candidates_tried": []}
        emit_progress(session, scan, f"session validation completed label={label} status={result['session_status']}", phase="session_validation", agent="auth_agent", tool="login_session", event_type="session_validation_completed", context=result)
        return result
    normalized = normalize_bearer_token(access_token)
    if not normalized.get("authorization_header"):
        result = {"session_status": "token_unavailable", "reason": "bearer token could not be normalized", "validation_url": validation_url, "final_selected_validation_endpoint": None, "candidates_tried": [], "token_metadata": normalized}
        emit_progress(session, scan, f"session validation completed label={label} status={result['session_status']}", phase="session_validation", agent="auth_agent", tool="login_session", event_type="session_validation_completed", context=result)
        return result
    headers = {"Authorization": normalized["authorization_header"]}
    try:
        selected_response = None
        selected_url = None
        attempts = []
        for candidate in candidates:
            candidate_url = urljoin(target_url + "/", candidate.lstrip("/"))
            if _is_public_validation_endpoint(candidate_url):
                _mark_endpoint_candidate_status(session, scan, candidate_url, "rejected_public", "public or auth workflow endpoint cannot confirm authenticated session")
                attempts.append({"endpoint": candidate_url, "status": "skipped_public_or_auth_workflow_endpoint"})
                continue
            emit_progress(
                session,
                scan,
                f"validation endpoint tried label={label} path={urlparse(candidate_url).path}",
                phase="session_validation",
                agent="auth_agent",
                tool="login_session",
                event_type="session_validation_endpoint_tried",
                context={"session_label": label, "endpoint": candidate_url},
            )
            baseline_response = httpx.get(candidate_url, follow_redirects=False, timeout=10)
            _record_exchange(session, scan, "GET", candidate_url, {}, None, baseline_response)
            response = httpx.get(candidate_url, headers=headers, follow_redirects=False, timeout=10)
            _record_exchange(session, scan, "GET", candidate_url, {"Authorization": "Bearer <masked>"}, None, response)
            parsed_json = _parse_json_body(response.text)
            baseline_requires_auth = baseline_response.status_code in {401, 403}
            authenticated_success = 200 <= response.status_code < 300
            authenticated_shape = _looks_authenticated_response(response.text, parsed_json)
            candidate_status = None
            candidate_reason = None
            if response.status_code == 404:
                candidate_status = "rejected_404"
                candidate_reason = "authenticated request returned 404; workflow behavior was not confirmed"
            elif response.status_code == 405:
                candidate_status = "rejected_405"
                candidate_reason = "authenticated request returned 405 for GET; method-specific endpoint not validated"
            elif not baseline_requires_auth and authenticated_success:
                candidate_status = "rejected_public"
                candidate_reason = "endpoint did not require authentication in baseline request"
            attempt = {
                "endpoint": candidate_url,
                "baseline_status_code": baseline_response.status_code,
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type"),
                "json_keys": _json_keys(response.text),
                "body_preview": response.text[:1000],
                "baseline_requires_auth": baseline_requires_auth,
                "authenticated_response": baseline_requires_auth and authenticated_success and authenticated_shape,
                "auth_failure": response.status_code in {401, 403},
                "candidate_status": candidate_status,
                "candidate_reject_reason": candidate_reason,
            }
            attempts.append(attempt)
            if candidate_status:
                _mark_endpoint_candidate_status(session, scan, candidate_url, candidate_status, candidate_reason or candidate_status)
            emit_progress(
                session,
                scan,
                f"validation status label={label} status={response.status_code}",
                phase="session_validation",
                agent="auth_agent",
                tool="login_session",
                event_type="session_validation_endpoint_result",
                context={"session_label": label, "endpoint": candidate_url, "status_code": response.status_code, "body_preview": response.text[:300]},
            )
            if attempt["authenticated_response"]:
                _mark_endpoint_candidate_status(session, scan, candidate_url, "confirmed_protected", "baseline required auth and authenticated request returned protected resource shape")
                selected_response = response
                selected_url = candidate_url
                break
        if not attempts:
            result = {"session_status": "authenticated_behavior_not_proven", "reason": "Login/session material exists but no post-login workflow request or behavior difference could be confirmed.", "validation_url": None, "final_selected_validation_endpoint": None, "workflow_request_inventory_count": inventory.get("request_count") or 0, "authenticated_behavior_proof": behavior_proof, "candidates_tried": []}
            emit_progress(session, scan, f"session validation completed label={label} status={result['session_status']}", phase="session_validation", agent="auth_agent", tool="login_session", event_type="session_validation_completed", context=result)
            return result
        validation_url = selected_url or validation_url
        response = selected_response
        token_meta = _decode_jwt_unverified(normalized.get("token_value"))
        verification_check = _detect_account_verification_requirement(target_url, profile, attempts)
        evidence = {
            "session_label": label,
            "token_attached": True,
            "auth_header_type": "bearer",
            "token_source": "memory",
            "token_was_masked": False,
            "token_metadata": {key: value for key, value in normalized.items() if key != "token_value"},
            "endpoint_candidates_tried": attempts,
            "final_selected_validation_endpoint": validation_url if selected_response is not None else None,
            "status_code": response.status_code if response else attempts[-1].get("status_code"),
            "body_preview": response.text[:1000] if response else attempts[-1].get("body_preview"),
            "decoded_jwt_sub": token_meta.get("sub") or token_meta.get("email"),
            "decoded_jwt_role": token_meta.get("role"),
            "verification_check": verification_check,
        }
        auth_failures = [item for item in attempts if item.get("status_code") in {401, 403}]
        if response and any(item.get("endpoint") == validation_url and item.get("authenticated_response") for item in attempts):
            final_session_status = "usable"
            final_reason = None
        elif auth_failures:
            final_session_status = "account_not_verified" if verification_check.get("possible_verification_required") else "token_validation_failed"
            final_reason = verification_check.get("reason") or "workflow validation rejected the bearer token or session material"
        else:
            final_session_status = "authenticated_behavior_not_proven"
            final_reason = "Login/session material exists but no post-login workflow request or behavior difference could be confirmed."
        evidence["final_session_status"] = final_session_status
        evidence["final_reason"] = final_reason
        path = write_evidence(scan.id, f"session_validation_{label}", evidence)
        session.add(Evidence(scan_id=scan.id, kind="auth", path=str(path), summary=f"Session validation for {label}: HTTP {evidence['status_code']}", metadata_json={"tool": "session_validation", "session_label": label, "status_code": evidence["status_code"]}))
        if behavior_proof.get("authenticated_behavior_proven") or (response and any(item.get("endpoint") == validation_url and item.get("authenticated_response") for item in attempts)):
            result = {"session_status": "usable", "reason": None, "validation_url": validation_url, "status_code": response.status_code, "evidence_path": str(path), "valid_sessions_count": _usable_session_count(session, scan) + 1, "candidates_tried": attempts}
            emit_progress(session, scan, f"session validation completed label={label} status={result['session_status']}", phase="session_validation", agent="auth_agent", tool="login_session", event_type="session_validation_completed", context=result)
            return result
        result = {"session_status": final_session_status, "reason": final_reason, "validation_url": validation_url if selected_response is not None else None, "final_selected_validation_endpoint": validation_url if selected_response is not None else None, "status_code": evidence["status_code"], "evidence_path": str(path), "candidates_tried": attempts, "token_metadata": {key: value for key, value in normalized.items() if key != "token_value"}, "verification_check": verification_check}
        emit_progress(session, scan, f"session validation completed label={label} status={result['session_status']}", phase="session_validation", agent="auth_agent", tool="login_session", event_type="session_validation_completed", context=result)
        return result
    except Exception as exc:
        result = {"session_status": "login_success_validation_error", "reason": str(exc), "validation_url": validation_url, "final_selected_validation_endpoint": None, "candidates_tried": []}
        emit_progress(session, scan, f"session validation completed label={label} status={result['session_status']}", level="ERROR", phase="session_validation", agent="auth_agent", tool="login_session", event_type="session_validation_completed", context=result)
        return result


def _session_validation_candidates(session: Session, scan: Scan, target_url: str, profile: dict) -> list[str]:
    discovered = []
    for item in (getattr(scan, "scan_config", None) or {}).get("known_protected_endpoints") or []:
        if isinstance(item, str):
            value = item
            method = "GET"
        elif isinstance(item, dict):
            value = str(item.get("path") or item.get("url") or "")
            method = str(item.get("method") or "GET").upper()
        else:
            continue
        sanitized = sanitize_candidate_endpoint(value, target_url, "known_protected_endpoint")
        if sanitized:
            discovered.append(sanitized.url if not _same_target(target_url, sanitized.url) else (urlparse(sanitized.url).path or sanitized.url))
            _endpoint(session, scan, sanitized.url, "api", "known_protected_endpoint", method=method, metadata={"base_url": target_url, "candidate_status": "user_provided"})
    for endpoint in session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id).limit(500).all():
        metadata = getattr(endpoint, "metadata_json", None) or {}
        if str(metadata.get("candidate_status") or "").startswith("rejected_"):
            continue
        sanitized = sanitize_candidate_endpoint(endpoint.url, target_url, getattr(endpoint, "source", None) or "endpoint_inventory")
        if not sanitized:
            continue
        path = urlparse(sanitized.url).path or sanitized.url
        if _is_auth_workflow_endpoint(path):
            continue
        lowered = path.lower()
        if _is_public_validation_endpoint(path):
            continue
        if getattr(endpoint, "endpoint_type", None) in {"authenticated_api", "api", "api_spec"} or any(token in lowered for token in ["/identity/api", "/workshop/api", "/community/api", "/api/"]):
            discovered.append(path if _same_target(target_url, sanitized.url) else sanitized.url)
    return list(dict.fromkeys(str(item) for item in discovered if item and sanitize_candidate_endpoint(str(item), target_url, "session_validation") and not _is_auth_workflow_endpoint(str(item))))


def _is_public_validation_endpoint(path: str) -> bool:
    lowered = (urlparse(path).path or path or "/").lower().rstrip("/") or "/"
    if lowered in {"/", "/health", "/robots.txt", "/sitemap.xml", "/manifest.json", "/identity", "/workshop", "/community"}:
        return True
    if _is_auth_workflow_endpoint(lowered):
        return True
    if lowered.startswith(("/identity/api/", "/workshop/api/", "/community/api/", "/api/")):
        return False
    if lowered.startswith(("/static/", "/images/", "/assets/", "/css/", "/js/")):
        return True
    return False


def _looks_authenticated_response(body: str, parsed_json) -> bool:
    lowered = body[:4000].lower()
    if isinstance(parsed_json, dict) and any(key.lower() in {"id", "email", "username", "role", "vehicleid", "vehicles", "profile", "user"} for key in parsed_json.keys()):
        return True
    return any(token in lowered for token in ["email", "username", "vehicle", "profile", "account", "tenant", "role"])


def _is_auth_workflow_endpoint(path: str) -> bool:
    lowered = str(path or "").lower()
    auth_workflow_markers = [
        "/auth/login",
        "/auth/signup",
        "/auth/register",
        "/auth/verify",
        "/auth/v2/check-otp",
        "/auth/v3/check-otp",
        "/auth/check-otp",
        "/auth/forgot",
        "/auth/forget",
        "/auth/reset",
        "/auth/logout",
        "/auth/refresh",
    ]
    return any(marker in lowered for marker in auth_workflow_markers)


def _detect_account_verification_requirement(target_url: str, profile: dict, attempts: list[dict]) -> dict:
    profile_id = str(profile.get("profile_id") or profile.get("name") or "").lower()
    body_text = " ".join(str(item.get("body_preview") or "")[:1000].lower() for item in attempts)
    invalid_token = any(item.get("status_code") in {401, 403} and "invalid token" in str(item.get("body_preview") or "").lower() for item in attempts)
    verification_terms = any(term in body_text for term in ["verify", "verification", "otp", "not verified", "inactive account"])
    possible = "crapi" in profile_id and (invalid_token or verification_terms)
    return {
        "possible_verification_required": possible,
        "reason": "crAPI token was rejected during authenticated workflow validation; account verification or token incompatibility may be required" if possible else None,
        "verification_endpoint_candidates": [
            urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
            for path in ["/identity/api/auth/verify", "/identity/api/auth/v2/check-otp", "/identity/api/auth/v3/check-otp"]
        ] if "crapi" in profile_id else [],
    }


def _run_session_validation(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    sessions = _authenticated_sessions_for_scan(session, scan)
    proof = _build_authenticated_behavior_proof(session, scan, target_url)
    if not sessions:
        gate = proof.get("auth_gate") or {}
        output = {"reason": gate.get("reason") or "no login_success sessions available for validation", "valid_sessions_count": 0, "login_sessions_count": gate.get("login_sessions_count", 0), "usable_session_material_count": gate.get("usable_session_material_count", 0), "authenticated_behavior_count": gate.get("authenticated_behavior_count", 0), "authorization_candidate_count": gate.get("authorization_candidate_count", 0), "auth_gate_status": gate.get("status"), "authenticated_behavior_proof": proof}
        return _record_tool(session, scan, "session_validation", "validate authenticated behavior", RunStatus.COMPLETED.value if proof.get("authenticated_behavior_proven") else RunStatus.MISSING_PREREQUISITE.value, output, "auth", "Session validation", "prompt_session_validation")
    results = []
    valid_count = 0
    for auth_session in sessions:
        secret = _load_session_secret(auth_session)
        if secret.get("token_storage_error"):
            auth_session.session_status = "token_storage_error"
            results.append({"label": auth_session.credential_label, "session_status": "token_storage_error", "reason": secret.get("reason"), "token_metadata": secret.get("token_metadata")})
            continue
        token = secret.get("token")
        validation = _validate_authenticated_session_token(session, scan, target_url, auth_session.credential_label, token)
        auth_session.session_status = validation.get("session_status")
        metadata = dict(auth_session.metadata_json or {})
        metadata["token_validation"] = validation
        auth_session.metadata_json = metadata
        if validation.get("session_status") == "usable":
            valid_count += 1
        results.append(
            {
                "label": auth_session.credential_label,
                "username": auth_session.username,
                "session_status": validation.get("session_status"),
                "reason": validation.get("reason"),
                "validation_url": validation.get("validation_url"),
                "evidence_path": validation.get("evidence_path"),
                "token_source": secret.get("source"),
                "token_captured": bool(token),
                "token_was_masked": bool(secret.get("token_was_masked")),
            }
        )
    gate = proof.get("auth_gate") or {}
    output = {"sessions": results, "valid_sessions_count": valid_count, "login_sessions_count": gate.get("login_sessions_count", valid_count), "usable_session_material_count": gate.get("usable_session_material_count", valid_count), "authenticated_behavior_count": gate.get("authenticated_behavior_count", 0), "authorization_candidate_count": gate.get("authorization_candidate_count", 0), "required_valid_sessions_for_authorization": 2, "auth_gate_status": gate.get("status"), "authenticated_behavior_proof": proof}
    emit_progress(
        session,
        scan,
        f"session validation completed valid_sessions_count={valid_count}",
        phase="session_validation",
        agent="auth_agent",
        tool="session_validation",
        event_type="session_validation_summary",
        context=output,
        live=True,
    )
    status = RunStatus.COMPLETED.value if valid_count else RunStatus.MISSING_PREREQUISITE.value
    if valid_count and valid_count < 2 and scan.allow_authorization_testing:
        output["reason"] = "authorization testing requires two behavior-proven user sessions; only one validated"
    elif not valid_count:
        output["reason"] = "Authorization testing requires confirmed authenticated behavior and testable workflow requests. SAIF captured login/session material but could not prove post-login application behavior or identify authorization-sensitive requests. This is a coverage blocker, not a vulnerability."
    return _record_tool(session, scan, "session_validation", "validate authenticated sessions", status, output, "auth", "Session validation", "prompt_session_validation")


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
    all_auth_sessions = _authenticated_sessions_for_scan(session, scan)
    auth_sessions = [item for item in all_auth_sessions if item.session_status == "usable"]
    if not all_auth_sessions:
        output = {"reason": "authenticated sessions not available"}
        return _record_tool(session, scan, "authenticated_crawling", "authenticated API crawl", RunStatus.MISSING_CREDENTIALS.value, output, "auth", "Authenticated crawling", "prompt_authenticated_crawling")
    if not auth_sessions:
        output = {
            "reason": "login sessions exist but authenticated behavior was not proven from workflow evidence",
            "authenticated_sessions": [
                {"label": item.credential_label, "login_status": item.login_status, "session_status": item.session_status}
                for item in all_auth_sessions
            ],
            "required_artifact": "authenticated_behavior_proven",
            "how_to_make_testable": "enable browser capture, provide HAR after login, paste an authenticated request, or provide a post-login action",
        }
        return _record_tool(session, scan, "authenticated_crawling", "authenticated API crawl", RunStatus.MISSING_PREREQUISITE.value, output, "auth", "Authenticated crawling", "prompt_authenticated_crawling")
    profile = profile_from_scan_artifacts(session, scan, target_url).profile
    paths = _session_validation_candidates(session, scan, target_url, profile)
    if not paths:
        discovered = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id, DiscoveredEndpoint.endpoint_type.in_(["api", "authenticated_api", "api_auth"])).limit(50).all()
        paths = [urlparse(item.url).path or item.url for item in discovered]
    paths = [path for path in paths if not _is_public_validation_endpoint(path)]
    if not paths:
        inventory = _latest_workflow_inventory(session, scan, target_url)
        candidates = _authorization_candidate_requests(inventory)
        if candidates:
            paths = [urlparse(item["url"]).path or item["url"] for item in candidates]
        else:
            output = {"reason": "Authenticated behavior was proven, but no workflow requests suitable for authenticated crawling were identified", "required_artifact": "workflow_request_inventory_built"}
            return _record_tool(session, scan, "authenticated_crawling", "authenticated API crawl", RunStatus.MISSING_PREREQUISITE.value, output, "auth", "Authenticated crawling", "prompt_authenticated_crawling")
    if not paths:
        output = {"reason": "Authenticated behavior was proven, but no workflow requests suitable for authenticated crawling were identified", "required_artifact": "workflow_request_inventory_built"}
        return _record_tool(session, scan, "authenticated_crawling", "authenticated API crawl", RunStatus.MISSING_PREREQUISITE.value, output, "auth", "Authenticated crawling", "prompt_authenticated_crawling")
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
                    auth_session.session_status = "token_validation_failed"
                parsed_json = _parse_json_body(response.text)
                ids = []
                _collect_ids(parsed_json, ids)
                for item in ids[:100]:
                    object_count += 1
                    session.add(DiscoveredObject(scan_id=scan.id, object_type=item["field"], object_ref=f"{url}#{item['value']}", source="authenticated_crawling", metadata_json={"session": auth_session.credential_label, "url": url, "value": item["value"]}))
                if response.status_code != 404:
                    _endpoint(session, scan, url, "authenticated_api", "authenticated_crawling", method="GET", metadata={"session": auth_session.credential_label, "status_code": response.status_code, "ids_found": len(ids)})
                results.append({"session": auth_session.credential_label, "url": url, "method": "GET", "auth_header_type_used": "bearer" if headers.get("Authorization") else "cookie" if cookies else "none", "token_attached": bool(headers.get("Authorization") or cookies), "auth_header_type": "bearer" if headers.get("Authorization") else None, "token_source": secret.get("source"), "token_was_masked": False, "decoded_jwt_sub": token_meta.get("sub") or token_meta.get("email"), "decoded_jwt_role": token_meta.get("role"), "token_subject": token_meta.get("sub") or token_meta.get("email"), "masked_token": auth_session.access_token_masked or _mask_token(secret.get("token")), "status_code": response.status_code, "body_preview": response.text[:1000], "json_keys": _json_keys(response.text), "ids_found": ids[:20], "reason": "bearer token rejected during workflow validation" if response.status_code == 401 else None})
            except Exception as exc:
                session_statuses[auth_session.credential_label] = RunStatus.EXECUTION_ERROR.value
                results.append({"session": auth_session.credential_label, "url": url, "error": str(exc)})
    output = {"requests": results, "objects_discovered": object_count, "session_statuses": session_statuses}
    _artifact(session, scan, "authenticated_crawling", "authenticated_api_inventory", output)
    emit_progress(session, scan, f"authenticated inventory built endpoints={len([item for item in results if item.get('status_code') and item.get('status_code') != 404])} objects={object_count}", phase="authenticated_crawling", agent="auth_agent", tool="authenticated_crawling", event_type="authenticated_inventory_built", context={"endpoint_count": len([item for item in results if item.get("status_code") and item.get("status_code") != 404]), "object_count": object_count, "session_statuses": session_statuses})
    if object_count:
        emit_progress(session, scan, f"resource ownership map built objects={object_count}", phase="authenticated_crawling", agent="auth_agent", tool="authenticated_crawling", event_type="resource_ownership_map_built", context={"object_count": object_count})
    status = RunStatus.COMPLETED.value if any(value == RunStatus.COMPLETED.value for value in session_statuses.values()) else RunStatus.MISSING_PREREQUISITE.value
    if status == RunStatus.MISSING_PREREQUISITE.value:
        if any(item.get("token_was_masked") for item in results):
            output["reason"] = "execution token unavailable or masked token used"
        elif any(item.get("status_code") == 401 and item.get("token_attached") for item in results):
            output["reason"] = "Authenticated behavior was not proven from workflow evidence"
    return _record_tool(session, scan, "authenticated_crawling", "authenticated API crawl", status, output, "auth", "Authenticated crawling", "prompt_authenticated_crawling")


def _run_authenticated_resource_discovery(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    endpoint_count = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id, DiscoveredEndpoint.endpoint_type == "authenticated_api").count()
    object_count = _discovered_object_count(session, scan)
    output = {
        "authenticated_endpoint_count": endpoint_count,
        "objects_discovered": object_count,
        "reason": None if endpoint_count else "authenticated crawling did not produce authenticated endpoint inventory",
    }
    status = RunStatus.COMPLETED.value if endpoint_count else RunStatus.MISSING_PREREQUISITE.value
    return _record_tool(session, scan, "authenticated_resource_discovery", "summarize authenticated resource discovery", status, output, "auth", "Authenticated resource discovery", "prompt_authenticated_resource_discovery")


def _run_resource_ownership_map(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    objects = session.query(DiscoveredObject).filter(DiscoveredObject.scan_id == scan.id).limit(100).all()
    output = {
        "object_count": len(objects),
        "ownership_entries": [
            {"object_type": item.object_type, "object_ref": item.object_ref, "source": item.source, "metadata": item.metadata_json}
            for item in objects[:50]
        ],
        "reason": None if objects else "no object identifiers discovered from authenticated resources",
    }
    status = RunStatus.COMPLETED.value if objects else RunStatus.MISSING_PREREQUISITE.value
    return _record_tool(session, scan, "resource_ownership_map", "build resource ownership map", status, output, "authz", "Resource ownership map", "prompt_resource_ownership_map")


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
        input_names = [str(item).lower() for item in form.get("inputs") or []]
        if any("pass" in item or "otp" in item for item in input_names):
            flow_type = "login"
        _endpoint(session, scan, form["action"], "form", "auth_session_mapping", method=form.get("method") or "POST", metadata={"inputs": form.get("inputs") or [], "request_template_ready": bool(form.get("inputs"))})
        for name in form.get("inputs") or []:
            _parameter(session, scan, name, "form", form["action"], "auth_session_mapping", {"method": form.get("method") or "POST"})
        if flow_type in {"login", "logout", "registration", "password_reset", "oauth", "oidc", "saml", "token"}:
            _auth_flow(session, scan, flow_type, form["action"], {"form": form, "source": "form", "endpoint_confidence": "high", "behavior_signals": ["credential_form_fields"]})
    hints = (scan.scan_config or {}).get("login_workflow_hints") or {}
    if hints.get("login_url"):
        login_url = urljoin(target_url + "/", str(hints.get("login_url")).lstrip("/"))
        _endpoint(session, scan, login_url, "form", "manual_login_workflow_hint", method="POST", metadata={"request_template_ready": bool(hints.get("username_field") and hints.get("password_field")), "hints": hints})
        _auth_flow(session, scan, "login", login_url, {"source": "manual_login_workflow_hint", "endpoint_confidence": "high", "behavior_signals": ["manual_login_url", "tester_supplied_workflow"]})
    credentials = load_credentials()
    for item in credentials:
        auth_type = str(item.get("auth_type") or "form")
        _auth_mechanism(session, scan, auth_type, None, "high", {"credential_label": item.get("label"), "source": "configs/credentials.yaml"})
        if auth_type in {"bearer", "api_key", "cookie"}:
            _session_mechanism(session, scan, auth_type, "credentials", "jwt" if auth_type == "bearer" else auth_type, "high", {"credential_label": item.get("label")})
    provisioning = {"status": RunStatus.PLANNED.value, "next_stage": "account_provisioning"}
    output = {
        "checked": checked,
        "credentials_configured": bool(credentials),
        "credential_labels": [item.get("label") for item in credentials],
        "generated_account_provisioning": provisioning,
        "root_status_code": root_output.get("status_code"),
        "endpoint_inventory": _endpoint_inventory(session, scan, target_url),
        "login_workflow_discovered": bool(session.query(DiscoveredAuthFlow).filter(DiscoveredAuthFlow.scan_id == scan.id, DiscoveredAuthFlow.flow_type.in_(["login", "token"])).count()),
        "login_discovery_model": "behavior_signals_with_endpoint_names_as_weak_hints",
    }
    status = RunStatus.COMPLETED.value if checked or html else RunStatus.NOT_APPLICABLE.value
    _artifact(session, scan, "discovered_auth_endpoints", "auth_session_mapping", output)
    return _record_tool(session, scan, "auth_session_mapping", "auth/session discovery", status, output, "auth", "Authentication and session mapping", "prompt_auth_session_mapping")


def _attempt_generated_account_provisioning(session: Session, scan: Scan, target_url: str) -> dict:
    selection = profile_from_scan_artifacts(session, scan, target_url)
    signup_urls = [item["url"] for item in _auth_endpoint_gate(session, scan, target_url, {"registration"})["ready"]]
    login_urls = [item["url"] for item in _auth_endpoint_gate(session, scan, target_url, {"login", "token"})["ready"]]
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
    inventory = _latest_workflow_inventory(session, scan, target_url)
    candidates = _authorization_candidate_requests(inventory)
    _infer_resources_from_inventory(session, scan, inventory)
    objects = session.query(DiscoveredObject).filter(DiscoveredObject.scan_id == scan.id).limit(100).all()
    if len(all_sessions) >= 2 and len(sessions) < 2:
        output = {
            "reason": "authenticated sessions exist but behavior proof did not validate two usable sessions",
            "authenticated_sessions": [
                {"label": item.credential_label, "session_status": item.session_status, "login_status": item.login_status}
                for item in all_sessions
            ],
            "usable_sessions": [item.credential_label for item in sessions],
        }
        return _record_tool(session, scan, "authorization_matrix", "authenticated cross-account object replay", RunStatus.MISSING_PREREQUISITE.value, output, "authz", "Authorization matrix", "prompt_authorization_matrix")
    if len(sessions) >= 2 and candidates:
        checks = []
        findings_created = 0
        subject = sessions[0]
        alternate = sessions[1]
        for candidate in candidates[:25]:
            url = candidate["url"]
            try:
                subject_headers, subject_cookies = _auth_headers_for_session(subject)
                alternate_headers, alternate_cookies = _auth_headers_for_session(alternate)
                method = str(candidate.get("method") or "GET").upper()
                owner_response = httpx.request(method, url, headers=subject_headers, cookies=subject_cookies, follow_redirects=False, timeout=10)
                alternate_response = httpx.request(method, url, headers=alternate_headers, cookies=alternate_cookies, follow_redirects=False, timeout=10)
                _record_exchange(session, scan, method, url, _masked_headers(subject_headers), None, owner_response)
                _record_exchange(session, scan, method, url, _masked_headers(alternate_headers), None, alternate_response)
                observed = "same_status" if owner_response.status_code == alternate_response.status_code else "different_status"
                body_same = owner_response.text[:2000] == alternate_response.text[:2000]
                issue = owner_response.status_code in {200, 201} and alternate_response.status_code in {200, 201} and body_same
                matrix_status = RunStatus.FINDING_CREATED.value if issue else RunStatus.COMPLETED.value
                if issue:
                    findings_created += 1
                    _finding(session, scan, "Possible cross-account workflow access", f"{alternate.credential_label} received the same response for workflow request {candidate['request_id']} discovered with {subject.credential_label}.")
                session.add(
                    AuthorizationMatrix(
                        scan_id=scan.id,
                        subject=alternate.credential_label,
                        role="generated_user",
                        endpoint=url,
                        object_ref=(objects[0].object_ref if objects else candidate["request_id"]),
                        expected_access="different user should not receive identical account/object-sensitive response",
                        observed_access=observed,
                        status=matrix_status,
                        metadata_json={"owner_session": subject.credential_label, "attacker_session": alternate.credential_label, "owner_status": owner_response.status_code, "actual_status_code": alternate_response.status_code, "body_same": body_same, "request_id": candidate["request_id"], "candidate_tags": candidate.get("candidate_tags")},
                    )
                )
                checks.append({"request_id": candidate["request_id"], "url": url, "owner_status": owner_response.status_code, "alternate_status": alternate_response.status_code, "body_same": body_same, "status": matrix_status})
            except Exception as exc:
                checks.append({"request_id": candidate.get("request_id"), "status": RunStatus.EXECUTION_ERROR.value, "error": str(exc)})
        output = {"mode": "workflow_behavior_comparison", "sessions": [item.credential_label for item in sessions[:2]], "requests_tested": len(checks), "resource_candidates": len(objects), "findings_created": findings_created, "checks": checks}
        status = RunStatus.FINDING_CREATED.value if findings_created else RunStatus.COMPLETED.value
        return _record_tool(session, scan, "authorization_matrix", "authenticated cross-account object replay", status, output, "authz", "Authorization matrix", "prompt_authorization_matrix")

    if len(sessions) >= 2 and not candidates:
        status = RunStatus.MISSING_PREREQUISITE.value
        reason = "No authorization-testable workflow requests identified"
        output = {"reason": reason, "authenticated_sessions": [item.credential_label for item in sessions], "workflow_request_inventory_count": inventory.get("request_count") or 0, "authorization_candidates": 0, "objects": len(objects)}
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
    auth_sessions = [item for item in _authenticated_sessions_for_scan(session, scan) if item.session_status == "usable"]
    inventory = _latest_workflow_inventory(session, scan, target_url)
    candidates = _authorization_candidate_requests(inventory)
    _infer_resources_from_inventory(session, scan, inventory)
    objects = session.query(DiscoveredObject).filter(DiscoveredObject.scan_id == scan.id).all()
    authenticated_endpoints = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id, DiscoveredEndpoint.endpoint_type == "authenticated_api").all()
    if len(auth_sessions) >= 2:
        cases = ["IDOR/BOLA", "BFLA", "horizontal privilege escalation", "vertical privilege escalation", "tenant isolation", "forced browsing"]
        if not candidates:
            output = {"test_cases": cases, "reason": "workflow inventory did not identify authorization-testable requests", "authenticated_sessions": [item.credential_label for item in auth_sessions], "workflow_request_inventory_count": inventory.get("request_count") or 0, "authenticated_endpoint_count": len(authenticated_endpoints)}
            return _record_tool(session, scan, "idor_bola_bfla_planner", "plan IDOR/BOLA/BFLA tests", RunStatus.MISSING_PREREQUISITE.value, output, "authz", "IDOR/BOLA/BFLA planning", "prompt_idor_bola_bfla")
        output = {"test_cases": cases, "authenticated_sessions": [item.credential_label for item in auth_sessions], "object_count": len(objects), "authorization_candidate_count": len(candidates), "authenticated_endpoint_count": len(authenticated_endpoints), "status": "authorization_matrix can execute workflow request comparison"}
        return _record_tool(session, scan, "idor_bola_bfla_planner", "plan IDOR/BOLA/BFLA tests", RunStatus.COMPLETED.value, output, "authz", "IDOR/BOLA/BFLA planning", "prompt_idor_bola_bfla")

    credentials = load_credentials()
    status = RunStatus.PLANNED.value if credentials else RunStatus.MISSING_CREDENTIALS.value
    cases = ["IDOR/BOLA", "BFLA", "horizontal privilege escalation", "vertical privilege escalation", "tenant isolation", "forced browsing"]
    output = {"test_cases": cases, "reason": None if credentials else "credentials are required for replay-based authorization testing"}
    return _record_tool(session, scan, "idor_bola_bfla_planner", "plan IDOR/BOLA/BFLA tests", status, output, "authz", "IDOR/BOLA/BFLA planning", "prompt_idor_bola_bfla")


def _run_mass_assignment_testing(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    templates = _request_templates(session, scan, target_url)
    output = {
        "request_templates_count": len(templates),
        "reason": None if templates else "mass assignment testing requires request templates from authenticated resource discovery",
        "test_strategy": "compare accepted/rejected extra fields only after authenticated request templates exist",
    }
    status = RunStatus.PLANNED.value if templates else RunStatus.MISSING_PREREQUISITE.value
    return _record_tool(session, scan, "mass_assignment_testing", "plan mass assignment checks", status, output, "authz", "Mass assignment testing", "prompt_mass_assignment")


def _run_cross_account_access_testing(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    usable_sessions = [item for item in _authenticated_sessions_for_scan(session, scan) if item.session_status == "usable"]
    object_count = _discovered_object_count(session, scan)
    output = {
        "usable_sessions_count": len(usable_sessions),
        "object_count": object_count,
        "reason": None if len(usable_sessions) >= 2 and object_count else "cross-account testing requires two valid sessions and discovered user-owned objects",
    }
    status = RunStatus.PLANNED.value if len(usable_sessions) >= 2 and object_count else RunStatus.MISSING_PREREQUISITE.value
    return _record_tool(session, scan, "cross_account_access_testing", "plan cross-account replay checks", status, output, "authz", "Cross-account access testing", "prompt_cross_account_access")


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


def _request_template_for_parameter(session: Session, scan: Scan, param: DiscoveredParameter, target_url: str) -> dict | None:
    endpoint = param.endpoint or target_url
    if not endpoint:
        return None
    location = (param.location or "query").lower()
    endpoint_path = urlparse(endpoint).path.lower()
    profile = profile_from_scan_artifacts(session, scan, target_url).profile if target_url else {}
    metadata = param.metadata_json or {}
    method = str(metadata.get("method") or "").upper()
    content_type = str(metadata.get("content_type") or "").lower()
    if not method:
        if location in {"json", "body"} or any(token in endpoint_path for token in ["signup", "register", "login", "auth", "token", "verify", "otp", "reset"]):
            method = "POST"
        elif location == "form":
            method = "POST"
        else:
            method = "GET"
    body_template = None
    query_template = {}
    if method in {"POST", "PUT", "PATCH"} or location in {"json", "body", "form"}:
        user = _generated_users(scan.id)[0]
        if any(token in endpoint_path for token in ["signup", "register"]):
            candidates = registration_payloads(profile, user)
            body_template = dict(candidates[0] if candidates else {"name": user["name"], "email": user["email"], "number": user["number"], "password": user["password"]})
        elif any(token in endpoint_path for token in ["login", "token"]):
            body_template = dict((login_payloads(profile, user["email"], user["password"]) or [{"email": user["email"], "password": user["password"]}])[0])
        else:
            body_template = dict(metadata.get("body_template") or {param.name: "__SAIF_PAYLOAD__"})
        body_template.setdefault(param.name, "")
        content_type = content_type or "application/json"
    else:
        query_template[param.name] = "__SAIF_PAYLOAD__"
    return {
        "endpoint": endpoint,
        "method": method,
        "parameter": param.name,
        "parameter_location": "json" if body_template is not None else "query",
        "content_type": content_type or None,
        "body_template": body_template,
        "query_template": query_template,
        "source": param.source,
        "metadata": metadata,
    }


def _execute_request_template(template: dict, payload: str | None = None) -> tuple[httpx.Response, dict]:
    method = str(template["method"]).upper()
    url = template["endpoint"]
    headers = {}
    params = dict(template.get("query_template") or {})
    body = None
    if template.get("body_template") is not None:
        body = dict(template["body_template"])
        if payload is not None:
            body[template["parameter"]] = payload
        headers["content-type"] = template.get("content_type") or "application/json"
    else:
        if payload is not None:
            params[template["parameter"]] = payload
    if method in {"POST", "PUT", "PATCH"}:
        response = httpx.request(method, url, json=body, headers=headers, follow_redirects=False, timeout=8)
    else:
        response = httpx.request(method, url, params=params or None, follow_redirects=False, timeout=8)
    request_summary = {
        "method": method,
        "url": url,
        "parameter": template["parameter"],
        "parameter_location": template["parameter_location"],
        "content_type": headers.get("content-type"),
        "body_fields": sorted((body or {}).keys()),
        "query_fields": sorted(params.keys()),
    }
    return response, request_summary


def _baseline_for_template(template: dict) -> dict:
    try:
        response, request_summary = _execute_request_template(template, None)
        return {
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "body_hash": _body_hash(response.text),
            "body_length": len(response.text),
            "interesting_markers": _interesting_markers(response.text),
            "request_template": request_summary,
            "_body": response.text,
        }
    except Exception as exc:
        return {"error": str(exc), "status_code": None, "content_type": "", "body_hash": "", "body_length": 0, "interesting_markers": [], "request_template": template, "_body": ""}


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


def _host_from_url(value: str) -> str | None:
    if not value:
        return None
    parsed = urlparse(value if "://" in value else f"//{value}")
    return parsed.hostname


def _ai_analyze_attempt(session: Session, scan: Scan, vuln_type: str, baseline: dict, attempt: dict) -> dict:
    endpoint = str(((attempt.get("request_template") or {}).get("url")) or ((attempt.get("request_template") or {}).get("endpoint")) or "")
    discovered_endpoints = {endpoint} if endpoint else set()
    target = endpoint or getattr(scan, "target_url", None) or ""
    result = ask_ai_for_payload_strategy(
        session,
        scan,
        current_phase="controlled_payload_execution",
        scope={"target": target, "allowed_hosts": [_host_from_url(target)] if target else []},
        evidence={
            "vulnerability_type": vuln_type,
            "baseline": {k: v for k, v in baseline.items() if not k.startswith("_")},
            "attempt": attempt,
            "evidence_ids": [str(attempt.get("evidence_id"))] if attempt.get("evidence_id") else [],
        },
        discovered_endpoints=discovered_endpoints,
        endpoint=endpoint or None,
        destructive_allowed=bool(scan.enable_destructive_tests or scan.destructive_test_policy == "lab_full_allowed"),
    )
    decision = result.get("decision") or {}
    if not result.get("approved"):
        return {
            "finding_candidate": False,
            "vulnerability_type": vuln_type,
            "confidence": "low",
            "reason": f"AI payload strategy rejected; deterministic analysis used: {result.get('reason')}",
            "reportable": False,
            "needs_manual_confirmation": False,
            "ai_validation": result,
        }
    return {
        "finding_candidate": bool(decision.get("finding_candidate")),
        "vulnerability_type": vuln_type,
        "confidence": str(decision.get("confidence") or "low"),
        "reason": str(decision.get("reason") or result.get("reason") or ""),
        "next_payload_strategy": str(decision.get("next_payload_strategy") or ""),
        "next_payload": str(decision.get("next_payload") or ""),
        "stop_condition": str(decision.get("stop_condition") or ""),
        "reportable": bool(decision.get("reportable")),
        "needs_manual_confirmation": bool(decision.get("needs_manual_confirmation")),
        "ai_validation": result,
    }


def _adaptive_payload_loop(session: Session, scan: Scan, vuln_type: str, category: str, target_url: str, parameter_filter=None) -> dict:
    settings = get_settings()
    started = time.monotonic()
    deadline = started + max(1, settings.max_runtime_seconds_for_adaptive_tool)
    request_count = 0
    ai_decision_count = 0
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
    endpoint_parameter_counts: dict[str, int] = {}
    endpoints_seen: set[str] = set()
    for param in params:
        template = _request_template_for_parameter(session, scan, param, target_url)
        endpoint_for_budget = (template or {}).get("endpoint") or param.endpoint or target_url
        endpoints_seen.add(endpoint_for_budget)
        if len(endpoints_seen) > settings.max_endpoints_per_family:
            status = "stopped_budget_exceeded"
            break
        endpoint_parameter_counts[endpoint_for_budget] = endpoint_parameter_counts.get(endpoint_for_budget, 0) + 1
        if endpoint_parameter_counts[endpoint_for_budget] > settings.max_parameters_per_endpoint:
            continue
        if not template:
            attempts.append({"endpoint": param.endpoint or target_url, "parameter": param.name, "status": RunStatus.INVALID_REQUEST_TEMPLATE.value, "reason": "no request template could be built"})
            status = RunStatus.INVALID_REQUEST_TEMPLATE.value if status == RunStatus.COMPLETED.value else status
            emit_progress(session, scan, f"invalid request template {vuln_type} {param.name}", phase=_phase_for_tool(f"{vuln_type}_adaptive"), agent=f"{vuln_type}_agent", tool=f"{vuln_type}_adaptive", event_type="invalid_request_template", context={"parameter": param.name, "endpoint": param.endpoint})
            continue
        endpoint = template["endpoint"]
        baseline = _baseline_for_template(template)
        request_count += 1
        for index, payload in enumerate(payloads[: settings.max_payloads_per_parameter], start=1):
            if time.monotonic() > deadline or request_count >= settings.max_total_requests_per_tool:
                status = "stopped_budget_exceeded"
                attempts.append({"endpoint": endpoint, "parameter": param.name, "status": status, "reason": "Adaptive tool exceeded configured runtime/request budget", "request_count": request_count})
                break
            try:
                response, request_summary = _execute_request_template(template, payload)
                request_count += 1
                reflection = payload in response.text
                error_marker = bool(_interesting_markers(response.text))
                attempt_status = RunStatus.INVALID_REQUEST_TEMPLATE.value if response.status_code == 405 else RunStatus.COMPLETED.value
                if attempt_status == RunStatus.INVALID_REQUEST_TEMPLATE.value:
                    status = RunStatus.INVALID_REQUEST_TEMPLATE.value if status == RunStatus.COMPLETED.value else status
                    emit_progress(
                        session,
                        scan,
                        f"invalid request template {vuln_type} {param.name} status=405",
                        phase=_phase_for_tool(f"{vuln_type}_adaptive"),
                        agent=f"{vuln_type}_agent",
                        tool=f"{vuln_type}_adaptive",
                        event_type="invalid_request_template",
                        context={"endpoint": endpoint, "parameter": param.name, "request_template": request_summary},
                    )
                attempt = {
                    "payload": payload,
                    "location": template["parameter_location"],
                    "endpoint": endpoint,
                    "method": template["method"],
                    "parameter": param.name,
                    "status_code": response.status_code,
                    "request_template": request_summary,
                    "body_hash": _body_hash(response.text),
                    "body_length_delta": len(response.text) - int(baseline.get("body_length") or 0),
                    "reflection": reflection,
                    "error_marker": error_marker,
                    "body_preview": response.text[:1000],
                }
                path = write_evidence(scan.id, f"adaptive_{vuln_type}_{param.name}_{index}", {"baseline": {k: v for k, v in baseline.items() if not k.startswith("_")}, "attempt": attempt})
                attempt["evidence_path"] = str(path)
                if attempt_status == RunStatus.INVALID_REQUEST_TEMPLATE.value:
                    decision = {
                        "finding_candidate": False,
                        "vulnerability_type": vuln_type,
                        "confidence": "none",
                        "reason": "HTTP 405 indicates the request template method/body is invalid for this endpoint; repair template before payload testing.",
                        "reportable": False,
                        "needs_manual_confirmation": False,
                    }
                else:
                    if ai_decision_count < settings.max_ai_payload_decisions_per_tool:
                        decision = _ai_analyze_attempt(session, scan, vuln_type, baseline, attempt)
                        ai_decision_count += 1
                    else:
                        decision = {"finding_candidate": False, "vulnerability_type": vuln_type, "confidence": "low", "reason": "AI payload decision budget exhausted; deterministic result recorded only.", "reportable": False, "needs_manual_confirmation": False}
                attempts.append(attempt)
                decisions.append({"attempt": index, "parameter": param.name, "ai_decision": decision})
                payload_attempt = PayloadAttempt(
                    scan_id=scan.id,
                    test_case_id=f"adaptive.{vuln_type}",
                    agent_name=f"{vuln_type}_agent",
                    vulnerability_type=vuln_type,
                    endpoint=endpoint,
                    method=template["method"],
                    parameter_location=template["parameter_location"],
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
                    status=RunStatus.INVALID_REQUEST_TEMPLATE.value if response.status_code == 405 else RunStatus.FINDING_CREATED.value if decision.get("reportable") else RunStatus.COMPLETED.value,
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
            if status == "stopped_budget_exceeded":
                break
        if status == "stopped_budget_exceeded":
            break
    reason = "Adaptive tool exceeded configured runtime/request budget" if status == "stopped_budget_exceeded" else None
    return {"status": status, "reason": reason, "payload_source": active_payload_source(category).__dict__, "attempts": attempts, "ai_decisions": decisions, "budget": {"request_count": request_count, "ai_decision_count": ai_decision_count, "deadline_seconds": settings.max_runtime_seconds_for_adaptive_tool, "max_total_requests": settings.max_total_requests_per_tool}}


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
        normalized = normalize_bearer_token(access_token)
        if not normalized.get("authorization_header"):
            tests.append({"session": auth_session.credential_label, "status": RunStatus.EXECUTION_ERROR.value, "reason": "bearer token could not be normalized", "token_metadata": normalized})
            continue
        token_meta = _decode_jwt_unverified(access_token)
        valid_headers = {"Authorization": normalized["authorization_header"]}
        tampered_headers = {"Authorization": normalize_bearer_token(_tamper_token(normalized["token_value"]))["authorization_header"]}
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


def _run_rate_limit_planner(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    endpoints = session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id).all()
    candidates = [
        endpoint.url
        for endpoint in endpoints
        if any(token in endpoint.url.lower() for token in ["login", "signup", "register", "otp", "verify", "forgot", "reset", "coupon", "auth"])
    ]
    policy = "lab_full_allowed" if (scan.destructive_test_policy == "lab_full_allowed" or scan.enable_destructive_tests) else "low_volume" if scan.allow_rate_limit_testing else "detect_only"
    output = {
        "candidate_endpoints": candidates[:100],
        "test_families": ["rate limiting", "OTP throttling", "password reset throttling", "coupon/validation throttling"],
        "rate_limit_policy": policy,
        "execution_policy": "planner_only",
        "required_artifact": "rate_limit_executor selected plus valid request template and approved test-owned account/session",
        "executor_required": True,
        "max_requests_per_endpoint": 0,
        "attempts": [],
    }
    if not candidates:
        status = RunStatus.MISSING_PREREQUISITE.value
        output["reason"] = "no rate-limit candidate endpoints discovered"
    elif "rate_limit_executor" in set((scan.scan_config or {}).get("selected_tools") or []):
        status = RunStatus.COMPLETED.value
        output["reason"] = "planner completed; executor must perform controlled traffic separately"
    else:
        status = RunStatus.PLANNED.value
        output["reason"] = "planner only; rate_limit_executor was not selected"
    return _record_tool(session, scan, "rate_limit_planner", "plan rate limit and OTP tests", status, output, "business_logic", "Rate limit and OTP planning", "prompt_rate_limit")


def _run_rate_limit_executor(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    output = {
        "target": target_url,
        "execution_policy": "controlled_executor_requires_explicit_template",
        "status": RunStatus.MISSING_PREREQUISITE.value,
        "request_count": 0,
        "attempts": [],
        "reason": "rate_limit_executor requires an approved request template, test-owned account/session, and explicit executor policy; no repeated requests were sent",
    }
    return _record_tool(
        session,
        scan,
        "rate_limit_executor",
        "controlled rate limit executor skipped: missing approved template/session",
        RunStatus.MISSING_PREREQUISITE.value,
        output,
        "business_logic",
        "Rate limit controlled executor",
        "prompt_rate_limit_executor",
    )


def _run_auth_authorization_planner(session: Session, scan: Scan, target_url: str, prompt: str, parsed: dict) -> dict:
    output = {"reason": "Authentication/authorization testing requires configured credentials and sessions."}
    return _record_tool(session, scan, "auth_authorization_planner", "plan auth/authorization checks", RunStatus.MISSING_CREDENTIALS.value, output, "auth", "Auth/authorization planning", "prompt_auth_authorization")
