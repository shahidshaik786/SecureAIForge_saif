from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

import httpx
import yaml


PROFILE_DIR = Path("configs/profiles")
PROFILE_ORDER = [
    "crapi",
    "spa_react_api",
    "spring_boot_api",
    "graphql_api",
    "generic_rest_api",
    "generic_web",
    "network_device",
    "linux_server",
    "windows_server",
    "database_server",
    "internal_network",
    "generic_network",
]


@dataclass
class ProfileSelection:
    primary_profile: str
    secondary_profiles: list[str]
    lab_profile: str | None
    confidence: str
    profile: dict
    matched_rules: list[str]
    observed: dict


def load_profile(profile_id: str) -> dict:
    path = PROFILE_DIR / f"{profile_id}.yaml"
    if not path.exists() and "-" in profile_id:
        path = PROFILE_DIR / f"{profile_id.replace('-', '_')}.yaml"
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    data.setdefault("profile_id", data.get("name") or profile_id)
    return data


def load_profiles() -> dict[str, dict]:
    return {profile_id: load_profile(profile_id) for profile_id in PROFILE_ORDER if load_profile(profile_id)}


def detect_profile(target_url: str, html: str = "", headers: dict | None = None, discovered_routes: list[str] | None = None) -> ProfileSelection:
    headers = headers or {}
    discovered_routes = discovered_routes or []
    observed = _observed(target_url, html, headers, discovered_routes)
    scores: list[tuple[int, str, list[str]]] = []
    for profile_id, profile in load_profiles().items():
        score, matches = _score_profile(profile, observed)
        scores.append((score, profile_id, matches))
    scores.sort(reverse=True)
    selected_score, primary, matches = scores[0] if scores else (0, "generic_web", [])
    if selected_score <= 0:
        primary = "generic_rest_api" if observed["api_style"] != "html_web" else "generic_web"
        matches = ["generic fallback"]
    secondaries = [profile_id for score, profile_id, _ in scores[1:4] if score > 0 and profile_id != primary]
    lab_profile = "crapi" if primary == "crapi" or any(profile_id == "crapi" and score >= 3 for score, profile_id, _ in scores) else None
    confidence = "high" if selected_score >= 5 else "medium" if selected_score >= 2 else "low"
    return ProfileSelection(
        primary_profile=primary,
        secondary_profiles=secondaries,
        lab_profile=lab_profile,
        confidence=confidence,
        profile=load_profile(primary),
        matched_rules=matches,
        observed=observed,
    )


def profile_from_scan_artifacts(session, scan, target_url: str) -> ProfileSelection:
    from saif.db.models import DiscoveredEndpoint, PipelineArtifact

    artifacts = session.query(PipelineArtifact).filter(PipelineArtifact.scan_id == scan.id).all()
    html = ""
    headers = {}
    for artifact in artifacts:
        data = artifact.data or {}
        if artifact.name in {"http_client", "http_baseline"} or artifact.artifact_type in {"http", "recon"}:
            html = str(data.get("body_preview") or data.get("html") or html)
            headers = data.get("headers") or headers
    routes = [item.url for item in session.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.scan_id == scan.id).limit(500).all()]
    return detect_profile(target_url, html=html, headers=headers, discovered_routes=routes)


def auth_endpoint_candidates(profile: dict) -> list[str]:
    values = []
    for item in profile.get("auth_endpoint_candidates", []) or []:
        if isinstance(item, dict):
            values.extend(str(value) for value in item.values() if value)
        else:
            values.append(str(item))
    return list(dict.fromkeys(values))


def protected_endpoint_candidates(profile: dict) -> list[str]:
    return list(dict.fromkeys(str(item) for item in (profile.get("common_protected_endpoints") or []) if item))


def registration_payloads(profile: dict, user: dict | None = None) -> list[dict]:
    payloads = []
    for template in profile.get("registration_payload_templates") or []:
        if not isinstance(template, dict):
            continue
        payloads.append(_render_template(template, None, None, user or {}))
    return payloads


def login_payloads(profile: dict, username: str | None, password: str | None) -> list[dict]:
    payloads = []
    for template in profile.get("login_payload_templates") or []:
        if not isinstance(template, dict):
            continue
        payloads.append(_render_template(template, username, password))
    if not payloads and username and password:
        payloads.extend(
            [
                {"email": username, "password": password},
                {"username": username, "password": password},
                {"user": username, "password": password},
            ]
        )
    return payloads


def _render_template(template: dict, username: str | None, password: str | None, context: dict | None = None) -> dict:
    context = context or {}
    rendered = {}
    for key, value in template.items():
        text = str(value)
        values = {
            "username": username or str(context.get("username") or context.get("email") or ""),
            "email": username or str(context.get("email") or ""),
            "password": password or str(context.get("password") or ""),
            "name": str(context.get("name") or ""),
            "number": str(context.get("number") or ""),
            "phone": str(context.get("phone") or context.get("number") or ""),
            "tenant": str(context.get("tenant") or ""),
            "role": str(context.get("role") or ""),
        }
        for placeholder, replacement in values.items():
            text = text.replace(f"{{{{{placeholder}}}}}", replacement)
        rendered[key] = text
    return rendered


def _observed(target_url: str, html: str, headers: dict, routes: list[str]) -> dict:
    haystack = " ".join([html, " ".join(f"{k}: {v}" for k, v in headers.items()), " ".join(routes)]).lower()
    content_type = str(headers.get("content-type") or headers.get("Content-Type") or "").lower()
    server = str(headers.get("server") or headers.get("Server") or "").lower()
    return {
        "target_url": target_url,
        "haystack": haystack,
        "server": server,
        "content_type": content_type,
        "frontend_framework": "react" if any(token in haystack for token in ["react", "__react", "react-dom"]) else "unknown",
        "backend_framework": "spring_boot" if any(token in haystack for token in ["x-application-context", "spring", "whitelabel error page"]) else "unknown",
        "api_style": "graphql" if "graphql" in haystack else "rest" if any(token in haystack for token in ["/api", "application/json", "swagger", "openapi"]) else "html_web",
        "auth_style": "oauth" if "oauth" in haystack or "openid" in haystack else "saml" if "saml" in haystack else "form_or_token" if any(token in haystack for token in ["login", "signin", "token", "authorization"]) else "unknown",
        "token_style": "jwt" if "eyj" in haystack or "jwt" in haystack or "bearer" in haystack else "cookie" if "set-cookie" in haystack or "cookie" in haystack else "unknown",
        "route_patterns": sorted(set(re.findall(r"/[a-zA-Z0-9_./{}:-]*(?:api|auth|login|register|graphql|swagger|openapi)[a-zA-Z0-9_./{}:-]*", haystack)))[:100],
    }


def _score_profile(profile: dict, observed: dict) -> tuple[int, list[str]]:
    score = 0
    matches = []
    haystack = observed["haystack"]
    rules = profile.get("detection_rules") or {}
    for token in rules.get("contains", []) or []:
        if str(token).lower() in haystack:
            score += 2
            matches.append(f"contains:{token}")
    for token in rules.get("route_contains", []) or []:
        if str(token).lower() in haystack:
            score += 2
            matches.append(f"route:{token}")
    for key in ["frontend_framework", "backend_framework", "api_style", "auth_style", "token_style"]:
        expected = rules.get(key)
        if expected and observed.get(key) == expected:
            score += 2
            matches.append(f"{key}:{expected}")
    server_contains = rules.get("server_contains")
    if server_contains and str(server_contains).lower() in observed["server"]:
        score += 1
        matches.append(f"server:{server_contains}")
    return score, matches
