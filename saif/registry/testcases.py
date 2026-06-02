from pathlib import Path

import yaml
from pydantic import BaseModel


class TestCaseDefinition(BaseModel):
    id: str
    phase: str
    agent: str
    name: str | None = None
    title: str | None = None
    tool: str
    enabled: bool = True
    deterministic: bool = False
    description: str | None = None
    category: str | None = None
    prerequisites: list[str] | None = None
    required_artifacts: list[str] | None = None
    payload_category: str | None = None
    evidence_requirements: list[str] | None = None
    report_template: str | None = None


class TestCaseRegistry(BaseModel):
    profile: str
    phases: list[str]
    test_cases: list[TestCaseDefinition]


REGISTRY_DIR = Path("configs/testcases")
PROFILE_ALIASES = {
    "auto": "api-security",
    "api": "api-security",
    "api-security": "api-security",
    "web": "web-api",
    "web-api": "web-api",
    "custom": "web-api",
    "custom-application": "web-api",
    "generic-web": "web-api",
    "generic-web-api": "web-api",
    "generic-rest": "api-security",
    "generic-rest-api": "api-security",
    "graphql": "api-security",
    "crapi": "crapi",
    "juice-shop": "web-api",
    "owasp-juice-shop": "web-api",
    "dvwa": "web-api",
    "generic-network": "web-api",
    "network-device": "web-api",
}
PROFILE_FILES = {
    "web-api": "web_api.yaml",
    "api-security": "api_security.yaml",
    "crapi": "crapi.yaml",
}


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Test case registry not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for item in data.get("test_cases", []) or []:
        if not item.get("name") and item.get("title"):
            item["name"] = item["title"]
    return data


def _merge_registry(profile: str, data: dict) -> dict:
    parent_profile = data.get("extends")
    if not parent_profile:
        data["profile"] = profile
        return data
    parent = load_testcases(str(parent_profile)).model_dump()
    merged_cases = {item["id"]: item for item in parent.get("test_cases", [])}
    for item in data.get("test_cases", []) or []:
        merged_cases[item["id"]] = item
    phases = list(dict.fromkeys((parent.get("phases") or []) + (data.get("phases") or [])))
    return {"profile": profile, "phases": phases, "test_cases": list(merged_cases.values())}


def load_testcases(profile: str = "web-api", path: Path | None = None) -> TestCaseRegistry:
    requested = (profile or "web-api").strip()
    canonical = PROFILE_ALIASES.get(requested, requested)
    if path:
        data = _load_yaml(path)
        canonical = requested if requested != "auto" else data.get("profile", canonical)
    else:
        registry_path = REGISTRY_DIR / PROFILE_FILES.get(canonical, f"{canonical.replace('-', '_')}.yaml")
        data = _load_yaml(registry_path)
    data = _merge_registry(canonical, data)
    registry = TestCaseRegistry(**data)
    if registry.profile != canonical:
        raise ValueError(f"Registry profile {registry.profile!r} does not match requested {canonical!r}")
    return registry
