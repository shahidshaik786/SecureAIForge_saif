from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from saif.config import get_settings
from saif.db.models import Agent, TestCase
from saif.registry.testcases import load_testcases


AGENT_DESCRIPTIONS = {
    "orchestrator": "Coordinates scan phases, test cases, agents, tools, evidence, and reports.",
    "orchestrator_agent": "Coordinates scan lifecycle, pause/resume/stop checks, and agent job sequencing.",
    "ai_planner_agent": "Builds executable AI plans and reviews evidence through Ollama.",
    "tool_manager_agent": "Checks, installs, and records external tool availability.",
    "recon": "Collects target baseline and fingerprinting context.",
    "recon_agent": "Runs baseline HTTP, technology, and port/service enumeration.",
    "web_enumeration": "Builds route, content, and crawl inventories.",
    "web_discovery_agent": "Runs crawl, link, static asset, and directory discovery jobs.",
    "api_enumeration": "Discovers and parses API specifications and endpoints.",
    "api_discovery_agent": "Finds OpenAPI/Swagger documents and API path hints.",
    "authentication": "Discovers auth flows and manages sessions.",
    "auth_agent": "Maps login, registration, session, and SSO/OIDC/SAML flows.",
    "token_agent": "Extracts and catalogs cookies, CSRF values, JWTs, and bearer tokens.",
    "authorization": "Coordinates role-aware replay, IDOR/BOLA, and BFLA testing.",
    "authorization_agent": "Builds authorization matrices and plans IDOR/BOLA/BFLA testing.",
    "input_validation": "Coordinates XSS, SQLi, SSRF, and traversal checks.",
    "input_validation_agent": "Plans input validation tests against discovered parameters and endpoints.",
    "business_logic_agent": "Plans workflow and business-logic testing based on discovered functionality.",
    "reporting": "Generates evidence-backed reports.",
    "reporting_agent": "Builds JSON/HTML reports from findings, evidence, jobs, and tool runs.",
}


def initialize_workspace() -> list[Path]:
    settings = get_settings()
    paths = [Path(".saif"), settings.evidence_dir, settings.report_dir]
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)
    return paths


def seed_foundation(session: Session, profile: str = "web-api") -> None:
    if profile == "auto":
        profile = "api-security"
    for name, description in AGENT_DESCRIPTIONS.items():
        existing = session.scalar(select(Agent).where(Agent.name == name))
        if not existing:
            session.add(Agent(name=name, description=description, enabled=True))

    registry = load_testcases(profile)
    for test_case in registry.test_cases:
        existing = session.scalar(
            select(TestCase).where(TestCase.case_id == test_case.id, TestCase.profile == registry.profile)
        )
        definition = test_case.model_dump()
        if existing:
            existing.phase = test_case.phase
            existing.agent = test_case.agent
            existing.name = test_case.name
            existing.category = test_case.category
            existing.prerequisites = test_case.prerequisites
            existing.tool = test_case.tool
            existing.enabled = test_case.enabled
            existing.definition = definition
        else:
            session.add(
                TestCase(
                    case_id=test_case.id,
                    profile=registry.profile,
                    phase=test_case.phase,
                    agent=test_case.agent,
                    name=test_case.name,
                    category=test_case.category,
                    prerequisites=test_case.prerequisites,
                    tool=test_case.tool,
                    enabled=test_case.enabled,
                    definition=definition,
                )
            )
