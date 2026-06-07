from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    category: str
    passive_hooks: tuple[str, ...]
    active_hooks: tuple[str, ...]
    prerequisites: tuple[str, ...]
    selected_category_required: str | None
    risk_level: str
    run_passive: Callable | None = None
    run_active: Callable | None = None


def default_modules() -> list[ModuleSpec]:
    names = [
        ("AuthWorkflowModule", "auth", "auth_testing", "medium"),
        ("SessionAnalyzerModule", "auth", "session_management", "medium"),
        ("AuthorizationReplayModule", "authorization", "authorization_matrix", "high"),
        ("BOLAModule", "authorization", "bola_idor", "high"),
        ("BFLAModule", "authorization", "bfla", "high"),
        ("MassAssignmentModule", "authorization", "mass_assignment", "high"),
        ("ParameterMinerModule", "analysis", None, "low"),
        ("ContentTypeConfusionModule", "input_validation", "content_type", "medium"),
        ("MethodOverrideModule", "input_validation", "method_override", "medium"),
        ("RateLimitModule", "business_logic", "rate_limiting", "medium"),
        ("ErrorDisclosureModule", "passive", None, "low"),
        ("SecurityHeadersModule", "passive", "security_headers", "low"),
        ("APIDocsModule", "discovery", "api_discovery", "low"),
        ("JSAnalyzerModule", "discovery", "api_discovery", "low"),
        ("CrawlerModule", "discovery", "recon", "low"),
        ("PayloadStrategyModule", "input_validation", "xss", "medium"),
        ("OllamaAdvisorModule", "ai", None, "low"),
    ]
    return [ModuleSpec(name, category, ("request_response",), ("request_template",), (), selected, risk) for name, category, selected, risk in names]
