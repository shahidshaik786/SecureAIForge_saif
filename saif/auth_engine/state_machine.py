"""Deterministic prerequisites for authenticated and authorization testing."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthRuntimeState:
    valid_sessions_count: int = 0
    authenticated_behavior_proven: bool = False
    workflow_request_inventory_count: int = 0
    authorization_testable_requests_count: int = 0
    request_templates_count: int = 0
    discovered_objects_count: int = 0


def authenticated_crawling_ready(state: AuthRuntimeState) -> bool:
    return state.valid_sessions_count >= 1 and state.authenticated_behavior_proven and state.workflow_request_inventory_count > 0


def authorization_ready(state: AuthRuntimeState) -> bool:
    return state.valid_sessions_count >= 2 and state.authenticated_behavior_proven and state.authorization_testable_requests_count > 0


def bola_bfla_ready(state: AuthRuntimeState) -> bool:
    return authorization_ready(state) and (state.discovered_objects_count > 0 or state.authorization_testable_requests_count > 0)


def input_validation_ready(state: AuthRuntimeState) -> bool:
    return state.request_templates_count > 0
