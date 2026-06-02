from __future__ import annotations


INVALID_DISCOVERY_ONLY_MESSAGE = "Invalid scan configuration: discovery_only cannot be used with full/destructive/authenticated testing."


NON_DISCOVERY_FLAGS = [
    "full",
    "allow_authenticated_testing",
    "allow_authorization_testing",
    "allow_payload_testing",
    "allow_rate_limit_testing",
    "enable_destructive_tests",
]


def has_non_discovery_testing(config: dict) -> bool:
    return any(bool(config.get(flag)) for flag in NON_DISCOVERY_FLAGS) or str(config.get("destructive_test_policy") or "") == "lab_full_allowed"


def resolve_execution_profile(config: dict) -> str:
    raw_value = config.get("execution_profile")
    if raw_value:
        return str(raw_value)
    if str(config.get("destructive_test_policy") or "") == "lab_full_allowed" or bool(config.get("enable_destructive_tests")):
        return "destructive-full-scan"
    if has_non_discovery_testing(config):
        return "full-authorized-scan"
    return "discovery_only"


def normalize_scan_config(config: dict) -> dict:
    normalized = dict(config)
    normalized["execution_profile"] = resolve_execution_profile(normalized)
    if normalized["execution_profile"] == "discovery_only" and has_non_discovery_testing(normalized):
        raise ValueError(INVALID_DISCOVERY_ONLY_MESSAGE)
    if str(normalized.get("destructive_test_policy") or "") == "lab_full_allowed" and normalized["execution_profile"] != "destructive-full-scan":
        raise ValueError(INVALID_DISCOVERY_ONLY_MESSAGE)
    return normalized
