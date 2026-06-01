from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


SECLISTS_CANDIDATES = {
    "xss": [
        "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
        "/usr/share/seclists/Fuzzing/XSS/xss-polyglots.txt",
    ],
    "sqli": [
        "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt",
        "/usr/share/seclists/Fuzzing/Databases/SQLi-Auth-Bypass.txt",
    ],
    "ssrf": [
        "/usr/share/seclists/Fuzzing/SSRF/SSRF-Whitelist-bypass.txt",
    ],
    "lfi_path_traversal": [
        "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
        "/usr/share/seclists/Fuzzing/Path-Traversal/path-traversal.txt",
    ],
    "open_redirect": [
        "/usr/share/seclists/Fuzzing/Open-Redirect/Open-Redirect-payloads.txt",
    ],
}

FALLBACK_FILES = {
    "xss": "configs/payloads/xss_small.txt",
    "sqli": "configs/payloads/sqli_small.txt",
    "ssrf": "configs/payloads/ssrf_small.txt",
    "lfi_path_traversal": "configs/payloads/path_traversal_small.txt",
    "open_redirect": "configs/payloads/open_redirect_small.txt",
    "jwt": "configs/payloads/jwt_tests.yaml",
}


@dataclass(frozen=True)
class PayloadSource:
    category: str
    path: str | None
    source_type: str
    available: bool


def active_payload_source(category: str) -> PayloadSource:
    for candidate in SECLISTS_CANDIDATES.get(category, []):
        if Path(candidate).is_file():
            return PayloadSource(category=category, path=candidate, source_type="SecLists", available=True)
    fallback = FALLBACK_FILES.get(category)
    if fallback and Path(fallback).is_file():
        return PayloadSource(category=category, path=fallback, source_type="SAIF fallback", available=True)
    return PayloadSource(category=category, path=None, source_type="missing", available=False)


def payload_library_status() -> dict:
    categories = sorted(set(SECLISTS_CANDIDATES) | set(FALLBACK_FILES))
    status = {}
    for category in categories:
        seclists = next((path for path in SECLISTS_CANDIDATES.get(category, []) if Path(path).is_file()), None)
        fallback = FALLBACK_FILES.get(category)
        active = active_payload_source(category)
        status[category] = {
            "seclists": seclists,
            "seclists_available": bool(seclists),
            "fallback": fallback,
            "fallback_available": bool(fallback and Path(fallback).is_file()),
            "active_source": active.source_type,
            "active_path": active.path,
        }
    return status


def load_payloads(category: str, limit: int = 20) -> list[str]:
    source = active_payload_source(category)
    if not source.path:
        return []
    if source.path.endswith((".yaml", ".yml")):
        return []
    payloads = []
    with Path(source.path).open("r", encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            payloads.append(value)
            if len(payloads) >= limit:
                break
    return payloads
