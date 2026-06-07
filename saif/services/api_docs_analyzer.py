from __future__ import annotations

import json
from urllib.parse import urljoin

import httpx

from saif.core.request_map import upsert_request_response
from saif.services.evidence import write_evidence


DOC_PATHS = [
    "/swagger",
    "/swagger-ui",
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/redoc",
    "/postman.json",
    "/postman_collection.json",
    "/graphql",
    "/graphql/schema",
    "/schema.graphql",
    "/wsdl",
    "/service.wsdl",
    "/asyncapi.json",
]


def discover_api_documentation(scan_id: int, target_url: str, *, timeout: int = 10) -> dict:
    found = []
    operations = []
    for path in DOC_PATHS:
        url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = httpx.get(url, timeout=timeout, follow_redirects=True)
        except Exception as exc:
            found.append({"url": url, "status": "error", "error": str(exc)})
            continue
        body = response.text
        found.append({"url": url, "status": response.status_code, "content_type": response.headers.get("content-type")})
        if response.status_code >= 400:
            continue
        parsed = _parse_json(body)
        if parsed:
            operations.extend(_openapi_operations(parsed, target_url))
        elif "swagger" in body.lower() or "openapi" in body.lower():
            found[-1]["documentation_ui"] = True
    for operation in operations:
        upsert_request_response(scan_id, operation["request_template"])
    inventory = {"scan_id": scan_id, "sources_checked": found, "operation_count": len(operations), "operations": operations}
    write_evidence(scan_id, "api_documentation_inventory", inventory)
    return inventory


def _openapi_operations(data: dict, target_url: str) -> list[dict]:
    operations = []
    paths = data.get("paths") or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                continue
            parameters = operation.get("parameters") or []
            request_body = operation.get("requestBody") or {}
            content_types = sorted((request_body.get("content") or {}).keys())
            tags = set(operation.get("tags") or [])
            if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                tags.add("state_changing")
            if any(token in path.lower() for token in ["{id}", "user", "account", "tenant", "admin"]):
                tags.add("object_id")
            request_template = {
                "source": "openapi",
                "method": method.upper(),
                "url": urljoin(target_url.rstrip("/") + "/", str(path).lstrip("/")),
                "content_type": content_types[0] if content_types else "",
                "body_shape": {"type": "schema", "content_types": content_types, "required": list((request_body.get("required") if isinstance(request_body.get("required"), list) else []) or [])},
                "response": {"status": None, "content_type": ""},
                "tags": sorted(tags | {"api", "documentation"}),
            }
            operations.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "parameters": parameters,
                    "request_body_schema": request_body,
                    "response_schema": operation.get("responses") or {},
                    "content_types": content_types,
                    "auth_requirements": operation.get("security") or data.get("security") or [],
                    "role_hints": [tag for tag in tags if "admin" in str(tag).lower() or "role" in str(tag).lower()],
                    "object_identifiers": [param for param in parameters if "id" in str(param.get("name", "")).lower()],
                    "state_changing": method.upper() in {"POST", "PUT", "PATCH", "DELETE"},
                    "request_template": request_template,
                    "security_relevance": "high" if request_template["tags"] else "medium",
                }
            )
    return operations


def _parse_json(text: str) -> dict | None:
    try:
        value = json.loads(text)
    except Exception:
        return None
    return value if isinstance(value, dict) and ("openapi" in value or "swagger" in value or "paths" in value) else None
