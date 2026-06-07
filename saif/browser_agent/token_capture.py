from __future__ import annotations


def summarize_browser_tokens(storage_state: dict) -> dict:
    tokens = []
    for origin in (storage_state or {}).get("origins", []) or []:
        for item in origin.get("localStorage", []) or []:
            name = str(item.get("name") or "")
            if any(token in name.lower() for token in ["token", "auth", "session"]):
                tokens.append({"origin": origin.get("origin"), "name": name, "secret_ref": f"browser_storage:{name}", "value": "<masked>"})
    return {"token_count": len(tokens), "tokens": tokens}
