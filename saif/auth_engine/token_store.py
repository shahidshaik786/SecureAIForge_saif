"""Token normalization helpers used before any authenticated replay."""

from __future__ import annotations

import hashlib


def _mask_token(token: str | None) -> str | None:
    if not token:
        return None
    if len(token) <= 20:
        return token[:6] + "...<masked>"
    return f"{token[:10]}...<masked>...{token[-8:]}"


def normalize_bearer_token(raw_value: str | None) -> dict:
    """Return jwt-only token value plus metadata without leaking the token."""
    raw = str(raw_value or "").strip()
    header_prefix_stripped = False
    while raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
        header_prefix_stripped = True
    parts = raw.split(".") if raw else []
    jwt_shape = len(parts) == 3 and all(parts)
    token_hash = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest() if raw else None
    return {
        "token_value": raw or None,
        "token_type": "jwt" if jwt_shape else "bearer" if raw else None,
        "token_format": "jwt" if jwt_shape else "opaque" if raw else None,
        "token_length": len(raw),
        "token_hash": token_hash,
        "masked_token": _mask_token(raw),
        "jwt_shape_valid": jwt_shape,
        "jwt_part_count": len(parts) if raw else 0,
        "authorization_header": f"Bearer {raw}" if raw else None,
        "authorization_header_type": "bearer" if raw else None,
        "header_mode": "bearer_prefix_stripped" if header_prefix_stripped else "raw_token",
        "header_mode_used": "Authorization: Bearer <token>" if raw else None,
        "token_was_masked": "...<masked>" in raw,
    }
