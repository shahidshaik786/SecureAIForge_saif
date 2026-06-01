from __future__ import annotations

from pathlib import Path
import os

import yaml


def load_credentials(path: Path | None = None) -> list[dict]:
    credential_path = path or Path(os.environ.get("SAIF_CREDENTIALS_PATH") or "configs/credentials.yaml")
    if not credential_path.exists():
        return []
    data = yaml.safe_load(credential_path.read_text(encoding="utf-8")) or {}
    credentials = data.get("credentials") or []
    return [item for item in credentials if isinstance(item, dict)]
