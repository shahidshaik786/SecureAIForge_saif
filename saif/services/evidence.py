import json
from datetime import datetime, timezone
from pathlib import Path

from saif.config import get_settings


def write_evidence(scan_id: int, test_case_id: str, payload: dict) -> Path:
    filename_case = test_case_id.replace("/", "_").replace(".", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = get_settings().evidence_dir / f"scan-{scan_id}"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{timestamp}-{filename_case}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
