from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import date, datetime
from pathlib import Path
from typing import Any


def make_json_safe(obj: Any, max_depth: int = 8, max_string: int = 4000, max_list: int = 200) -> Any:
    return _safe(obj, max_depth=max_depth, max_string=max_string, max_list=max_list, seen=set(), path="$")


def remove_circular_refs(obj: Any) -> Any:
    return make_json_safe(obj)


def summarize_for_db_log(obj: Any) -> Any:
    return make_json_safe(obj, max_depth=6, max_string=1200, max_list=80)


def write_full_context_to_file(obj: Any, evidence_path: str | Path) -> Path:
    path = Path(evidence_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(make_json_safe(obj), indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def _safe(obj: Any, *, max_depth: int, max_string: int, max_list: int, seen: set[int], path: str) -> Any:
    if max_depth < 0:
        return {"truncated": True, "reason": "max_depth", "path": path}
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, str):
        return obj if len(obj) <= max_string else obj[:max_string] + "...[truncated]"
    if isinstance(obj, (datetime, date, Path)):
        return str(obj)
    obj_id = id(obj)
    if isinstance(obj, (Mapping, list, tuple, set, frozenset)):
        if obj_id in seen:
            return {"circular_ref": True, "path": path}
        seen.add(obj_id)
        try:
            if isinstance(obj, Mapping):
                result = {}
                for index, (key, value) in enumerate(obj.items()):
                    if index >= max_list:
                        result["..."] = {"truncated": True, "remaining": len(obj) - max_list}
                        break
                    safe_key = str(_safe(key, max_depth=max_depth - 1, max_string=160, max_list=max_list, seen=seen, path=f"{path}.<key>"))
                    result[safe_key] = _safe(value, max_depth=max_depth - 1, max_string=max_string, max_list=max_list, seen=seen, path=f"{path}.{safe_key}")
                return result
            values = list(obj)
            result = [
                _safe(value, max_depth=max_depth - 1, max_string=max_string, max_list=max_list, seen=seen, path=f"{path}[{index}]")
                for index, value in enumerate(values[:max_list])
            ]
            if len(values) > max_list:
                result.append({"truncated": True, "remaining": len(values) - max_list})
            return result
        finally:
            seen.discard(obj_id)
    if hasattr(obj, "isoformat"):
        try:
            return obj.isoformat()
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        return _safe(vars(obj), max_depth=max_depth - 1, max_string=max_string, max_list=max_list, seen=seen, path=path)
    return str(obj)[:max_string]
