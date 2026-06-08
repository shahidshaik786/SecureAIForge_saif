from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass

from saif.config import get_settings


_AI_LOCK = threading.Lock()


@dataclass(frozen=True)
class OllamaRuntime:
    profile: str
    model: str
    per_attempt_timeout_seconds: int
    total_budget_seconds: int
    max_attempts: int
    num_ctx: int
    num_predict: int
    temperature: float
    parallel_ai_calls: int
    queue_ai_calls: bool


def runtime_for_stage(stage: str) -> OllamaRuntime:
    settings = get_settings()
    profile = str(settings.ollama_profile or "low_gpu").strip() or "low_gpu"
    stage_key = str(stage or "").split(":", 1)[0]
    if profile == "rtx_12gb":
        per_attempt = {
            "initial_planning": 300,
            "response_advisor": 240,
            "response_review": 240,
            "response_analysis": 240,
            "payload_strategy": 240,
            "evidence_review": 300,
            "finding_review": 240,
            "report_wording": 300,
            "phase_decision": 240,
        }.get(stage_key, 240)
        max_attempts = max(1, int(settings.ollama_max_retries or 2))
        num_predict = _predict_for_stage(stage_key, initial=768, advisor=512, report=1024)
        return OllamaRuntime(
            profile=profile,
            model=settings.ollama_model or "qwen2.5-coder:14b",
            per_attempt_timeout_seconds=per_attempt,
            total_budget_seconds=per_attempt * max_attempts + 20,
            max_attempts=max_attempts,
            num_ctx=8192,
            num_predict=num_predict,
            temperature=0.1,
            parallel_ai_calls=max(1, int(settings.max_parallel_ai_calls or 1)),
            queue_ai_calls=True,
        )
    per_attempt = {
        "initial_planning": 180,
        "response_advisor": 90,
        "response_review": 90,
        "response_analysis": 90,
        "payload_strategy": 120,
        "evidence_review": 120,
        "finding_review": 120,
        "report_wording": 120,
        "phase_decision": 90,
    }.get(stage_key, 90)
    max_attempts = max(1, int(settings.ollama_max_retries or 1))
    if settings.low_resource_mode:
        max_attempts = min(max_attempts, 1)
    return OllamaRuntime(
        profile="low_gpu",
        model=settings.ollama_model or "qwen2.5-coder:7b",
        per_attempt_timeout_seconds=per_attempt,
        total_budget_seconds=per_attempt * max_attempts + 10,
        max_attempts=max_attempts,
        num_ctx=1536,
        num_predict=_predict_for_stage(stage_key, initial=256, advisor=128, report=256),
        temperature=0.1,
        parallel_ai_calls=1,
        queue_ai_calls=True,
    )


@contextmanager
def queued_ai_call(enabled: bool = True):
    if not enabled:
        yield
        return
    _AI_LOCK.acquire()
    try:
        yield
    finally:
        _AI_LOCK.release()


def budget_remaining(started_perf: float, total_budget_seconds: int) -> float:
    return max(0.0, float(total_budget_seconds) - (time.perf_counter() - started_perf))


def _predict_for_stage(stage: str, *, initial: int, advisor: int, report: int) -> int:
    if stage == "initial_planning":
        return initial
    if stage in {"report_wording", "evidence_review"}:
        return report
    return advisor
