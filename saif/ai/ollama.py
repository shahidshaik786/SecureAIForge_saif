from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from saif.config import get_settings


@dataclass
class OllamaAttempt:
    attempt: int
    model: str
    http_status: int | None
    response_status: str
    duration_ms: int
    error_message: str | None = None
    request_summary: dict | None = None
    response_summary: str | None = None


class OllamaHTTPError(RuntimeError):
    def __init__(self, status_code: int, body: str, attempts: list[dict] | None = None) -> None:
        self.status_code = status_code
        self.body = body
        self.attempts = attempts or []
        super().__init__(f"Ollama HTTP {status_code}: {body}")


class OllamaChatError(RuntimeError):
    status = "failed_ai_chat"

    def __init__(self, message: str, attempts: list[dict] | None = None) -> None:
        self.attempts = attempts or []
        super().__init__(message)


class OllamaTimeoutError(OllamaChatError):
    status = "failed_ai_timeout"


class OllamaServerError(OllamaChatError):
    status = "failed_ai_500"


class OllamaJSONError(OllamaChatError):
    status = "failed_ai_parse"


class OllamaClient:
    def __init__(self, model: str | None = None, base_url: str | None = None) -> None:
        settings = get_settings()
        self.base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self.url = f"{self.base_url}/api/chat"
        self.model = model or settings.ollama_model
        self.last_call_attempts: list[dict] = []
        self.last_raw_response: str = ""

    def chat_json(self, messages: list[dict], timeout: int | None = None, stage: str | None = None) -> dict:
        data = self.chat(messages, timeout=timeout, format_="json", stage=stage)
        content = data.get("message", {}).get("content", "{}")
        self.last_raw_response = str(content)
        try:
            parsed = json.loads(str(content))
        except json.JSONDecodeError as exc:
            raise OllamaJSONError(f"Ollama returned non-JSON content: {exc}", self.last_call_attempts) from exc
        if not isinstance(parsed, dict):
            raise OllamaJSONError("Ollama JSON response was not an object", self.last_call_attempts)
        return parsed

    def chat(self, messages: list[dict], timeout: int | None = None, format_: str | None = None, stage: str | None = None) -> dict:
        settings = get_settings()
        total_attempts = max(1, settings.ollama_max_retries + 1)
        timeout_seconds = timeout or settings.ollama_timeout_seconds
        self.last_call_attempts = []
        self.last_raw_response = ""
        last_error: Exception | None = None
        base_num_predict = max(64, settings.ollama_num_predict)

        for attempt in range(1, total_attempts + 1):
            attempt_started = time.perf_counter()
            retry_index = attempt - 1
            attempt_messages = _messages_for_attempt(messages, retry_index)
            num_predict = max(128, int(base_num_predict / (2**retry_index)))
            payload: dict[str, Any] = {
                "model": self.model,
                "messages": attempt_messages,
                "stream": False,
                "keep_alive": settings.ollama_keep_alive,
                "options": {
                    "num_ctx": settings.ollama_num_ctx,
                    "num_predict": num_predict,
                    "temperature": settings.ollama_temperature,
                },
            }
            if format_:
                payload["format"] = format_
            request_summary = {
                "stage": stage,
                "model": self.model,
                "message_count": len(attempt_messages),
                "prompt_chars_estimate": sum(len(str(item.get("content", ""))) for item in attempt_messages),
                "timeout_seconds": timeout_seconds,
                "num_predict": num_predict,
                "num_ctx": settings.ollama_num_ctx,
                "temperature": settings.ollama_temperature,
                "keep_alive": settings.ollama_keep_alive,
            }
            try:
                response = httpx.post(self.url, json=payload, timeout=_httpx_timeout(timeout_seconds))
                duration_ms = int((time.perf_counter() - attempt_started) * 1000)
                body_preview = response.text[:1000]
                if response.status_code >= 500:
                    self._record_attempt(attempt, response.status_code, "failed_ai_500", duration_ms, body_preview, request_summary, body_preview)
                    last_error = OllamaServerError(f"HTTP {response.status_code}: {body_preview}", self.last_call_attempts)
                    if attempt < total_attempts:
                        _sleep_backoff(settings.ollama_retry_backoff_seconds, retry_index)
                        continue
                    raise last_error
                if response.status_code >= 400:
                    self._record_attempt(attempt, response.status_code, "failed_ai_http", duration_ms, body_preview, request_summary, body_preview)
                    raise OllamaHTTPError(response.status_code, body_preview, self.last_call_attempts)
                try:
                    parsed = response.json()
                except json.JSONDecodeError as exc:
                    self._record_attempt(attempt, response.status_code, "failed_ai_parse", duration_ms, str(exc), request_summary, body_preview)
                    last_error = OllamaJSONError(f"Ollama returned invalid response JSON: {exc}", self.last_call_attempts)
                    if attempt < total_attempts:
                        _sleep_backoff(settings.ollama_retry_backoff_seconds, retry_index)
                        continue
                    raise last_error from exc
                self._record_attempt(attempt, response.status_code, "completed", duration_ms, None, request_summary, _response_summary(parsed))
                return parsed
            except httpx.TimeoutException as exc:
                duration_ms = int((time.perf_counter() - attempt_started) * 1000)
                self._record_attempt(attempt, None, "failed_ai_timeout", duration_ms, str(exc), request_summary, None)
                last_error = OllamaTimeoutError(str(exc), self.last_call_attempts)
            except (httpx.ConnectError, httpx.ReadError) as exc:
                duration_ms = int((time.perf_counter() - attempt_started) * 1000)
                self._record_attempt(attempt, None, "failed_ai_connection", duration_ms, str(exc), request_summary, None)
                last_error = OllamaChatError(str(exc), self.last_call_attempts)
            if attempt < total_attempts:
                _sleep_backoff(settings.ollama_retry_backoff_seconds, retry_index)

        if isinstance(last_error, OllamaChatError):
            raise last_error
        raise OllamaChatError("Ollama chat request failed", self.last_call_attempts)

    def _record_attempt(
        self,
        attempt: int,
        http_status: int | None,
        response_status: str,
        duration_ms: int,
        error_message: str | None,
        request_summary: dict | None,
        response_summary: str | None,
    ) -> None:
        self.last_call_attempts.append(
            OllamaAttempt(
                attempt=attempt,
                model=self.model,
                http_status=http_status,
                response_status=response_status,
                duration_ms=duration_ms,
                error_message=error_message,
                request_summary=request_summary,
                response_summary=response_summary,
            ).__dict__
        )

    def tags(self, timeout: int = 5) -> dict:
        response = httpx.get(f"{self.base_url}/api/tags", timeout=_httpx_timeout(timeout))
        if response.status_code >= 400:
            raise OllamaHTTPError(response.status_code, response.text[:1000])
        return response.json()

    def installed_models(self) -> list[str]:
        data = self.tags()
        models = data.get("models", [])
        names = [item.get("name") for item in models if item.get("name")]
        return sorted(names)

    def require_configured_base_url(self) -> None:
        if not self.base_url:
            raise ValueError("OLLAMA_BASE_URL is not configured")

    def require_configured_model(self) -> None:
        if not self.model:
            raise ValueError("OLLAMA_MODEL is not configured")

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.model)


def _httpx_timeout(timeout_seconds: int | float) -> httpx.Timeout:
    settings = get_settings()
    read_timeout = max(float(timeout_seconds), float(settings.ollama_read_timeout_seconds))
    return httpx.Timeout(
        timeout=float(timeout_seconds),
        connect=float(settings.ollama_connect_timeout_seconds),
        read=read_timeout,
        write=float(settings.ollama_connect_timeout_seconds),
        pool=float(settings.ollama_connect_timeout_seconds),
    )


def _messages_for_attempt(messages: list[dict], retry_index: int) -> list[dict]:
    if retry_index <= 0:
        return messages
    max_chars = 16000 if retry_index == 1 else 8000
    compacted = []
    for item in messages:
        value = dict(item)
        content = str(value.get("content", ""))
        if len(content) > max_chars:
            value["content"] = content[:max_chars] + "\n...[truncated for retry]"
        compacted.append(value)
    return compacted


def _sleep_backoff(base_seconds: int | float, retry_index: int) -> None:
    time.sleep(float(base_seconds) * (2**retry_index))


def _response_summary(parsed: dict) -> str:
    content = parsed.get("message", {}).get("content")
    if content is None:
        return json.dumps(parsed, sort_keys=True)[:1000]
    return str(content)[:1000]
