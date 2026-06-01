from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = Field(
        default="postgresql+psycopg2://saif:saifpass@localhost:5432/saif_db",
        alias="DATABASE_URL",
    )
    evidence_dir: Path = Field(default=Path(".saif/evidence"), alias="SAIF_EVIDENCE_DIR")
    report_dir: Path = Field(default=Path(".saif/reports"), alias="SAIF_REPORT_DIR")
    log_dir: Path = Field(default=Path(".saif/logs"), alias="SAIF_LOG_DIR")
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="qwen2.5-coder:7b", alias="OLLAMA_MODEL")
    ollama_timeout_seconds: int = Field(default=240, alias="OLLAMA_TIMEOUT_SECONDS")
    ollama_connect_timeout_seconds: int = Field(default=10, alias="OLLAMA_CONNECT_TIMEOUT_SECONDS")
    ollama_read_timeout_seconds: int = Field(default=240, alias="OLLAMA_READ_TIMEOUT_SECONDS")
    ollama_max_retries: int = Field(default=2, alias="OLLAMA_MAX_RETRIES")
    ollama_retry_backoff_seconds: int = Field(default=5, alias="OLLAMA_RETRY_BACKOFF_SECONDS")
    ollama_num_ctx: int = Field(default=4096, alias="OLLAMA_NUM_CTX")
    ollama_num_predict: int = Field(default=768, alias="OLLAMA_NUM_PREDICT")
    ollama_temperature: float = Field(default=0.1, alias="OLLAMA_TEMPERATURE")
    ollama_keep_alive: str = Field(default="10m", alias="OLLAMA_KEEP_ALIVE")
    ollama_fallback_model: str | None = Field(default="qwen2.5-coder:7b", alias="OLLAMA_FALLBACK_MODEL")
    ollama_fast_model: str = Field(default="qwen2.5-coder:7b", alias="OLLAMA_FAST_MODEL")
    ollama_deep_model: str | None = Field(default=None, alias="OLLAMA_DEEP_MODEL")
    ai_max_evidence_chars: int = Field(default=12000, alias="AI_MAX_EVIDENCE_CHARS")
    ai_max_endpoints_in_prompt: int = Field(default=30, alias="AI_MAX_ENDPOINTS_IN_PROMPT")
    ai_max_findings_in_prompt: int = Field(default=20, alias="AI_MAX_FINDINGS_IN_PROMPT")
    ai_max_token_samples: int = Field(default=0, alias="AI_MAX_TOKEN_SAMPLES")
    max_parallel_ai_calls: int = Field(default=1, alias="SAIF_MAX_PARALLEL_AI_CALLS")
    demo_project_name: str = Field(default="saif-demo", alias="SAIF_PROJECT_NAME")
    authorized_testing_mode: bool = Field(default=True, alias="SAIF_AUTHORIZED_TESTING_MODE")
    max_parallel_agents: int = Field(default=3, alias="SAIF_MAX_PARALLEL_AGENTS")
    max_parallel_tools: int = Field(default=2, alias="SAIF_MAX_PARALLEL_TOOLS")
    max_http_requests_per_second: int = Field(default=5, alias="SAIF_MAX_HTTP_REQUESTS_PER_SECOND")
    tool_timeout_seconds: int = Field(default=300, alias="SAIF_TOOL_TIMEOUT_SECONDS")
    crawler_max_depth: int = Field(default=2, alias="SAIF_CRAWLER_MAX_DEPTH")
    crawler_max_urls: int = Field(default=200, alias="SAIF_CRAWLER_MAX_URLS")
    dir_discovery_max_words: int = Field(default=5000, alias="SAIF_DIR_DISCOVERY_MAX_WORDS")
    apt_upgrade: bool = Field(default=False, alias="SAIF_APT_UPGRADE")
    wordlist_web_common: Path | None = Field(default=None, alias="WORDLIST_WEB_COMMON")
    max_ai_payload_iterations: int = Field(default=5, alias="SAIF_MAX_AI_PAYLOAD_ITERATIONS")
    max_payloads_per_parameter: int = Field(default=20, alias="SAIF_MAX_PAYLOADS_PER_PARAMETER")
    max_test_time_per_endpoint_seconds: int = Field(default=120, alias="SAIF_MAX_TEST_TIME_PER_ENDPOINT_SECONDS")
    ssrf_callback_url: str | None = Field(default=None, alias="SAIF_SSRF_CALLBACK_URL")
    scan_heartbeat_seconds: int = Field(default=10, alias="SAIF_SCAN_HEARTBEAT_SECONDS")
    scan_stale_after_seconds: int = Field(default=120, alias="SAIF_SCAN_STALE_AFTER_SECONDS")
    dashboard_username: str | None = Field(default=None, alias="SAIF_DASHBOARD_USERNAME")
    dashboard_password: str | None = Field(default=None, alias="SAIF_DASHBOARD_PASSWORD")
    allow_secret_view: bool = Field(default=False, alias="SAIF_ALLOW_SECRET_VIEW")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
