from dataclasses import asdict, dataclass

from saif.config import get_settings


@dataclass(frozen=True)
class ResourceLimits:
    max_parallel_agents: int
    max_parallel_tools: int
    max_http_requests_per_second: int
    tool_timeout_seconds: int
    crawler_max_depth: int
    crawler_max_urls: int
    dir_discovery_max_words: int


def current_resource_limits() -> ResourceLimits:
    settings = get_settings()
    return ResourceLimits(
        max_parallel_agents=settings.max_parallel_agents,
        max_parallel_tools=settings.max_parallel_tools,
        max_http_requests_per_second=settings.max_http_requests_per_second,
        tool_timeout_seconds=settings.tool_timeout_seconds,
        crawler_max_depth=settings.crawler_max_depth,
        crawler_max_urls=settings.crawler_max_urls,
        dir_discovery_max_words=settings.dir_discovery_max_words,
    )


def resource_limits_payload() -> dict:
    return asdict(current_resource_limits())
