import os
from dataclasses import dataclass
from urllib.parse import urlparse

from rich.console import Console
from sqlalchemy import select
from sqlalchemy.orm import Session

from saif.config import get_settings
from saif.db.models import Project, Target


@dataclass(frozen=True)
class ResolvedTarget:
    url: str
    source: str


def resolve_target(
    cli_target: str | None = None,
    prompt_target: str | None = None,
    interactive: bool = False,
) -> ResolvedTarget:
    target = cli_target
    source = "cli-arg"
    if not target:
        target = prompt_target
        source = "prompt"
    if not target:
        target = os.getenv("TARGET_URL")
        source = "env"
    if not target and interactive:
        try:
            target = input("Target URL (authorized staging target): ").strip()
            source = "interactive"
        except EOFError:
            target = None
    if not target:
        raise ValueError(
            "No target provided. Use --target http://host:port, include a target URL in the prompt, "
            "set TARGET_URL for this shell, or run interactively."
        )
    parsed = urlparse(target)
    is_ip = bool(__import__("re").match(r"^(?:\d{1,3}\.){3}\d{1,3}$", target))
    if not is_ip and (parsed.scheme not in {"http", "https"} or not parsed.netloc):
        raise ValueError(f"Target must be an HTTP(S) URL or single IP, got {target!r}")
    return ResolvedTarget(url=target.rstrip("/"), source=source)


def upsert_project_target(
    session: Session,
    project_name: str,
    target_url: str,
    console: Console | None = None,
) -> tuple[Project, Target]:
    project = session.scalar(select(Project).where(Project.name == project_name))
    if not project:
        project = Project(name=project_name)
        session.add(project)
        session.flush()

    target = session.scalar(select(Target).where(Target.project_id == project.id))
    if target:
        scope = dict(target.scope or {})
        scope.pop("safe_mode", None)
        scope["authorized_testing_mode"] = True
        scope.setdefault("type", "web-api")
        if target.url != target_url:
            if console:
                console.print(f"[yellow]updating target[/yellow] {target.url} -> {target_url}")
            target.url = target_url
            scope["updated"] = True
        target.scope = scope
    else:
        target = Target(project_id=project.id, url=target_url, scope={"type": "web-api", "authorized_testing_mode": True})
        session.add(target)
        session.flush()

    if console:
        console.print(f"Selected project: {project.name}")
        console.print(f"Selected target: {target.url}")
    return project, target
