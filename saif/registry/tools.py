from pathlib import Path
from shutil import which

import yaml
from pydantic import BaseModel


class ToolDefinition(BaseModel):
    name: str
    kind: str
    required: bool = False


class ToolCategory(BaseModel):
    name: str
    tools: list[ToolDefinition]


def load_tools(path: Path | None = None) -> list[ToolCategory]:
    registry_path = path or Path("configs/tools.yaml")
    data = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    return [ToolCategory(name=name, tools=[ToolDefinition(**item) for item in tools]) for name, tools in data["categories"].items()]


def check_tool(tool: ToolDefinition) -> str:
    if tool.kind in {"python", "planned"}:
        return "registered"
    return "available" if which(tool.name) else "missing"
