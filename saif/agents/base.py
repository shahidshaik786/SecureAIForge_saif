from dataclasses import dataclass

from saif.registry.testcases import TestCaseDefinition


@dataclass(frozen=True)
class AgentContext:
    project_name: str
    target_url: str
    scan_id: int


class BaseAgent:
    name = "base"

    def plan(self, test_case: TestCaseDefinition, context: AgentContext) -> dict:
        return {
            "agent": self.name,
            "test_case_id": test_case.id,
            "target": context.target_url,
            "status": "planned",
        }
