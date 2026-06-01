from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from rich.console import Console
from sqlalchemy import select
from sqlalchemy.orm import Session

from saif.agents.base import AgentContext, BaseAgent
from saif.agents.factory import get_agent
from saif.db.models import (
    Evidence,
    Finding,
    Project,
    Request,
    Response,
    RunStatus,
    Scan,
    ScanStatus,
    Target,
    TestCase,
    TestRun,
    ToolRun,
)
from saif.registry.testcases import load_testcases
from saif.config import get_settings
from saif.services.evidence import write_evidence
from saif.services.reporting import generate_report
from saif.tools.http_client import HttpClientTool


@dataclass
class ScanRow:
    timestamp: str
    project: str
    scan_id: int
    phase: str
    agent: str
    test_case_id: str
    test_case_name: str
    tool: str
    target: str
    status: str
    evidence_path: str


class OrchestratorAgent(BaseAgent):
    name = "orchestrator"

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console(width=180)
        self.http_client = HttpClientTool()

    def run(self, session: Session, project_name: str, profile: str, ai_provider: str | None) -> list[ScanRow]:
        project = session.scalar(select(Project).where(Project.name == project_name))
        if not project:
            raise ValueError(f"Project {project_name!r} was not found")
        target = session.scalar(select(Target).where(Target.project_id == project.id))
        if not target:
            raise ValueError(f"Project {project_name!r} has no target")

        registry = load_testcases(profile)
        scan = Scan(
            project_id=project.id,
            profile=profile,
            ai_provider=ai_provider,
            authorized_testing_mode=get_settings().authorized_testing_mode,
            status=ScanStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc),
        )
        session.add(scan)
        session.flush()

        rows: list[ScanRow] = []
        try:
            for definition in registry.test_cases:
                db_case = session.scalar(
                    select(TestCase).where(TestCase.case_id == definition.id, TestCase.profile == profile)
                )
                agent = get_agent(definition.agent)
                context = AgentContext(project_name=project.name, target_url=target.url, scan_id=scan.id)
                plan = agent.plan(definition, context)

                test_run = TestRun(scan_id=scan.id, test_case_id=db_case.id if db_case else None, status=RunStatus.RUNNING.value)
                session.add(test_run)
                session.flush()

                if definition.tool == "http_client":
                    status, evidence_path = self._run_http_client(session, scan, test_run, definition, target.url, plan)
                elif definition.tool in {"json-report", "html-report"}:
                    report_format = "html" if definition.tool == "html-report" else "json"
                    report_path = generate_report(session, project.name, report_format)
                    status = RunStatus.COMPLETED.value
                    evidence_payload = {"event": "report_generated", "format": report_format, "report_path": str(report_path), "plan": plan}
                    evidence_path = write_evidence(scan.id, definition.id, evidence_payload)
                    session.add(
                        Evidence(
                            scan_id=scan.id,
                            test_run_id=test_run.id,
                            kind="report",
                            path=str(evidence_path),
                            summary=f"Generated {report_format.upper()} report at {report_path}",
                            metadata_json={"format": report_format, "report_path": str(report_path)},
                        )
                    )
                else:
                    status = RunStatus.MISSING_PREREQUISITE.value
                    evidence_payload = {
                        "event": "registered_not_executed",
                        "reason": "Stage 1 registers this capability until prerequisites are configured.",
                        "tool": definition.tool,
                        "plan": plan,
                    }
                    evidence_path = write_evidence(scan.id, definition.id, evidence_payload)
                    session.add(
                        Evidence(
                            scan_id=scan.id,
                            test_run_id=test_run.id,
                            kind="skeleton",
                            path=str(evidence_path),
                            summary=f"{definition.tool} is registered for future execution.",
                            metadata_json={"tool": definition.tool},
                        )
                    )

                test_run.status = status
                test_run.output = {"evidence_path": str(evidence_path)}
                rows.append(
                    ScanRow(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        project=project.name,
                        scan_id=scan.id,
                        phase=definition.phase,
                        agent=definition.agent,
                        test_case_id=definition.id,
                        test_case_name=definition.name,
                        tool=definition.tool,
                        target=target.url,
                        status=status,
                        evidence_path=str(evidence_path),
                    )
                )

            scan.status = ScanStatus.COMPLETED.value
            scan.completed_at = datetime.now(timezone.utc)
        except Exception:
            scan.status = ScanStatus.FAILED.value
            scan.completed_at = datetime.now(timezone.utc)
            raise
        return rows

    def print_rows(self, rows: list[ScanRow]) -> None:
        self.console.print_json(data=[asdict(row) for row in rows])

    def _run_http_client(
        self,
        session: Session,
        scan: Scan,
        test_run: TestRun,
        definition,
        target_url: str,
        plan: dict,
    ) -> tuple[str, str]:
        result = self.http_client.get(target_url)
        tool_run = ToolRun(
            scan_id=scan.id,
            test_run_id=test_run.id,
            tool_name="http_client",
            command=f"GET {target_url}",
            status=RunStatus.COMPLETED.value if result["ok"] else RunStatus.EXECUTION_ERROR.value,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            output={"ok": result["ok"], "error": result.get("error")},
        )
        session.add(tool_run)
        session.flush()

        request = Request(scan_id=scan.id, tool_run_id=tool_run.id, **result["request"])
        session.add(request)
        session.flush()
        session.add(Response(request_id=request.id, **result["response"]))

        evidence_payload = {"event": "http_client_result", "plan": plan, "result": result}
        evidence_path = write_evidence(scan.id, definition.id, evidence_payload)
        evidence = Evidence(
            scan_id=scan.id,
            test_run_id=test_run.id,
            kind="http",
            path=str(evidence_path),
            summary=f"HTTP GET completed with status {result['response']['status_code']}",
            metadata_json={"tool_run_id": tool_run.id, "ok": result["ok"]},
        )
        session.add(evidence)
        session.flush()
        if result["ok"]:
            session.add(
                Finding(
                    scan_id=scan.id,
                    test_run_id=test_run.id,
                    title="HTTP service reachable",
                    severity="info",
                    description="Baseline request completed and was stored as evidence.",
                    evidence_id=evidence.id,
                    status="informational",
                )
            )
        return tool_run.status, str(evidence_path)
