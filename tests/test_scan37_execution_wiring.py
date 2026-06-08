from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from saif.ai.gate import AIContext, log_ai_context
from saif.db.models import AiCallRun, Base, Project, Scan
from saif.services import debug_export, evidence as evidence_module, prompt_runner


class Scan37ExecutionWiringTests(unittest.TestCase):
    def test_missing_playwright_triggers_install_and_resumes_browser_capture(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with TemporaryDirectory() as tmp, Session(engine) as session:
            settings = SimpleNamespace(
                evidence_dir=Path(tmp),
                autonomous_tool_install=True,
                dynamic_tool_install=True,
                tool_install_require_authorized_mode=True,
                ollama_can_suggest_install_commands=True,
                tool_install_lab_mode=True,
                low_resource_mode=True,
            )
            original_settings = prompt_runner.get_settings
            original_evidence_settings = evidence_module.get_settings
            original_capture = prompt_runner.capture_authenticated_browser_traffic
            original_ask = prompt_runner.ask_ollama_for_install_plan
            original_run_install = prompt_runner.run_install_plan
            calls = {"capture": 0, "ask": 0, "install": 0}

            def fake_capture(scan_id, target_url, storage_state=None):
                calls["capture"] += 1
                if calls["capture"] == 1:
                    return {"status": "skipped_playwright_missing", "error": "No module named playwright", "observed_endpoints": []}
                return {"status": "completed_with_requests", "observed_endpoints": [{"url": f"{target_url}/api/orders/1", "method": "GET", "candidate_type": "api"}]}

            def fake_ask(*args, **kwargs):
                calls["ask"] += 1
                return {"status": "timeout", "install_plan": {}}

            def fake_install(**kwargs):
                calls["install"] += 1
                return {"status": "completed", "evidence_path": str(Path(tmp) / "scan-1" / "tool_install_events.jsonl")}

            try:
                prompt_runner.get_settings = lambda: settings
                evidence_module.get_settings = lambda: settings
                prompt_runner.capture_authenticated_browser_traffic = fake_capture
                prompt_runner.ask_ollama_for_install_plan = fake_ask
                prompt_runner.run_install_plan = fake_install
                project = Project(name="scan37-browser")
                session.add(project)
                session.flush()
                scan = Scan(project_id=project.id, profile="auto", authorized_testing_mode=True)
                session.add(scan)
                session.flush()

                result = prompt_runner._record_browser_authenticated_capture(session, scan, "http://example.test")
            finally:
                prompt_runner.get_settings = original_settings
                evidence_module.get_settings = original_evidence_settings
                prompt_runner.capture_authenticated_browser_traffic = original_capture
                prompt_runner.ask_ollama_for_install_plan = original_ask
                prompt_runner.run_install_plan = original_run_install

        self.assertEqual(result["status"], "completed_with_requests")
        self.assertEqual(calls, {"capture": 2, "ask": 1, "install": 1})

    def test_ai_timeout_attempts_create_trace_index_and_ai_call_run(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with TemporaryDirectory() as tmp, Session(engine) as session:
            settings = SimpleNamespace(
                evidence_dir=Path(tmp),
                ai_debug=True,
                ai_trace_every_call=True,
                store_agent_reactions=True,
                ollama_profile="low_gpu",
                ollama_timeout_seconds=90,
                ollama_max_retries=1,
                ollama_model="fake",
            )
            original_gate_settings = __import__("saif.ai.gate", fromlist=["get_settings"]).get_settings
            original_advisor_settings = __import__("saif.ai.advisor", fromlist=["get_settings"]).get_settings
            original_tracing_settings = __import__("saif.ai.tracing", fromlist=["get_settings"]).get_settings
            import saif.ai.gate as gate_module
            import saif.ai.advisor as advisor_module
            import saif.ai.tracing as tracing_module

            try:
                gate_module.get_settings = lambda: settings
                advisor_module.get_settings = lambda: settings
                tracing_module.get_settings = lambda: settings
                project = Project(name="scan37-ai")
                session.add(project)
                session.flush()
                scan = Scan(project_id=project.id, profile="auto", authorized_testing_mode=True)
                session.add(scan)
                session.flush()
                context = AIContext(
                    provider="Ollama",
                    model="fake",
                    base_url="http://ollama.test",
                    prompt="scan http://example.test",
                    scan_plan={"ai_planning_error": "timed out", "ai_available": False, "deterministic_mode": True},
                    ai_call_attempts=[{"response_status": "failed_ai_timeout", "duration_ms": 10, "request_summary": {"stage": "initial_planning"}}],
                )

                log_ai_context(session, scan, context, {}, "http://example.test", ["browser_authenticated_capture"])
                session.flush()
                index = json.loads((Path(tmp) / f"scan-{scan.id}" / "ai" / "ai_trace_index.json").read_text(encoding="utf-8"))
                reactions = (Path(tmp) / f"scan-{scan.id}" / "agent_reactions.jsonl").read_text(encoding="utf-8")
                ai_runs = session.query(AiCallRun).filter(AiCallRun.scan_id == scan.id).all()
            finally:
                gate_module.get_settings = original_gate_settings
                advisor_module.get_settings = original_advisor_settings
                tracing_module.get_settings = original_tracing_settings

        self.assertGreaterEqual(index["total_ai_calls"], 1)
        self.assertEqual(index["calls"][0]["status"], "timeout")
        self.assertIn("initial_planning", reactions)
        self.assertEqual(ai_runs[0].response_status, "timeout")

    def test_debug_export_generated_for_auth_blocked_scan(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with TemporaryDirectory() as tmp, Session(engine) as session:
            original_settings = debug_export.get_settings
            debug_export.get_settings = lambda: SimpleNamespace(evidence_dir=Path(tmp), ollama_profile="low_gpu")
            try:
                project = Project(name="scan37-debug")
                session.add(project)
                session.flush()
                scan = Scan(project_id=project.id, profile="auto", status="auth_blocked", scan_config={"auth_gate": {"status": "no_authorization_testable_requests"}})
                session.add(scan)
                session.flush()
                json_path, html_path = debug_export.generate_full_ai_debug_export(session, scan.id)
                self.assertTrue(json_path.exists())
                self.assertTrue(html_path.exists())
                payload = json.loads(json_path.read_text(encoding="utf-8"))
            finally:
                debug_export.get_settings = original_settings

        self.assertEqual(payload["status"], "auth_blocked")


if __name__ == "__main__":
    unittest.main()
