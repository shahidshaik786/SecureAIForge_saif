from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from saif.agents.install_agent import is_command_safe, run_install_plan
import saif.agents.install_agent as install_agent


class InstallAgentTests(unittest.TestCase):
    def test_blocks_obviously_destructive_command(self) -> None:
        ok, reason = is_command_safe("rm -rf /")
        self.assertFalse(ok)
        self.assertIn("blocked", reason or "")

    def test_retry_with_corrected_plan_succeeds(self) -> None:
        with TemporaryDirectory() as tmp:
            original_get_settings = install_agent.get_settings
            install_agent.get_settings = lambda: type(
                "S",
                (),
                {"evidence_dir": Path(tmp), "tool_install_max_retries": 1, "tool_timeout_seconds": 5},
            )()
            calls = []

            def runner(command: str, timeout: int):
                calls.append(command)
                return subprocess.CompletedProcess(command, 1 if command == "bad install" else 0, stdout="ok", stderr="failed")

            def correction(plan: dict, result: dict):
                return {"commands": ["good install"], "verify_commands": ["good --version"]}

            try:
                result = run_install_plan(
                    scan_id=7,
                    tool="demo-tool",
                    capability="demo",
                    required_for="test",
                    reason="unit test",
                    install_plan={"commands": ["bad install"], "verify_commands": ["bad --version"]},
                    command_runner=runner,
                    correction_provider=correction,
                    max_retries=1,
                )
            finally:
                install_agent.get_settings = original_get_settings

            self.assertEqual(result["status"], "completed")
            self.assertIn("good install", calls)
            events_path = Path(tmp) / "scan-7" / "tool_install_events.jsonl"
            self.assertTrue(events_path.exists())
            text = events_path.read_text(encoding="utf-8")
            self.assertIn("tool_install_summary", text)
            self.assertIn("installed_and_resumed", text)


if __name__ == "__main__":
    unittest.main()
