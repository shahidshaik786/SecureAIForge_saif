from __future__ import annotations

import unittest

from saif.agents import tool_manager_agent


class ToolManagerAgentTests(unittest.TestCase):
    def test_tool_manager_asks_guarded_ai_for_install_plan(self) -> None:
        calls = []
        original = tool_manager_agent.ask_ai_for_phase_decision

        def fake_ask(*args, **kwargs):
            calls.append(kwargs)
            return {
                "approved": True,
                "decision": {
                    "install_plan": {
                        "tool": "playwright",
                        "commands": [".venv/bin/python -m pip install playwright"],
                        "verify_commands": [".venv/bin/python -c \"import playwright\""],
                    }
                },
            }

        try:
            tool_manager_agent.ask_ai_for_phase_decision = fake_ask
            result = tool_manager_agent.ask_ollama_for_install_plan(
                object(),
                object(),
                tool="playwright",
                capability="browser_capture",
                phase="tool_need_advisor",
                scope={"target": "http://example.test"},
                evidence={"required_for": "browser_authenticated_capture"},
            )
        finally:
            tool_manager_agent.ask_ai_for_phase_decision = original

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["install_plan"]["tool"], "playwright")
        self.assertEqual(calls[0]["current_phase"], "tool_need_advisor")
        self.assertIn("recommend_open_source_tool_install_commands", calls[0]["allowed_actions"])

    def test_rejected_or_timeout_plan_allows_fallback(self) -> None:
        original = tool_manager_agent.ask_ai_for_phase_decision

        def fake_ask(*args, **kwargs):
            return {"approved": False, "decision": {}, "reason": "timeout"}

        try:
            tool_manager_agent.ask_ai_for_phase_decision = fake_ask
            result = tool_manager_agent.ask_ollama_for_install_plan(
                object(),
                object(),
                tool="playwright",
                capability="browser_capture",
                phase="tool_need_advisor",
                scope={},
                evidence={},
            )
        finally:
            tool_manager_agent.ask_ai_for_phase_decision = original

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["install_plan"], {})


if __name__ == "__main__":
    unittest.main()
