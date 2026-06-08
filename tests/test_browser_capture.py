from __future__ import annotations

import builtins
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from saif.browser_agent import browser_authenticated_capture as capture_module


class BrowserCaptureTests(unittest.TestCase):
    def test_browser_missing_evidence_includes_install_commands(self) -> None:
        original_import = builtins.__import__
        original_get_settings = capture_module.get_settings
        with TemporaryDirectory() as tmp:
            capture_module.get_settings = lambda: type("S", (), {"evidence_dir": Path(tmp)})()

            def fake_import(name, *args, **kwargs):
                if name.startswith("playwright"):
                    raise ModuleNotFoundError("No module named playwright")
                return original_import(name, *args, **kwargs)

            try:
                builtins.__import__ = fake_import
                result = capture_module.capture_authenticated_browser_traffic(9, "http://example.test")
            finally:
                builtins.__import__ = original_import
                capture_module.get_settings = original_get_settings

        self.assertEqual(result["status"], "skipped_playwright_missing")
        self.assertIn(".venv/bin/python -m playwright install chromium", result["install_commands"])
        self.assertIn("auth_coverage_impact", result)


if __name__ == "__main__":
    unittest.main()
