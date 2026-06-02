from __future__ import annotations

import unittest

from saif.config import Settings
from saif.services import dashboard as dashboard_service


class DashboardBindingSettingsTests(unittest.TestCase):
    def test_dashboard_defaults_bind_to_all_interfaces(self) -> None:
        settings = Settings(_env_file=None)

        self.assertEqual(settings.dashboard_host, "0.0.0.0")
        self.assertEqual(settings.dashboard_port, 8787)
        self.assertTrue(settings.dashboard_allow_remote)
        self.assertTrue(settings.dashboard_no_auth_explicitly_allowed)

    def test_stop_dashboard_removes_stale_pid_file(self) -> None:
        original_pid_file = dashboard_service.PID_FILE
        original_pid_running = dashboard_service._pid_running
        tmp_path = __import__("pathlib").Path(".saif/test-dashboard.pid")
        try:
            dashboard_service.PID_FILE = tmp_path
            dashboard_service._pid_running = lambda pid: False
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_text("12345", encoding="utf-8")

            result = dashboard_service.stop_dashboard()

            self.assertEqual(result["status"], "stale_pid_removed")
            self.assertFalse(tmp_path.exists())
        finally:
            dashboard_service.PID_FILE = original_pid_file
            dashboard_service._pid_running = original_pid_running
            if tmp_path.exists():
                tmp_path.unlink()

    def test_dashboard_start_reports_occupied_port(self) -> None:
        original_get_settings = dashboard_service.get_settings
        original_port_check = dashboard_service._port_is_occupied
        try:
            dashboard_service.get_settings = lambda: Settings(_env_file=None)
            dashboard_service._port_is_occupied = lambda port: True

            with self.assertRaisesRegex(RuntimeError, "port 8787 is already in use"):
                dashboard_service.run_dashboard()
        finally:
            dashboard_service.get_settings = original_get_settings
            dashboard_service._port_is_occupied = original_port_check


if __name__ == "__main__":
    unittest.main()
