from __future__ import annotations

from types import SimpleNamespace
import unittest

from saif.dashboard import actions as dashboard_actions
from saif.dashboard.actions import ButtonState, finding_actions, scan_actions


class DashboardActionStateTests(unittest.TestCase):
    def test_button_state_shape(self) -> None:
        state = ButtonState(False, "reason", "Pause", "btn-warning", True).as_dict()
        self.assertEqual(state["enabled"], False)
        self.assertEqual(state["reason"], "reason")
        self.assertEqual(state["label"], "Pause")
        self.assertEqual(state["css_class"], "btn-warning")
        self.assertTrue(state["confirm_required"])

    def test_finding_retest_closed_disabled(self) -> None:
        actions = finding_actions(SimpleNamespace(status="closed"))
        self.assertFalse(actions["retest"]["enabled"])
        self.assertTrue(actions["reopen"]["enabled"])

    def test_finding_open_actions(self) -> None:
        actions = finding_actions(SimpleNamespace(status="finding_created"))
        self.assertTrue(actions["retest"]["enabled"])
        self.assertTrue(actions["mark-false-positive"]["enabled"])

    def test_stale_worker_scan_can_resume_and_continue(self) -> None:
        original_status_snapshot = dashboard_actions.status_snapshot
        original_helpers = (
            dashboard_actions._active_process,
            dashboard_actions._has_reportable_data,
            dashboard_actions._has_auth_context,
            dashboard_actions._has_account_context,
            dashboard_actions._authz_context,
            dashboard_actions._can_create_accounts,
        )
        try:
            dashboard_actions.status_snapshot = lambda session, scan_id: {"status": "worker_stale"}
            dashboard_actions._active_process = lambda session, scan_id: None
            dashboard_actions._has_reportable_data = lambda session, scan_id: False
            dashboard_actions._has_auth_context = lambda session, scan_id, scan: False
            dashboard_actions._has_account_context = lambda session, scan_id, scan: False
            dashboard_actions._authz_context = lambda session, scan_id, scan: False
            dashboard_actions._can_create_accounts = lambda session, scan: False
            states = scan_actions(object(), SimpleNamespace(id=17, status="created", enable_destructive_tests=False))
            self.assertTrue(states["resume"]["enabled"])
            self.assertTrue(states["continue_phase"]["enabled"])
            self.assertFalse(states["pause"]["enabled"])
        finally:
            dashboard_actions.status_snapshot = original_status_snapshot
            (
                dashboard_actions._active_process,
                dashboard_actions._has_reportable_data,
                dashboard_actions._has_auth_context,
                dashboard_actions._has_account_context,
                dashboard_actions._authz_context,
                dashboard_actions._can_create_accounts,
            ) = original_helpers

    def test_stale_worker_with_tracked_process_can_resume(self) -> None:
        original_status_snapshot = dashboard_actions.status_snapshot
        original_helpers = (
            dashboard_actions._active_process,
            dashboard_actions._has_reportable_data,
            dashboard_actions._has_auth_context,
            dashboard_actions._has_account_context,
            dashboard_actions._authz_context,
            dashboard_actions._can_create_accounts,
        )
        try:
            dashboard_actions.status_snapshot = lambda session, scan_id: {"status": "worker_stale"}
            dashboard_actions._active_process = lambda session, scan_id: SimpleNamespace(pid=12345, status="started")
            dashboard_actions._has_reportable_data = lambda session, scan_id: False
            dashboard_actions._has_auth_context = lambda session, scan_id, scan: False
            dashboard_actions._has_account_context = lambda session, scan_id, scan: False
            dashboard_actions._authz_context = lambda session, scan_id, scan: False
            dashboard_actions._can_create_accounts = lambda session, scan: False
            states = scan_actions(object(), SimpleNamespace(id=17, status="created", enable_destructive_tests=False))
            self.assertTrue(states["resume"]["enabled"])
            self.assertFalse(states["force_stop"]["enabled"])
        finally:
            dashboard_actions.status_snapshot = original_status_snapshot
            (
                dashboard_actions._active_process,
                dashboard_actions._has_reportable_data,
                dashboard_actions._has_auth_context,
                dashboard_actions._has_account_context,
                dashboard_actions._authz_context,
                dashboard_actions._can_create_accounts,
            ) = original_helpers


if __name__ == "__main__":
    unittest.main()
