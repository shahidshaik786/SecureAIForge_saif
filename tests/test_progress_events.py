from __future__ import annotations

from types import SimpleNamespace
import unittest

try:
    from saif.services import progress
except ModuleNotFoundError as exc:
    progress = None
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None


@unittest.skipIf(IMPORT_ERROR is not None, f"progress dependencies unavailable: {IMPORT_ERROR}")
class ProgressEventTests(unittest.TestCase):
    def test_emit_progress_commits_immediately_for_live_dashboard_visibility(self) -> None:
        class FakeSession:
            def __init__(self):
                self.added = []
                self.flush_called = False
                self.commit_called = False

            def add(self, item):
                self.added.append(item)

            def flush(self):
                self.flush_called = True

            def commit(self):
                self.commit_called = True

        original_write_runtime_log = progress._write_runtime_log
        session = FakeSession()
        scan = SimpleNamespace(id=123, last_activity_at=None, current_phase=None, current_agent=None, current_tool=None, progress_message=None)
        try:
            progress._write_runtime_log = lambda *args, **kwargs: None
            progress.emit_progress(session, scan, "phase started", phase="precheck", event_type="precheck_started")
        finally:
            progress._write_runtime_log = original_write_runtime_log
        self.assertTrue(session.flush_called)
        self.assertTrue(session.commit_called)
        self.assertEqual(scan.current_phase, "precheck")


if __name__ == "__main__":
    unittest.main()
