from __future__ import annotations

from types import SimpleNamespace
import unittest

try:
    from fastapi.testclient import TestClient
    from saif.dashboard import app as dashboard_app
except ModuleNotFoundError as exc:
    TestClient = None
    dashboard_app = None
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None


@unittest.skipIf(IMPORT_ERROR is not None, f"dashboard dependencies unavailable: {IMPORT_ERROR}")
class DashboardApiTests(unittest.TestCase):
    def setUp(self) -> None:
        class FakeSessionScope:
            def __enter__(self):
                return object()

            def __exit__(self, *args):
                return False

        self.original_session_scope = dashboard_app.session_scope
        self.original_get_settings = dashboard_app.get_settings
        self.original_scans = dashboard_app.services.scans
        self.original_scan_detail = dashboard_app.services.scan_detail
        self.original_table = dashboard_app.services.table
        self.original_scan_action = dashboard_app.services.scan_action
        self.original_popen = dashboard_app.subprocess.Popen
        self.original_create_dashboard_scan = dashboard_app._create_dashboard_scan
        self.original_start_background_command = dashboard_app._start_background_command

        dashboard_app.session_scope = lambda: FakeSessionScope()
        dashboard_app.get_settings = lambda: SimpleNamespace(
            dashboard_password=None,
            dashboard_username=None,
            ollama_model="qwen2.5-coder:7b",
            log_dir=__import__("pathlib").Path(".saif/logs"),
        )
        dashboard_app.services.scans = lambda session: [{"scan_id": 15, "status": "running"}]
        dashboard_app.services.scan_detail = lambda session, scan_id: {"summary": {"scan_id": scan_id}, "coverage": [], "production_readiness": {"status": "manual_review_required"}}
        dashboard_app.services.table = lambda session, scan_id, model: [{"id": 1, "scan_id": scan_id, "status": "completed"}]
        dashboard_app.services.scan_action = lambda session, scan_id, action, phase=None: {"ok": True, "scan_id": scan_id, "action": action, "status": f"{action}_requested"}
        dashboard_app._create_dashboard_scan = lambda payload: {"scan_id": 22, "project": "saif-dashboard-test", "target": payload["target"]}

        class FakeProcess:
            pid = 12345

        dashboard_app.subprocess.Popen = lambda *args, **kwargs: FakeProcess()
        self.client = TestClient(dashboard_app.create_app())

    def tearDown(self) -> None:
        dashboard_app.session_scope = self.original_session_scope
        dashboard_app.get_settings = self.original_get_settings
        dashboard_app.services.scans = self.original_scans
        dashboard_app.services.scan_detail = self.original_scan_detail
        dashboard_app.services.table = self.original_table
        dashboard_app.services.scan_action = self.original_scan_action
        dashboard_app.subprocess.Popen = self.original_popen
        dashboard_app._create_dashboard_scan = self.original_create_dashboard_scan
        dashboard_app._start_background_command = self.original_start_background_command

    def test_health_and_scans_are_plain_json(self) -> None:
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        scans = self.client.get("/api/scans")
        self.assertEqual(scans.status_code, 200)
        self.assertIsInstance(scans.json(), list)

    def test_scan_summary_routes_are_plain_json(self) -> None:
        for path in ["/api/scans/15", "/api/scans/15/summary", "/api/scans/15/production-readiness", "/api/scans/15/coverage"]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIsInstance(response.json(), (dict, list))

    def test_scan_resource_routes_are_plain_json_lists(self) -> None:
        for resource in ["events", "tool-runs", "agent-jobs", "findings", "evidence", "payload-attempts", "ai-calls", "processes", "auth-sessions"]:
            response = self.client.get(f"/api/scans/15/{resource}")
            self.assertEqual(response.status_code, 200, resource)
            self.assertIsInstance(response.json(), list)

    def test_post_actions_return_small_json(self) -> None:
        dashboard_app._start_background_command = lambda command, *, scan_id=None, log_path=None: {"ok": True, "scan_id": scan_id, "pid": 12345, "status": "started", "command": " ".join(command)}
        response = self.client.post("/api/scans/start", json={"target": "http://example.test", "profile": "auto", "mode": "black-box", "confirm_authorized": True})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["scan_id"], 22)
        self.assertEqual(response.json()["pid"], 12345)
        self.assertEqual(response.json()["live_url"], "/scans/22/live")
        self.assertNotIn("process", response.json())

        response = self.client.post("/api/scans/15/pause")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["action"], "pause")

        response = self.client.post("/api/scans/15/continue?phase=account_provisioning")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["pid"], 12345)
        self.assertNotIn("process", response.json())

        response = self.client.post("/api/scans/15/run-phase?phase=session_validation")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["phase"], "session_validation")

        response = self.client.post("/api/scans/15/stop-force")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["pid"], 12345)

        response = self.client.post("/api/scans/15/auth/validate")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["phase"], "session_validation")

    def test_scan_start_passes_existing_scan_id_to_worker(self) -> None:
        captured = {}

        def fake_start(command, *, scan_id=None, log_path=None):
            captured["command"] = command
            captured["scan_id"] = scan_id
            captured["log_path"] = log_path
            return {"ok": True, "scan_id": scan_id, "pid": 4321, "status": "started"}

        dashboard_app._start_background_command = fake_start
        client = TestClient(dashboard_app.create_app())
        response = client.post("/api/scans/start", json={"target": "http://example.test", "profile": "crapi", "mode": "gray-box", "confirm_authorized": True})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["scan_id"], 22)
        self.assertEqual(captured["scan_id"], 22)
        self.assertIn("run-existing", captured["command"])
        self.assertIn("22", captured["command"])

    def test_scan_start_preserves_destructive_full_scan_payload(self) -> None:
        captured = {}

        def fake_create(payload):
            captured.update(payload)
            return {"scan_id": 22, "project": "saif-dashboard-test", "target": payload["target"]}

        dashboard_app._create_dashboard_scan = fake_create
        dashboard_app._start_background_command = lambda command, *, scan_id=None, log_path=None: {"ok": True, "scan_id": scan_id, "pid": 4321, "status": "started"}
        client = TestClient(dashboard_app.create_app())
        response = client.post(
            "/api/scans/start",
            json={
                "target": "http://example.test",
                "profile": "auto",
                "engagement_mode": "gray-box",
                "auth_mode": "auto",
                "execution_profile": "destructive-full-scan",
                "destructive_method_policy": "lab_full_allowed",
                "destructive_test_policy": "lab_full_allowed",
                "full": True,
                "allow_account_generation": True,
                "allow_authenticated_testing": True,
                "allow_authorization_testing": True,
                "allow_payload_testing": True,
                "allow_rate_limit_testing": True,
                "allow_test_owned_object_creation": True,
                "enable_destructive_tests": True,
                "confirm_authorized": True,
                "confirm_destructive_testing": True,
            },
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(captured["profile"], "auto")
        self.assertEqual(captured["engagement_mode"], "gray-box")
        self.assertEqual(captured["auth_mode"], "auto")
        self.assertEqual(captured["execution_profile"], "destructive-full-scan")
        self.assertEqual(captured["destructive_method_policy"], "lab_full_allowed")
        self.assertEqual(captured["destructive_test_policy"], "lab_full_allowed")
        self.assertTrue(captured["full"])
        self.assertTrue(captured["allow_account_generation"])
        self.assertTrue(captured["allow_authenticated_testing"])
        self.assertTrue(captured["allow_authorization_testing"])
        self.assertTrue(captured["allow_payload_testing"])
        self.assertTrue(captured["allow_rate_limit_testing"])
        self.assertTrue(captured["allow_test_owned_object_creation"])
        self.assertTrue(captured["enable_destructive_tests"])

    def test_scan_start_requires_authorization_confirmation(self) -> None:
        response = self.client.post("/api/scans/start", json={"target": "http://example.test", "profile": "auto", "mode": "black-box"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Authorization confirmation", response.json()["error"])

    def test_worker_process_requires_scan_id(self) -> None:
        started = {"value": False}

        def fake_popen(*args, **kwargs):
            started["value"] = True
            return SimpleNamespace(pid=999)

        dashboard_app.subprocess.Popen = fake_popen
        with self.assertRaises(ValueError):
            dashboard_app._start_background_command(["python", "-m", "saif.cli", "scan", "run-existing"])
        self.assertFalse(started["value"])


if __name__ == "__main__":
    unittest.main()
