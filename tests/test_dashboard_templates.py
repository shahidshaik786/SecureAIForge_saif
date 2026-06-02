from __future__ import annotations

from types import SimpleNamespace
import unittest

try:
    from fastapi.testclient import TestClient
    from saif.dashboard import app as dashboard_app
    from saif.dashboard import services as dashboard_services
except ModuleNotFoundError as exc:
    TestClient = None
    dashboard_app = None
    dashboard_services = None
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None


@unittest.skipIf(IMPORT_ERROR is not None, f"dashboard dependencies unavailable: {IMPORT_ERROR}")
class DashboardTemplateTests(unittest.TestCase):
    def setUp(self) -> None:
        class FakeSessionScope:
            def __enter__(self):
                return object()

            def __exit__(self, *args):
                return False

        self.original_session_scope = dashboard_app.session_scope
        self.original_overview = dashboard_app.services.overview
        self.original_scans = dashboard_app.services.scans
        self.original_watch = dashboard_app.services.watch
        self.original_latest_scan_id = dashboard_app.services.latest_scan_id
        self.original_latest_active_scan_id = dashboard_app.services.latest_active_scan_id
        self.original_get_settings = dashboard_app.get_settings
        dashboard_app.session_scope = lambda: FakeSessionScope()
        dashboard_app.services.overview = lambda session: {
            "total_scans": 0,
            "running_scans": 0,
            "completed_scans": 0,
            "failed_scans": 0,
            "total_findings": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "info_findings": 0,
            "open_findings": 0,
            "closed_findings": 0,
            "manual_review_items": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "status_counts": {},
            "readiness_counts": {},
            "top_affected_targets": [],
        }
        dashboard_app.services.scans = lambda session: []
        dashboard_app.services.watch = lambda session, scan_id: {}
        dashboard_app.services.latest_scan_id = lambda session: None
        dashboard_app.services.latest_active_scan_id = lambda session: None
        dashboard_app.get_settings = lambda: SimpleNamespace(dashboard_password=None, dashboard_username=None, ollama_model="qwen2.5-coder:7b")

    def tearDown(self) -> None:
        dashboard_app.session_scope = self.original_session_scope
        dashboard_app.services.overview = self.original_overview
        dashboard_app.services.scans = self.original_scans
        dashboard_app.services.watch = self.original_watch
        dashboard_app.services.latest_scan_id = self.original_latest_scan_id
        dashboard_app.services.latest_active_scan_id = self.original_latest_active_scan_id
        dashboard_app.get_settings = self.original_get_settings

    def test_overview_returns_complete_default_shape(self) -> None:
        class EmptyResult:
            def all(self):
                return []

            def first(self):
                return None

        class FakeSession:
            def scalars(self, statement):
                return EmptyResult()

            def scalar(self, statement):
                return 0

        overview = dashboard_services.overview(FakeSession())
        for key in [
            "total_scans",
            "running_scans",
            "completed_scans",
            "failed_scans",
            "total_findings",
            "critical_findings",
            "high_findings",
            "medium_findings",
            "low_findings",
            "info_findings",
            "open_findings",
            "closed_findings",
            "manual_review_items",
            "severity_counts",
            "status_counts",
            "readiness_counts",
        ]:
            self.assertIn(key, overview)
        self.assertEqual(overview["severity_counts"], {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})

    def test_dashboard_template_loader_uses_directory_string(self) -> None:
        dashboard_app.validate_dashboard_assets()
        searchpath = dashboard_app.templates.env.loader.searchpath
        self.assertIn(str(dashboard_app.TEMPLATES_DIR), searchpath)
        self.assertIsNotNone(dashboard_app.templates.env.get_template("index.html"))

    def test_dashboard_home_renders_without_template_signature_error(self) -> None:
        response = TestClient(dashboard_app.create_app()).get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Security AI Framework", response.text)

    def test_dashboard_home_renders_when_overview_optional_keys_missing(self) -> None:
        dashboard_app.services.overview = lambda session: {}
        response = TestClient(dashboard_app.create_app()).get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Findings By Severity", response.text)

    def test_dashboard_command_pages_render(self) -> None:
        client = TestClient(dashboard_app.create_app())
        for path in ["/control", "/scans"]:
            response = client.get(path)
            self.assertEqual(response.status_code, 200, path)
        self.assertIn("Start New Scan", client.get("/control").text)
        self.assertIn("Live Scan Monitor", client.get("/live", follow_redirects=False).text)

    def test_control_page_separates_application_and_execution_profiles(self) -> None:
        response = TestClient(dashboard_app.create_app()).get("/control")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Application Profile", response.text)
        self.assertIn("Execution Profile", response.text)
        self.assertIn("Destructive Test Cases - Full Authorized Scan", response.text)
        self.assertNotIn("crAPI Full Test", response.text)

    def test_live_latest_prefers_latest_running_scan(self) -> None:
        dashboard_app.services.scans = lambda session: [
            {"scan_id": 15, "status": "stopped"},
            {"scan_id": 22, "status": "running"},
        ]
        dashboard_app.services.latest_active_scan_id = lambda session: 22
        dashboard_app.services.watch = lambda session, scan_id: {"status": "running", "scan_id": scan_id}
        response = TestClient(dashboard_app.create_app()).get("/live", follow_redirects=False)
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["location"], "/scans/22/live")

    def test_specific_live_route_uses_requested_scan_id(self) -> None:
        dashboard_app.services.watch = lambda session, scan_id: {"status": "running", "scan_id": scan_id}
        response = TestClient(dashboard_app.create_app()).get("/scans/22/live")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Live Scan Monitor #22", response.text)

    def test_static_assets_load(self) -> None:
        client = TestClient(dashboard_app.create_app())
        self.assertEqual(client.get("/static/dashboard.css").status_code, 200)
        self.assertEqual(client.get("/static/dashboard.js").status_code, 200)

    def test_overview_avoids_raw_json_blocks(self) -> None:
        response = TestClient(dashboard_app.create_app()).get("/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("<pre>{", response.text)
        self.assertIn("Top Affected Targets", response.text)


if __name__ == "__main__":
    unittest.main()
