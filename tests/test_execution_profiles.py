from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from saif.ai.gate import AIPlanNotApprovedError
from saif.cli import _advisory_ai_context, _expanded_workflow_phases, _has_deterministic_workflow
from saif.db.models import Base, Project, RunStatus, Scan, TestCase
from saif.services.prompt_runner import (
    _apply_selected_category_allowlist,
    _build_authenticated_behavior_proof,
    _dependency_block_for_tool,
    _deterministic_tools_for_execution_profile,
    _auth_failed_stop_reason,
    _request_template_for_parameter,
    _is_public_validation_endpoint,
    _run_rate_limit_executor,
    _session_validation_candidates,
    application_profile_for_existing_scan,
    normalize_bearer_token,
    tools_for_execution_profile,
)


class ExecutionProfileTests(unittest.TestCase):
    def test_destructive_full_scan_uses_deterministic_workflow_when_ai_plan_invalid(self) -> None:
        scan_config = {"execution_profile": "destructive-full-scan"}
        phases = _expanded_workflow_phases(scan_config)
        self.assertTrue(_has_deterministic_workflow(scan_config, phases))

        ai_context = _advisory_ai_context(
            prompt="scan http://crapi.test",
            target="http://crapi.test",
            selected_tools=[],
            execution_profile="destructive-full-scan",
            workflow_phases=phases,
            exc=AIPlanNotApprovedError(reason="AI returned mode=default-enumeration and test_cases=[]", raw_plan={"mode": "default-enumeration", "test_cases": []}),
        )

        self.assertEqual(ai_context.scan_plan["ai_planning_status"], "warning")
        self.assertFalse(ai_context.scan_plan["ai_available"])
        self.assertTrue(ai_context.scan_plan["deterministic_mode"])
        self.assertEqual(ai_context.scan_plan["mode"], "destructive-full-scan")
        self.assertEqual(phases[:4], ["enumeration", "endpoint_inventory", "request_templates", "auth_endpoint_classification"])
        self.assertEqual(phases[4:8], ["account_provisioning", "login_session_user1", "login_session_user2", "session_validation"])
        self.assertIn("Ollama did not return valid executable test plan; deterministic workflow was used", ai_context.scan_plan["ai_planning_warning"])

    def test_destructive_full_scan_tool_order_starts_with_auth_workflow(self) -> None:
        tools = _deterministic_tools_for_execution_profile(
            "destructive-full-scan",
            ["auth_session_mapping", "authorization_matrix", "account_provisioning", "session_validation", "login_session", "api_method_probe", "root_link_inventory"],
        )

        self.assertEqual(tools[:4], ["root_link_inventory", "api_method_probe", "auth_session_mapping", "account_provisioning"])

    def test_destructive_full_scan_selects_auth_authz_and_payload_tools(self) -> None:
        tools = tools_for_execution_profile(
            {
                "execution_profile": "destructive-full-scan",
                "full": True,
                "select_all_applicable": True,
                "allow_account_generation": True,
                "allow_authenticated_testing": True,
                "allow_authorization_testing": True,
                "allow_payload_testing": True,
                "allow_rate_limit_testing": True,
                "enable_destructive_tests": True,
                "destructive_test_policy": "lab_full_allowed",
            }
        )

        for required in [
            "auth_session_mapping",
            "account_provisioning",
            "login_session",
            "authenticated_crawling",
            "authorization_matrix",
            "idor_bola_bfla_planner",
            "input_validation_planner",
            "xss_adaptive",
            "sqli_adaptive",
            "ssrf_adaptive",
            "jwt_adaptive",
            "business_logic_planner",
            "rate_limit_planner",
        ]:
            self.assertIn(required, tools)

    def test_application_profile_is_not_replaced_by_execution_mode(self) -> None:
        scan = SimpleNamespace(profile="custom", scan_config={"application_profile": "crapi", "execution_profile": "destructive-full-scan"})
        self.assertEqual(application_profile_for_existing_scan(scan), "crapi")

    def test_auth_authorization_debug_selects_only_auth_tools(self) -> None:
        tools = tools_for_execution_profile(
            {
                "execution_profile": "auth-authorization-debug",
                "allow_account_generation": True,
                "allow_authenticated_testing": True,
                "allow_authorization_testing": True,
                "allow_payload_testing": False,
                "allow_rate_limit_testing": False,
            }
        )

        for required in [
            "root_link_inventory",
            "robots_txt",
            "sitemap_xml",
            "static_asset_inventory",
            "openapi_discovery",
            "api_path_hints",
            "api_profile_probe",
            "api_method_probe",
            "crawler",
        ]:
            self.assertIn(required, tools)
        for required in [
            "auth_session_mapping",
            "account_provisioning",
            "login_session",
            "session_validation",
            "authenticated_crawling",
            "authenticated_resource_discovery",
            "resource_ownership_map",
            "authorization_matrix",
            "idor_bola_bfla_planner",
            "mass_assignment_testing",
            "cross_account_access_testing",
        ]:
            self.assertIn(required, tools)
        for excluded in ["xss_adaptive", "sqli_adaptive", "ssrf_adaptive", "rate_limit_planner", "nmap_top_ports", "ffuf_api_paths", "gobuster_api_paths", "katana"]:
            self.assertNotIn(excluded, tools)

    def test_bearer_token_normalization_strips_prefix_once(self) -> None:
        token = "aaa.bbb.ccc"
        normalized = normalize_bearer_token(f"Bearer {token}")
        self.assertEqual(normalized["token_value"], token)
        self.assertEqual(normalized["authorization_header"], f"Bearer {token}")
        self.assertTrue(normalized["jwt_shape_valid"])

    def test_session_validation_candidates_exclude_auth_workflow_endpoints(self) -> None:
        class Query:
            def filter(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return [
                    SimpleNamespace(url="http://example.test/identity/api/auth/login"),
                    SimpleNamespace(url="http://example.test/identity/api/auth/signup"),
                    SimpleNamespace(url="http://example.test/identity/api/auth/v2/check-otp"),
                    SimpleNamespace(url="http://example.test/identity/api/v2/user"),
                ]

        class FakeSession:
            def query(self, model):
                return Query()

        scan = SimpleNamespace(id=1, profile="crapi")
        candidates = _session_validation_candidates(FakeSession(), scan, "http://example.test", {"name": "crapi"})
        self.assertIn("/identity/api/v2/user", candidates)
        self.assertNotIn("/identity/api/auth/login", candidates)
        self.assertNotIn("/identity/api/auth/signup", candidates)
        self.assertNotIn("/identity/api/auth/v2/check-otp", candidates)

    def test_public_health_endpoint_cannot_validate_session(self) -> None:
        self.assertTrue(_is_public_validation_endpoint("/health"))
        self.assertTrue(_is_public_validation_endpoint("/robots.txt"))
        self.assertTrue(_is_public_validation_endpoint("/identity/api/auth/login"))
        self.assertFalse(_is_public_validation_endpoint("/identity/api/v2/user"))

    def test_selected_categories_are_hard_tool_allowlist(self) -> None:
        tools = ["http_client", "nmap_top_ports", "xss_adaptive", "business_logic_testing", "authorization_matrix"]
        selected, audit = _apply_selected_category_allowlist(tools, ["authorization_matrix"])

        self.assertEqual(selected, ["authorization_matrix"])
        skipped = {item["tool"] for item in audit["skipped_unselected_tools"]}
        self.assertIn("nmap_top_ports", skipped)
        self.assertIn("xss_adaptive", skipped)

    def test_api_discovery_basic_excludes_aggressive_tools(self) -> None:
        tools = ["openapi_discovery", "static_asset_inventory", "api_path_hints", "api_profile_probe", "crawler", "katana", "ffuf_dir", "gobuster_dir"]
        selected, audit = _apply_selected_category_allowlist(tools, ["api_discovery"])

        self.assertEqual(selected, ["openapi_discovery", "static_asset_inventory", "api_path_hints", "api_profile_probe"])
        skipped = {item["tool"] for item in audit["skipped_unselected_tools"]}
        self.assertIn("crawler", skipped)
        self.assertIn("katana", skipped)

    def test_session_validation_candidates_skip_rejected_endpoint_statuses(self) -> None:
        class Query:
            def filter(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def all(self):
                return [
                    SimpleNamespace(url="http://example.test/identity/api/v2/user", source="crawler", endpoint_type="api", metadata_json={"candidate_status": "rejected_404"}),
                    SimpleNamespace(url="http://example.test/identity/api/v2/vehicles", source="crawler", endpoint_type="api", metadata_json={}),
                ]

        class FakeSession:
            def query(self, model):
                return Query()

        candidates = _session_validation_candidates(FakeSession(), SimpleNamespace(id=1), "http://example.test", {})
        self.assertNotIn("/identity/api/v2/user", candidates)
        self.assertIn("/identity/api/v2/vehicles", candidates)

    def test_rate_limit_executor_never_sends_requests_without_prerequisites(self) -> None:
        class FakeSession:
            def __init__(self):
                self.added = []

            def query(self, model):
                class Query:
                    def filter(self, *args, **kwargs):
                        return self

                    def order_by(self, *args, **kwargs):
                        return self

                    def one_or_none(self):
                        return None

                    def first(self):
                        return None

                return Query()

            def add(self, item):
                self.added.append(item)

            def flush(self):
                return None

            def commit(self):
                return None

        scan = SimpleNamespace(id=1, current_phase="rate_limiting", current_agent="business_logic_agent", current_tool="rate_limit_executor")
        with patch("saif.services.prompt_runner.httpx.get", side_effect=AssertionError("executor must not send GET")), patch("saif.services.prompt_runner.httpx.post", side_effect=AssertionError("executor must not send POST")):
            result = _run_rate_limit_executor(FakeSession(), scan, "http://example.test", "", {})

        self.assertEqual(result["status"], RunStatus.MISSING_PREREQUISITE.value)
        self.assertIn("no repeated requests were sent", result["reason"])

    def test_test_case_uniqueness_is_scoped_to_scan(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            project = Project(name="tc-scope")
            session.add(project)
            session.flush()
            scans = [Scan(project_id=project.id, profile="auto"), Scan(project_id=project.id, profile="auto")]
            session.add_all(scans)
            session.flush()
            session.add_all(
                [
                    TestCase(scan_id=scans[0].id, case_id="same.case", profile="auto", phase="recon", agent="a", name="case", tool="t"),
                    TestCase(scan_id=scans[1].id, case_id="same.case", profile="auto", phase="recon", agent="a", name="case", tool="t"),
                ]
            )
            session.commit()

            self.assertEqual(session.query(TestCase).filter(TestCase.case_id == "same.case").count(), 2)

    def test_authenticated_behavior_proof_from_manual_request(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            project = Project(name="behavior-proof")
            session.add(project)
            session.flush()
            scan = Scan(
                project_id=project.id,
                profile="auto",
                scan_config={
                    "known_authenticated_requests": [
                        "GET /x9/action/submit?id=123 HTTP/1.1\nAuthorization: Bearer token\n\n"
                    ]
                },
            )
            session.add(scan)
            session.flush()

            proof = _build_authenticated_behavior_proof(session, scan, "http://example.test")

            self.assertTrue(proof["authenticated_behavior_proven"])
            self.assertIn("session_material", proof["proof_type"])
            self.assertGreaterEqual(len(proof["authorization_testable_requests"]), 1)

    def test_authorization_block_uses_behavior_gate_not_protected_endpoint_candidates(self) -> None:
        class Query:
            def __init__(self, count_value=0):
                self.count_value = count_value

            def filter(self, *args, **kwargs):
                return self

            def order_by(self, *args, **kwargs):
                return self

            def count(self):
                return self.count_value

            def all(self):
                return []

            def first(self):
                return None

        class FakeSession:
            def query(self, model):
                return Query()

        scan = SimpleNamespace(id=1, scan_config={"auth_gate": {"status": "authenticated_behavior_not_proven", "reason": "no behavior diff"}}, project_id=1)
        block = _dependency_block_for_tool(FakeSession(), scan, "authorization_matrix")

        self.assertEqual(block["missing_artifact"], "authenticated_behavior_not_proven")
        self.assertNotEqual(block["missing_artifact"], "protected_endpoint_candidates")

    def test_ready_for_authorization_does_not_become_auth_blocked(self) -> None:
        scan = SimpleNamespace(scan_config={"execution_profile": "destructive-full-scan", "auth_gate": {"status": "ready_for_authorization", "login_sessions_count": 2, "authorization_candidate_count": 1}})
        result = {"output": {"valid_sessions_count": 0, "auth_gate_status": "ready_for_authorization"}}

        self.assertIsNone(_auth_failed_stop_reason(scan, "session_validation", result))

    def test_missing_existing_scan_defaults_to_auto_application_profile(self) -> None:
        self.assertEqual(application_profile_for_existing_scan(None), "auto")

    def test_crapi_signup_parameter_uses_post_json_template(self) -> None:
        param = SimpleNamespace(
            name="email",
            location="json",
            endpoint="http://example.test/identity/api/auth/signup",
            source="api_method_probe",
            metadata_json={},
        )
        scan = SimpleNamespace(id=42)
        profile = {"name": "crapi", "registration_endpoint": "/identity/api/auth/signup"}
        with patch("saif.services.prompt_runner.profile_from_scan_artifacts", return_value=SimpleNamespace(profile=profile)):
            template = _request_template_for_parameter(None, scan, param, "http://example.test")

        self.assertIsNotNone(template)
        self.assertEqual(template["method"], "POST")
        self.assertEqual(template["parameter_location"], "json")
        self.assertIn("email", template["body_template"])
        self.assertFalse(template["query_template"])

    def test_dependency_block_requires_templates_before_payload_tests(self) -> None:
        class Query:
            def __init__(self, count_value=0, rows=None):
                self.count_value = count_value
                self.rows = rows or []

            def filter(self, *args, **kwargs):
                return self

            def order_by(self, *args, **kwargs):
                return self

            def all(self):
                return self.rows

            def count(self):
                return self.count_value

            def first(self):
                return None

        class FakeSession:
            def query(self, model):
                return Query()

        block = _dependency_block_for_tool(FakeSession(), SimpleNamespace(id=99), "xss_adaptive")

        self.assertIsNotNone(block)
        self.assertEqual(block["missing_artifact"], "request_templates")
        self.assertIn(RunStatus.MISSING_PREREQUISITE.value, {RunStatus.MISSING_PREREQUISITE.value})


if __name__ == "__main__":
    unittest.main()
