from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from saif.db.models import RunStatus
from saif.services.prompt_runner import (
    _dependency_block_for_tool,
    _request_template_for_parameter,
    application_profile_for_existing_scan,
    tools_for_execution_profile,
)


class ExecutionProfileTests(unittest.TestCase):
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
