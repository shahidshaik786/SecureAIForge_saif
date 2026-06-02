from __future__ import annotations

import unittest

from saif.registry.testcases import load_testcases


class TestCaseRegistryTests(unittest.TestCase):
    def test_web_api_registry_loads(self) -> None:
        registry = load_testcases("web-api")
        self.assertEqual(registry.profile, "web-api")
        self.assertTrue(any(item.id == "recon.http_baseline" for item in registry.test_cases))

    def test_auto_resolves_to_api_security(self) -> None:
        registry = load_testcases("auto")
        self.assertEqual(registry.profile, "api-security")
        self.assertTrue(any(item.id == "api.bola" for item in registry.test_cases))

    def test_crapi_extends_web_api(self) -> None:
        registry = load_testcases("crapi")
        ids = {item.id for item in registry.test_cases}
        self.assertEqual(registry.profile, "crapi")
        self.assertIn("recon.http_baseline", ids)
        self.assertIn("crapi.bola_idor", ids)
        self.assertIn("crapi.production_readiness", ids)

    def test_generic_rest_alias_does_not_raise_profile_mismatch(self) -> None:
        registry = load_testcases("generic-rest-api")
        self.assertEqual(registry.profile, "api-security")

    def test_ui_application_profiles_fall_back_to_generic_web_api_registry(self) -> None:
        for profile in ["custom", "juice-shop", "owasp-juice-shop", "dvwa", "generic-web-api"]:
            with self.subTest(profile=profile):
                registry = load_testcases(profile)
                self.assertEqual(registry.profile, "web-api")
                self.assertTrue(any(item.id == "recon.http_baseline" for item in registry.test_cases))


if __name__ == "__main__":
    unittest.main()
