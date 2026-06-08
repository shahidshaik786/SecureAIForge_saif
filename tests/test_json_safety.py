from __future__ import annotations

import json
import unittest

from saif.utils.json_safety import make_json_safe, remove_circular_refs


class JsonSafetyTests(unittest.TestCase):
    def test_make_json_safe_handles_circular_reference(self) -> None:
        payload = {"items": []}
        payload["items"].append(payload)

        safe = make_json_safe(payload)

        json.dumps(safe)
        self.assertIn("circular_ref", str(safe))

    def test_remove_circular_refs_alias(self) -> None:
        payload = {}
        payload["self"] = payload
        self.assertIn("circular_ref", str(remove_circular_refs(payload)))


if __name__ == "__main__":
    unittest.main()
