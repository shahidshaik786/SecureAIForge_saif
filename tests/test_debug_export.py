from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from saif.db.models import Base, Project, Scan
from saif.services import debug_export


class DebugExportTests(unittest.TestCase):
    def test_failed_scan_debug_export_contains_status_and_crash(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with TemporaryDirectory() as tmp, Session(engine) as session:
            original_get_settings = debug_export.get_settings
            debug_export.get_settings = lambda: type("S", (), {"evidence_dir": Path(tmp), "ollama_profile": "low_gpu"})()
            try:
                project = Project(name="debug-export")
                session.add(project)
                session.flush()
                scan = Scan(project_id=project.id, profile="auto", status="failed", scan_config={"crash": {"message": "boom", "traceback": "trace"}})
                session.add(scan)
                session.flush()

                json_path, _ = debug_export.generate_full_ai_debug_export(session, scan.id)
                payload = json.loads(json_path.read_text(encoding="utf-8"))
            finally:
                debug_export.get_settings = original_get_settings

        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["crash"]["message"], "boom")


if __name__ == "__main__":
    unittest.main()
