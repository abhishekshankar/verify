"""Guard checks for private connection material and evidence-based readiness."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hosted.lightsail import prepare_bridge as preparation
from hosted.lightsail.cutover import Blocked


class PreparationGuards(unittest.TestCase):
    def test_passfile_has_both_databases_and_preserves_special_characters(self):
        value = preparation.source_passfile("example.rds.amazonaws.com", "verify_owner", "a:b\\c$' ")
        self.assertEqual(value, "example.rds.amazonaws.com:5432:verify:verify_owner:a\\:b\\\\c$' \n"
                                "example.rds.amazonaws.com:5432:postgres:verify_owner:a\\:b\\\\c$' \n")

    def test_newline_nul_and_carriage_return_cannot_add_passfile_entries(self):
        for value in ("a\nother:5432:*:*:x", "a\rb", "a\0b"):
            with self.subTest(value=repr(value)), self.assertRaises(Blocked):
                preparation.source_passfile("host", "verify_owner", value)

    def test_evidence_requires_exact_target_success_and_freshness(self):
        now = datetime.now(timezone.utc)
        report = {"status": "PASSED", "instanceId": "i-test", "capturedAtUtc": now.isoformat()}
        path = SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=0, st_mode=0o100600),
                               is_file=lambda: True, read_text=lambda: json.dumps(report))
        self.assertEqual(preparation.fresh_report(path, "PASSED", "i-test"), report)
        for field, wrong in (("status", "FAILED"), ("instanceId", "i-other"),
                             ("capturedAtUtc", (now - timedelta(days=2)).isoformat())):
            old = report[field]
            report[field] = wrong
            with self.subTest(field=field), self.assertRaises(Blocked):
                preparation.fresh_report(path, "PASSED", "i-test")
            report[field] = old

    def test_readiness_file_must_be_private_and_root_owned(self):
        for owner, mode in ((1000, 0o100600), (0, 0o100644)):
            path = SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=owner, st_mode=mode), is_file=lambda: True)
            with self.assertRaises(Blocked):
                preparation.fresh_report(path, "PASSED", "i-test")

    def test_atomic_configuration_update_keeps_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "configuration.json"
            preparation.private_atomic(path, b'{"old":true}\n')
            preparation.private_atomic(path, b'{"new":true}\n')
            self.assertEqual(path.read_bytes(), b'{"new":true}\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual([item.name for item in path.parent.iterdir()], ["configuration.json"])


if __name__ == "__main__":
    unittest.main()
