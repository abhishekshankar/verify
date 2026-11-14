"""Offline acceptance checks for the read-only post-cutover evidence helper."""
from copy import deepcopy
from datetime import datetime
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hosted.lightsail import prove_live_target as live


class BackupEvidence(unittest.TestCase):
    captured = "2026-11-14T18:00:00+00:00"

    def fixture(self, offset=1):
        instant = int(datetime.fromisoformat(self.captured).timestamp())
        return [{"name": "verify", "status": {"code": 0}, "backup": [
            {"type": "full", "label": "20261114-180001F", "timestamp": {"start": instant + offset, "stop": instant + 20}}]}]

    def test_retirement_requires_backup_started_after_activation(self):
        with self.assertRaises(live.cutover.Blocked):
            live.backup_gate(self.fixture(-1), self.captured, True)
        self.assertFalse(live.backup_gate(self.fixture(-1), self.captured, False)["startedAfterCutover"])
        self.assertTrue(live.backup_gate(self.fixture(), self.captured, True)["startedAfterCutover"])

    def test_failed_backup_and_bad_repository_status_do_not_pass(self):
        value = self.fixture()
        value[0]["backup"][0]["error"] = True
        with self.assertRaises(live.cutover.Blocked):
            live.backup_gate(value, self.captured, True)
        value = self.fixture()
        value[0]["status"]["code"] = 1
        with self.assertRaises(live.cutover.Blocked):
            live.backup_gate(value, self.captured, True)


class LiveDataEvidence(unittest.TestCase):
    def fixture(self):
        return {name: {"rows": 2, "sha256": "original"} for name in live.TABLES}

    def test_legitimate_writes_key_rotation_and_retention_are_allowed(self):
        before = self.fixture()
        after = deepcopy(before)
        after["event"] = {"rows": 3, "sha256": "new"}
        after["access_log"] = {"rows": 3, "sha256": "new"}
        after["tenant"]["sha256"] = "rotated"
        after["event_payload"] = {"rows": 1, "sha256": "retained"}
        live.check_append_only(before, after)

    def test_append_only_loss_or_replacement_blocks_evidence(self):
        for replacement in ({"rows": 1, "sha256": "original"}, {"rows": 2, "sha256": "changed"}):
            before, after = self.fixture(), self.fixture()
            after["event"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(live.cutover.Blocked):
                live.check_append_only(before, after)

    def test_connection_environment_cannot_redirect_local_inspection(self):
        with patch.dict(os.environ, {"PGHOSTADDR": "source", "PGSERVICE": "source", "PGPASSWORD": "private",
                                     "VERIFY_DATABASE_URL": "private", "PATH": "/usr/bin"}, clear=True):
            result = live.clean_environment()
        self.assertFalse(any(name.startswith(("PG", "VERIFY_")) for name in result))
        self.assertEqual(result["PATH"], "/usr/bin")


class SourceFenceEvidence(unittest.TestCase):
    def exercise(self, allowed=False, count=0):
        queries = []

        class Connection:
            info = SimpleNamespace(get_parameters=lambda: {"host": live.SOURCE_HOST, "dbname": "postgres",
                                                           "user": "verify_owner", "sslmode": "verify-full"})
            def __enter__(self):
                return self
            def __exit__(self, *unused):
                pass
            def execute(self, query):
                queries.append(query)
                if "current_setting" in query:
                    value = ("on", True)
                elif "datallowconn" in query:
                    value = (allowed,)
                else:
                    value = (count,)
                return SimpleNamespace(fetchone=lambda: value)

        def connect(dsn, **options):
            self.assertIn("dbname=postgres", dsn)
            self.assertIn("default_transaction_read_only=on", options["options"])
            return Connection()

        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name in ("source-service.conf", "source.pgpass"):
                path = work / name
                path.touch(mode=0o600)
            with patch.object(live, "WORK", work), patch.dict(os.environ, {}, clear=True), \
                    patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)), \
                    patch.dict(sys.modules, {"psycopg": SimpleNamespace(connect=connect)}):
                result = live.source_fence()
        self.assertTrue(all(query.startswith("SELECT ") for query in queries))
        return result

    def test_fenced_empty_source_passes_without_mutation(self):
        self.assertEqual(self.exercise()["remainingVerifySessions"], 0)

    def test_admission_or_remaining_session_blocks(self):
        for arguments in ({"allowed": True}, {"count": 1}):
            with self.subTest(arguments=arguments), self.assertRaises(live.cutover.Blocked):
                self.exercise(**arguments)


if __name__ == "__main__":
    unittest.main()
