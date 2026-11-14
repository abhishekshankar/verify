import copy
from datetime import datetime, timezone
import tempfile
from pathlib import Path
import unittest

from hosted.config import secret
from hosted.lightsail.source_gate import evaluate, EXPECTED
from hosted.lightsail.compare_data import fingerprint


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.meta = {
            "capturedAtUtc": self.now.isoformat(), "database": "verify", "serverVersionNum": "160000",
            "serverEncoding": "UTF8", "sslConnection": True, "rdsLogicalReplication": "1",
            "walLevel": "logical", "replicationRole": True, "freeReplicationSlots": 4,
            "maxWalSenders": 4, "largeObjects": 0, "sequences": 0, "extensions": ["plpgsql"],
            "otherUserRelations": 0,
            "tables": [{"name": n, "schema": "public", "selectPrivilege": True, "primaryKey": n != "access_log",
                        "rls": False, "replicaOrAlwaysTriggers": False, "blocksUpdateDelete": True,
                        "blocksTruncate": True} for n in EXPECTED]
        }

    def gate(self, meta=None, strategy="logical"):
        return evaluate(meta or self.meta, self.now, strategy, "123456789012")

    def test_disabled_logical_is_a_hard_block_for_logical_strategy(self):
        self.meta.update(rdsLogicalReplication="0", walLevel="replica")
        report = self.gate()
        self.assertEqual(report["status"], "BLOCKED")
        self.assertFalse(report["sourceLogicalReplicationReady"])

    def test_disabled_logical_does_not_block_consistent_copy_rehearsal(self):
        self.meta.update(rdsLogicalReplication="0", walLevel="replica", replicationRole=False)
        report = self.gate(strategy="write-drain")
        self.assertTrue(report["sourceRehearsalReady"])
        self.assertFalse(report["sourceLogicalReplicationReady"])
        self.assertIn("Approve writer fence, apply barrier and rollback", report["remainingGates"])

    def test_unknown_data_and_missing_security_fail_closed(self):
        for field, value in (("largeObjects", 1), ("sequences", 1), ("sslConnection", False),
                             ("database", "other"), ("otherUserRelations", 1)):
            with self.subTest(field=field):
                meta = copy.deepcopy(self.meta)
                meta[field] = value
                self.assertFalse(self.gate(meta, "write-drain")["sourceRehearsalReady"])

    def test_stale_snapshot_and_missing_tables_are_blocked(self):
        self.meta["capturedAtUtc"] = "2025-12-31T00:00:00+00:00"
        self.meta["tables"].pop()
        self.assertGreaterEqual(len(self.gate()["blockers"]), 2)

    def test_access_log_cannot_silently_lose_append_only_guards(self):
        table = next(t for t in self.meta["tables"] if t["name"] == "access_log")
        table["blocksUpdateDelete"] = False
        self.assertFalse(self.gate()["sourceRehearsalReady"])

    def test_account_input_is_required(self):
        self.assertFalse(evaluate(self.meta, self.now)["sourceRehearsalReady"])

    def test_file_credentials_preserve_exact_hmac_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "key"
            p.write_bytes(b"synthetic key with trailing whitespace \n")
            self.assertEqual(secret("EXAMPLE", {"EXAMPLE_FILE": str(p)}), "synthetic key with trailing whitespace \n")

    def test_conflicting_credentials_fail_without_values(self):
        with self.assertRaisesRegex(RuntimeError, "Set only") as caught:
            secret("EXAMPLE", {"EXAMPLE": "do-not-echo", "EXAMPLE_FILE": "unused"})
        self.assertNotIn("do-not-echo", str(caught.exception))

    def test_multiset_fingerprint_preserves_duplicate_multiplicity(self):
        one = fingerprint(iter([('{"a":1}',)]))
        two = fingerprint(iter([('{"a":1}',), ('{"a":1}',)]))
        self.assertNotEqual(one["sha256"], two["sha256"])
        self.assertEqual(two["rows"], 2)


if __name__ == "__main__":
    unittest.main()
