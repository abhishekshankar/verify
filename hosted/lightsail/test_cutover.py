"""Failure-injection checks for coordinator identity and single-writer boundaries."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hosted.lightsail import cutover as migration
from hosted.lightsail.migration_proxy import Gate


class SQL(str):
    def format(self, *args):
        return SQL(str(self).format(*args))
    def join(self, items):
        return SQL(str(self).join(items))


class Result:
    def __init__(self, row=(None,)):
        self.row = row
    def fetchone(self):
        return self.row


class CoordinatorFailures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.state_file = self.directory / "state.json"
        self.state_file.write_text(json.dumps({"version": 1, "mode": "source", "targetActivated": False}))
        self.gate = Gate(self.state_file, queue_seconds=20)
        self.db = {"admission": True, "queries": [], "lost_fence_response": False, "rollback_error": False,
                   "delay_recovery": False}
        self.inject = {"stage_failure": False, "lost_target_response": False, "lost_drain_response": False,
                       "delayed_target_before_persist": False,
                       "delete_state_on_failure": False}
        db, inject = self.db, self.inject

        class Connection:
            def __init__(self, management=False, rescue=False):
                self.management, self.rescue = management, rescue
                self.info = SimpleNamespace(backend_pid=102 if management else 101)
                self.broken = self.closed = False
            def execute(self, query, args=None):
                text = str(query)
                if self.rescue and db["delay_recovery"] and "SELECT pg_terminate_backend" in text:
                    time.sleep(1)
                if self.broken:
                    raise ConnectionError("simulated broken connection")
                db["queries"].append(text)
                if text == "ROLLBACK" and db["rollback_error"] and not self.management:
                    self.broken = True
                    raise ConnectionError("simulated dead source session")
                if text == "ALTER DATABASE verify ALLOW_CONNECTIONS false":
                    db["admission"] = False
                    if db["lost_fence_response"]:
                        self.broken = True
                        raise ConnectionError("simulated committed fence with lost response")
                if text == "ALTER DATABASE verify ALLOW_CONNECTIONS true":
                    db["admission"] = True
                if "SELECT datallowconn" in text:
                    return Result((db["admission"],))
                if "SELECT count(*) FROM pg_stat_activity" in text:
                    return Result((0,))
                return Result((1,))
            def close(self):
                self.closed = True

        self.source, self.management = Connection(), Connection(management=True)
        self.connections = iter([self.source, self.management])
        def connect(*args, **kwargs):
            try:
                return next(self.connections)
            except StopIteration:
                return Connection(management=True, rescue=True)
        self.fake_psycopg = SimpleNamespace(connect=connect, sql=SimpleNamespace(
            SQL=SQL, Identifier=lambda *parts: SQL(".".join(parts))))
        self.tables = {name: {"rows": 1 if name == "tenant" else 0, "sha256": "b" * 64}
                       for name in migration.TABLES}
        tables, state_file = self.tables, self.state_file

        class Runner:
            deadline = None
            def archive_check(self):
                pass
            def timeout(self, maximum=30):
                return maximum
            def schema(self, **kwargs):
                return "f" * 64
            def dump(self, path):
                path.write_bytes(b"synthetic dump fixture")
            def stage(self, dump, name):
                if inject["stage_failure"]:
                    if inject["delete_state_on_failure"]:
                        state_file.unlink()
                    raise RuntimeError("synthetic restore failure")
            def inspect(self, name):
                return {"tables": tables, "chainsOk": True, "tenantsChecked": 1, "eventsChecked": 0}
            def pg(self, query, *args, **kwargs):
                if "SELECT oid FROM pg_database" in query:
                    return b"100\n"
                if "SELECT datname FROM pg_database WHERE oid=" in query:
                    return b"verify\n"
                return b""
            def run(self, *args, **kwargs):
                return b""

        self.runner = Runner()
        self.config = {"instanceId": "i-01234567890123456", "accountId": "123456789012",
                       "sourceHost": "source.example.invalid", "sourceService": "verify_source_gate",
                       "workDirectory": str(self.directory), "readiness": {
                           key: True for key in ("applicationFeatureTestsPassed", "encryptedBackupRestoreTestPassed",
                            "oldAlbRequestsDrained", "allOtherSourceWritersDisabled", "httpsCertificateAndRenewalPathVerified",
                            "databaseDeadlineInterruptTestPassed")}}
        self.config["readiness"]["retainedSourceAutomatedBackupDays"] = 7
        self.rehearsal = self.directory / "rehearsal.json"
        self.rehearsal.write_text(json.dumps({"status": "REHEARSAL_PASSED", "measuredSeconds": 1,
            "capturedAtUtc": datetime.now(timezone.utc).isoformat(), "schemaSha256": "f" * 64,
            **{key: self.config[key] for key in ("instanceId", "accountId", "sourceHost")}}))

    def tearDown(self):
        self.temp.cleanup()

    def control(self, socket, request, timeout=5):
        if request["action"] == "status":
            return {"ok": True, **self.gate.status()}
        if request["mode"] == "target" and self.inject["delayed_target_before_persist"]:
            raise TimeoutError("server has received activation but has not persisted yet")
        result = self.gate.change(request["mode"], request["expected"])
        if request["mode"] == "target" and self.inject["lost_target_response"]:
            raise TimeoutError("target transition committed but response lost")
        if request["mode"] == "drain" and self.inject["lost_drain_response"]:
            raise TimeoutError("drain transition committed but response lost")
        return {"ok": True, **result}

    def run_cutover(self):
        def subprocess(command, **kwargs):
            return SimpleNamespace(returncode=1 if "is-active" in command else 0)
        with patch.dict("sys.modules", {"psycopg": self.fake_psycopg}), \
             patch.object(migration, "STATE", self.state_file), \
             patch.object(migration, "WRITER", self.directory / "writer-enabled"), \
             patch.object(migration, "control", self.control), \
             patch.object(migration, "check_source"), \
             patch.object(migration, "source_inventory", return_value=self.tables), \
             patch.object(migration, "save_dump", return_value={"versionId": "synthetic"}), \
             patch.object(migration, "app_healthy", return_value=True), \
             patch.object(migration.subprocess, "run", side_effect=subprocess):
            return migration.cutover(self.config, self.runner, self.rehearsal)

    def report(self):
        paths = list(self.directory.glob("*-cutover.json"))
        self.assertEqual(len(paths), 1)
        return json.loads(paths[0].read_text())

    def test_success_leaves_source_durably_fenced_and_target_authoritative(self):
        self.assertEqual(self.run_cutover()["status"], "TARGET_AUTHORITATIVE")
        self.assertFalse(self.db["admission"])
        self.assertTrue(self.gate.status()["targetActivated"])
        self.assertNotIn("ALTER DATABASE verify ALLOW_CONNECTIONS true", self.db["queries"])

    def test_lost_target_response_never_unfences_the_stale_source(self):
        self.inject["lost_target_response"] = True
        with self.assertRaises(migration.Blocked):
            self.run_cutover()
        self.assertFalse(self.db["admission"])
        self.assertTrue(self.gate.status()["targetActivated"])
        self.assertEqual(self.report()["status"], "TARGET_NEEDS_REPAIR")
        self.assertNotIn("ALTER DATABASE verify ALLOW_CONNECTIONS true", self.db["queries"])

    def test_dead_source_connection_does_not_skip_abort_to_source(self):
        self.inject["stage_failure"] = True
        self.db["rollback_error"] = True
        with self.assertRaises(migration.Blocked):
            self.run_cutover()
        self.assertEqual(self.gate.status()["mode"], "source")
        self.assertTrue(self.db["admission"])
        self.assertEqual(self.report()["status"], "ABORTED_TO_SOURCE")

    def test_activation_inflight_cannot_unfence_even_while_disk_flag_is_false(self):
        self.inject["delayed_target_before_persist"] = True
        with self.assertRaises(migration.Blocked):
            self.run_cutover()
        self.assertFalse(self.db["admission"])
        self.assertFalse(self.gate.status()["targetActivated"])
        self.assertEqual(self.report()["status"], "TARGET_ACTIVATION_UNCERTAIN_SOURCE_FENCED")
        self.assertNotIn("ALTER DATABASE verify ALLOW_CONNECTIONS true", self.db["queries"])

    def test_recovery_network_wait_is_bounded_and_does_not_claim_source_restored(self):
        self.inject["stage_failure"] = True
        self.db["delay_recovery"] = True
        original_budget = migration.WallBudget
        with patch.object(migration, "WallBudget", side_effect=lambda seconds: original_budget(.025 if seconds == 4 else seconds)):
            started = time.monotonic()
            with self.assertRaises(migration.Blocked):
                self.run_cutover()
        self.assertLess(time.monotonic() - started, .5)
        self.assertEqual(self.gate.status()["mode"], "drain")
        self.assertEqual(self.report()["status"], "OPERATOR_RECOVERY_REQUIRED")
        self.assertIn("SOURCE_AUTHORITY_RECOVERY_DeadlineExpired", self.report()["recoveryErrors"])

    def test_committed_admission_fence_with_lost_response_is_recovered(self):
        self.db["lost_fence_response"] = True
        with self.assertRaises(migration.Blocked):
            self.run_cutover()
        self.assertTrue(self.db["admission"])
        self.assertEqual(self.gate.status()["mode"], "source")
        self.assertEqual(self.report()["status"], "ABORTED_TO_SOURCE")

    def test_lost_drain_response_is_recovered_from_observed_mode(self):
        self.inject["lost_drain_response"] = True
        with self.assertRaises(migration.Blocked):
            self.run_cutover()
        self.assertEqual(self.gate.status()["mode"], "source")
        self.assertEqual(self.report()["status"], "ABORTED_TO_SOURCE")

    def test_missing_durable_state_never_permits_automatic_unfence(self):
        self.inject.update(stage_failure=True, delete_state_on_failure=True)
        with self.assertRaises(migration.Blocked):
            self.run_cutover()
        self.assertEqual(self.gate.status()["mode"], "drain")
        self.assertEqual(self.report()["status"], "OPERATOR_RECOVERY_REQUIRED")
        self.assertNotIn("ALTER DATABASE verify ALLOW_CONNECTIONS true", self.db["queries"])


class IdentityGuards(unittest.TestCase):
    def test_wall_budget_interrupts_waits_and_cancels_cleanly(self):
        budget = migration.WallBudget(.025)
        started = time.monotonic()
        try:
            budget.arm()
            with self.assertRaises(migration.DeadlineExpired):
                time.sleep(1)
        finally:
            budget.cancel()
        self.assertLess(time.monotonic() - started, .5)
        self.assertFalse(budget.armed)

    def test_source_environment_cannot_redirect_a_local_target_write(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "PGHOST": "source.example.invalid", "PGHOSTADDR": "10.99.99.99", "PGUSER": "source_owner",
            "PGPORT": "6543", "PGSERVICE": "source", "PGPASSWORD": "synthetic-secret"}):
            runner = migration.Runner({"workDirectory": directory})
            with patch.object(migration.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b"")) as run:
                runner.pg("SELECT 1")
                command = run.call_args.args[0]
                environment = run.call_args.kwargs["env"]
                self.assertFalse(any(key.startswith("PG") for key in environment))
                self.assertIn("/var/run/postgresql", command)
                self.assertEqual(command[command.index("-U") + 1], "postgres")
                self.assertEqual(command[command.index("-p") + 1], "5432")

    def test_unknown_or_inconsistent_gate_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            self.assertIsNone(migration.durable_target_state(path))
            for state in ({"version": 1, "mode": "target", "targetActivated": False},
                          {"version": 1, "mode": "drain", "targetActivated": "false"}):
                path.write_text(json.dumps(state))
                self.assertIsNone(migration.durable_target_state(path))


if __name__ == "__main__":
    unittest.main()
