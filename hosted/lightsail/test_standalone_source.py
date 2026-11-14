"""Guard tests for SOURCE recovery and standalone preparation; no AWS calls."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hosted.lightsail import prepare_standalone_source as standalone
from hosted.lightsail import recover_source_bridge as recovery


def ready_report():
    return {"status": "STANDALONE_SOURCE_TASK_READY", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
            "accountId": standalone.ACCOUNT, "instanceId": standalone.INSTANCE, "sourceHost": standalone.SOURCE_HOST,
            "sourceImageDigest": standalone.SOURCE_IMAGE, "sourceTaskDefinition": standalone.TASK_DEFINITION,
            "sourceBackendKind": "standalone", "sourceTaskGroup": "family:verify-ledger", "standaloneStartedBy": "verify-migration-test",
            "standaloneRegisteredTargetGroups": [], "originalServiceDesiredCount": 1, "originalServiceHealthy": True,
            "sourceTargetGroup": standalone.SOURCE_TG, "httpsSourceOnly": True, "dnsStillOriginalAlb": True,
            "originalServiceTaskIps": ["10.40.11.4"], "sourcePrivateIp": "10.40.11.37",
            "sourceTaskArn": "arn:aws:ecs:us-west-2:842676017161:task/verify-ledger/123", "sourceEni": "eni-123"}


class ReadyEvidence(unittest.TestCase):
    def checked(self, value):
        with patch.object(standalone, "private_json", return_value=value):
            return standalone.checked_ready(Path("ignored"), "pinned")

    def test_exact_fresh_standalone_is_accepted(self):
        self.assertEqual(self.checked(ready_report())["sourcePrivateIp"], "10.40.11.37")

    def test_managed_or_registered_backend_and_changed_image_are_rejected(self):
        for key, value in (("sourceBackendKind", "service"), ("sourceTaskGroup", "service:verify-ledger"),
                           ("standaloneRegisteredTargetGroups", [standalone.SOURCE_TG]), ("sourceImageDigest", "changed"),
                           ("httpsSourceOnly", False), ("originalServiceHealthy", False)):
            report = ready_report()
            report[key] = value
            with self.subTest(key=key), self.assertRaises(standalone.cutover.Blocked):
                self.checked(report)

    def test_stale_report_or_reused_service_address_is_rejected(self):
        report = ready_report()
        report["capturedAtUtc"] = (datetime.now(timezone.utc) - timedelta(seconds=121)).isoformat()
        with self.assertRaises(standalone.cutover.Blocked):
            self.checked(report)
        report = ready_report()
        report["sourcePrivateIp"] = report["originalServiceTaskIps"][0]
        with self.assertRaises(standalone.cutover.Blocked):
            self.checked(report)


class RestartBoundary(unittest.TestCase):
    def test_active_or_queued_source_request_blocks_before_database_or_restart(self):
        for active, queued in ((1, 0), (0, 1)):
            state = {"ok": True, "mode": "source", "targetActivated": False, "active": active, "queued": queued}
            def contents(path, *unused, **kwargs):
                if str(path) == "/etc/verify/target-install.json":
                    return json.dumps({"accountId": recovery.ACCOUNT, "instanceId": recovery.INSTANCE})
                return json.dumps({"mode": "source"})
            connector = SimpleNamespace(connect=lambda *a, **k: self.fail("Database access must not precede the idle-bridge gate"))
            with self.subTest(active=active, queued=queued), patch.dict(sys.modules, {"psycopg": connector}), \
                    patch.object(recovery.os, "geteuid", return_value=0), patch.object(Path, "read_text", contents), \
                    patch.object(recovery.cutover, "durable_target_state", return_value=False), \
                    patch.object(recovery.cutover, "WRITER", SimpleNamespace(exists=lambda: False)), \
                    patch.object(recovery.subprocess, "run", return_value=SimpleNamespace(returncode=1)) as process, \
                    patch.object(recovery.cutover, "control", return_value=state), self.assertRaises(recovery.cutover.Blocked):
                recovery.guard({"10.40.11.4"})
            self.assertEqual(process.call_count, 1)
            self.assertEqual(process.call_args.args[0], ["systemctl", "is-active", "--quiet", "verify.service"])


class PreparationOrder(unittest.TestCase):
    def exercise(self, busy=False):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            config_path, environment = work / "config.json", work / "migration.env"
            config_path.write_text(json.dumps({"readiness": {"oldAlbRequestsDrained": True, "allOtherSourceWritersDisabled": True},
                                               "evidence": {"sourceRouting": {"old": "must disappear"}}}))
            environment.write_text("VERIFY_MIGRATION_SOURCE=http://10.40.11.4:8080\n")
            gate = {"ok": True, "mode": "source", "targetActivated": False, "active": int(busy), "queued": 0}
            calls = []
            def restart(arguments, **unused):
                self.assertFalse(json.loads(config_path.read_text())["readiness"]["oldAlbRequestsDrained"])
                self.assertNotIn("sourceRouting", json.loads(config_path.read_text())["evidence"])
                self.assertEqual(environment.read_text(), "VERIFY_MIGRATION_SOURCE=http://10.40.11.37:8080\n")
                calls.append(arguments)
                return SimpleNamespace(returncode=0)
            with patch.object(standalone, "CONFIG", config_path), patch.object(standalone, "WORK", work), \
                    patch.object(standalone, "ENVIRONMENT", environment), patch.object(standalone, "checked_ready", return_value=ready_report()), \
                    patch.object(standalone, "guard", return_value={"bridge": gate}), \
                    patch.object(standalone, "expected_api", return_value=(401, b'{"error":"unauthorized"}')), \
                    patch.object(standalone.cutover, "control", return_value=gate), \
                    patch.object(standalone.subprocess, "run", side_effect=restart), \
                    patch.object(standalone, "transition", return_value={"status": "STANDALONE_SOURCE_TRANSITION_VERIFIED"}):
                if busy:
                    with self.assertRaises(standalone.cutover.Blocked):
                        standalone.prepare(work / "ready.json", "pinned")
                    self.assertEqual(environment.read_text(), "VERIFY_MIGRATION_SOURCE=http://10.40.11.4:8080\n")
                else:
                    standalone.prepare(work / "ready.json", "pinned")
                    self.assertIn("standaloneSource", json.loads(config_path.read_text())["evidence"])
            return calls

    def test_stale_readiness_is_invalidated_before_the_only_service_restart(self):
        self.assertEqual(self.exercise(), [["systemctl", "restart", "verify-migration.service"]])

    def test_newly_busy_bridge_blocks_repoint_and_restart(self):
        self.assertEqual(self.exercise(busy=True), [])


class RollbackEvidence(unittest.TestCase):
    def test_invalidating_an_accepted_report_removes_the_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"readiness": {"oldAlbRequestsDrained": False, "allOtherSourceWritersDisabled": False},
                                          "evidence": {"sourceRouting": {"path": "previously-valid-pin"}}}))
            with patch.object(standalone, "CONFIG", config), patch.object(standalone, "transition", return_value={}) as proof:
                result = standalone.invalidate()
            proof.assert_called_once_with(require_clean_routing=False)
            self.assertEqual(result["status"], "STANDALONE_SOURCE_READINESS_INVALIDATED")
            self.assertNotIn("sourceRouting", json.loads(config.read_text())["evidence"])

    def test_rollback_proof_uses_fresh_managed_ip_and_pinned_standalone_only(self):
        with tempfile.TemporaryDirectory() as directory:
            config, environment = Path(directory) / "config.json", Path(directory) / "migration.env"
            config.write_text(json.dumps({"readiness": {"oldAlbRequestsDrained": False, "allOtherSourceWritersDisabled": False},
                "evidence": {"standaloneSource": {"readyReport": "ready", "readyReportSha256": "ready-hash",
                    "preparedReport": "prepared", "preparedReportSha256": "prepared-hash"}}}))
            environment.write_text("VERIFY_MIGRATION_SOURCE=http://10.40.11.37:8080\n")
            ready = ready_report()
            prepared = {key: ready[key] for key in ("sourceTaskArn", "sourcePrivateIp", "standaloneStartedBy")}
            prepared["status"] = "STANDALONE_SOURCE_BRIDGE_PREPARED"
            with patch.object(standalone, "CONFIG", config), patch.object(standalone, "ENVIRONMENT", environment), \
                    patch.object(standalone, "checked_ready", return_value=ready), \
                    patch.object(standalone, "private_json", return_value=prepared), \
                    patch.object(standalone, "guard", return_value={"bridge": {"mode": "source"}, "sourceSessions": []}) as proof, \
                    patch.object(standalone, "expected_api", return_value=(401, b'{"error":"unauthorized"}')):
                result = standalone.transition(managed_source_ip="10.40.11.99")
            proof.assert_called_once_with({"10.40.11.37", "10.40.11.99"})
            self.assertEqual(result["managedSourcePrivateIp"], "10.40.11.99")
            self.assertEqual(result["status"], "STANDALONE_SOURCE_ROLLBACK_VERIFIED")


if __name__ == "__main__":
    unittest.main()
