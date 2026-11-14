"""Offline network-permission and SOURCE rollback ordering checks."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hosted.lightsail import route_source_bridge as route


class NetworkGuards(unittest.TestCase):
    def test_exact_private_peers_are_collected(self):
        value = {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                                   "UserIdGroupPairs": [{"GroupId": "sg-a", "UserId": route.ACCOUNT},
                                                        {"GroupId": "sg-b", "UserId": route.ACCOUNT}]}]}
        self.assertEqual(route.port_peers(value, 5432)[0], {"sg-a", "sg-b"})

    def test_all_protocol_cidr_cannot_hide_database_reachability(self):
        value = {"IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
        with self.assertRaises(route.Blocked):
            route.port_peers(value, 5432)

    def test_port_range_ipv6_and_prefix_access_are_rejected(self):
        for field in ("Ipv6Ranges", "PrefixListIds"):
            rule = {"IpProtocol": "tcp", "FromPort": 5400, "ToPort": 5500, field: [{"id": "unreviewed"}]}
            with self.subTest(field=field), self.assertRaises(route.Blocked):
                route.port_peers({"IpPermissions": [rule]}, 5432)

    def test_other_protocol_or_port_does_not_grant_postgres_tcp(self):
        value = {"IpPermissions": [{"IpProtocol": "udp", "FromPort": 5432, "ToPort": 5432,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                                   {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
        self.assertEqual(route.port_peers(value, 5432)[0], set())

    def test_cross_account_peer_is_not_accepted(self):
        value = {"IpPermissions": [{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-a", "UserId": "000000000000"}]}]}
        with self.assertRaises(route.Blocked):
            route.port_peers(value, 5432)

    def test_source_zero_weight_and_disabled_stickiness_are_explicit(self):
        actions = [{"Type": "forward", "ForwardConfig": {"TargetGroups": [
            {"TargetGroupArn": "bridge", "Weight": 100}, {"TargetGroupArn": route.SOURCE_TG, "Weight": 0}],
            "TargetGroupStickinessConfig": {"Enabled": False}}}]
        self.assertEqual(route.targets(actions), ({"bridge": 100, route.SOURCE_TG: 0}, False))
        actions[0]["ForwardConfig"]["TargetGroupStickinessConfig"]["Enabled"] = True
        self.assertTrue(route.targets(actions)[1])

    def test_duplicate_or_noninteger_forwarding_weight_is_rejected(self):
        for groups in ([{"TargetGroupArn": "bridge", "Weight": 1}, {"TargetGroupArn": "bridge", "Weight": 0}],
                       [{"TargetGroupArn": "bridge", "Weight": True}]):
            with self.assertRaises(route.Blocked):
                route.targets([{"Type": "forward", "ForwardConfig": {"TargetGroups": groups}}])


class RollbackOrder(unittest.TestCase):
    def fixture(self, old):
        calls = []
        current = {"actions": [{"Type": "forward", "ForwardConfig": {"TargetGroups": [
            {"TargetGroupArn": "bridge", "Weight": 100}, {"TargetGroupArn": route.SOURCE_TG, "Weight": 0}],
            "TargetGroupStickinessConfig": {"Enabled": False}}}]}
        class LoadBalancer:
            def describe_target_health(self, **unused):
                return {"TargetHealthDescriptions": old}
            def register_targets(self, **unused):
                calls.append("register")
            def modify_listener(self, **arguments):
                calls.append("restore-route")
                current["actions"] = arguments["DefaultActions"]
        class ECS:
            def update_service(self, **unused):
                calls.append("restore-grace")
        operation = route.Operation.__new__(route.Operation)
        operation.clients = {"elbv2": LoadBalancer(), "ecs": ECS()}
        operation.stable_task = lambda unused: {"healthCheckGracePeriodSeconds": 0}
        operation.target_proof = lambda invalidate=False: calls.append("invalidate" if invalidate else "proof")
        operation.group = lambda *unused: ("bridge", [])
        operation.rules = lambda *unused: ({"DefaultActions": current["actions"]}, {})
        operation.save = lambda *unused: calls.append("save")
        state = {"phase": "DRAINING", "bridgeTargetGroup": "bridge", "acmeTargetGroup": "acme",
                 "before": {"httpsActions": [{"Type": "forward", "TargetGroupArn": route.SOURCE_TG}],
                            "task": {"healthCheckGracePeriodSeconds": 0}}}
        return operation, calls, state

    def test_unregistered_source_is_registered_before_any_route_or_grace_restore(self):
        operation, calls, state = self.fixture([])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(state))
            with patch.object(route, "STATE", path):
                result = operation.rollback()
        self.assertEqual(result["status"], "ROLLBACK_WAITING_FOR_SOURCE_HEALTH")
        self.assertEqual(calls, ["invalidate", "save", "register"])

    def test_draining_source_does_not_restore_public_routing(self):
        old = [{"Target": route.EXPECTED_TARGET, "TargetHealth": {"State": "draining"}}]
        operation, calls, state = self.fixture(old)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(state))
            with patch.object(route, "STATE", path):
                result = operation.rollback()
        self.assertEqual(result["status"], "ROLLBACK_WAITING_FOR_SOURCE_HEALTH")
        self.assertEqual(calls, ["invalidate"])

    def test_healthy_source_restores_route_before_health_grace(self):
        old = [{"Target": route.EXPECTED_TARGET, "TargetHealth": {"State": "healthy"}}]
        operation, calls, state = self.fixture(old)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(state))
            with patch.object(route, "STATE", path):
                result = operation.rollback()
        self.assertEqual(result["status"], "SOURCE_ROUTING_AND_GRACE_RESTORED")
        self.assertLess(calls.index("restore-route"), calls.index("restore-grace"))
        self.assertEqual(calls[:3], ["invalidate", "invalidate", "save"])


class TargetReadinessEvidence(unittest.TestCase):
    def evidence(self):
        from datetime import datetime, timedelta, timezone
        return {"status": "SOURCE_HTTP_DRAIN_AND_WRITER_NETWORK_VERIFIED",
                "capturedAtUtc": datetime.now(timezone.utc).isoformat(), "accountId": route.ACCOUNT,
                "instanceId": route.INSTANCE, "sourceHost": route.SOURCE_HOST,
                "sourcePrivateIp": route.SOURCE_IP, "targetPrivateIp": route.TARGET_IP,
                "sourceTaskArn": "verified-standalone-task", "sourceImageDigest": route.SOURCE_IMAGE,
                "sourceTaskRunningCount": 1, "bridgeTargetGroup": "bridge",
                "drainMethod": "ECS_SERVICE_STOPPED_STANDALONE_SOURCE", "sourceBackendKind": "standalone",
                "singleStandaloneRunning": True, "sourceTaskGroup": "family:verify-ledger",
                "standaloneStartedBy": "verify-migration-test", "originalServiceDesiredCount": 0,
                "originalServiceRunningCount": 0, "originalServicePendingCount": 0,
                "oldServiceTasks": [{"taskArn": "old-managed-task", "lastStatus": "STOPPED"}],
                "drain": {"serviceScaleDownRequested": True, "originalDelayUnchanged": True,
                          "elapsedSeconds": 301, "configuredDelaySeconds": 300,
                          "targetAbsentFromRegisteredList": True, "allOldTargetsNotRegistered": True},
                "routing": {"positiveWeightTargetGroups": ["bridge"], "sourceTargetGroupWeight": 0,
                            "targetGroupStickinessEnabled": False, "allResolvedAlbAddressesReachBridge": True,
                            "allListenersAndRulesReviewed": True},
                "writerNetwork": {"databaseClientGroups": [route.SOURCE_SG, route.TARGET_SG],
                                  "allPeerInterfacesMatched": True, "noCidrOrPrefixDatabaseAccess": True,
                                  "sourceDatabasePrivate": True, "sourceTaskIdentityUnchanged": True}}

    def invoke(self, value, supplied_digest=None):
        import hashlib
        from hosted.lightsail import attest_source_route as attestation
        data = json.dumps(value).encode()
        path = SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=0, st_mode=0o100600),
                               read_bytes=lambda: data)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"readiness": {"oldAlbRequestsDrained": False,
                                                       "allOtherSourceWritersDisabled": False}}))
            with patch.object(attestation, "CONFIG", config), patch.object(attestation, "WORK", Path(directory)), \
                    patch.object(attestation, "snapshot", return_value={"status": "SOURCE_WRITER_AND_BRIDGE_VERIFIED"}) as observed:
                result = attestation.accept(path, supplied_digest or hashlib.sha256(data).hexdigest())
                return result, json.loads(config.read_text()), observed.call_count

    def test_verified_report_and_fresh_source_proof_set_readiness(self):
        result, config, observations = self.invoke(self.evidence())
        self.assertEqual(result["status"], "SOURCE_ROUTING_EVIDENCE_PINNED")
        self.assertEqual(observations, 1)
        self.assertFalse(config["readiness"]["oldAlbRequestsDrained"])
        self.assertFalse(config["readiness"]["allOtherSourceWritersDisabled"])

    def test_stopped_task_is_not_enough_without_completed_deregistration(self):
        from hosted.lightsail.cutover import Blocked
        value = self.evidence()
        value["drain"]["allOldTargetsNotRegistered"] = False
        with self.assertRaises(Blocked):
            self.invoke(value)

    def test_changed_report_checksum_is_rejected(self):
        from hosted.lightsail.cutover import Blocked
        with self.assertRaises(Blocked):
            self.invoke(self.evidence(), supplied_digest="0" * 64)

    def test_retired_manual_deregistration_evidence_cannot_be_pinned(self):
        from hosted.lightsail.cutover import Blocked
        value = self.evidence()
        value["drainMethod"] = "MANUAL_DEREGISTRATION_WITH_HEALTH_GRACE"
        with self.assertRaises(Blocked):
            self.invoke(value)

    def test_stopping_managed_task_or_pending_replacement_cannot_be_pinned(self):
        from hosted.lightsail.cutover import Blocked
        for field in ("originalServiceDesiredCount", "originalServiceRunningCount", "originalServicePendingCount"):
            value = self.evidence()
            value[field] = 1
            with self.subTest(field=field), self.assertRaises(Blocked):
                self.invoke(value)
        value = self.evidence()
        value["oldServiceTasks"][0]["lastStatus"] = "STOPPING"
        with self.assertRaises(Blocked):
            self.invoke(value)

    def execute_fixture(self, expired=False, tampered=False):
        from datetime import datetime, timedelta, timezone
        import hashlib
        from hosted.lightsail import attest_source_route as attestation
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            report_path, pin_path, config_path = work / "report.json", work / "pin.json", work / "config.json"
            report = self.evidence()
            report_path.write_text(json.dumps(report))
            report_path.chmod(0o600)
            report_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
            pin = {"status": "SOURCE_ROUTING_EVIDENCE_PINNED", "accountId": route.ACCOUNT,
                   "instanceId": route.INSTANCE,
                   "capturedAtUtc": (datetime.now(timezone.utc) - timedelta(seconds=301 if expired else 0)).isoformat(),
                   "routingReport": str(report_path), "routingReportSha256": report_hash,
                   "sourceTaskArn": report["sourceTaskArn"], "sourceImageDigest": report["sourceImageDigest"],
                   "drainMethod": report["drainMethod"], "standaloneStartedBy": report["standaloneStartedBy"]}
            pin_path.write_text(json.dumps(pin))
            pin_path.chmod(0o600)
            pin_hash = hashlib.sha256(pin_path.read_bytes()).hexdigest()
            if tampered:
                pin_path.write_text(pin_path.read_text() + " ")
            reference = {"path": str(pin_path), "sha256": pin_hash, "routingReport": str(report_path),
                         "routingReportSha256": report_hash, "sourceTaskArn": report["sourceTaskArn"],
                         "sourceImageDigest": report["sourceImageDigest"]}
            config = {"workDirectory": str(work), "readiness": {"oldAlbRequestsDrained": False,
                       "allOtherSourceWritersDisabled": False}, "evidence": {"sourceRouting": reference}}
            config_path.write_text(json.dumps(config))
            config_path.chmod(0o600)
            class PrivatePath:
                def __init__(self, value):
                    self.path = Path(value)
                def read_bytes(self):
                    return self.path.read_bytes()
                def stat(self):
                    return SimpleNamespace(st_uid=0, st_mode=self.path.stat().st_mode)
            invoked = []
            def coordinator(current, runner, rehearsal):
                self.assertTrue(current["readiness"]["oldAlbRequestsDrained"])
                self.assertTrue(current["readiness"]["allOtherSourceWritersDisabled"])
                self.assertFalse(json.loads(config_path.read_text())["readiness"]["oldAlbRequestsDrained"])
                invoked.append(True)
                return {"status": "TARGET_AUTHORITATIVE"}
            with patch.object(attestation, "CONFIG", config_path), patch.object(attestation, "WORK", work), \
                    patch.object(attestation, "Path", PrivatePath), \
                    patch.object(attestation, "snapshot", return_value={"status": "SOURCE_WRITER_AND_BRIDGE_VERIFIED"}), \
                    patch.object(attestation.cutover, "read_config", side_effect=lambda unused: json.loads(config_path.read_text())), \
                    patch.object(attestation.cutover, "cutover", side_effect=coordinator):
                result = attestation.execute(work / "rehearsal.json")
            return result, invoked, json.loads(config_path.read_text())

    def test_execute_enables_only_in_memory_after_fresh_pinned_evidence(self):
        result, invoked, config = self.execute_fixture()
        self.assertEqual(result["status"], "TARGET_AUTHORITATIVE")
        self.assertEqual(invoked, [True])
        self.assertFalse(config["readiness"]["oldAlbRequestsDrained"])
        self.assertFalse(config["readiness"]["allOtherSourceWritersDisabled"])

    def test_expired_pin_cannot_reach_the_coordinator(self):
        from hosted.lightsail.cutover import Blocked
        with self.assertRaises(Blocked):
            self.execute_fixture(expired=True)

    def test_tampered_pin_cannot_reach_the_coordinator(self):
        from hosted.lightsail.cutover import Blocked
        with self.assertRaises(Blocked):
            self.execute_fixture(tampered=True)

    def test_invalidation_removes_the_pin_so_false_flags_cannot_reuse_it(self):
        from hosted.lightsail import attest_source_route as attestation
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"readiness": {"oldAlbRequestsDrained": False, "allOtherSourceWritersDisabled": False},
                                          "evidence": {"sourceRouting": {"path": "previously-valid-pin"}}}))
            with patch.object(attestation, "CONFIG", config), patch.object(attestation, "snapshot", return_value={}), \
                    patch.object(attestation.cutover, "cutover") as coordinator:
                attestation.invalidate("10.40.11.37")
                self.assertNotIn("sourceRouting", json.loads(config.read_text())["evidence"])
                with self.assertRaises(attestation.cutover.Blocked):
                    attestation.execute(Path(directory) / "rehearsal.json")
                coordinator.assert_not_called()


class RetiredMethod(unittest.TestCase):
    def test_manual_deregistration_never_reaches_aws(self):
        operation = route.Operation.__new__(route.Operation)
        with self.assertRaises(route.Blocked):
            operation.handover()
        with self.assertRaises(route.Blocked):
            operation.verify()


if __name__ == "__main__":
    unittest.main()
