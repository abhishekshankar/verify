"""Offline deletion, before-state, encryption and authority boundary tests."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from hosted.lightsail import retire_source as retire


def proof():
    return {"status": "TARGET_LIVE_READ_ONLY_PROOF_PASSED", "capturedAtUtc": retire.now(),
            "accountId": retire.ACCOUNT, "instanceId": retire.INSTANCE, "cutoverReportSha256": "a"*64,
            "bridge": {"mode": "target", "targetActivated": True, "queueTimeouts": 0, "queued": 0},
            "latestFullBackup": {"startedAfterCutover": True},
            "targetDatabase": {"chainsOk": True, "readOnlyConsistentSnapshot": True},
            "sourceFence": {"checked": True, "admissionAllowed": False, "remainingVerifySessions": 0, "sourceHost": retire.SOURCE_HOST},
            "recoveryMaterial": {"finalDump": {"downloadedAndHashed": True}, "recoveryParameters": {
                name.rsplit("/", 1)[1]: {"decryptedAndByteMatched": True} for name in retire.PARAMETERS}}}


class Flow(retire.Retirement):
    def __init__(self):
        self.events = []
        self.saved = {"operationId": retire.OPERATION, "instanceId": retire.INSTANCE, "accountId": retire.ACCOUNT,
            "phase": "BEFORE_STATE_SAVED", "dbiResourceId": "db-original", "kmsKeyId": "key-original",
            "standaloneTaskArn": "task-pinned", "before": {}, "cutoverReportSha256": "a"*64}
        self.db = {"DBInstanceStatus": "available", "DbiResourceId": "db-original", "KmsKeyId": "key-original", "DeletionProtection": False}
        self.task = {"taskArn": "task-pinned", "lastStatus": "STOPPED", "desiredStatus": "STOPPED"}
        self.active = []
        self.current_proof = proof()
        self.history = {"Status": "retained", "KmsKeyId": "key-original", "RestoreWindow": {"EarliestTime": "earlier", "LatestTime": "later"}}
        self.clients = {"rds": self, "ecs": self}
        self.proof_sha256 = "b"*64
        self.lose_delete_response = False

    def state(self):
        return deepcopy(self.saved)

    def checked_state(self):
        self.proof()
        return self.state()

    def proof(self, require_source=True):
        self.events.append("proof")
        return retire.check_proof(self.current_proof, require_source)

    def target(self):
        self.events.append("protected-target")
        return {}

    def source(self):
        return {"standalone": self.task, "activeTaskArns": self.active}

    def database(self):
        self.events.append("read-rds")
        return deepcopy(self.db)

    def automated(self, resource_id):
        self.events.append("read-history:"+resource_id)
        return self.history

    def quick_target_gate(self):
        self.events.append("fresh-target-gate")
        return {"status": "TARGET_RETIREMENT_GATE_PASSED"}

    def archive(self, label, value):
        self.events.append("archive:"+label)
        return {"key": label, "versionId": "version", "sha256": "c"*64}

    def save(self, value):
        self.events.append("save:"+value["phase"])
        value["_s3VersionId"] = "saved-version"
        self.saved = deepcopy(value)

    def stop_task(self, **arguments):
        self.events.append("stop-task")
        self.stop_arguments = arguments

    def modify_db_instance(self, **arguments):
        self.events.append("modify-rds")
        self.modify_arguments = arguments

    def delete_db_instance(self, **arguments):
        self.events.append("delete-rds")
        self.delete_arguments = arguments
        self.db["DBInstanceStatus"] = "deleting"
        if self.lose_delete_response:
            raise OSError("injected response loss")


class ProofTests(unittest.TestCase):
    def test_target_postbackup_and_all_independent_recovery_values_required(self):
        retire.check_proof(proof())
        for section, key, replacement in (
                ("bridge", "mode", "source"), ("bridge", "targetActivated", False),
                ("latestFullBackup", "startedAfterCutover", False),
                ("sourceFence", "admissionAllowed", True), ("sourceFence", "remainingVerifySessions", 1)):
            value = proof(); value[section][key] = replacement
            with self.subTest(section=section, key=key), self.assertRaises(retire.Blocked):
                retire.check_proof(value)
        value = proof(); value["recoveryMaterial"]["recoveryParameters"].pop("export-key")
        with self.assertRaises(retire.Blocked):
            retire.check_proof(value)

    def test_stale_proof_blocks_retirement(self):
        value = proof(); value["capturedAtUtc"] = (datetime.now(timezone.utc)-timedelta(seconds=301)).isoformat()
        with self.assertRaises(retire.Blocked):
            retire.check_proof(value)

    def test_permanent_policy_is_exact_reads_with_context_bound_keys(self):
        policy = retire.recovery_policy({"arn:aws:kms:us-west-2:842676017161:key/exact-key"})
        read, decrypt = policy["Statement"]
        self.assertEqual(read["Action"], "ssm:GetParameter")
        self.assertEqual(len(read["Resource"]), 4)
        self.assertFalse(any("*" in value for value in read["Resource"]+decrypt["Resource"]))
        self.assertEqual(decrypt["Action"], "kms:Decrypt")
        self.assertEqual(decrypt["Condition"]["StringEquals"]["kms:EncryptionContext:PARAMETER_ARN"], read["Resource"])
        self.assertNotIn("DateLessThan", json.dumps(policy))
        self.assertNotIn("PutParameter", json.dumps(policy))


class RetirementOrderTests(unittest.TestCase):
    def test_stop_requires_saved_intent_and_targets_only_pinned_task(self):
        flow = Flow(); flow.task.update(lastStatus="RUNNING", desiredStatus="RUNNING"); flow.active = ["task-pinned"]
        self.assertEqual(flow.stop_source()["status"], "SOURCE_TASK_STOP_REQUESTED")
        self.assertLess(flow.events.index("archive:stop-source-intent"), flow.events.index("save:SOURCE_TASK_STOP_INTENT"))
        self.assertLess(flow.events.index("save:SOURCE_TASK_STOP_INTENT"), flow.events.index("stop-task"))
        self.assertEqual(flow.stop_arguments["task"], "task-pinned")
        self.assertNotIn("delete-rds", flow.events)

    def test_failed_before_state_archive_prevents_stop(self):
        flow = Flow(); flow.task.update(lastStatus="RUNNING", desiredStatus="RUNNING")
        flow.archive = Mock(side_effect=retire.Blocked("injected archive failure"))
        with self.assertRaises(retire.Blocked):
            flow.stop_source()
        self.assertNotIn("stop-task", flow.events)

    def test_stopping_process_prevents_database_delete(self):
        flow = Flow(); flow.task.update(lastStatus="STOPPING")
        with self.assertRaises(retire.Blocked):
            flow.delete_rds()
        self.assertNotIn("delete-rds", flow.events)

    def test_database_identifier_reuse_prevents_delete(self):
        flow = Flow(); flow.db["DbiResourceId"] = "different-resource"
        with self.assertRaises(retire.Blocked):
            flow.delete_rds()
        self.assertNotIn("delete-rds", flow.events)

    def test_retention_false_is_explicit_and_intent_saved_before_delete(self):
        flow = Flow()
        self.assertEqual(flow.delete_rds()["status"], "SOURCE_RDS_DELETION_REQUESTED")
        self.assertEqual(flow.delete_arguments,
                         {"DBInstanceIdentifier": "verify-ledger", "SkipFinalSnapshot": True, "DeleteAutomatedBackups": False})
        self.assertLess(flow.events.index("archive:delete-source-rds-intent"), flow.events.index("save:RDS_DELETE_INTENT"))
        self.assertLess(flow.events.index("save:RDS_DELETE_INTENT"), flow.events.index("delete-rds"))
        self.assertEqual(flow.events[-2:], ["read-rds", "delete-rds"])

    def test_protection_removal_does_not_delete_in_same_call(self):
        flow = Flow(); flow.db["DeletionProtection"] = True
        self.assertEqual(flow.delete_rds()["status"], "SOURCE_RDS_PROTECTION_REMOVAL_REQUESTED")
        self.assertEqual(flow.modify_arguments, {"DBInstanceIdentifier": "verify-ledger", "DeletionProtection": False, "ApplyImmediately": True})
        self.assertNotIn("delete-rds", flow.events)

    def test_lost_delete_response_is_observed_without_resubmission(self):
        flow = Flow(); flow.lose_delete_response = True
        with self.assertRaises(OSError):
            flow.delete_rds()
        self.assertIn("deleteIntent", flow.saved)
        self.assertEqual(flow.delete_rds()["databaseStatus"], "deleting")
        self.assertEqual(flow.events.count("delete-rds"), 1)

    def test_changed_backup_key_blocks_deletion(self):
        flow = Flow(); flow.history["KmsKeyId"] = "unexpected-key"
        with self.assertRaises(retire.Blocked):
            flow.delete_rds()
        self.assertNotIn("delete-rds", flow.events)

    def test_missing_database_without_pinned_intent_is_not_claimed_retired(self):
        flow = Flow(); flow.db = None
        with self.assertRaises(retire.Blocked):
            flow.status()

    def test_completed_deletion_requires_actual_retained_backup(self):
        flow = Flow(); flow.db = None; flow.saved["deleteIntent"] = {"versionId": "intent"}; flow.history["Status"] = "active"
        with self.assertRaises(retire.Blocked):
            flow.status()
        flow.history["Status"] = "retained"
        result = flow.status()
        self.assertEqual(result["status"], "VERIFY_SOURCE_TASK_AND_RDS_RETIRED")
        self.assertEqual(flow.saved["phase"], "SOURCE_TASK_AND_RDS_RETIRED")


class EncryptionTests(unittest.TestCase):
    def test_changed_permanent_policy_blocks_each_destructive_state_gate(self):
        instance = object.__new__(retire.Retirement)
        before = b'{"before":"verified"}'
        import hashlib
        state = {"cutoverReportSha256": "a"*64, "before": {"key": "before.json", "versionId": "exact",
                  "sha256": hashlib.sha256(before).hexdigest()}}
        instance.state = Mock(return_value=state)
        instance.proof = Mock(return_value=proof())
        instance.read_object = Mock(return_value=(before, {}))
        instance.target = Mock(return_value={})
        keys = {"arn:aws:kms:us-west-2:842676017161:key/exact-key"}
        instance.recovery_parameters = Mock(return_value=(keys, []))
        instance.policies = Mock(return_value={retire.READ_POLICY: {"Version": "2012-10-17", "Statement": []}})
        with self.assertRaises(retire.Blocked):
            instance.checked_state()
        instance.policies.return_value = {retire.READ_POLICY: retire.recovery_policy(keys)}
        self.assertEqual(instance.checked_state(), state)

    def test_retained_history_rejects_disabled_or_pending_deletion_key(self):
        history = {"DbiResourceId": "db-original", "DBInstanceArn": retire.DB_ARN, "Encrypted": True,
                   "BackupRetentionPeriod": 7, "RestoreWindow": {"EarliestTime": "earlier", "LatestTime": "later"},
                   "KmsKeyId": "arn:aws:kms:us-west-2:842676017161:key/key-original"}
        instance = object.__new__(retire.Retirement)
        rds, kms = Mock(), Mock(); instance.clients = {"rds": rds, "kms": kms}
        rds.describe_db_instance_automated_backups.return_value = {"DBInstanceAutomatedBackups": [history]}
        for state, deletion in (("Disabled", None), ("PendingDeletion", "future"), ("Enabled", "future")):
            key = {"Arn": history["KmsKeyId"], "KeyState": state}
            if deletion:
                key["DeletionDate"] = deletion
            kms.describe_key.return_value = {"KeyMetadata": key}
            with self.subTest(state=state, deletion=deletion), self.assertRaises(retire.Blocked):
                instance.automated("db-original")
        kms.describe_key.return_value = {"KeyMetadata": {"Arn": history["KmsKeyId"], "KeyState": "Enabled"}}
        self.assertEqual(instance.automated("db-original"), history)
        self.assertEqual(rds.describe_db_instance_automated_backups.call_args.kwargs, {"DbiResourceId": "db-original"})


if __name__ == "__main__":
    unittest.main()
