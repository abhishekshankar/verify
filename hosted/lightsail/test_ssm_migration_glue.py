"""Evidence transfer and orchestration failures, with no AWS or process calls."""
import base64
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hosted.lightsail import ssm_migration_glue as glue


class GlueTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.work = self.root / "cutover"
        self.work.mkdir(mode=0o700)
        self.current = self.root / "current"
        helpers = self.current / "hosted/lightsail"
        helpers.mkdir(parents=True)
        for name in ("cutover.py", "attest_source_route.py", "prepare_standalone_source.py", "recover_source_bridge.py"):
            shutil.copyfile(Path(glue.__file__).with_name(name), helpers / name)
        identity = self.root / "target-install.json"
        identity.write_text(json.dumps({"accountId": glue.ACCOUNT, "instanceId": glue.INSTANCE}))
        self.worker = glue.TARGET_WORKER.replace("/opt/verify-migration/cutover", str(self.work)).replace(
            "/opt/verify/current", str(self.current)).replace("/etc/verify/target-install.json", str(identity))
        self.calls = []

    def tearDown(self):
        self.directory.cleanup()

    def payload(self, mode="execute", age=0):
        raw = json.dumps({"status": "STANDALONE_SOURCE_TASK_READY" if mode == "prepare" else
                          "SOURCE_HTTP_DRAIN_AND_WRITER_NETWORK_VERIFIED",
                          "capturedAtUtc": (datetime.now(timezone.utc)-timedelta(seconds=age)).isoformat()}).encode()
        value = {"mode": mode, "intentId": "fixture", "evidence": {
            "sha256": hashlib.sha256(raw).hexdigest(), "s3": {
                "bucket": glue.BUCKET, "key": "live/verify-ledger/routing/standalone-source-20261114/token/proof.json",
                "versionId": "exact-version"}}}
        path = self.work / "abcdef012345-rehearsal.json"
        report = {"status": "REHEARSAL_PASSED", "capturedAtUtc": datetime.now(timezone.utc).isoformat(), "measuredSeconds": 3}
        path.write_text(json.dumps(report)); path.chmod(0o600)
        value["rehearsal"] = {"report": str(path), "reportSha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        return value, raw

    def invoke(self, payload, raw, *, version="exact-version", encryption="AES256", child=None):
        s3 = Mock()
        s3.get_object.return_value = {"ContentLength": len(raw), "VersionId": version,
                                      "ServerSideEncryption": encryption, "Body": io.BytesIO(raw)}
        modules = {"boto3": SimpleNamespace(client=Mock(return_value=s3)),
                   "botocore": SimpleNamespace(), "botocore.config": SimpleNamespace(Config=lambda **kw: kw)}

        def run(command, **kwargs):
            self.calls.append((command, kwargs))
            if child:
                return child(command, kwargs)
            action = command[3]
            statuses = {"prepare": "STANDALONE_SOURCE_TRANSITION_VERIFIED", "accept": "SOURCE_ROUTING_EVIDENCE_PINNED",
                        "execute": "TARGET_AUTHORITATIVE", "rehearse": "REHEARSAL_PASSED"}
            return subprocess.CompletedProcess(command, 0, json.dumps({"status": statuses[action]}).encode(), b"")

        output = io.StringIO()
        original_stat = Path.stat
        def root_owned_stat(path, *args, **kwargs):
            observed = list(original_stat(path, *args, **kwargs))
            observed[4] = 0
            return os.stat_result(observed)
        previous_umask = os.umask(0o077)
        try:
            with patch.dict(sys.modules, modules), patch.object(sys, "argv", ["worker", base64.b64encode(json.dumps(payload).encode()).decode()]), \
                    patch.object(subprocess, "run", side_effect=run), patch.object(os, "geteuid", return_value=0), \
                    patch.object(Path, "stat", root_owned_stat), contextlib.redirect_stdout(output):
                try:
                    exec(compile(self.worker, "reviewed-target-worker", "exec"), {})
                except SystemExit as error:
                    self.assertEqual(error.code, 2)
        finally:
            os.umask(previous_umask)
        return json.loads(output.getvalue()), s3

    def test_exact_version_download_precedes_accept_and_execute(self):
        payload, raw = self.payload()
        with patch.dict(os.environ, {"PGHOST": "must-not-propagate", "VERIFY_DB_PASSWORD": "fixture-only"}):
            result, s3 = self.invoke(payload, raw)
        self.assertEqual(result["status"], "TARGET_AUTHORITATIVE")
        self.assertEqual([call[0][3] for call in self.calls], ["accept", "execute"])
        self.assertEqual(s3.get_object.call_args.kwargs["VersionId"], "exact-version")
        self.assertEqual(s3.get_object.call_args.kwargs["ExpectedBucketOwner"], glue.ACCOUNT)
        for command, kwargs in self.calls:
            self.assertEqual(command[0], str(self.current / ".venv/bin/python"))
            self.assertNotIn("PGHOST", kwargs["env"])
            self.assertNotIn("VERIFY_DB_PASSWORD", kwargs["env"])
            self.assertEqual(kwargs["env"]["PGPASSFILE"], str(self.work / "source.pgpass"))

    def test_wrong_object_version_blocks_before_any_target_command(self):
        payload, raw = self.payload()
        result, _ = self.invoke(payload, raw, version="other-version")
        self.assertEqual(result["status"], "SSM_GLUE_BLOCKED")
        self.assertEqual(self.calls, [])

    def test_wrong_content_checksum_blocks_before_any_target_command(self):
        payload, raw = self.payload()
        result, _ = self.invoke(payload, raw+b" ")
        self.assertEqual(result["status"], "SSM_GLUE_BLOCKED")
        self.assertEqual(self.calls, [])

    def test_stale_ready_blocks_before_bridge_restart(self):
        payload, raw = self.payload("prepare", age=121)
        result, _ = self.invoke(payload, raw)
        self.assertEqual(result["status"], "SSM_GLUE_BLOCKED")
        self.assertEqual(self.calls, [])

    def test_changed_deployed_coordinator_blocks_before_object_download(self):
        (self.current / "hosted/lightsail/cutover.py").write_text("# changed\n")
        payload, raw = self.payload()
        result, s3 = self.invoke(payload, raw)
        self.assertEqual(result["status"], "SSM_GLUE_BLOCKED")
        s3.get_object.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_failed_accept_never_starts_coordinator(self):
        payload, raw = self.payload()
        result, _ = self.invoke(payload, raw, child=lambda command, kwargs:
                                subprocess.CompletedProcess(command, 2, b'{"status":"BLOCKED"}', b"private diagnostic"))
        self.assertEqual(result["status"], "SSM_GLUE_BLOCKED")
        self.assertEqual([call[0][3] for call in self.calls], ["accept"])
        self.assertNotIn("private diagnostic", json.dumps(result))
        self.assertEqual(len(list(self.work.glob("glue-error-*.json"))), 1)

    def test_rehearsal_checksum_change_blocks_before_accept(self):
        payload, raw = self.payload()
        Path(payload["rehearsal"]["report"]).write_text("{}")
        result, _ = self.invoke(payload, raw)
        self.assertEqual(result["status"], "SSM_GLUE_BLOCKED")
        self.assertEqual(self.calls, [])

    def test_payload_remains_data_and_never_becomes_shell_code(self):
        payload = {"mode": "prepare", "intentId": "$(touch /forbidden)`id`\n'"}
        command = glue.command_for(payload)
        self.assertNotIn(payload["intentId"], command)
        first = command.splitlines()[0].split()
        self.assertEqual(json.loads(base64.b64decode(first[2])), payload)
        compile(glue.TARGET_WORKER, "reviewed-target-worker", "exec")

    def test_poll_has_a_bound_and_never_resubmits(self):
        ssm = Mock()
        ssm.get_command_invocation.return_value = {"Status": "InProgress"}
        with patch.object(glue.time, "monotonic", side_effect=[0, 1, 46]), patch.object(glue.time, "sleep"):
            result = glue.poll(ssm, "existing-id")
        self.assertEqual(result["ssmStatus"], "PENDING")
        self.assertEqual(result["commandId"], "existing-id")
        ssm.send_command.assert_not_called()

    def test_only_successful_rehearsal_is_saved_for_execution(self):
        ssm = Mock()
        result = {"status": "REHEARSAL_PASSED", "reportSha256": "a"*64, "reportCapturedAtUtc": datetime.now(timezone.utc).isoformat()}
        ssm.get_command_invocation.return_value = {"Status": "Failed", "ResponseCode": 2, "StandardOutputContent": json.dumps(result)}
        rehearsal = self.root / "last.json"
        with patch.object(glue, "ROOT", self.root), patch.object(glue, "REHEARSAL", rehearsal):
            glue.poll(ssm, "failed")
            self.assertFalse(rehearsal.exists())
            ssm.get_command_invocation.return_value.update(Status="Success", ResponseCode=0)
            glue.poll(ssm, "success")
            self.assertEqual(json.loads(rehearsal.read_text()), result)

    def test_lost_submit_response_persists_intent_and_blocks_second_execute(self):
        args = SimpleNamespace(operation="execute", route_script=Path("reviewed.py"), command_id=None)
        ssm = Mock()
        ssm.send_command.side_effect = OSError("injected response loss")
        with patch.object(glue, "ROOT", self.root), patch.object(glue, "read_rehearsal_record", return_value={}), \
                patch.object(glue, "fresh_evidence", return_value={}), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(OSError):
                glue.operate(args, ssm)
            record = glue.pending_execution()
            self.assertNotIn("commandId", record)
            self.assertEqual(record["submissionState"], "MAY_HAVE_BEEN_SUBMITTED")
            with self.assertRaisesRegex(RuntimeError, "intent already exists"):
                glue.operate(args, ssm)
        self.assertEqual(ssm.send_command.call_count, 1)

    def test_discovery_recovers_only_exact_saved_submission(self):
        payload = {"mode": "execute", "intentId": "a"*32}
        command = glue.command_for(payload)
        ssm = Mock()
        with patch.object(glue, "ROOT", self.root):
            record = glue.reserve_execution(payload, command)
            ssm.list_commands.side_effect = [
                {"Commands": [{"Comment": "unrelated"}], "NextToken": "next"},
                {"Commands": [{"Comment": record["comment"], "InstanceIds": [glue.INSTANCE],
                               "DocumentName": "AWS-RunShellScript", "Parameters": {"commands": [command]}, "CommandId": "found-id"}]}]
            result = glue.discover_execution(ssm, record)
            self.assertEqual(result["commandId"], "found-id")
            self.assertEqual(glue.pending_execution()["commandId"], "found-id")
        self.assertEqual(ssm.list_commands.call_args_list[1].kwargs["NextToken"], "next")
        ssm.send_command.assert_not_called()

    def test_empty_discovery_never_clears_execute_intent(self):
        payload = {"mode": "execute", "intentId": "b"*32}
        ssm = Mock()
        ssm.list_commands.return_value = {"Commands": []}
        with patch.object(glue, "ROOT", self.root):
            record = glue.reserve_execution(payload, glue.command_for(payload))
            with self.assertRaisesRegex(RuntimeError, "exactly one submission"):
                glue.discover_execution(ssm, record)
            self.assertEqual(glue.pending_execution(), record)
            with self.assertRaisesRegex(RuntimeError, "intent already exists"):
                glue.reserve_execution(payload, glue.command_for(payload))
        ssm.send_command.assert_not_called()

    def test_same_comment_with_changed_payload_stays_blocked(self):
        payload = {"mode": "execute", "intentId": "c"*32}
        ssm = Mock()
        with patch.object(glue, "ROOT", self.root):
            record = glue.reserve_execution(payload, glue.command_for(payload))
            ssm.list_commands.return_value = {"Commands": [{"Comment": record["comment"], "InstanceIds": [glue.INSTANCE],
                "DocumentName": "AWS-RunShellScript", "Parameters": {"commands": ["changed"]}, "CommandId": "wrong-id"}]}
            with self.assertRaisesRegex(RuntimeError, "different target or payload"):
                glue.discover_execution(ssm, record)
            self.assertNotIn("commandId", glue.pending_execution())
        ssm.send_command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
