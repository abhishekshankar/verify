#!/usr/bin/env python3
"""Execute an isolated, same-host encrypted S3 PostgreSQL PITR restore test.

This is an operator command, not an auto-discovered unit test. Primary remains on
5432; restored copy uses loopback/Unix5433 and a newly created data directory.
Only a synthetic probe table in the private target's postgres DB is modified.
"""
import argparse
import configparser
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid

from hosted.lightsail.cutover import Blocked, Runner, durable_target_state, write_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-instance-id", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    work = Path("/opt/verify-migration")
    runner = Runner({"workDirectory": str(work)})
    token = uuid.uuid4().hex[:12]
    restore_dir = Path("/var/lib/postgresql") / ("verify-pitr-" + token)
    backup_config = Path(str(restore_dir) + "-pgbackrest.conf")
    probe = "verify_restore_probe_" + token
    started = start_attempted = probe_created = passed = False
    report = None
    try:
        if os.geteuid() != 0:
            raise Blocked("Restore test requires the new target administrator")
        installed = json.loads(Path("/etc/verify/target-install.json").read_text())
        if installed.get("instanceId") != args.expected_instance_id or installed.get("accountId") != "842676017161":
            raise Blocked("Target identity mismatch")
        state = json.loads(Path("/var/lib/verify-migration/state.json").read_text())
        if durable_target_state() is not False or state["mode"] != "source":
            raise Blocked("Run the restore test only while SOURCE remains authoritative")
        if Path("/etc/verify/production-writer-enabled").exists():
            raise Blocked("A target writer marker already exists")
        if shutil.disk_usage("/var/lib/postgresql").free < 2 * 1024**3:
            raise Blocked("Insufficient free disk for a separate recovery copy")
        with socket.socket() as probe_socket:
            probe_socket.bind(("127.0.0.1", 5433))
        config = configparser.ConfigParser(interpolation=None)
        config.read("/etc/pgbackrest/pgbackrest.conf")
        expected = {"repo1-type": "s3", "repo1-s3-region": "us-west-2",
                    "repo1-s3-bucket": "verify-ledger-migration-842676017161-20261114",
                    "repo1-path": "/live/verify-ledger/pgbackrest", "repo1-cipher-type": "aes-256-cbc"}
        if any(config.get("global", key, fallback=None) != value for key, value in expected.items()):
            raise Blocked("Backup destination/encryption differs from the reviewed policy")
        import boto3
        actual_region = boto3.client("s3", region_name="us-west-2").get_bucket_location(
            Bucket=expected["repo1-s3-bucket"]).get("LocationConstraint") or "us-east-1"
        if actual_region != expected["repo1-s3-region"]:
            raise Blocked("Live backup bucket region does not match the restore configuration")
        recovered = boto3.client("ssm", region_name="us-west-2").get_parameter(
            Name="/verify-ledger/infra/backup-cipher-key", WithDecryption=True)["Parameter"]
        if recovered["Type"] != "SecureString" or not hmac.compare_digest(
                recovered["Value"], config.get("global", "repo1-cipher-pass")):
            raise Blocked("Independent encryption-key recovery failed")
        # Restore uses the independently recovered key, not the live local key file.
        config.set("global", "repo1-cipher-pass", recovered["Value"])
        with backup_config.open("x") as output:
            config.write(output)
        os.chmod(backup_config, 0o640)
        runner.run(["chown", "root:postgres", str(backup_config)])
        before = runner.inspect("verify")
        if not before["chainsOk"]:
            raise Blocked("The rehearsal database chain is not valid")
        runner.pg(f'CREATE TABLE public."{probe}" (step text PRIMARY KEY); INSERT INTO public."{probe}" VALUES (\'seed\');')
        probe_created = True
        runner.run(["runuser", "-u", "postgres", "--", "pgbackrest", "--stanza=verify", "--type=full", "backup"], maximum=180)
        info = json.loads(runner.run(["runuser", "-u", "postgres", "--", "pgbackrest", "--stanza=verify", "--output=json", "info"]))
        full = [backup for backup in info[0].get("backup", []) if backup.get("type") == "full"]
        if not full:
            raise Blocked("No completed off-host full backup exists")
        label = max(full, key=lambda item: item["timestamp"]["stop"])["label"]
        runner.pg(f'INSERT INTO public."{probe}" VALUES (\'kept\');')
        cutoff = runner.pg("SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US') || '+00';").decode().strip()
        time.sleep(.05)
        runner.pg(f'INSERT INTO public."{probe}" VALUES (\'excluded\');')
        runner.archive_check()
        runner.run(["install", "-d", "-m", "0700", "-o", "postgres", "-g", "postgres", str(restore_dir)])
        runner.run(["runuser", "-u", "postgres", "--", "pgbackrest", "--config=" + str(backup_config),
                    "--stanza=verify", "--set=" + label, "--pg1-path=" + str(restore_dir),
                    "--type=time", "--target=" + cutoff, "--target-action=promote", "restore"], maximum=180)
        pg_config = restore_dir / "postgresql.conf"
        pg_config.write_text(f"data_directory='{restore_dir}'\nport=5433\nlisten_addresses='127.0.0.1'\n"
            f"unix_socket_directories='/var/run/postgresql'\nhba_file='{restore_dir}/pg_hba.conf'\n"
            "ssl=off\narchive_mode=off\nshared_buffers='64MB'\nmax_connections=100\nhot_standby=on\n")
        (restore_dir / "pg_hba.conf").write_text("local all postgres peer\nlocal all all reject\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n")
        runner.run(["chown", "postgres:postgres", str(pg_config), str(restore_dir / "pg_hba.conf")])
        start_attempted = True
        runner.run(["runuser", "-u", "postgres", "--", "/usr/lib/postgresql/16/bin/pg_ctl", "-D", str(restore_dir),
                    "-l", str(restore_dir / "restore-server.log"), "-o", "-c config_file=" + str(pg_config),
                    "-w", "-t", "30", "start"], maximum=35)
        started = True
        query_command = ["runuser", "-u", "postgres", "--", "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                         "-h", "/var/run/postgresql", "-p", "5433", "-U", "postgres", "-d", "postgres"]
        deadline = time.monotonic() + 30
        while runner.run(query_command, b"SELECT pg_is_in_recovery();").decode().strip() != "f":
            if time.monotonic() > deadline:
                raise Blocked("Restored server did not reach the requested recovery timestamp")
            time.sleep(.1)
        steps = runner.run(query_command, f'SELECT step FROM public."{probe}" ORDER BY step;'.encode()).decode().split()
        if steps != ["kept", "seed"]:
            raise Blocked("PITR failed to retain the earlier probe and exclude the later commit")
        restored = json.loads(runner.run(["runuser", "-u", "postgres", "--", "/opt/verify/current/.venv/bin/python", "-m",
            "hosted.lightsail.cutover", "inspect", "--database", "verify", "--port", "5433"]))
        if restored != before or not restored["chainsOk"]:
            raise Blocked("Restored application data/chains differ from the pre-backup copy")
        report = {"schemaVersion": 1, "status": "ENCRYPTED_S3_PITR_RESTORE_VERIFIED", "instanceId": args.expected_instance_id,
                  "capturedAtUtc": datetime.now(timezone.utc).isoformat(), "backupLabel": label, "recoveryTargetUtc": cutoff,
                  "earlierProbeRetained": True, "laterProbeExcluded": True, "applicationDataMatch": True,
                  "data": restored, "cipher": "aes-256-cbc", "backupRegion": actual_region,
                  "bucketLocationVerified": True, "independentCipherParameterVersion": recovered["Version"],
                  "sourceAuthoritative": True, "restoredPort": 5433,
                  "scope": "Separate off-host-backup+WAL restore; source RDS and production traffic unchanged"}
        passed = True
    except Exception as exc:
        report = {"schemaVersion": 1, "status": "PITR_TEST_BLOCKED", "errorClass": type(exc).__name__,
                  "reason": str(exc) if isinstance(exc, Blocked) else "Private restore test failed; details suppressed",
                  "restoreDirectory": str(restore_dir), "capturedAtUtc": datetime.now(timezone.utc).isoformat()}
    finally:
        try:
            if start_attempted:
                status = subprocess.run(["runuser", "-u", "postgres", "--", "/usr/lib/postgresql/16/bin/pg_ctl",
                    "-D", str(restore_dir), "status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                    env={key: value for key, value in runner.env.items() if not key.startswith("PG")})
                if status.returncode == 0:
                    runner.run(["runuser", "-u", "postgres", "--", "/usr/lib/postgresql/16/bin/pg_ctl", "-D", str(restore_dir),
                                "-m", "fast", "-w", "-t", "15", "stop"], maximum=20)
                elif status.returncode != 3:
                    raise Blocked("Cannot prove the separate recovery server is stopped")
            if probe_created:
                runner.pg(f'DROP TABLE public."{probe}";')
            if passed:
                shutil.rmtree(restore_dir)
                backup_config.unlink(missing_ok=True)
        except Exception as cleanup:
            passed = False
            report["status"] = "PITR_TEST_CLEANUP_REQUIRED"
            report["cleanupErrorClass"] = type(cleanup).__name__
        output = work / ("pitr-restore-" + token + ".json")
        write_report(output, report)
    if passed:
        data = (json.dumps(report, indent=2) + "\n").encode()
        location = "live/verify-ledger/verification/" + output.name
        saved = boto3.client("s3", region_name="us-west-2").put_object(
            Bucket="verify-ledger-migration-842676017161-20261114", Key=location,
            Body=data, ServerSideEncryption="AES256", ContentType="application/json")
        if not saved.get("VersionId") or saved.get("ServerSideEncryption") != "AES256":
            raise Blocked("Restore evidence was not durably saved")
        runner.run(["systemctl", "enable", "--now", "verify-backup.timer"])
        print(json.dumps({"status": report["status"], "report": str(output), "s3Key": location,
                          "s3VersionId": saved["VersionId"], "reportSha256": hashlib.sha256(data).hexdigest(),
                          "dailyBackupTimerEnabled": True, "productionWriterEnabled": False}))
        return 0
    print(json.dumps({"status": report["status"], "report": str(output)}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
