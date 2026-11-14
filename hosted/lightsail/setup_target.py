#!/usr/bin/env python3
"""Prepare only the private EC2 database, credentials and encrypted backups.

No production writer marker, public routing, source database change or secret
rotation. Uses exact existing export-key bytes; new target secrets are saved to
independent SSM SecureString parameters and verified before use.
"""
import argparse
import configparser
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import uuid

from hosted.lightsail.cutover import Blocked, ROOT, Runner, durable_target_state, write_report

ACCOUNT = "842676017161"
BUCKET = "verify-ledger-migration-842676017161-20261114"
BACKUP_REGION = "us-west-2"
EXPORT_SECRET = "arn:aws:secretsmanager:us-west-2:842676017161:secret:verify-ledger/export-key-JkD827"
PARAMETER_ROOT = "/verify-ledger/infra/"


def private_file(path, value):
    data = value.encode()
    if path.exists():
        if not hmac.compare_digest(path.read_bytes(), data) or path.stat().st_mode & 0o077:
            raise Blocked("An existing credential file differs or is not private")
        return
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def recoverable_secret(ssm, label, filename, initial=None):
    name = PARAMETER_ROOT + label
    path = Path("/etc/verify/secrets") / filename
    try:
        response = ssm.get_parameter(Name=name, WithDecryption=True)
        if response["Parameter"]["Type"] != "SecureString":
            raise Blocked("Existing recovery parameter is not encrypted")
        value = response["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        value = path.read_text() if path.exists() else (initial if initial is not None else secrets.token_urlsafe(48))
        if initial is not None and not hmac.compare_digest(value.encode(), initial.encode()):
            raise Blocked("Existing export credential differs from the source")
        ssm.put_parameter(Name=name, Type="SecureString", Value=value, Tier="Standard", Overwrite=False,
                          Description="Verify ledger infrastructure recovery credential")
    if initial is not None and not hmac.compare_digest(value.encode(), initial.encode()):
        raise Blocked("Existing recovery credential differs from the exact source export key")
    recovered = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]
    if recovered["Type"] != "SecureString" or not hmac.compare_digest(value.encode(), recovered["Value"].encode()):
        raise Blocked("Independent encrypted credential readback failed")
    private_file(path, value)
    return value, {"name": name, "version": recovered["Version"], "sha256": hashlib.sha256(value.encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-instance-id", required=True)
    parser.add_argument("--source-dump", type=Path, required=True)
    parser.add_argument("--dump-sha256", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    work = Path("/opt/verify-migration")
    try:
        if os.geteuid() != 0:
            raise Blocked("Run only as root on the new private target")
        installed = json.loads(Path("/etc/verify/target-install.json").read_text())
        if installed["instanceId"] != args.expected_instance_id or installed["accountId"] != ACCOUNT:
            raise Blocked("Target installation identity mismatch")
        if durable_target_state() is not False or json.loads(Path("/var/lib/verify-migration/state.json").read_text())["mode"] != "source":
            raise Blocked("Setup is allowed only before target activation, in SOURCE mode")
        if Path("/etc/verify/production-writer-enabled").exists():
            raise Blocked("A target writer marker already exists; inspect before setup")
        if subprocess.run(["systemctl", "is-active", "--quiet", "verify.service"]).returncode == 0:
            raise Blocked("The private target app must be stopped during setup")
        if not re.fullmatch(r"[a-f0-9]{64}", args.dump_sha256) or hashlib.sha256(args.source_dump.read_bytes()).hexdigest() != args.dump_sha256:
            raise Blocked("Source rehearsal dump checksum mismatch")
        if work.stat().st_mode & 0o077:
            raise Blocked("Migration directory must be private")
        import boto3
        if boto3.client("sts", region_name="us-west-2").get_caller_identity()["Account"] != ACCOUNT:
            raise Blocked("AWS caller account mismatch")
        actual_region = boto3.client("s3", region_name=BACKUP_REGION).get_bucket_location(Bucket=BUCKET).get("LocationConstraint") or "us-east-1"
        if actual_region != BACKUP_REGION:
            raise Blocked("Backup bucket region differs from the verified configuration")
        ssm = boto3.client("ssm", region_name="us-west-2")
        source_key = boto3.client("secretsmanager", region_name="us-west-2").get_secret_value(SecretId=EXPORT_SECRET)
        exact_key = source_key.get("SecretString")
        if not isinstance(exact_key, str) or not 32 <= len(exact_key.encode()) <= 65536 or "\0" in exact_key:
            raise Blocked("Source export key format differs from the reviewed application")
        _, export_record = recoverable_secret(ssm, "export-key", "export-key", initial=exact_key)
        runtime, runtime_record = recoverable_secret(ssm, "runtime-db-password", "db-password")
        maintenance, maintenance_record = recoverable_secret(ssm, "maintenance-db-password", "maintenance-db-password")
        cipher, cipher_record = recoverable_secret(ssm, "backup-cipher-key", "backup-cipher-key")
        for value in (runtime, maintenance, cipher):
            if not re.fullmatch(r"[A-Za-z0-9_-]{40,128}", value):
                raise Blocked("Target-only credential format is unexpected")
        runner = Runner({"workDirectory": str(work)})
        roles = runner.pg("SELECT rolname FROM pg_roles WHERE rolname IN ('verify_owner','verify_app','verify_retention','verify_runtime','verify_maintenance') ORDER BY rolname;").decode().split()
        expected_roles = {"verify_owner", "verify_app", "verify_retention", "verify_runtime", "verify_maintenance"}
        if not roles:
            runner.pg((ROOT / "target_roles.sql").read_text())
        elif set(roles) != expected_roles:
            raise Blocked("Partial target roles exist; inspect instead of overwriting")
        # Values are restricted to generated URL-safe tokens and are sent on stdin,
        # never argv or process environment, and never written to shared logs.
        runner.pg(f"ALTER ROLE verify_runtime PASSWORD '{runtime}'; ALTER ROLE verify_maintenance PASSWORD '{maintenance}';")
        exists = runner.pg("SELECT count(*) FROM pg_database WHERE datname='verify';").decode().strip() == "1"
        if not exists:
            runner.pg("CREATE DATABASE verify OWNER verify_owner TEMPLATE template0 ENCODING 'UTF8';")
        checkpoint = Path("/etc/verify/data-rehearsal.json")
        if checkpoint.exists():
            if json.loads(checkpoint.read_text()).get("sourceDumpSha256") != args.dump_sha256:
                raise Blocked("Rehearsal checkpoint belongs to a different dump")
        else:
            relations = runner.pg("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','v','m','S','f','p');", "verify").decode().strip()
            if relations != "0":
                raise Blocked("Target already has uncheckpointed relations; inspect before restoring")
            runner.run(["runuser", "-u", "postgres", "--", "pg_restore", "--single-transaction", "--exit-on-error",
                        "--no-owner", "--role=verify_owner", "--host=/var/run/postgresql", "--port=5432",
                        "--username=postgres", "--dbname=verify"], args.source_dump.read_bytes())
            write_report(checkpoint, {"sourceDumpSha256": args.dump_sha256, "restoredAtUtc": datetime.now(timezone.utc).isoformat()})
        runner.pg((ROOT / "target_runtime_grants.sql").read_text(), "verify")
        runner.pg((ROOT / "runtime_preflight.sql").read_text(), "verify", expected="verify")
        data_check = runner.inspect("verify")
        if not data_check["chainsOk"]:
            raise Blocked("Restored application chains failed verification")
        configuration = ("[verify]\npg1-path=/var/lib/postgresql/16/main\npg1-socket-path=/var/run/postgresql\n\n"
            "[global]\nrepo1-type=s3\nrepo1-s3-region=us-west-2\nrepo1-s3-endpoint=s3.us-west-2.amazonaws.com\n"
            f"repo1-s3-bucket={BUCKET}\nrepo1-path=/live/verify-ledger/pgbackrest\nrepo1-s3-key-type=auto\n"
            f"repo1-cipher-type=aes-256-cbc\nrepo1-cipher-pass={cipher}\nrepo1-retention-full-type=time\n"
            "repo1-retention-full=7\nrepo1-bundle=y\ncompress-type=gz\nprocess-max=1\nstart-fast=y\nlog-level-console=warn\nlog-level-file=warn\n")
        path = Path("/etc/pgbackrest/pgbackrest.conf")
        path.parent.mkdir(mode=0o755, exist_ok=True)
        # mkdir's requested mode is masked by this script's private umask.
        # PostgreSQL must be able to traverse the directory to read its 0640 file.
        os.chmod(path.parent, 0o750)
        runner.run(["chown", "root:postgres", str(path.parent)])
        if path.exists() and path.read_text().strip() and path.read_text() != configuration:
            existing = configparser.ConfigParser(interpolation=None)
            existing.read(path)
            if existing.get("global", "repo1-cipher-pass", fallback=cipher) != cipher:
                raise Blocked("An existing backup encryption key differs; do not replace it")
        path.write_text(configuration)
        os.chmod(path, 0o640)
        runner.run(["chown", "root:postgres", str(path)])
        runner.run(["runuser", "-u", "postgres", "--", "pgbackrest", "--stanza=verify", "stanza-create"])
        runner.archive_check()
        test_database = "verify_stage_" + uuid.uuid4().hex[:12]
        runner.pg(f'CREATE DATABASE "{test_database}" OWNER postgres TEMPLATE template0 ENCODING \'UTF8\';')
        test_log = work / ("feature-tests-" + test_database + ".log")
        environment = {key: value for key, value in runner.env.items() if not key.startswith(("PG", "VERIFY_"))}
        environment.update(VERIFY_TEST_PG_DSN=f"host=/var/run/postgresql port=5432 user=postgres dbname={test_database}", VERIFY_DB_POOL="10")
        try:
            tests = subprocess.run(["runuser", "-u", "postgres", "--", "/opt/verify/current/.venv/bin/python", "-m",
                                    "unittest", "hosted.test_hosted", "-v"], env=environment,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            test_log.write_bytes(tests.stdout)
            os.chmod(test_log, 0o600)
            if tests.returncode or b"OK" not in tests.stdout:
                raise Blocked("Private PostgreSQL application feature tests failed; inspect private test log")
        finally:
            runner.pg(f'DROP DATABASE "{test_database}" WITH (FORCE);')
        report = {"schemaVersion": 1, "status": "PRIVATE_TARGET_RESTORED_FEATURE_TESTED_BACKUP_CONFIGURED",
                  "capturedAtUtc": datetime.now(timezone.utc).isoformat(), "instanceId": args.expected_instance_id,
                  "sourceDumpSha256": args.dump_sha256, "data": data_check,
                  "exportSourceSecretVersion": source_key["VersionId"], "recoveryCredentials": {
                      "runtime": runtime_record, "maintenance": maintenance_record, "cipher": cipher_record, "export": export_record},
                  "featureTestsPassed": True, "backup": {"bucket": BUCKET, "region": actual_region, "bucketLocationVerified": True,
                       "prefix": "live/verify-ledger/pgbackrest", "cipher": "aes-256-cbc", "retentionDays": 7},
                  "scope": "Private target only. Production writer disabled; PITR restore test still required."}
        output = work / ("target-setup-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
        write_report(output, report)
        print(json.dumps({"status": report["status"], "report": str(output), "featureTestsPassed": True,
                          "sourceDumpSha256": args.dump_sha256, "productionWriterEnabled": False}))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "errorClass": type(exc).__name__,
                          "reason": str(exc) if isinstance(exc, Blocked) else "Inspect private target setup state; secret details suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
