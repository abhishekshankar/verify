#!/usr/bin/env python3
"""Repoint only the unused SOURCE bridge after an ECS task replacement.

The public HTTPS source route must already have been recovered and evidenced by
CloudShell. This command never changes AWS, database admission/data, writer
authorization, Caddy or the frozen coordinator. It explicitly restarts only the
migration bridge and invalidates all prior drain evidence under the cutover lock.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time

from hosted.lightsail import cutover
from hosted.lightsail.attest_source_route import ACCOUNT, INSTANCE, SOURCE_HOST, SOURCE_IMAGE
from hosted.lightsail.prepare_bridge import CONFIG, WORK, private_atomic, request

TASK_DEFINITION = "arn:aws:ecs:us-west-2:842676017161:task-definition/verify-ledger:1"
SOURCE_TG = "arn:aws:elasticloadbalancing:us-west-2:842676017161:targetgroup/verify-ledger/63e16a3aeef8d276"
ENVIRONMENT = Path("/etc/verify/migration.env")


def require(condition, reason):
    if not condition:
        raise cutover.Blocked(reason)


def checked_report(path, digest):
    metadata = path.stat()
    require(metadata.st_uid == 0 and not metadata.st_mode & 0o077, "Recovery report must be private and root-owned")
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, "Recovery evidence checksum mismatch")
    value = json.loads(raw)
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(value["capturedAtUtc"])).total_seconds()
    require(value.get("status") == "SOURCE_ROUTING_RECOVERED" and 0 <= age <= 120,
            "A fresh completed public-source recovery report is required")
    require(value.get("accountId") == ACCOUNT and value.get("instanceId") == INSTANCE
            and value.get("sourceHost") == SOURCE_HOST and value.get("sourceImageDigest") == SOURCE_IMAGE
            and value.get("sourceTaskDefinition") == TASK_DEFINITION
            and value.get("sourceTargetGroup") == SOURCE_TG and value.get("sourceTargetHealth") == "healthy"
            and value.get("httpsSourceOnly") is True and value.get("dnsStillOriginalAlb") is True
            and value.get("sourceGraceSeconds") == 0,
            "Recovery evidence must identify the healthy original source architecture")
    address = ipaddress.ip_address(value["sourcePrivateIp"])
    require(address.version == 4 and address.is_private and not address.is_loopback
            and value.get("sourceTaskArn", "").startswith("arn:aws:ecs:us-west-2:842676017161:task/verify-ledger/")
            and value.get("sourceEni", "").startswith("eni-"), "Invalid recovered ECS task identity")
    return value


def guard(source_ips):
    import psycopg
    require(os.geteuid() == 0, "Run bridge recovery through SSM as root")
    installed = json.loads(Path("/etc/verify/target-install.json").read_text())
    require(installed.get("accountId") == ACCOUNT and installed.get("instanceId") == INSTANCE, "Target identity mismatch")
    require(cutover.durable_target_state() is False and json.loads(cutover.STATE.read_text()).get("mode") == "source"
            and not cutover.WRITER.exists(), "SOURCE recovery is prohibited after or during uncertain target activation")
    require(subprocess.run(["systemctl", "is-active", "--quiet", "verify.service"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3).returncode != 0,
            "The target application writer is active")
    gate = cutover.control(cutover.SOCKET, {"action": "status"}, timeout=1)
    require(gate.get("ok") and gate.get("mode") == "source" and gate.get("targetActivated") is False
            and gate.get("active") == 0 and gate.get("queued") == 0,
            "The live bridge must be unambiguously SOURCE with no active or queued requests before restart")
    for name in list(os.environ):
        if name.startswith("PG"):
            del os.environ[name]
    for key, filename in (("PGSERVICEFILE", "source-service.conf"), ("PGPASSFILE", "source.pgpass")):
        path = WORK / filename
        require(path.stat().st_uid == 0 and not path.stat().st_mode & 0o077, "Source connection material is not private")
        os.environ[key] = str(path)
    config = json.loads(CONFIG.read_text())
    require(config.get("sourceHost") == SOURCE_HOST and config.get("sourceService") == "verify_source_gate",
            "Source connection identity changed")
    with psycopg.connect("service=verify_source_gate application_name=verify-source-recovery-proof", autocommit=True,
            connect_timeout=3, options="-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=1000") as connection:
        cutover.check_source(connection, config)
        require(connection.execute("SHOW transaction_read_only").fetchone() == ("on",), "Source proof is not read-only")
        rows = connection.execute("SELECT pid,usename,host(client_addr),state FROM pg_stat_activity WHERE datname='verify' "
            "AND backend_type='client backend' AND pid<>pg_backend_pid() AND usename<>'rdsadmin'").fetchall()
        require(all(row[1] == "verify_owner" and row[2] in source_ips for row in rows),
                "Source has a session outside the old and independently verified replacement ECS tasks")
    return {"bridge": gate, "sourceAdmissionAllowed": True, "sourceReadOnlyVerifiedTls": True,
            "sourceSessions": [{"pid": row[0], "user": row[1], "clientAddress": row[2], "state": row[3]} for row in rows]}


def repoint(report_path, digest):
    recovery = checked_report(report_path, digest)
    current = ENVIRONMENT.read_text().strip()
    prefix = "VERIFY_MIGRATION_SOURCE=http://"
    require(current.startswith(prefix) and current.endswith(":8080"), "Bridge source configuration is unexpected")
    old_ip = current[len(prefix):-5]
    ipaddress.ip_address(old_ip)
    new_ip = recovery["sourcePrivateIp"]
    before = guard({old_ip, new_ip})
    status, body, _ = request(new_ip, 8080, "/v1/verify-chain")
    require(status == 401 and body.startswith(b'{"error":'), "Recovered private ECS task is not serving the expected API")
    config = json.loads(CONFIG.read_text())
    config["readiness"]["oldAlbRequestsDrained"] = False
    config["readiness"]["allOtherSourceWritersDisabled"] = False
    config.setdefault("evidence", {}).pop("sourceRouting", None)
    config["evidence"]["sourceTaskRecovery"] = {"path": str(report_path), "sha256": digest,
                                                "sourceTaskArn": recovery["sourceTaskArn"], "sourcePrivateIp": new_ip}
    private_atomic(CONFIG, (json.dumps(config, indent=2) + "\n").encode())
    observed = cutover.control(cutover.SOCKET, {"action": "status"}, timeout=1)
    require(observed.get("mode") == "source" and observed.get("targetActivated") is False
            and observed.get("active") == 0 and observed.get("queued") == 0,
            "The unused SOURCE bridge became busy; wait for existing requests before repointing")
    private_atomic(ENVIRONMENT, (prefix + new_ip + ":8080\n").encode())
    # Root-owned 0600 EnvironmentFile is read by systemd before privilege drop.
    result = subprocess.run(["systemctl", "restart", "verify-migration.service"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=12)
    require(result.returncode == 0, "Unused bridge restart failed; public source routing remains the recovery path")
    until = time.monotonic() + 8
    while True:
        try:
            response = request("127.0.0.1", 8082, "/v1/verify-chain")
            if response[:2] == (status, body):
                break
        except (OSError, TimeoutError):
            pass
        require(time.monotonic() < until, "Repointed SOURCE bridge did not become healthy")
        time.sleep(.1)
    after = guard({old_ip, new_ip})
    output = WORK / ("source-task-recovery-" + str(time.time_ns()) + ".json")
    cutover.write_report(output, {"status": "SOURCE_BRIDGE_REPOINTED_PUBLIC_SOURCE_RESTORED",
        "capturedAtUtc": datetime.now(timezone.utc).isoformat(), "accountId": ACCOUNT, "instanceId": INSTANCE,
        "oldPrivateIp": old_ip, "newPrivateIp": new_ip, "recoveryReportSha256": digest, "before": before, "after": after,
        "routingReadinessInvalidated": True, "databaseChanges": 0, "awsChanges": 0,
        "scope": "Only the unused SOURCE bridge was repointed/restarted. Original database remains authoritative."})
    return {"status": "SOURCE_BRIDGE_REPOINTED_PUBLIC_SOURCE_RESTORED", "report": str(output), "sourcePrivateIp": new_ip}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--routing-report", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        with open("/run/verify-cutover.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = repoint(args.routing_report, args.sha256)
        print(json.dumps(result))
        return 0
    except Exception as error:
        print(json.dumps({"status": "SOURCE_BRIDGE_RECOVERY_BLOCKED", "errorClass": type(error).__name__,
            "reason": str(error) if isinstance(error, cutover.Blocked) else "Inspect private recovery state; credentials suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
