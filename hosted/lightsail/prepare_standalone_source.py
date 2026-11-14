#!/usr/bin/env python3
"""Prepare and attest a standalone, same-revision SOURCE bridge backend.

prepare changes only private migration evidence/environment and restarts an idle
bridge while public traffic still uses the healthy managed ECS source. transition
is read-only and permits only the exact reviewed managed and standalone source
IPs. Neither command changes AWS, database admission/data, or target authority.
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
from hosted.lightsail.recover_source_bridge import ENVIRONMENT, TASK_DEFINITION, SOURCE_TG, guard


def require(condition, reason):
    if not condition:
        raise cutover.Blocked(reason)


def private_json(path, digest):
    metadata = path.stat()
    require(path.is_file() and metadata.st_uid == 0 and not metadata.st_mode & 0o077,
            "Standalone evidence must be a private root-owned file")
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, "Standalone evidence checksum mismatch")
    return json.loads(raw)


def checked_ready(path, digest, maximum_age=120):
    value = private_json(path, digest)
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(value["capturedAtUtc"])).total_seconds()
    require(value.get("status") == "STANDALONE_SOURCE_TASK_READY" and 0 <= age <= maximum_age,
            "A fresh standalone source-task readiness report is required")
    require(value.get("accountId") == ACCOUNT and value.get("instanceId") == INSTANCE
            and value.get("sourceHost") == SOURCE_HOST and value.get("sourceImageDigest") == SOURCE_IMAGE
            and value.get("sourceTaskDefinition") == TASK_DEFINITION and value.get("sourceBackendKind") == "standalone"
            and value.get("sourceTaskGroup") == "family:verify-ledger"
            and value.get("standaloneStartedBy", "").startswith("verify-migration-")
            and value.get("standaloneRegisteredTargetGroups") == [], "Unreviewed standalone source identity")
    require(value.get("originalServiceDesiredCount") == 1 and value.get("originalServiceHealthy") is True
            and value.get("sourceTargetGroup") == SOURCE_TG and value.get("httpsSourceOnly") is True
            and value.get("dnsStillOriginalAlb") is True, "Public traffic must still use the healthy original managed source")
    source_ips = value.get("originalServiceTaskIps", [])
    require(isinstance(source_ips, list) and len(source_ips) == 1 and value["sourcePrivateIp"] not in source_ips,
            "Standalone and managed source task addresses must be distinct")
    for candidate in source_ips + [value["sourcePrivateIp"]]:
        address = ipaddress.ip_address(candidate)
        require(address.version == 4 and address.is_private and not address.is_loopback, "Expected private ECS source addresses")
    require(value.get("sourceTaskArn", "").startswith("arn:aws:ecs:us-west-2:842676017161:task/verify-ledger/")
            and value.get("sourceEni", "").startswith("eni-"), "Standalone task/ENI identity is missing")
    return value


def expected_api(host, port):
    status, body, _ = request(host, port, "/v1/verify-chain")
    require(status == 401 and body.startswith(b'{"error":'), "The reviewed source API is not healthy")
    return status, body


def transition(managed_source_ip=None, require_clean_routing=True):
    config = json.loads(CONFIG.read_text())
    reference = config.get("evidence", {}).get("standaloneSource", {})
    ready = checked_ready(Path(reference["readyReport"]), reference["readyReportSha256"], maximum_age=86400)
    prepared = private_json(Path(reference["preparedReport"]), reference["preparedReportSha256"])
    require(prepared.get("status") == "STANDALONE_SOURCE_BRIDGE_PREPARED"
            and all(prepared.get(key) == ready.get(key) for key in ("sourceTaskArn", "sourcePrivateIp", "standaloneStartedBy")),
            "Pinned standalone preparation does not match the source task")
    ip = ready["sourcePrivateIp"]
    managed_ips = ready["originalServiceTaskIps"]
    if managed_source_ip is not None:
        address = ipaddress.ip_address(managed_source_ip)
        require(address.version == 4 and address in ipaddress.ip_network("10.40.0.0/16") and managed_source_ip != ip,
                "Replacement managed source address is outside the reviewed VPC")
        managed_ips = [managed_source_ip]
    require(ENVIRONMENT.read_text().strip() == "VERIFY_MIGRATION_SOURCE=http://" + ip + ":8080",
            "The live bridge does not point to the reviewed standalone source")
    proof = guard(set(managed_ips + [ip]))
    require(expected_api(ip, 8080) == expected_api("127.0.0.1", 8082), "Standalone and bridge API responses differ")
    if require_clean_routing:
        require(config.get("readiness", {}).get("oldAlbRequestsDrained") is False
            and config.get("readiness", {}).get("allOtherSourceWritersDisabled") is False
            and not config.get("evidence", {}).get("sourceRouting"), "Stale cutover routing evidence remains usable")
    result = {"status": "STANDALONE_SOURCE_TRANSITION_VERIFIED", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
            "accountId": ACCOUNT, "instanceId": INSTANCE, "sourcePrivateIp": ip, "sourceTaskArn": ready["sourceTaskArn"],
            "standaloneStartedBy": ready["standaloneStartedBy"], "productionWriterEnabled": False,
            "sourceAdmissionAllowed": True, "bridge": proof["bridge"], "sourceConnections": proof["sourceSessions"],
            "permittedManagedSourceIps": managed_ips, "readyReportSha256": reference["readyReportSha256"]}
    if managed_source_ip is not None:
        result.update(status="STANDALONE_SOURCE_ROLLBACK_VERIFIED", managedSourcePrivateIp=managed_source_ip)
    return result


def invalidate():
    result = transition(require_clean_routing=False)
    config = json.loads(CONFIG.read_text())
    config["readiness"]["oldAlbRequestsDrained"] = False
    config["readiness"]["allOtherSourceWritersDisabled"] = False
    config.setdefault("evidence", {}).pop("sourceRouting", None)
    private_atomic(CONFIG, (json.dumps(config, indent=2) + "\n").encode())
    return {**result, "status": "STANDALONE_SOURCE_READINESS_INVALIDATED"}


def prepare(path, digest):
    ready = checked_ready(path, digest)
    source_ip, managed_ips = ready["sourcePrivateIp"], ready["originalServiceTaskIps"]
    current = ENVIRONMENT.read_text().strip()
    require(current in {"VERIFY_MIGRATION_SOURCE=http://" + ip + ":8080" for ip in managed_ips + [source_ip]},
            "Recover the bridge to the currently observed source task before standalone preparation")
    before = guard(set(managed_ips + [source_ip]))
    desired_api = expected_api(source_ip, 8080)
    config = json.loads(CONFIG.read_text())
    config["readiness"]["oldAlbRequestsDrained"] = False
    config["readiness"]["allOtherSourceWritersDisabled"] = False
    config.setdefault("evidence", {}).pop("sourceRouting", None)
    config["evidence"].pop("standaloneSource", None)
    private_atomic(CONFIG, (json.dumps(config, indent=2) + "\n").encode())
    observed = cutover.control(cutover.SOCKET, {"action": "status"}, timeout=1)
    require(observed.get("mode") == "source" and observed.get("targetActivated") is False
            and observed.get("active") == 0 and observed.get("queued") == 0,
            "The unused SOURCE bridge became busy; wait for existing requests")
    private_atomic(ENVIRONMENT, ("VERIFY_MIGRATION_SOURCE=http://" + source_ip + ":8080\n").encode())
    result = subprocess.run(["systemctl", "restart", "verify-migration.service"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=12)
    require(result.returncode == 0, "Unused SOURCE bridge restart failed; public managed source remains authoritative")
    until = time.monotonic() + 8
    while True:
        try:
            if expected_api("127.0.0.1", 8082) == desired_api:
                break
        except (OSError, TimeoutError):
            pass
        require(time.monotonic() < until, "Standalone SOURCE bridge did not become ready")
        time.sleep(.1)
    after = guard(set(managed_ips + [source_ip]))
    output = WORK / ("standalone-source-prepared-" + str(time.time_ns()) + ".json")
    cutover.write_report(output, {"status": "STANDALONE_SOURCE_BRIDGE_PREPARED", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
        "accountId": ACCOUNT, "instanceId": INSTANCE, "sourcePrivateIp": source_ip, "sourceTaskArn": ready["sourceTaskArn"],
        "standaloneStartedBy": ready["standaloneStartedBy"], "readyReportSha256": digest, "before": before, "after": after,
        "databaseChanges": 0, "awsChanges": 0, "targetWriterEnabled": False})
    config["evidence"]["standaloneSource"] = {"readyReport": str(path), "readyReportSha256": digest,
        "preparedReport": str(output), "preparedReportSha256": hashlib.sha256(output.read_bytes()).hexdigest()}
    private_atomic(CONFIG, (json.dumps(config, indent=2) + "\n").encode())
    return {**transition(), "preparationReport": str(output)}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(dest="operation", required=True)
    item = operations.add_parser("prepare")
    item.add_argument("--ready-report", type=Path, required=True)
    item.add_argument("--sha256", required=True)
    operations.add_parser("transition")
    operations.add_parser("invalidate")
    item = operations.add_parser("rollback-proof")
    item.add_argument("--managed-source-ip", required=True)
    args = parser.parse_args()
    try:
        with open("/run/verify-cutover.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.operation == "prepare":
                result = prepare(args.ready_report, args.sha256)
            elif args.operation == "invalidate":
                result = invalidate()
            elif args.operation == "rollback-proof":
                result = transition(managed_source_ip=args.managed_source_ip)
            else:
                result = transition()
        print(json.dumps(result))
        return 0
    except Exception as error:
        print(json.dumps({"status": "STANDALONE_SOURCE_PREPARATION_BLOCKED", "errorClass": type(error).__name__,
            "reason": str(error) if isinstance(error, cutover.Blocked) else "Inspect private standalone preparation; credentials suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
