#!/usr/bin/env python3
"""Source writer inventory, pinned routing evidence, and guarded final execution.

Run on the staged target with its application venv. The snapshot reads only
metadata using a verified-TLS, read-only source connection. accept requires the
exact checked CloudShell drain report; invalidate only clears readiness gates.
snapshot, accept, and invalidate do not change database admission, gate mode,
writer authorization, DNS, or application services. execute revalidates the pinned
evidence under the cutover lock, then invokes the reviewed coordinator to fence
the source database and activate the target writer. DNS remains a separate step.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import time

from hosted.lightsail import cutover
from hosted.lightsail.prepare_bridge import private_atomic

ACCOUNT = "842676017161"
INSTANCE = "i-0e3509a6723d2c0c5"
SOURCE_HOST = "verify-ledger.cjcos4w8eowk.us-west-2.rds.amazonaws.com"
TARGET_IP = "10.40.0.249"
WORK = Path("/opt/verify-migration/cutover")
CONFIG = WORK / "coordinator.json"
SOURCE_SG = "sg-0c32da8357326fd75"
TARGET_SG = "sg-0d0af838e410d73da"
SOURCE_IMAGE = "sha256:9e67c0dd5340e4619513f539037b831406225e101ea910dcb1caaf7c7afc48b2"
COORDINATOR_SHA256 = "240021ca6954155ae3c181f3040322ed838020a3860bf1e7582f4204e05d8a8a"


def require(condition, reason):
    if not condition:
        raise cutover.Blocked(reason)


def response(host, port, path):
    connection = http.client.HTTPConnection(host, port, timeout=2)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        result = connection.getresponse()
        return result.status, result.read(65536)
    finally:
        connection.close()


def snapshot(source_ip):
    import psycopg
    import ipaddress
    address = ipaddress.ip_address(source_ip)
    require(address.version == 4 and address.is_private and not address.is_loopback, "Expected a private ECS source address")
    require(os.geteuid() == 0, "Target source attestation requires root")
    installed = json.loads(Path("/etc/verify/target-install.json").read_text())
    require(installed.get("accountId") == ACCOUNT and installed.get("instanceId") == INSTANCE, "Target identity mismatch")
    require(cutover.durable_target_state() is False and json.loads(cutover.STATE.read_text()).get("mode") == "source",
            "Source routing changes are prohibited after or during uncertain target activation")
    require(not cutover.WRITER.exists(), "Target writer authorization already exists")
    require(subprocess.run(["systemctl", "is-active", "--quiet", "verify.service"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3).returncode != 0,
            "The target writer service is active")
    gate = cutover.control(cutover.SOCKET, {"action": "status"}, timeout=1)
    require(gate.get("ok") and gate.get("mode") == "source" and gate.get("targetActivated") is False
            and gate.get("queueTimeouts") == 0 and gate.get("queueDeadlineSeconds") == 20,
            "SOURCE bridge state is not verified")
    require(Path("/etc/verify/migration.env").read_text().strip() == "VERIFY_MIGRATION_SOURCE=http://" + source_ip + ":8080",
            "Bridge does not point to the observed source task")
    config = json.loads(CONFIG.read_text())
    require(config.get("instanceId") == INSTANCE and config.get("accountId") == ACCOUNT
            and config.get("sourceHost") == SOURCE_HOST and config.get("sourceService") == "verify_source_gate",
            "Coordinator source identity differs from the reviewed deployment")
    for name in list(os.environ):
        if name.startswith("PG"):
            del os.environ[name]
    os.environ["PGSERVICEFILE"] = str(WORK / "source-service.conf")
    os.environ["PGPASSFILE"] = str(WORK / "source.pgpass")
    for name in ("PGSERVICEFILE", "PGPASSFILE"):
        stat = Path(os.environ[name]).stat()
        require(stat.st_uid == 0 and not stat.st_mode & 0o077, "Source connection material must remain private")
    with psycopg.connect("service=verify_source_gate application_name=verify-migration-writer-proof",
            autocommit=True, connect_timeout=3,
            options="-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=1000") as connection:
        cutover.check_source(connection, config)
        require(connection.execute("SHOW default_transaction_read_only").fetchone()[0] == "on", "Source attestation is not read-only")
        identity = connection.execute("SELECT current_database(),current_user,current_setting('server_version_num'),(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())").fetchone()
        rows = connection.execute("""SELECT pid,usename,host(client_addr),application_name,state,
                                     xact_start IS NOT NULL
                                     FROM pg_stat_activity
                                     WHERE datname='verify' AND backend_type='client backend'
                                     AND pid<>pg_backend_pid() AND usename<>'rdsadmin'
                                     ORDER BY pid""").fetchall()
        require(all(row[1] == "verify_owner" and row[2] == source_ip for row in rows),
                "A source database session is outside the single observed ECS writer")
        writers = connection.execute("SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolname NOT IN ('verify_owner','rdsadmin') AND (rolsuper OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND (has_table_privilege(pg_roles.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(pg_roles.oid,c.oid,'INSERT,UPDATE'))))").fetchall()
        require(not writers, "Unexpected source login writers")
    direct = response(source_ip, 8080, "/v1/verify-chain")
    through = response("127.0.0.1", 8082, "/v1/verify-chain")
    require(direct == through and direct[0] == 401 and direct[1].startswith(b'{"error":'),
            "Source and bridge unauthenticated API behavior differ")
    require(response("127.0.0.1", 8082, "/__migration_health")[0] == 200, "Bridge health failed")
    return {"status": "SOURCE_WRITER_AND_BRIDGE_VERIFIED", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
            "accountId": ACCOUNT, "instanceId": INSTANCE, "sourceHost": SOURCE_HOST, "sourcePrivateIp": source_ip,
            "sourceDatabase": identity[0], "sourceDatabaseUser": identity[1], "sourceVersion": identity[2],
            "sourceVerifiedTls": identity[3] is True, "sourceReadOnlySnapshot": True, "sourceAdmissionAllowed": True,
            "otherSourceLoginWriters": [], "sourceConnections": [
                {"pid": row[0], "user": row[1], "clientAddress": row[2], "applicationName": row[3],
                 "state": row[4], "transactionActive": row[5]} for row in rows],
            "sourceConnectionsOnlyObservedTask": True, "sourceApiStatus": 401, "bridgeApiStatus": 401,
            "bridge": gate, "productionWriterEnabled": False}


def checked_report(report_path, digest):
    require(report_path.stat().st_uid == 0 and not report_path.stat().st_mode & 0o077, "Routing evidence must be private and root-owned")
    raw = report_path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, "Routing report differs from the independently supplied object checksum")
    report = json.loads(raw)
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(report["capturedAtUtc"])).total_seconds()
    require(0 <= age <= 300 and report.get("status") == "SOURCE_HTTP_DRAIN_AND_WRITER_NETWORK_VERIFIED",
            "A fresh successful CloudShell routing report is required")
    require(report.get("accountId") == ACCOUNT and report.get("instanceId") == INSTANCE
            and report.get("sourceHost") == SOURCE_HOST and report.get("targetPrivateIp") == TARGET_IP,
            "Routing evidence identity mismatch")
    grace_remaining = (datetime.fromisoformat(report["sourceGraceExpiresAtUtc"]) - datetime.now(timezone.utc)).total_seconds()
    require(grace_remaining > 600 and report.get("sourceGraceRemainingSeconds", 0) > 600,
            "The independently observed ECS health grace is expired or too close to expiry")
    drain = report["drain"]
    require(drain.get("explicitDeregistrationRequested") is True
            and drain.get("originalDelayUnchanged") is True
            and drain.get("elapsedSeconds", -1) >= drain.get("configuredDelaySeconds", 999999)
            and drain.get("targetAbsentFromRegisteredList") is True
            and drain.get("explicitTargetReason") == "Target.NotRegistered",
            "The old ALB target has not completed its configured deregistration drain")
    routing = report["routing"]
    require(routing.get("positiveWeightTargetGroups") == [report["bridgeTargetGroup"]]
            and routing.get("sourceTargetGroupWeight") == 0 and routing.get("targetGroupStickinessEnabled") is False
            and routing.get("allResolvedAlbAddressesReachBridge") is True
            and routing.get("allListenersAndRulesReviewed") is True,
            "Unreviewed public routing can still bypass the bridge")
    network = report["writerNetwork"]
    require(set(network.get("databaseClientGroups", [])) == {SOURCE_SG, TARGET_SG}
            and network.get("allPeerInterfacesMatched") is True
            and network.get("noCidrOrPrefixDatabaseAccess") is True
            and network.get("sourceDatabasePrivate") is True
            and network.get("sourceTaskIdentityUnchanged") is True,
            "Source writer network inventory is incomplete")
    require(report.get("sourceTaskArn") and report.get("sourceImageDigest") == SOURCE_IMAGE
            and report.get("sourceTaskRunningCount") == 1, "Single source task evidence is incomplete")
    return report


def accept(report_path, digest):
    report = checked_report(report_path, digest)
    proof = snapshot(report["sourcePrivateIp"])
    config = json.loads(CONFIG.read_text())
    # Persistent booleans must never outlive the short source/task/grace evidence.
    # Only execute() can set these in an in-memory configuration under the lock.
    config["readiness"]["oldAlbRequestsDrained"] = False
    config["readiness"]["allOtherSourceWritersDisabled"] = False
    evidence = {"status": "SOURCE_ROUTING_EVIDENCE_PINNED", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
                "instanceId": INSTANCE, "accountId": ACCOUNT, "routingReport": str(report_path),
                "routingReportSha256": digest, "sourceWriterProof": proof,
                "sourceTaskArn": report["sourceTaskArn"], "sourceImageDigest": report["sourceImageDigest"],
                "sourceGraceExpiresAtUtc": report["sourceGraceExpiresAtUtc"],
                "scope": "ALB configured drain completed; exact SG/ENI/task inventory plus read-only login-writer proof. Final SHARE/admission fence remains mandatory."}
    output = WORK / ("routing-attestation-" + str(time.time_ns()) + ".json")
    cutover.write_report(output, evidence)
    config.setdefault("evidence", {})["sourceRouting"] = {"path": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                                                         "routingReport": str(report_path), "routingReportSha256": digest,
                                                         "sourceTaskArn": report["sourceTaskArn"],
                                                         "sourceImageDigest": report["sourceImageDigest"]}
    private_atomic(CONFIG, (json.dumps(config, indent=2) + "\n").encode())
    return {"status": evidence["status"], "report": str(output), "sourceWriterProof": proof}


def execute(rehearsal_path):
    """Revalidate fresh pinned evidence and run the unchanged coordinator atomically."""
    config = json.loads(CONFIG.read_text())
    require(config.get("readiness", {}).get("oldAlbRequestsDrained") is False
            and config.get("readiness", {}).get("allOtherSourceWritersDisabled") is False,
            "Persistent routing readiness must remain false; pin evidence through accept first")
    reference = config.get("evidence", {}).get("sourceRouting", {})
    attestation_path = Path(reference["path"])
    require(attestation_path.stat().st_uid == 0 and not attestation_path.stat().st_mode & 0o077,
            "Pinned routing attestation must be private and root-owned")
    data = attestation_path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == reference["sha256"], "Pinned attestation checksum changed")
    attestation = json.loads(data)
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(attestation["capturedAtUtc"])).total_seconds()
    require(attestation.get("status") == "SOURCE_ROUTING_EVIDENCE_PINNED" and 0 <= age <= 300
            and attestation.get("instanceId") == INSTANCE and attestation.get("accountId") == ACCOUNT,
            "Pinned source attestation expired or has a different identity")
    require(attestation["routingReport"] == reference["routingReport"]
            and attestation["routingReportSha256"] == reference["routingReportSha256"],
            "Pinned routing report references disagree")
    report = checked_report(Path(reference["routingReport"]), reference["routingReportSha256"])
    require(all(attestation.get(key) == report.get(key) for key in ("sourceTaskArn", "sourceImageDigest", "sourceGraceExpiresAtUtc"))
            and reference.get("sourceTaskArn") == report["sourceTaskArn"]
            and reference.get("sourceImageDigest") == report["sourceImageDigest"], "Source task evidence changed")
    proof = snapshot(report["sourcePrivateIp"])
    actual_hash = hashlib.sha256(Path(cutover.__file__).read_bytes()).hexdigest()
    require(actual_hash == COORDINATOR_SHA256, "Coordinator differs from the actual six-case proven version")
    config = cutover.read_config(CONFIG)
    require(config["readiness"].get("oldAlbRequestsDrained") is False
            and config["readiness"].get("allOtherSourceWritersDisabled") is False,
            "Persistent routing flags changed while executing")
    checked_report(Path(reference["routingReport"]), reference["routingReportSha256"])
    config["readiness"]["oldAlbRequestsDrained"] = True
    config["readiness"]["allOtherSourceWritersDisabled"] = True
    output = WORK / ("routing-execution-" + str(time.time_ns()) + ".json")
    cutover.write_report(output, {"status": "SOURCE_ROUTING_EXECUTION_REVALIDATED",
        "capturedAtUtc": datetime.now(timezone.utc).isoformat(), "instanceId": INSTANCE,
        "routingReportSha256": reference["routingReportSha256"], "attestationSha256": reference["sha256"],
        "sourceTaskArn": report["sourceTaskArn"], "sourceGraceExpiresAtUtc": report["sourceGraceExpiresAtUtc"],
        "coordinatorSha256": actual_hash, "sourceWriterProof": proof, "persistentRoutingFlags": False})
    result = cutover.cutover(config, cutover.Runner(config), rehearsal_path)
    return {**result, "routingExecutionProof": str(output), "coordinatorSha256": actual_hash}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for operation in ("snapshot", "invalidate"):
        item = commands.add_parser(operation)
        item.add_argument("--source-private-ip", required=True)
    item = commands.add_parser("accept")
    item.add_argument("--routing-report", required=True, type=Path)
    item.add_argument("--sha256", required=True)
    item = commands.add_parser("execute")
    item.add_argument("--rehearsal", required=True, type=Path)
    args = parser.parse_args()
    try:
        with open("/run/verify-cutover.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.command == "accept":
                result = accept(args.routing_report, args.sha256)
            elif args.command == "execute":
                result = execute(args.rehearsal)
            else:
                result = snapshot(args.source_private_ip)
                if args.command == "invalidate":
                    config = json.loads(CONFIG.read_text())
                    config["readiness"]["oldAlbRequestsDrained"] = False
                    config["readiness"]["allOtherSourceWritersDisabled"] = False
                    private_atomic(CONFIG, (json.dumps(config, indent=2) + "\n").encode())
                    result["status"] = "SOURCE_ROUTING_READINESS_INVALIDATED"
        print(json.dumps(result))
        return 0
    except Exception as error:
        print(json.dumps({"status": "SOURCE_ROUTING_ATTESTATION_BLOCKED", "errorClass": type(error).__name__,
                          "reason": str(error) if isinstance(error, cutover.Blocked) else "Inspect private routing state; credential details suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
