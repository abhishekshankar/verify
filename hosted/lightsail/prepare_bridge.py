#!/usr/bin/env python3
"""Prepare private migration credentials and the SOURCE-only bridge on the target.

The source phase never changes source data, DNS, ALB routing, or writer authority.
The HTTPS phase runs after HTTP-01 forwards from the existing ALB to Caddy. Its
certificate check connects to loopback with the real hostname. External routing
and writer-inventory readiness flags remain false until independently verified.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time

from hosted.lightsail.cutover import Blocked, STATE, WRITER, SOCKET, durable_target_state, write_report
from hosted.lightsail.migration_proxy import control
from hosted.lightsail.setup_target import ACCOUNT, BUCKET, BACKUP_REGION, private_file

MASTER_SECRET = "arn:aws:secretsmanager:us-west-2:842676017161:secret:rds!db-21c38256-8c38-4e4a-a8a3-c40c8c74e117-Me0ys9"
HOSTNAME = "ledger.optimise.work"
WORK = Path("/opt/verify-migration/cutover")
CONFIG = WORK / "coordinator.json"
VENV = "/opt/verify/current/.venv/bin/python"
APP_ENV = {"PYTHONPATH": "/opt/verify/current/src:/opt/verify/current"}


def fresh_report(path, status, instance):
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o077 or not path.is_file():
        raise Blocked("Readiness reports must be private root-owned regular files")
    report = json.loads(path.read_text())
    if report.get("status") != status or report.get("instanceId") != instance:
        raise Blocked("A readiness report does not match this target or the required success state")
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(report["capturedAtUtc"])).total_seconds()
    if not 0 <= age <= 86400:
        raise Blocked("Target readiness report is older than this migration session")
    return report


def reference(path):
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def private_atomic(path, payload):
    descriptor, temporary = tempfile.mkstemp(prefix=".prepare-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def pass_escape(value):
    if not isinstance(value, str) or any(character in value for character in ("\x00", "\n", "\r")):
        raise Blocked("Source passfile field contains unsupported framing characters")
    return value.replace("\\", "\\\\").replace(":", "\\:")


def source_passfile(host, user, password):
    return "".join(":".join(map(pass_escape, (host, "5432", database, user, password))) + "\n"
                   for database in ("verify", "postgres"))


def target_guard(instance):
    if os.geteuid() != 0:
        raise Blocked("Run this helper through SSM as root on the new target")
    installed = json.loads(Path("/etc/verify/target-install.json").read_text())
    if installed.get("instanceId") != instance or installed.get("accountId") != ACCOUNT:
        raise Blocked("Target installation identity mismatch")
    if durable_target_state() is not False or json.loads(STATE.read_text()).get("mode") != "source":
        raise Blocked("Bridge preparation requires the durable pre-cutover SOURCE state")
    if WRITER.exists() or subprocess.run(["systemctl", "is-active", "--quiet", "verify.service"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        raise Blocked("Private target app must remain stopped without writer authorization")
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    if WORK.stat().st_uid != 0 or WORK.stat().st_mode & 0o077:
        raise Blocked("Coordinator work directory must be private and root-owned")


def command(arguments, timeout=20, environment=None):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=environment)
    if result.returncode:
        error_path = WORK / ("private-prepare-error-" + str(time.time_ns()) + ".json")
        write_report(error_path, {"program": arguments[0], "returncode": result.returncode,
                                  "stderr": result.stderr.decode(errors="replace")[:16384]})
        raise Blocked("A preparation command failed; inspect private target evidence")
    return result.stdout


def request(host, port, path, tls=False):
    connection = http.client.HTTPConnection(host, port, timeout=3)
    certificate = None
    try:
        if tls:
            raw = socket.create_connection((host, port), timeout=3)
            connection.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=HOSTNAME)
            certificate = connection.sock.getpeercert()
        connection.request("GET", path, headers={"Host": HOSTNAME, "Connection": "close"})
        response = connection.getresponse()
        payload = response.read(65537)
        if len(payload) > 65536:
            raise Blocked("Unexpected oversized unauthenticated health response")
        return response.status, payload, certificate
    finally:
        connection.close()


def require_source_health(ip):
    status, body, _ = request(ip, 8080, "/v1/verify-chain")
    if status != 401 or not body.startswith(b'{"error":'):
        raise Blocked("Observed source task does not provide the expected unauthenticated API response")
    return status, body


def prepare_source(args):
    target_guard(args.expected_instance_id)
    address = ipaddress.ip_address(args.source_private_ip)
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
        raise Blocked("SOURCE upstream must be the observed ECS task private IPv4 address")
    if not re.fullmatch(r"verify-ledger\.[a-z0-9-]+\.us-west-2\.rds\.amazonaws\.com", args.source_host):
        raise Blocked("Unexpected Verify RDS hostname")
    source_response = require_source_health(str(address))
    setup = fresh_report(args.setup_report, "PRIVATE_TARGET_RESTORED_FEATURE_TESTED_BACKUP_CONFIGURED", args.expected_instance_id)
    runtime = fresh_report(args.runtime_report, "RUNTIME_ROLE_HTTP_TESTS_PASSED", args.expected_instance_id)
    pitr = fresh_report(args.pitr_report, "ENCRYPTED_S3_PITR_RESTORE_VERIFIED", args.expected_instance_id)
    if (setup.get("featureTestsPassed") is not True or runtime.get("testCount") != 11
            or any(runtime.get(key) is not True for key in ("httpSuitePassed", "verifiedTls", "productionDataUnchanged", "hbaRestored"))
            or runtime.get("applicationDatabaseRole") != "verify_runtime" or runtime.get("maintenanceDatabaseRole") != "verify_maintenance"
            or runtime.get("productionWriterEnabled") is not False or runtime.get("sourceConnections") != 0
            or runtime.get("cleanupErrors") or runtime.get("failureClass")
            or any(pitr.get(key) is not True for key in ("earlierProbeRetained", "laterProbeExcluded", "applicationDataMatch", "bucketLocationVerified"))
            or pitr.get("cipher") != "aes-256-cbc" or pitr.get("backupRegion") != BACKUP_REGION):
        raise Blocked("Readiness proof details are incomplete")
    export_digest = hashlib.sha256(Path("/etc/verify/secrets/export-key").read_bytes()).hexdigest()
    if setup["recoveryCredentials"]["export"]["sha256"] != export_digest:
        raise Blocked("The exact source export HMAC recovery proof no longer matches")
    ca = args.source_ca.read_bytes()
    if not 0 < len(ca) < 2 * 1024 * 1024 or b"-----BEGIN CERTIFICATE-----" not in ca:
        raise Blocked("Expected the already-verified AWS RDS CA bundle")
    ca_target = WORK / "rds-ca.pem"
    private_file(ca_target, ca.decode("ascii"))
    import boto3
    from botocore.config import Config
    aws = boto3.client("secretsmanager", region_name="us-west-2",
                       config=Config(connect_timeout=2, read_timeout=3, retries={"max_attempts": 0}))
    secret = aws.get_secret_value(SecretId=MASTER_SECRET)
    credential = json.loads(secret["SecretString"])
    if credential.get("username") != "verify_owner" or not credential.get("password"):
        raise Blocked("Unexpected source owner credential format")
    service = "verify_source_gate"
    service_file, pass_file = WORK / "source-service.conf", WORK / "source.pgpass"
    private_file(service_file, f"[{service}]\nhost={args.source_host}\nport=5432\ndbname=verify\nuser=verify_owner\nsslmode=verify-full\nsslrootcert={ca_target}\nconnect_timeout=3\n")
    private_file(pass_file, source_passfile(args.source_host, "verify_owner", credential["password"]))
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("PG", "VERIFY_"))}
    environment.update(APP_ENV)
    deadline = json.loads(command(["runuser", "-u", "postgres", "--", VENV, "-m",
                                  "hosted.lightsail.prove_database_deadline"], timeout=8, environment=environment))
    if deadline.get("status") != "DATABASE_DEADLINE_PROVED" or deadline.get("oldBackendSettled") is not True:
        raise Blocked("The actual driver deadline proof did not pass")
    deadline_path = WORK / ("driver-deadline-" + str(time.time_ns()) + ".json")
    write_report(deadline_path, deadline)
    configured = Path("/etc/verify/migration.env").read_text().strip()
    expected = "VERIFY_MIGRATION_SOURCE=http://" + str(address) + ":8080"
    if configured != expected:
        raise Blocked("Installed bridge source differs from the freshly observed task; update the stopped bridge explicitly")
    command(["systemctl", "enable", "--now", "verify-migration.service"])
    until = time.monotonic() + 8
    while True:
        try:
            status = control(SOCKET, {"action": "status"}, timeout=1)
            break
        except (OSError, ValueError):
            if time.monotonic() > until:
                raise Blocked("SOURCE bridge did not become ready")
            time.sleep(.1)
    if (not status.get("ok") or status.get("mode") != "source" or status.get("targetActivated")
            or status.get("queueDeadlineSeconds") != 20 or status.get("queueTimeouts")):
        raise Blocked("SOURCE bridge state differs from the reviewed gate")
    if request("127.0.0.1", 8082, "/__migration_health")[0] != 200 or request("127.0.0.1", 8082, "/v1/verify-chain")[:2] != source_response:
        raise Blocked("SOURCE bridge health or upstream response mismatch")
    config = {"accountId": ACCOUNT, "instanceId": args.expected_instance_id, "sourceHost": args.source_host,
              "sourceService": service, "exportKeySha256": export_digest, "backupBucket": BUCKET,
              "backupRegion": BACKUP_REGION, "backupPrefix": "live/verify-ledger/cutovers/", "workDirectory": str(WORK),
              "readiness": {"applicationFeatureTestsPassed": True, "encryptedBackupRestoreTestPassed": True,
                   "databaseDeadlineInterruptTestPassed": True, "httpsCertificateAndRenewalPathVerified": False,
                   "oldAlbRequestsDrained": False, "allOtherSourceWritersDisabled": False,
                   "retainedSourceAutomatedBackupDays": 7},
              "evidence": {"setup": reference(args.setup_report), "runtimeRoles": reference(args.runtime_report),
                   "pitr": reference(args.pitr_report), "databaseDeadline": reference(deadline_path),
                   "sourceCredentialVersion": secret["VersionId"], "sourcePrivateIp": str(address),
                   "sourceCaSha256": hashlib.sha256(ca).hexdigest(),
                   "sourceAutomatedBackupRetention": "Retain seven days when deleting the old RDS instance; deletion remains a separate gate"}}
    if CONFIG.exists():
        previous = json.loads(CONFIG.read_text())
        if any(previous.get(key) != config[key] for key in ("accountId", "instanceId", "sourceHost", "sourceService", "exportKeySha256")):
            raise Blocked("An existing coordinator configuration has a different identity")
        if previous.get("readiness", {}).get("oldAlbRequestsDrained") or previous.get("readiness", {}).get("httpsCertificateAndRenewalPathVerified"):
            raise Blocked("Later migration readiness already exists; do not reset it with SOURCE preparation")
    private_atomic(CONFIG, (json.dumps(config, indent=2) + "\n").encode())
    report = {"status": "SOURCE_BRIDGE_AND_PRIVATE_COORDINATOR_CONFIG_READY", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
              "instanceId": args.expected_instance_id, "sourcePrivateIp": str(address), "sourceHost": args.source_host,
              "configuration": reference(CONFIG), "databaseDeadline": deadline, "sourceBridge": status,
              "serviceFile": str(service_file), "passFile": str(pass_file), "sourcePassfileDatabaseEntries": ["verify", "postgres"],
              "productionWriterEnabled": False, "publicRoutingChanged": False, "sourceDatabaseChanged": False}
    output = WORK / ("source-bridge-" + str(time.time_ns()) + ".json")
    write_report(output, report)
    return {"status": report["status"], "report": str(output), "coordinatorConfiguration": str(CONFIG),
            "serviceFile": str(service_file), "passFile": str(pass_file), "databaseDeadline": deadline}


def prepare_https(args):
    target_guard(args.expected_instance_id)
    config = json.loads(CONFIG.read_text())
    if config.get("instanceId") != args.expected_instance_id or config.get("accountId") != ACCOUNT:
        raise Blocked("Coordinator identity mismatch")
    # This evidence records a read-only AWS observation, not a request for permission.
    evidence = fresh_report(args.acme_routing_report, "ACME_HTTP01_FORWARDING_VERIFIED", args.expected_instance_id)
    if (evidence.get("hostname") != HOSTNAME or evidence.get("sourceDnsStillOnAlb") is not True
            or evidence.get("targetPort") != 80 or evidence.get("pathPattern") != "/.well-known/acme-challenge/*"
            or evidence.get("targetHealthy") is not True):
        raise Blocked("HTTP-01 ALB forwarding evidence is incomplete")
    caddy = Path("/etc/caddy/Caddyfile").read_text()
    if "disable_tlsalpn_challenge" not in caddy or "reverse_proxy 127.0.0.1:8082" not in caddy or HOSTNAME not in caddy:
        raise Blocked("Caddy configuration differs from the reviewed HTTP-01 bridge configuration")
    command(["caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"])
    command(["systemctl", "enable", "--now", "caddy.service"])
    # Fail safely after one bounded attempt; an issued certificate may be retried.
    until = time.monotonic() + 45
    while True:
        try:
            status, body, certificate = request("127.0.0.1", 443, "/v1/verify-chain", tls=True)
            if status == 401 and body.startswith(b'{"error":'):
                break
        except (OSError, ssl.SSLError, http.client.HTTPException):
            pass
        if time.monotonic() > until:
            raise Blocked("Trusted target TLS is not ready; inspect Caddy and HTTP-01 forwarding before retrying")
        time.sleep(1)
    bridge = control(SOCKET, {"action": "status"}, timeout=1)
    if not bridge.get("ok") or bridge.get("mode") != "source" or bridge.get("targetActivated"):
        raise Blocked("TLS must be proved while SOURCE remains authoritative")
    # Caddy serves renewal HTTP-01 on target port80 now and after DNS migration.
    http_status = request("127.0.0.1", 80, "/")[0]
    if http_status not in (301, 302, 307, 308):
        raise Blocked("Caddy HTTP listener is not available for future HTTP-01 renewals")
    report = {"status": "TARGET_HTTPS_SOURCE_BRIDGE_VERIFIED", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
              "instanceId": args.expected_instance_id, "hostname": HOSTNAME, "certificate": certificate,
              "trustedTlsAndHostnameVerified": True, "http01ListenerAvailable": True,
              "sourceBridge": bridge, "acmeRouting": reference(args.acme_routing_report),
              "productionWriterEnabled": False, "dnsChanged": False}
    output = WORK / ("https-source-bridge-" + str(time.time_ns()) + ".json")
    write_report(output, report)
    config["readiness"]["httpsCertificateAndRenewalPathVerified"] = True
    config["evidence"]["https"] = reference(output)
    private_atomic(CONFIG, (json.dumps(config, indent=2) + "\n").encode())
    return {"status": report["status"], "report": str(output), "coordinatorConfiguration": str(CONFIG)}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("source")
    source.add_argument("--expected-instance-id", required=True)
    source.add_argument("--source-private-ip", required=True)
    source.add_argument("--source-host", required=True)
    for name in ("source-ca", "setup-report", "runtime-report", "pitr-report"):
        source.add_argument("--" + name, type=Path, required=True)
    https = commands.add_parser("https")
    https.add_argument("--expected-instance-id", required=True)
    https.add_argument("--acme-routing-report", type=Path, required=True)
    args = parser.parse_args()
    try:
        import fcntl
        with open("/run/verify-cutover.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = prepare_source(args) if args.command == "source" else prepare_https(args)
        print(json.dumps(result))
        return 0
    except Exception as error:
        print(json.dumps({"status": "BRIDGE_PREPARATION_BLOCKED", "errorClass": type(error).__name__,
                          "reason": str(error) if isinstance(error, Blocked) else "Inspect private target evidence; credentials suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
