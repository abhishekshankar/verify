#!/usr/bin/env python3
"""Read-only proof of the authoritative Verify target and recovery material.

Writes only a private evidence report. No database, service, gate, DNS, IAM or AWS
resource is changed. Unauthenticated HTTP probes must return 401; they do not
claim to exercise a customer's API key. --check-source-fence is a temporary
pre-retirement check. Omit it after separately recording source retirement; the
remaining proof has no dependency on RDS or either old Secrets Manager secret.
"""
import argparse
import configparser
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from hosted.lightsail import cutover
from hosted.lightsail.attest_source_route import ACCOUNT, INSTANCE, SOURCE_HOST
from hosted.lightsail.compare_data import TABLES
from hosted.lightsail.prepare_bridge import request

WORK = Path("/opt/verify-migration/cutover")
BUCKET = "verify-ledger-migration-842676017161-20261114"
MODULE = "hosted.lightsail.prove_live_target"
VENV = "/opt/verify/current/.venv/bin/python"
APP_ENV = {"PYTHONPATH": "/opt/verify/current/src:/opt/verify/current"}
READ_OPTIONS = "-c default_transaction_read_only=on -c statement_timeout=3000 -c lock_timeout=1000"
PARAMETERS = {"runtime-db-password": "db-password", "maintenance-db-password": "maintenance-db-password",
              "export-key": "export-key", "backup-cipher-key": "backup-cipher-key"}


def require(condition, reason):
    if not condition:
        raise cutover.Blocked(reason)


def clean_environment():
    value = {key: value for key, value in os.environ.items() if not key.startswith(("PG", "VERIFY_"))}
    value.update(APP_ENV)
    return value


def command(arguments, timeout=15):
    result = subprocess.run(arguments, env=clean_environment(), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    require(result.returncode == 0, "A read-only local proof command failed: " + Path(arguments[0]).name)
    return result.stdout


def private_json(path, digest=None):
    metadata = path.stat()
    require(path.is_file() and metadata.st_uid == 0 and not metadata.st_mode & 0o077,
            "Evidence must be a private root-owned regular file")
    raw = path.read_bytes()
    if digest is not None:
        require(hashlib.sha256(raw).hexdigest() == digest, "Evidence checksum differs from the supplied value")
    return json.loads(raw)


def checked_cutover(path, digest):
    proof = private_json(path, digest)
    require(proof.get("status") == "TARGET_AUTHORITATIVE"
            and proof.get("accountId") == ACCOUNT and proof.get("instanceId") == INSTANCE
            and proof.get("sourceDatabaseAdmissionFenced") is True
            and proof.get("sourceTargetTablesMatch") is True and proof.get("target", {}).get("chainsOk") is True,
            "The exact successful cutover report is required")
    require(set(proof["target"].get("tables", {})) == set(TABLES), "Cutover evidence must cover all seven tables")
    backup = proof["backup"]
    require(backup.get("bucket") == BUCKET and backup.get("key", "").startswith("live/verify-ledger/cutovers/")
            and backup["key"].endswith("/database.dump") and backup.get("versionId") not in (None, "", "null")
            and 0 < backup.get("bytes", 0) < 64 * 1024**2,
            "Final-copy backup identity differs from the reviewed destination")
    return proof


def gate_snapshot():
    require(cutover.durable_target_state() is True
            and json.loads(cutover.STATE.read_text()).get("mode") == "target", "Durable TARGET authority is not established")
    private_json(cutover.WRITER)
    value = cutover.control(cutover.SOCKET, {"action": "status"}, timeout=1)
    require(value.get("ok") and value.get("mode") == "target" and value.get("targetActivated") is True
            and value.get("queueTimeouts") == 0 and value.get("queued") == 0,
            "The TARGET bridge has failed authority or queue checks")
    return value


def database_snapshot():
    """Run as OS postgres; all data/chain reads share one read-only snapshot."""
    import psycopg
    from hosted.store import Store
    for name in list(os.environ):
        if name.startswith("PG"):
            del os.environ[name]

    class SnapshotStore(Store):
        def __init__(self, connection):
            self.connection = connection

        def q(self, query, parameters=()):
            return self.connection.execute(query.replace("?", "%s"), parameters)

    with psycopg.connect(host="/var/run/postgresql", port=5432, user="postgres", dbname="verify",
                         autocommit=True, connect_timeout=2, options=READ_OPTIONS) as connection:
        with connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            identity = connection.execute("SELECT current_database(),current_user,current_setting('server_version_num'),"
                "current_setting('server_encoding'),current_setting('transaction_read_only'),pg_is_in_recovery()").fetchone()
            require(identity[:2] == ("verify", "postgres") and str(identity[2]).startswith("16")
                    and identity[3:] == ("UTF8", "on", False), "Local primary database identity/read-only proof failed")
            relations = connection.execute("SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE c.relkind='r' AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema'").fetchall()
            require(set(relations) == {("public", name) for name in TABLES}, "Unexpected target tables")
            tables = cutover.source_inventory(connection)
            store = SnapshotStore(connection)
            tenants = connection.execute("SELECT id FROM public.tenant ORDER BY id").fetchall()
            chains = [store.verify_chain(row[0]) for row in tenants]
            settings = dict(connection.execute("SELECT name,setting FROM pg_settings WHERE name IN "
                "('fsync','full_page_writes','synchronous_commit','archive_mode','archive_command','archive_timeout')").fetchall())
            require(all(settings.get(key) == "on" for key in ("fsync", "full_page_writes", "synchronous_commit", "archive_mode"))
                    and settings.get("archive_command") == "pgbackrest --stanza=verify archive-push %p"
                    and settings.get("archive_timeout") == "60", "Durability/WAL settings changed")
            archiver = connection.execute("SELECT archived_count,last_archived_wal,last_archived_time,failed_count,last_failed_time "
                                          "FROM pg_stat_archiver").fetchone()
            roles = connection.execute("SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole FROM pg_roles "
                "WHERE rolname IN ('verify_owner','verify_app','verify_retention','verify_runtime','verify_maintenance') ORDER BY rolname").fetchall()
            expected = {"verify_owner": False, "verify_app": False, "verify_retention": False,
                        "verify_runtime": True, "verify_maintenance": True}
            require({row[0]: row[1] for row in roles} == expected and not any(any(row[2:]) for row in roles),
                    "Target application role boundaries changed")
    require(all(chain.get("ok") is True for chain in chains), "A target ledger chain failed verification")
    return {"tables": tables, "chainsOk": True, "tenantsChecked": len(chains),
            "eventsChecked": sum(chain["events"] for chain in chains), "readOnlyConsistentSnapshot": True,
            "database": "verify", "serverVersion": identity[2], "durabilitySettings": settings,
            "archiver": {"archivedCount": archiver[0], "lastArchivedWal": archiver[1],
                         "lastArchivedAtUtc": archiver[2].isoformat() if archiver[2] else None,
                         "failedCount": archiver[3], "lastFailedAtUtc": archiver[4].isoformat() if archiver[4] else None}}


def runtime_login():
    import psycopg
    password = Path("/etc/verify/secrets/db-password").read_text()
    with psycopg.connect(host="localhost", hostaddr="127.0.0.1", port=5432, user="verify_runtime", dbname="verify",
            password=password, sslmode="verify-full", sslrootcert="/etc/verify/tls/postgres-ca.pem",
            autocommit=True, connect_timeout=2, options=READ_OPTIONS) as connection:
        row = connection.execute("SELECT current_database(),current_user,current_setting('transaction_read_only'),"
                                 "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())").fetchone()
        require(row == ("verify", "verify_runtime", "on", True), "Actual runtime credential/TLS login failed")
        connection.execute("SELECT count(*) FROM public.tenant").fetchone()
    return {"role": "verify_runtime", "verifiedTls": True, "readOnlyLoginPassed": True}


def source_fence():
    import psycopg
    environment = {"PGSERVICEFILE": str(WORK / "source-service.conf"), "PGPASSFILE": str(WORK / "source.pgpass")}
    for name in list(os.environ):
        if name.startswith("PG"):
            del os.environ[name]
    for name, value in environment.items():
        metadata = Path(value).stat()
        require(metadata.st_uid == 0 and not metadata.st_mode & 0o077, "Source connection files are not private")
        os.environ[name] = value
    with psycopg.connect("service=verify_source_gate dbname=postgres application_name=verify-migration-final-proof",
                         autocommit=True, connect_timeout=3, options=READ_OPTIONS) as connection:
        params = connection.info.get_parameters()
        require(params.get("host") == SOURCE_HOST and params.get("dbname") == "postgres"
                and params.get("user") == "verify_owner" and params.get("sslmode") == "verify-full", "Source management identity changed")
        identity = connection.execute("SELECT current_setting('transaction_read_only'),"
                                      "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())").fetchone()
        require(identity == ("on", True), "Source fence proof must use read-only verified TLS")
        allowed = connection.execute("SELECT datallowconn FROM pg_database WHERE datname='verify'").fetchone()
        count = connection.execute("SELECT count(*) FROM pg_stat_activity WHERE datname='verify' AND usename<>'rdsadmin'").fetchone()[0]
        require(allowed == (False,) and count == 0, "Source admission or old sessions violate the committed writer fence")
    return {"checked": True, "admissionAllowed": False, "remainingVerifySessions": 0,
            "readOnlyVerifiedTls": True, "sourceHost": SOURCE_HOST}


def aws_reads(proof):
    """Native Python has boto3. This path calls only GetBucketLocation/GetObject/GetParameter."""
    import boto3
    from botocore.config import Config
    options = Config(connect_timeout=2, read_timeout=4, retries={"max_attempts": 0})
    s3 = boto3.client("s3", region_name="us-west-2", config=options)
    require(s3.get_bucket_location(Bucket=BUCKET).get("LocationConstraint") == "us-west-2", "Backup bucket region changed")
    backup = proof["backup"]
    result = s3.get_object(Bucket=BUCKET, Key=backup["key"], VersionId=backup["versionId"])
    try:
        require(result.get("VersionId") == backup["versionId"] and result.get("ServerSideEncryption") == "AES256"
                and result.get("ContentLength") == backup["bytes"], "Final backup version/encryption/length mismatch")
        data = result["Body"].read(64 * 1024**2)
        require(len(data) == backup["bytes"] and hashlib.sha256(data).hexdigest() == backup["sha256"],
                "Exact final backup version failed downloaded checksum verification")
    finally:
        result["Body"].close()
    ssm = boto3.client("ssm", region_name="us-west-2", config=options)
    recovered = {}
    for label, filename in PARAMETERS.items():
        parameter = ssm.get_parameter(Name="/verify-ledger/infra/" + label, WithDecryption=True)["Parameter"]
        path = Path("/etc/verify/secrets") / filename
        require(path.stat().st_uid == 0 and not path.stat().st_mode & 0o077, "Recovery material must remain private")
        require(parameter.get("Type") == "SecureString"
                and hmac.compare_digest(parameter["Value"].encode(), path.read_bytes()), "Independent recovery material differs")
        recovered[label] = {"version": parameter["Version"], "decryptedAndByteMatched": True}
    return {"finalDump": {**backup, "downloadedAndHashed": True}, "recoveryParameters": recovered,
            "oldSecretsManagerCalls": 0, "awsMutationCalls": 0}


def backup_gate(info, captured, required):
    require(len(info) == 1 and info[0].get("name") == "verify" and info[0].get("status", {}).get("code") == 0,
            "Backup repository does not report a healthy Verify stanza")
    full = [item for item in info[0].get("backup", []) if item.get("type") == "full"
            and item.get("timestamp", {}).get("stop") and not item.get("error")]
    require(bool(full), "No successful off-host full backup exists")
    latest = max(full, key=lambda item: item["timestamp"]["stop"])
    after = latest["timestamp"]["start"] >= datetime.fromisoformat(captured).timestamp()
    require(after or not required, "A completed full backup started after TARGET activation is required before retirement")
    return {"label": latest["label"], "startedAtEpoch": latest["timestamp"]["start"],
            "completedAtEpoch": latest["timestamp"]["stop"], "startedAfterCutover": after,
            "archiveStart": latest.get("archive", {}).get("start"), "archiveStop": latest.get("archive", {}).get("stop")}


def check_append_only(before, after):
    require(set(after) == set(TABLES), "Current database snapshot is incomplete")
    for name in ("access_log", "event", "tombstone", "run", "verdict"):
        require(after[name]["rows"] >= before[name]["rows"], "An append-only table lost rows since cutover")
        if after[name]["rows"] == before[name]["rows"]:
            require(after[name]["sha256"] == before[name]["sha256"], "An unchanged-size append-only table differs from cutover")


def prove(args, proof):
    require(os.geteuid() == 0, "Run the post-cutover proof as root on the target")
    installed = json.loads(Path("/etc/verify/target-install.json").read_text())
    require(installed.get("accountId") == ACCOUNT and installed.get("instanceId") == INSTANCE, "Target installation identity mismatch")
    first = gate_snapshot()
    units = {}
    for unit in ("verify.service", "verify-migration.service", "caddy.service", "verify-backup.timer", "postgresql@16-main.service"):
        properties = dict(line.split("=", 1) for line in command(["systemctl", "show", unit,
            "--property=ActiveState,SubState,UnitFileState,MainPID,NRestarts,Result"]).decode().splitlines())
        require(properties.get("ActiveState") == "active", "Required service is not active: " + unit)
        if unit != "postgresql@16-main.service":
            require(properties.get("UnitFileState") == "enabled", "Required service is not enabled: " + unit)
        units[unit] = properties
    require(command(["systemctl", "is-enabled", "postgresql.service"]).decode().strip() == "enabled",
            "PostgreSQL startup is not enabled")
    database = json.loads(command(["runuser", "-u", "postgres", "--", VENV, "-m", MODULE, "database"]))
    check_append_only(proof["target"]["tables"], database["tables"])
    runner = cutover.Runner({"workDirectory": str(WORK)})
    schema = runner.schema(database="verify")
    require(schema == proof["schemaSha256"], "Live target schema differs from the final verified copy")
    login = runtime_login()
    archiver = database["archiver"]
    require(archiver["archivedCount"] > 0 and archiver["lastArchivedAtUtc"]
            and (not archiver["lastFailedAtUtc"] or datetime.fromisoformat(archiver["lastArchivedAtUtc"]) >=
                 datetime.fromisoformat(archiver["lastFailedAtUtc"])), "Latest WAL archive failure has not recovered")
    pending_ages = []
    for path in Path("/var/lib/postgresql/16/main/pg_wal/archive_status").glob("*.ready"):
        try:
            pending_ages.append(time.time() - path.stat().st_mtime)
        except FileNotFoundError:
            pass  # A healthy archiver may finish between listing and stat.
    oldest = max(pending_ages, default=0)
    require(oldest < 300, "An unarchived WAL segment is older than five minutes")
    configuration = configparser.ConfigParser(interpolation=None)
    configuration.read("/etc/pgbackrest/pgbackrest.conf")
    expected = {"repo1-type": "s3", "repo1-s3-bucket": BUCKET, "repo1-s3-region": "us-west-2",
                "repo1-path": "/live/verify-ledger/pgbackrest", "repo1-cipher-type": "aes-256-cbc",
                "repo1-retention-full-type": "time", "repo1-retention-full": "7", "repo1-bundle": "y"}
    require(all(configuration.get("global", key, fallback=None) == value for key, value in expected.items()),
            "Encrypted backup destination/retention changed")
    require(hmac.compare_digest(configuration.get("global", "repo1-cipher-pass").encode(),
                                Path("/etc/verify/secrets/backup-cipher-key").read_bytes()), "Backup cipher configuration differs from recovery material")
    info = json.loads(command(["runuser", "-u", "postgres", "--", "pgbackrest", "--stanza=verify", "--output=json", "info"]))
    backup = backup_gate(info, proof["capturedAtUtc"], args.require_post_cutover_backup)
    aws = json.loads(command(["/usr/bin/python3", "-m", MODULE, "aws", "--cutover-report", str(args.cutover_report),
                              "--sha256", args.sha256], timeout=30))
    source = source_fence() if args.check_source_fence else {"checked": False, "scope": "No source connection requested; source retirement is separate AWS evidence"}
    endpoints, reference_body = {}, None
    for label, host, port, tls in (("localApp", "127.0.0.1", 8080, False), ("localBridge", "127.0.0.1", 8082, False),
                                  ("targetTrustedTls", "127.0.0.1", 443, True), ("publicDnsTrustedTls", "ledger.optimise.work", 443, True)):
        status, body, certificate = request(host, port, "/v1/verify-chain", tls=tls)
        require(status == 401 and body.startswith(b'{"error":'), "Unexpected unauthenticated API response: " + label)
        if reference_body is None:
            reference_body = body
        require(body == reference_body, "The app and routed API responses differ")
        endpoints[label] = {"status": status, "responseSha256": hashlib.sha256(body).hexdigest(), "trustedTls": tls,
                            "certificateExpires": certificate.get("notAfter") if certificate else None}
    final = gate_snapshot()
    require(final["forwarded"]["source"] == first["forwarded"]["source"]
            and final["forwarded"]["target"] >= first["forwarded"]["target"] + 3,
            "Proof requests did not exclusively reach the authoritative target")
    memory = {line.split(":", 1)[0]: int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines()
              if line.startswith(("MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"))}
    disk = shutil.disk_usage("/var/lib/postgresql")
    require(memory["MemAvailable"] >= 256 * 1024**2 and disk.free >= 2 * 1024**3, "Insufficient measured memory/disk headroom")
    return {"status": "TARGET_LIVE_READ_ONLY_PROOF_PASSED", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
            "accountId": ACCOUNT, "instanceId": INSTANCE, "cutoverReport": str(args.cutover_report), "cutoverReportSha256": args.sha256,
            "units": units, "targetDatabase": database, "schemaSha256": schema,
            "allTablesUnchangedSinceActivation": database["tables"] == proof["target"]["tables"], "runtimeLogin": login,
            "sourceFence": source, "latestFullBackup": backup, "pendingWalSegments": len(pending_ages), "oldestPendingWalSeconds": oldest,
            "recoveryMaterial": aws, "api": endpoints, "bridge": final, "memoryBytes": memory,
            "diskBytes": {"total": disk.total, "free": disk.free}, "databaseMutationStatements": 0, "awsMutationCalls": 0,
            "servicesRestarted": False, "customerAuthenticatedApiTest": False,
            "scope": "Live target, consistent read-only data/chains, runtime TLS login, service enablement and independent recovery material. Resource retirement and external-client checks remain separate."}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("database")
    for operation in ("aws", "prove"):
        item = commands.add_parser(operation)
        item.add_argument("--cutover-report", type=Path, required=True)
        item.add_argument("--sha256", required=True)
        if operation == "prove":
            item.add_argument("--check-source-fence", action="store_true")
            item.add_argument("--require-post-cutover-backup", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "database":
            result = database_snapshot()
        else:
            require(os.geteuid() == 0, "Run the proof as root")
            proof = checked_cutover(args.cutover_report, args.sha256)
            if args.command == "aws":
                result = aws_reads(proof)
            else:
                with open("/run/verify-cutover.lock", "w") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    result = prove(args, proof)
                    output = WORK / ("live-target-proof-" + str(time.time_ns()) + ".json")
                    cutover.write_report(output, result)
                    result = {"status": result["status"], "report": str(output),
                              "sourceFenceChecked": args.check_source_fence,
                              "postCutoverFullBackup": result["latestFullBackup"]["startedAfterCutover"]}
        print(json.dumps(result))
        return 0
    except Exception as error:
        print(json.dumps({"status": "LIVE_TARGET_PROOF_BLOCKED", "errorClass": type(error).__name__,
                          "reason": str(error) if isinstance(error, cutover.Blocked) else "Inspect private target state; credentials and row values suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
