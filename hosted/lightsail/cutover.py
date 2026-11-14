#!/usr/bin/env python3
"""Local EC2 rehearsal and coordinated source fence/copy/single-writer cutover.

Run as root on the staged target. Secrets stay in private libpq and credential
files. No DNS, AWS source deletion or backup deletion is performed. Once TARGET
is durable, source rollback is prohibited. Any failure after that boundary leaves
the source fenced and the target authoritative for an operator to repair.
"""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

from hosted.lightsail.compare_data import TABLES, fingerprint, inventory
from hosted.lightsail.migration_proxy import control

ROOT = Path(__file__).resolve().parent
SOCKET = "/run/verify-migration/control.sock"
STATE = Path("/var/lib/verify-migration/state.json")
WRITER = Path("/etc/verify/production-writer-enabled")


class Blocked(RuntimeError):
    pass


class DeadlineExpired(Blocked):
    pass


class WallBudget:
    """Linux process-wide deadline; interrupted DB sessions are closed/quarantined.

    Do not raise KeyboardInterrupt/SystemExit: psycopg may perform a lengthy
    cancellation drain for those exceptions. A private timeout leaves cancellation
    to the independent recovery connection, which terminates and settles both old
    backend PIDs before it can re-enable source admission.
    """
    def __init__(self, seconds):
        self.seconds = seconds
        self.armed = False

    def arm(self):
        if signal.getitimer(signal.ITIMER_REAL)[0]:
            raise Blocked("A different process alarm is active; do not override it")
        self.previous_handler = signal.signal(signal.SIGALRM, self._expired)
        signal.setitimer(signal.ITIMER_REAL, self.seconds)
        self.armed = True

    def _expired(self, signum, frame):
        raise DeadlineExpired("Cutover wall-clock budget expired; independently recover or preserve the fenced source")

    def cancel(self):
        if self.armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self.previous_handler)
            self.armed = False


def database_name(value):
    if value != "verify" and not re.fullmatch(r"verify_(?:stage|previous)_[a-f0-9]{12}", value):
        raise Blocked("Unexpected target database name")
    return value


def canonical_schema(raw):
    return "\n".join(line.rstrip() for line in raw.decode().splitlines()
                     if line.strip() and not line.startswith(("--", "\\restrict ", "\\unrestrict "))).encode()


def durable_target_state(path=None):
    """True=target authoritative, False=proved pre-target, None=unsafe uncertainty."""
    try:
        path = STATE if path is None else path
        state = json.loads(path.read_text())
        if (state.get("version") != 1 or state.get("mode") not in ("source", "drain", "target")
                or type(state.get("targetActivated")) is not bool
                or (state["mode"] == "target" and not state["targetActivated"])
                or (state["mode"] == "source" and state["targetActivated"])):
            return None
        return state["targetActivated"]
    except (OSError, ValueError, TypeError, AttributeError):
        return None


class Runner:
    def __init__(self, config):
        self.config = config
        self.deadline = None
        self.env = dict(os.environ, PYTHONPATH=str(ROOT.parents[1]) + "/src:" + str(ROOT.parents[1]))

    def timeout(self, maximum=30):
        if self.deadline is None:
            return maximum
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Blocked("Cutover deadline reached before target activation")
        return min(maximum, remaining)

    def run(self, command, data=None, maximum=30):
        environment = self.env
        if command[0] == "runuser":
            # Source connection variables must never redirect a local target write.
            environment = {key: value for key, value in self.env.items() if not key.startswith("PG")}
        result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=environment, timeout=self.timeout(maximum))
        if result.returncode:
            # Database stderr can contain rows/credentials; keep it out of shared logs.
            failure = Path(self.config["workDirectory"]) / ("private-command-error-" + uuid.uuid4().hex[:12] + ".json")
            write_report(failure, {"program": Path(command[0]).name, "returncode": result.returncode,
                                   "stderr": result.stderr.decode(errors="replace")[:16384]})
            raise Blocked("A private local command failed: " + Path(command[0]).name)
        return result.stdout

    def pg(self, query, database="postgres", expected=None):
        command = ["runuser", "-u", "postgres", "--", "psql", "-X", "-q", "-A", "-t",
                   "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql", "-p", "5432", "-U", "postgres", "-d", database]
        if expected:
            command += ["-v", "expected_database=" + expected]
        return self.run(command, query.encode())

    def dump(self, output):
        self.run(["pg_dump", "--dbname=service=" + self.config["sourceService"]
                  + " application_name=verify-migration-export", "--format=custom", "--no-owner",
                  "--file=" + str(output)])
        if not 0 < output.stat().st_size < 64 * 1024 * 1024:
            raise Blocked("Final dump exceeds the reviewed pilot bounds")

    def schema(self, source=False, database="verify"):
        command = ["pg_dump", "--schema-only", "--no-owner", "--no-privileges", "--no-comments"]
        if source:
            command += ["--dbname=service=" + self.config["sourceService"]
                        + " application_name=verify-migration-schema"]
        else:
            command = ["runuser", "-u", "postgres", "--"] + command + ["--host=/var/run/postgresql", "--port=5432", "--username=postgres", "--dbname=" + database]
        return hashlib.sha256(canonical_schema(self.run(command))).hexdigest()

    def stage(self, dump, name):
        database_name(name)
        self.pg(f'CREATE DATABASE "{name}" OWNER verify_owner TEMPLATE template0 ENCODING \'UTF8\';')
        self.run(["runuser", "-u", "postgres", "--", "pg_restore", "--single-transaction", "--exit-on-error",
                  "--no-owner", "--role=verify_owner", "--host=/var/run/postgresql", "--port=5432",
                  "--username=postgres", "--dbname=" + name], dump.read_bytes())
        self.pg((ROOT / "target_runtime_grants.sql").read_text(), name)
        self.pg((ROOT / "runtime_preflight.sql").read_text(), name, expected=name)

    def inspect(self, name):
        database_name(name)
        result = self.run(["runuser", "-u", "postgres", "--", "/opt/verify/current/.venv/bin/python", "-m",
                           "hosted.lightsail.cutover", "inspect", "--database", name])
        return json.loads(result)

    def archive_check(self):
        self.pg("SELECT pg_switch_wal();")
        self.run(["runuser", "-u", "postgres", "--", "pgbackrest", "--stanza=verify",
                  "--archive-timeout=5", "check"], maximum=7)


def inspect_target(name, port=5432):
    import psycopg
    from hosted.store import PostgresStore
    database_name(name)
    if port not in (5432, 5433):
        raise Blocked("Unexpected local inspection port")
    dsn = f"host=/var/run/postgresql port={port} user=postgres dbname={name}"
    with psycopg.connect(dsn, autocommit=True) as connection:
        identity = connection.execute("SELECT current_database(),current_setting('server_version_num'),current_setting('server_encoding')").fetchone()
        if identity[0] != name or not str(identity[1]).startswith("16") or identity[2] != "UTF8":
            raise Blocked("Target database identity mismatch")
        tables = inventory(connection)
        tenants = connection.execute("SELECT id FROM public.tenant ORDER BY id").fetchall()
    store = PostgresStore(dsn, pool_size=1)
    try:
        chains = [store.verify_chain(row[0]) for row in tenants]
    finally:
        store.close()
    return {"tables": tables, "chainsOk": all(row.get("ok") is True for row in chains),
            "tenantsChecked": len(chains), "eventsChecked": sum(row.get("events", 0) for row in chains)}


def source_inventory(connection):
    from psycopg import sql
    result = {}
    connection.execute("SET LOCAL timezone = 'UTC'")
    for name in TABLES:
        with connection.cursor() as cursor:
            cursor.execute(sql.SQL('SELECT row_to_json(t)::text FROM public.{} AS t ORDER BY row_to_json(t)::text COLLATE "C"').format(sql.Identifier(name)))
            result[name] = fingerprint(cursor)
    return result


def check_source(connection, config):
    params = connection.info.get_parameters()
    if (params.get("host") != config["sourceHost"] or params.get("dbname") != "verify"
            or params.get("user") != "verify_owner" or params.get("sslmode") != "verify-full"):
        raise Blocked("Source must be the observed verified-TLS RDS verify/verify_owner endpoint")
    identity = connection.execute("SELECT current_database(),current_user,current_setting('server_version_num'),current_setting('server_encoding'),(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())").fetchone()
    if identity[:2] != ("verify", "verify_owner") or not str(identity[2]).startswith("16") or identity[3:] != ("UTF8", True):
        raise Blocked("Source database identity/TLS mismatch")
    names = connection.execute("SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema'").fetchall()
    if set(names) != {("public", name) for name in TABLES}:
        raise Blocked("Source contains unreviewed tables")
    other = connection.execute("SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND c.relkind IN ('S','v','m','f','p')), (SELECT count(*) FROM pg_largeobject_metadata), (SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database()), (SELECT count(*) FROM pg_subscription)").fetchone()
    if any(other):
        raise Blocked("Unreviewed relations, large objects, prepared transactions or subscriptions exist")
    writers = connection.execute("SELECT r.rolname FROM pg_roles r WHERE r.rolcanlogin AND r.rolname NOT IN ('verify_owner','rdsadmin') AND (r.rolsuper OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE'))))").fetchall()
    if writers:
        raise Blocked("Additional source login writers require an explicit fence")
    if not connection.execute("SELECT datallowconn FROM pg_database WHERE datname='verify'").fetchone()[0]:
        raise Blocked("Source database was already fenced; inspect the existing cutover state")


def app_healthy():
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=1)
    try:
        connection.request("GET", "/v1/verify-chain")
        response = connection.getresponse()
        return response.status == 401 and response.read(1024).startswith(b'{"error":')
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def read_config(path):
    config = json.loads(path.read_text())
    if path.stat().st_mode & 0o077:
        raise Blocked("Coordinator configuration must be private (0600)")
    for key, pattern in (("accountId", r"[0-9]{12}"), ("instanceId", r"i-[0-9a-f]{17}"),
                         ("sourceService", r"[a-z][a-z0-9_]{0,63}"),
                         ("exportKeySha256", r"[0-9a-f]{64}")):
        if not re.fullmatch(pattern, config.get(key, "")):
            raise Blocked("Invalid coordinator identity/configuration")
    installed = json.loads(Path("/etc/verify/target-install.json").read_text())
    if any(installed.get(key) != config[key] for key in ("instanceId", "accountId")):
        raise Blocked("Target installation identity mismatch")
    if hashlib.sha256(Path("/etc/verify/secrets/export-key").read_bytes()).hexdigest() != config["exportKeySha256"]:
        raise Blocked("Export HMAC key differs from the verified source key")
    if os.environ.get("PGPASSWORD") or not os.environ.get("PGSERVICEFILE") or not os.environ.get("PGPASSFILE"):
        raise Blocked("Use private libpq service/passfiles, not password environment variables")
    for key in ("PGSERVICEFILE", "PGPASSFILE"):
        if Path(os.environ[key]).stat().st_mode & 0o077:
            raise Blocked("Source connection files must be private (0600)")
    if config.get("backupPrefix") != "live/verify-ledger/cutovers/":
        raise Blocked("Backup prefix must match the reviewed instance policy")
    if config.get("backupBucket") != "verify-ledger-migration-842676017161-20261114" or config.get("backupRegion") != "us-west-2":
        raise Blocked("Backup bucket/region must match the verified Verify project destination")
    environment = dict(os.environ, PYTHONPATH=str(ROOT.parents[1]) + "/src:" + str(ROOT.parents[1]))
    location = subprocess.run(["/usr/bin/python3", "-m", "hosted.lightsail.cutover", "bucket-region",
                               "--bucket", config["backupBucket"]], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    if location.returncode or json.loads(location.stdout).get("bucketRegion") != config["backupRegion"]:
        raise Blocked("Live S3 bucket region does not match coordinator configuration")
    work = Path(config["workDirectory"])
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    if work.stat().st_mode & 0o077:
        raise Blocked("Migration working directory must be private (0700)")
    return config


def write_report(path, report):
    data = (json.dumps(report, indent=2) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def authorize_writer():
    payload = {"authorizedAtUtc": datetime.now(timezone.utc).isoformat(),
               "scope": "Verified target data; public traffic remains behind the migration gate"}
    write_report(WRITER, payload)
    directory = os.open(WRITER.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def revoke_writer():
    WRITER.unlink(missing_ok=True)
    directory = os.open(WRITER.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def save_dump(config, runner, path, suffix):
    digest = hashlib.sha256(path.read_bytes()).digest()
    key = config["backupPrefix"] + suffix + "/database.dump"
    # Native Python has the distro boto3 package. The deadline-bound child avoids
    # adding AWS libraries to the app venv or allowing SDK retries to overrun DRAIN.
    result = json.loads(runner.run(["/usr/bin/python3", "-m", "hosted.lightsail.cutover", "upload",
        "--region", config["backupRegion"], "--bucket", config["backupBucket"],
        "--key", key, "--dump", str(path), "--sha256", digest.hex()], maximum=4))
    version = result.get("VersionId")
    if not version or version == "null" or result.get("ServerSideEncryption") != "AES256":
        raise Blocked("Final backup encryption/version confirmation failed")
    return {"bucket": config["backupBucket"], "key": key, "versionId": version,
            "sha256": digest.hex(), "bytes": path.stat().st_size}


def upload_dump(args):
    import boto3
    from botocore.config import Config
    if not args.key.startswith("live/verify-ledger/cutovers/") or not args.key.endswith("/database.dump"):
        raise Blocked("Unexpected final-backup object prefix")
    data = args.dump.read_bytes()
    digest = hashlib.sha256(data).digest()
    if digest.hex() != args.sha256 or not 0 < len(data) < 64 * 1024 * 1024:
        raise Blocked("Final dump changed before upload")
    client = boto3.client("s3", region_name=args.region,
                          config=Config(connect_timeout=1, read_timeout=2, retries={"max_attempts": 0}))
    response = client.put_object(Bucket=args.bucket, Key=args.key, Body=data,
        ServerSideEncryption="AES256", ChecksumSHA256=base64.b64encode(digest).decode())
    return {key: response.get(key) for key in ("VersionId", "ServerSideEncryption", "ChecksumSHA256")}


def rehearsal(config, runner):
    import psycopg
    token = uuid.uuid4().hex[:12]
    stage, work = "verify_stage_" + token, Path(config["workDirectory"])
    dump = work / (token + "-rehearsal.dump")
    with psycopg.connect("service=" + config["sourceService"], autocommit=True) as source:
        check_source(source, config)
    with psycopg.connect("service=" + config["sourceService"] + " dbname=postgres", autocommit=True) as management:
        # Prove admission-fence permission without disabling any actual connections.
        with management.transaction(force_rollback=True):
            management.execute("ALTER DATABASE verify ALLOW_CONNECTIONS false")
    started = time.monotonic()
    runner.dump(dump)
    runner.stage(dump, stage)
    details = runner.inspect(stage)
    source_schema, target_schema = runner.schema(source=True), runner.schema(database=stage)
    if source_schema != target_schema or not details["chainsOk"]:
        raise Blocked("Rehearsal schema/chain verification failed")
    runner.archive_check()
    backup = save_dump(config, runner, dump, "rehearsal-" + token)
    elapsed = time.monotonic() - started
    if elapsed > 8:
        raise Blocked("Rehearsal exceeds eight seconds; the 20-second queue needs more proven headroom")
    report = {"schemaVersion": 1, "status": "REHEARSAL_PASSED", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
              "instanceId": config["instanceId"], "accountId": config["accountId"], "sourceHost": config["sourceHost"],
              "schemaSha256": source_schema, "measuredSeconds": elapsed, "stageDatabase": stage,
              "databaseFencePermissionRolledBack": True, "target": details, "backup": backup,
              "scope": "Fresh dump/restore/roles/chains/schema/WAL archive rehearsal; no source data, routing or login changes"}
    output = work / (token + "-rehearsal.json")
    write_report(output, report)
    return {"status": report["status"], "report": str(output), "measuredSeconds": elapsed}



def recover_source_authority(config, source, management, source_pid, management_pid,
                             source_address, fence_attempted, drain_attempted):
    """Bounded independent recovery before any TARGET activation attempt."""
    import psycopg
    budget, steps, rescue = WallBudget(4), [], None
    try:
        budget.arm()
        source.close()
        management.close()
        steps.append("OLD_DATABASE_SESSIONS_CLOSED_AND_QUARANTINED")
        options = {"autocommit": True, "connect_timeout": 1,
                   "options": "-c statement_timeout=1000 -c lock_timeout=1000"}
        if source_address:
            options["hostaddr"] = source_address
        rescue = psycopg.connect("service=" + config["sourceService"]
            + " dbname=postgres application_name=verify-migration-abort", **options)
        rescue.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid IN (%s,%s) AND application_name IN ('verify-migration-gate','verify-migration-recovery') AND usename='verify_owner'", (source_pid, management_pid))
        settle_deadline = time.monotonic() + 1
        while rescue.execute("SELECT count(*) FROM pg_stat_activity WHERE pid IN (%s,%s) AND application_name IN ('verify-migration-gate','verify-migration-recovery') AND usename='verify_owner'", (source_pid, management_pid)).fetchone()[0]:
            if time.monotonic() > settle_deadline:
                raise Blocked("Interrupted source sessions have not settled; do not unfence")
            time.sleep(.025)
        steps.append("OLD_DATABASE_BACKENDS_TERMINATED_AND_SETTLED")
        if fence_attempted:
            rescue.execute("ALTER DATABASE verify ALLOW_CONNECTIONS true")
        if rescue.execute("SELECT datallowconn FROM pg_database WHERE datname='verify'").fetchone()[0] is not True:
            raise Blocked("Source admission is not proved restored")
        steps.append("SOURCE_DATABASE_ADMISSION_RESTORED")
        if drain_attempted:
            observed = control(SOCKET, {"action": "status"}, timeout=1)
            if not observed.get("ok") or observed.get("targetActivated"):
                raise Blocked("Source bridge recovery state is uncertain")
            if observed.get("mode") == "drain":
                response = control(SOCKET, {"action": "set", "mode": "source", "expected": "drain"}, timeout=1)
                if not response.get("ok"):
                    raise Blocked("Source bridge transition rejected")
            elif observed.get("mode") != "source":
                raise Blocked("Unexpected bridge mode during source recovery")
            steps.append("SOURCE_ROUTING_RESTORED")
        return steps, None
    except Exception as error:
        return steps, "SOURCE_AUTHORITY_RECOVERY_" + type(error).__name__
    finally:
        budget.cancel()
        if rescue is not None:
            rescue.close()


def cutover(config, runner, rehearsal_path):
    import psycopg
    from psycopg import sql
    previous = json.loads(rehearsal_path.read_text())
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(previous["capturedAtUtc"])).total_seconds()
    if (previous.get("status") != "REHEARSAL_PASSED" or not 0 <= age <= 1800 or previous.get("measuredSeconds", 99) > 8
            or any(previous.get(key) != config[key] for key in ("instanceId", "accountId", "sourceHost"))):
        raise Blocked("A fresh successful rehearsal on this target is required")
    evidence = config.get("readiness", {})
    for key in ("applicationFeatureTestsPassed", "encryptedBackupRestoreTestPassed", "oldAlbRequestsDrained",
                "allOtherSourceWritersDisabled", "httpsCertificateAndRenewalPathVerified", "databaseDeadlineInterruptTestPassed"):
        if evidence.get(key) is not True:
            raise Blocked("Missing verified readiness evidence: " + key)
    if evidence.get("retainedSourceAutomatedBackupDays") != 7:
        raise Blocked("Seven-day recovery continuity requires retained source automated backups")
    status = control(SOCKET, {"action": "status"}, timeout=1)
    if (not status.get("ok") or status.get("mode") != "source" or status.get("targetActivated")
            or status.get("queueDeadlineSeconds") != 20 or status.get("queueTimeouts")):
        raise Blocked("The live source bridge must be healthy with the reviewed 20-second queue")
    if subprocess.run(["systemctl", "is-active", "--quiet", "verify.service"]).returncode == 0:
        raise Blocked("Stop the private target app before final database staging")
    if WRITER.exists():
        raise Blocked("Previous writer authorization exists; inspect the incomplete migration state")
    runner.archive_check()
    token, work = uuid.uuid4().hex[:12], Path(config["workDirectory"])
    stage, old = "verify_stage_" + token, "verify_previous_" + token
    dump, output = work / (token + "-final.dump"), work / (token + "-cutover.json")
    source = psycopg.connect("service=" + config["sourceService"] + " application_name=verify-migration-gate connect_timeout=3", autocommit=True)
    # The management connection remains outside verify, so recovery is possible
    # through postgres even after a coordinator/host crash closes all sessions.
    abort = psycopg.connect("service=" + config["sourceService"] + " dbname=postgres application_name=verify-migration-recovery connect_timeout=3", autocommit=True)
    drain_attempted = drained = fence_attempted = fenced = swapped = activated = activation_attempted = False
    source_pid, management_pid = source.info.backend_pid, abort.info.backend_pid
    source_address = getattr(source.info, "hostaddr", None)
    wall = WallBudget(15)
    def bridge(request):
        return control(SOCKET, request, timeout=runner.timeout(1))
    old_oid = int(runner.pg("SELECT oid FROM pg_database WHERE datname='verify';").strip())
    phase, result = "preflight", {"status": "BLOCKED", "token": token}
    try:
        check_source(source, config)
        if runner.schema(source=True) != previous["schemaSha256"]:
            raise Blocked("Source schema changed after rehearsal")
        source.execute("SET statement_timeout='4s'")
        source.execute("SET lock_timeout='3s'")
        abort.execute("SET statement_timeout='3s'")
        phase = "drain"
        # Budget begins before DRAIN is sent: the gate can persist its state before
        # its response reaches us, and queued clients must not lose that interval.
        started = time.monotonic()
        runner.deadline = started + 15
        wall.arm()
        drain_attempted = True
        control_result = bridge({"action": "set", "mode": "drain", "expected": "source"})
        if not control_result.get("ok"):
            raise Blocked("Bridge rejected the drain transition")
        drained = True
        while bridge({"action": "status"}).get("active"):
            runner.timeout(1)
            time.sleep(.025)
        phase = "source-table-fence"
        source.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        source.execute(sql.SQL("LOCK TABLE {} IN SHARE MODE").format(
            sql.SQL(", ").join(sql.Identifier("public", name) for name in sorted(TABLES))))
        source.execute("SET LOCAL statement_timeout='1s'")
        before = source_inventory(source)
        phase = "final-copy"
        runner.dump(dump)
        runner.stage(dump, stage)
        after = runner.inspect(stage)
        if before != after["tables"] or not after["chainsOk"] or runner.schema(database=stage) != previous["schemaSha256"]:
            raise Blocked("Final source/target table multiset, chain or schema mismatch")
        runner.timeout()
        backup = save_dump(config, runner, dump, token)
        phase = "target-database-swap"
        runner.pg("ALTER DATABASE verify WITH ALLOW_CONNECTIONS false;")
        runner.pg("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='verify' AND pid<>pg_backend_pid();")
        runner.pg(f'BEGIN; ALTER DATABASE verify RENAME TO "{old}"; ALTER DATABASE "{stage}" RENAME TO verify; COMMIT;')
        swapped = True
        runner.archive_check()
        authorize_writer()
        phase = "target-app-health"
        runner.run(["systemctl", "enable", "--now", "verify.service"], maximum=3)
        while not app_healthy():
            runner.timeout(1)
            time.sleep(.05)
        phase = "source-database-admission-fence"
        fence_attempted = True
        abort.execute("ALTER DATABASE verify ALLOW_CONNECTIONS false")
        fenced = True
        abort.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='verify' AND pid<>%s AND usename<>'rdsadmin'", (source.info.backend_pid,))
        while abort.execute("SELECT count(*) FROM pg_stat_activity WHERE datname='verify' AND pid<>%s AND usename<>'rdsadmin'", (source.info.backend_pid,)).fetchone()[0]:
            runner.timeout(1)
            time.sleep(.025)
        if abort.execute("SELECT datallowconn FROM pg_database WHERE datname='verify'").fetchone()[0]:
            raise Blocked("Source database admission fence was not established")
        runner.timeout()
        source.execute("COMMIT")
        phase = "activate-target"
        # Once sent, the control server might persist TARGET after a socket timeout.
        # A currently-false state file is then insufficient to justify unfencing.
        activation_attempted = True
        transition = bridge({"action": "set", "mode": "target", "expected": "drain"})
        activated = durable_target_state() is True
        if not activated or not transition.get("ok"):
            raise Blocked("Target activation needs operator inspection")
        phase = "target-authoritative"
        wall.cancel()
        runner.deadline = None
        result = {"schemaVersion": 1, "status": "TARGET_AUTHORITATIVE", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
                  "instanceId": config["instanceId"], "accountId": config["accountId"], "elapsedQueueSeconds": time.monotonic()-started,
                  "sourceDatabaseAdmissionFenced": True, "sourceTargetTablesMatch": True, "target": after,
                  "schemaSha256": previous["schemaSha256"], "backup": backup, "previousTargetDatabase": old,
                  "bridge": bridge({"action": "status"}),
                  "scope": "Target accepts writes; source remains fenced. DNS and source-resource retirement are separate verified steps."}
        write_report(output, result)
        return {"status": result["status"], "report": str(output), "elapsedQueueSeconds": result["elapsedQueueSeconds"]}
    except Exception as exc:
        wall.cancel()
        runner.deadline = None
        # Check durable state even if the activation command response was lost.
        durable = durable_target_state()
        activated = activated or durable is True
        recovery = []
        recovery_errors = []
        if activated or activation_attempted or durable is None:
            recovery.append("NO_SOURCE_UNFENCE_ATTEMPTED_TARGET_STATE_PROTECTED")
            if durable is None:
                recovery.append("DURABLE_GATE_STATE_UNCERTAIN_OPERATOR_INTERVENTION_REQUIRED")
        else:
            steps, recovery_error = recover_source_authority(config, source, abort,
                source_pid, management_pid, source_address, fence_attempted, drain_attempted)
            recovery.extend(steps)
            if recovery_error:
                recovery_errors.append(recovery_error)
            try:
                subprocess.run(["systemctl", "disable", "--now", "verify.service"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=True)
                revoke_writer()
                recovery.append("TARGET_APP_DISABLED")
                # Both database renames commit together. Inspect the immutable old
                # OID even if the subprocess response was lost after its commit.
                old_name = runner.pg(f"SELECT datname FROM pg_database WHERE oid={old_oid};").decode().strip()
                if old_name == old:
                    runner.pg("ALTER DATABASE verify WITH ALLOW_CONNECTIONS false;")
                    runner.pg("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='verify' AND pid<>pg_backend_pid();")
                    runner.pg(f'BEGIN; ALTER DATABASE verify RENAME TO "{stage}"; ALTER DATABASE "{old}" RENAME TO verify; COMMIT;')
                elif old_name != "verify":
                    raise Blocked("Unexpected private target database identity during abort")
                runner.pg("ALTER DATABASE verify WITH ALLOW_CONNECTIONS true;")
                recovery.append("PRIVATE_REHEARSAL_DATABASE_RESTORED")
            except Exception as cleanup:
                recovery_errors.append("PRIVATE_TARGET_RECOVERY_" + type(cleanup).__name__)
        final_status = "TARGET_NEEDS_REPAIR" if activated else "ABORTED_TO_SOURCE"
        if activation_attempted and not activated:
            final_status = "TARGET_ACTIVATION_UNCERTAIN_SOURCE_FENCED"
        if durable is None or recovery_errors:
            final_status = "OPERATOR_RECOVERY_REQUIRED"
        write_report(output, {"status": final_status, "phase": phase,
                              "errorClass": type(exc).__name__, "targetActivated": activated, "recovery": recovery,
                              "targetActivationAttempted": activation_attempted,
                              "recoveryErrors": recovery_errors, "durableTargetState": durable,
                              "targetDatabaseSwapped": swapped, "previousTargetDatabase": old if swapped else None,
                              "capturedAtUtc": datetime.now(timezone.utc).isoformat()})
        raise Blocked("Cutover stopped in " + phase + "; inspect private report " + str(output)) from None
    finally:
        wall.cancel()
        source.close()
        abort.close()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--database", required=True)
    inspect.add_argument("--port", type=int, choices=(5432, 5433), default=5432)
    upload = commands.add_parser("upload")
    for argument in ("region", "bucket", "key", "sha256"):
        upload.add_argument("--" + argument, required=True)
    upload.add_argument("--dump", required=True, type=Path)
    region = commands.add_parser("bucket-region")
    region.add_argument("--bucket", required=True)
    for mode in ("rehearse", "cutover"):
        task = commands.add_parser(mode)
        task.add_argument("--config", type=Path, required=True)
        if mode == "cutover":
            task.add_argument("--rehearsal", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            result = inspect_target(args.database, args.port)
        elif args.command == "upload":
            if os.geteuid() != 0:
                raise Blocked("Final backup upload must run as the private coordinator")
            result = upload_dump(args)
        elif args.command == "bucket-region":
            import boto3
            from botocore.config import Config
            client = boto3.client("s3", region_name="us-west-2",
                                  config=Config(connect_timeout=1, read_timeout=2, retries={"max_attempts": 0}))
            result = {"bucketRegion": client.get_bucket_location(Bucket=args.bucket).get("LocationConstraint") or "us-east-1"}
        else:
            if os.geteuid() != 0:
                raise Blocked("Coordinator must run as root on the staged target")
            with open("/run/verify-cutover.lock", "w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                config = read_config(args.config)
                runner = Runner(config)
                result = rehearsal(config, runner) if args.command == "rehearse" else cutover(config, runner, args.rehearsal)
        print(json.dumps(result))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "errorClass": type(exc).__name__,
                          "reason": str(exc) if isinstance(exc, Blocked) else "Inspect private operator state; details suppressed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
