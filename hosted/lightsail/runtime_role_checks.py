#!/usr/bin/env python3
"""Private target-only HTTP tests using the actual verify_runtime database login.

No AWS APIs or source database connections. Creates one uniquely named temporary
database, briefly adds exact database/user/loopback TLS HBA entries, exercises the
existing HTTP/concurrency suite, then restores HBA and removes the test database.
Production verify data, credentials, roles and writer state remain unchanged.
Run with the deployed application venv and PYTHONPATH=/opt/verify/current/src:/opt/verify/current.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import uuid

from hosted.lightsail.cutover import Blocked, Runner, durable_target_state, write_report

ACCOUNT = "842676017161"
HBA = Path("/etc/postgresql/16/main/pg_hba.conf")
CA = "/etc/verify/tls/postgres-ca.pem"


def checked_database(name):
    if not re.fullmatch(r"verify_stage_[a-f0-9]{12}", name):
        raise Blocked("Only a unique private test database is permitted")
    return name


def private_bytes(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def replace_hba(data, previous_stat):
    temporary = HBA.with_name(".verify-runtime-check-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, previous_stat.st_mode & 0o777)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chown(temporary, previous_stat.st_uid, previous_stat.st_gid)
        os.chmod(temporary, previous_stat.st_mode & 0o777)
        os.replace(temporary, HBA)
        directory = os.open(HBA.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def password_field(value):
    if any(char in value for char in ("\n", "\r", "\0")):
        raise Blocked("Credential cannot be represented in a private libpq passfile")
    return value.replace("\\", "\\\\").replace(":", "\\:")


def hba_block(database):
    checked_database(database)
    return (f"# BEGIN VERIFY PRIVATE RUNTIME TEST {database}\n"
            f"hostssl {database} verify_runtime 127.0.0.1/32 scram-sha-256\n"
            f"hostssl {database} verify_maintenance 127.0.0.1/32 scram-sha-256\n"
            f"# END VERIFY PRIVATE RUNTIME TEST {database}\n").encode()


def local_environment():
    return {key: value for key, value in os.environ.items() if not key.startswith(("PG", "VERIFY_"))}


def test_dsn(database, user, passfile):
    from psycopg.conninfo import make_conninfo
    checked_database(database)
    if user not in ("verify_runtime", "verify_maintenance"):
        raise Blocked("Unexpected test role")
    return make_conninfo(host="localhost", hostaddr="127.0.0.1", port=5432, dbname=database,
        user=user, passfile=str(passfile), sslmode="verify-full", sslrootcert=CA,
        connect_timeout=3, application_name="verify-runtime-role-check",
        options="-c statement_timeout=5000 -c lock_timeout=4000")


def run_suite(args):
    import unittest
    from hosted import test_hosted as original
    from hosted.store import PostgresStore
    checked_database(args.database)
    for name in list(os.environ):
        if name.startswith(("PG", "VERIFY_")):
            del os.environ[name]
    runner = Runner({"workDirectory": str(args.directory)})
    runtime_dsn = test_dsn(args.database, "verify_runtime", args.passfile)
    maintenance_dsn = test_dsn(args.database, "verify_maintenance", args.passfile)
    schema = args.schema.read_bytes()
    initialized = False

    def fresh_runtime_store(_unused):
        nonlocal initialized
        if initialized:
            runner.pg(f'DROP DATABASE "{args.database}" WITH (FORCE);')
        runner.pg(f'CREATE DATABASE "{args.database}" OWNER verify_owner TEMPLATE template0 ENCODING \'UTF8\';')
        initialized = True
        runner.run(["runuser", "-u", "postgres", "--", "pg_restore", "--single-transaction", "--exit-on-error",
                    "--no-owner", "--role=verify_owner", "--host=/var/run/postgresql", "--port=5432",
                    "--username=postgres", "--dbname=" + args.database], schema)
        store = PostgresStore(runtime_dsn, pool_size=args.pool)
        identity = store.q("SELECT current_database(),current_user,session_user,(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),pg_has_role(current_user,'verify_owner','MEMBER')").fetchone()
        if identity != (args.database, "verify_runtime", "verify_runtime", True, False):
            store.close()
            raise Blocked("HTTP test connection is not the restricted, authenticated TLS runtime role")
        attributes = store.q("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication FROM pg_roles WHERE rolname=current_user").fetchone()
        if any(attributes):
            store.close()
            raise Blocked("Runtime test role has unexpected administrative attributes")
        return store

    original.PG = runtime_dsn
    original.Store = fresh_runtime_store

    class RuntimeHosted(original.Hosted):
        def test_purge_keeps_chain_valid(self):
            # Retention is an administrative operation, not a web-runtime grant.
            old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=500)).isoformat()
            e1 = original.ev("r", "a", {"pii": "synthetic@example.invalid"}, "", at=old)
            e2 = original.ev("r", "b", {"n": 2}, e1["hash"])
            self.assertEqual(self.post([e1, e2])[0], 201)
            with self.assertRaises(Exception):
                self.store.q("DELETE FROM event_payload WHERE tenant_id='acme' AND seq=1")
            maintenance = PostgresStore(maintenance_dsn, pool_size=1)
            try:
                self.assertEqual(maintenance.q("SELECT current_user,session_user").fetchone(), ("verify_maintenance", "verify_maintenance"))
                self.assertEqual(maintenance.purge("acme", 400), 1)
            finally:
                maintenance.close()
            chain = self.call("GET", "/v1/verify-chain")[1]
            self.assertEqual((chain["ok"], chain["tombstoned"], chain["head"]), (True, 1, e2["hash"]))
            self.assertNotIn(b"synthetic@example.invalid", self.call("GET", "/v1/export", raw=True)[1])
            self.assertEqual(self.post([original.ev("r", "c", {}, e2["hash"])])[0], 201)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RuntimeHosted)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun != 11 or result.skipped:
        return 2
    print(json.dumps({"status": "RUNTIME_ROLE_HTTP_TESTS_PASSED", "testsRun": result.testsRun,
                      "poolSize": args.pool, "applicationRole": "verify_runtime", "retentionRole": "verify_maintenance",
                      "sslMode": "verify-full", "sourceConnections": 0}))
    return 0


def child_suite(args, database, passfile, schema, log):
    command = [sys.executable, str(Path(__file__).resolve()), "suite", "--database", database,
               "--passfile", str(passfile), "--schema", str(schema), "--directory", str(args.directory), "--pool", str(args.pool)]
    environment = local_environment()
    # The caller already supplied the deployed application PYTHONPATH; keep it.
    with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=180)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            raise
    if code:
        raise Blocked("Restricted-runtime HTTP tests failed; inspect the private log")


def prepare_and_test(args):
    if os.geteuid() != 0:
        raise Blocked("Run only as root on the private staged target")
    installed = json.loads(Path("/etc/verify/target-install.json").read_text())
    if installed.get("instanceId") != args.expected_instance_id or installed.get("accountId") != ACCOUNT:
        raise Blocked("Target installation identity mismatch")
    if durable_target_state() is not False:
        raise Blocked("Runtime rehearsal is prohibited after or during uncertain target activation")
    gate = json.loads(Path("/var/lib/verify-migration/state.json").read_text())
    if gate.get("mode") != "source" or Path("/etc/verify/production-writer-enabled").exists():
        raise Blocked("Runtime rehearsal requires SOURCE mode with the target writer disabled")
    if subprocess.run(["systemctl", "is-active", "--quiet", "verify.service"]).returncode == 0:
        raise Blocked("The private target app must be stopped")
    if not Path("/etc/verify/data-rehearsal.json").is_file():
        raise Blocked("Complete the source rehearsal restore before runtime testing")
    args.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.directory.stat().st_mode & 0o077 or args.directory.stat().st_uid != os.geteuid():
        raise Blocked("Test evidence directory must be private and owned by root")
    runner = Runner({"workDirectory": str(args.directory)})
    if runner.pg("SHOW hba_file;").decode().strip() != str(HBA):
        raise Blocked("Unexpected local PostgreSQL HBA identity")
    before = runner.inspect("verify")
    database = checked_database("verify_stage_" + uuid.uuid4().hex[:12])
    if runner.pg(f"SELECT count(*) FROM pg_database WHERE datname='{database}';").decode().strip() != "0":
        raise Blocked("Test database name collision")
    schema = args.directory / (database + "-schema.dump")
    schema_bytes = runner.run(["runuser", "-u", "postgres", "--", "pg_dump", "--schema-only", "--format=custom", "--no-owner",
                              "--host=/var/run/postgresql", "--port=5432", "--username=postgres", "--dbname=verify"])
    private_bytes(schema, schema_bytes)
    passfile = args.directory / (database + ".pgpass")
    rows = []
    for role, filename in (("verify_runtime", "db-password"), ("verify_maintenance", "maintenance-db-password")):
        path = Path("/etc/verify/secrets") / filename
        if path.stat().st_mode & 0o077:
            raise Blocked("Existing production credential file is not private")
        rows.append(f"localhost:5432:{database}:{role}:" + password_field(path.read_text()))
    private_bytes(passfile, ("\n".join(rows) + "\n").encode())
    original, original_stat = HBA.read_bytes(), HBA.stat()
    hba_backup = args.directory / (database + "-hba-before.conf")
    private_bytes(hba_backup, original)
    block = hba_block(database)
    log = args.directory / (database + "-http-tests.log")
    failure, cleanup_errors, suite_passed = None, [], False
    try:
        replace_hba(block + original, original_stat)
        if runner.pg("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL;").decode().strip() != "0":
            raise Blocked("Temporary HBA did not parse cleanly")
        if runner.pg("SELECT pg_reload_conf();").decode().strip() != "t":
            raise Blocked("Temporary HBA reload failed")
        child_suite(args, database, passfile, schema, log)
        suite_passed = True
    except Exception as exc:
        failure = type(exc).__name__
    finally:
        try:
            runner.pg(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE);')
            if runner.pg(f"SELECT count(*) FROM pg_database WHERE datname='{database}';").decode().strip() != "0":
                raise Blocked("Test database remains after cleanup")
        except Exception as exc:
            cleanup_errors.append("database:" + type(exc).__name__)
        try:
            current = HBA.read_bytes()
            if current.startswith(block):
                replace_hba(current[len(block):], original_stat)
                if runner.pg("SELECT pg_reload_conf();").decode().strip() != "t":
                    raise Blocked("Restored HBA reload failed")
            if HBA.read_bytes() != original:
                raise Blocked("HBA changed concurrently; inspect exact private backup before proceeding")
        except Exception as exc:
            cleanup_errors.append("hba:" + type(exc).__name__)
        passfile.unlink(missing_ok=True)
    after = runner.inspect("verify")
    unchanged = before == after
    passed = failure is None and not cleanup_errors and unchanged
    report = {"status": "RUNTIME_ROLE_HTTP_TESTS_PASSED" if passed else "RUNTIME_ROLE_TESTS_BLOCKED",
              "capturedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(), "instanceId": args.expected_instance_id,
              "testDatabase": database, "applicationDatabaseRole": "verify_runtime", "maintenanceDatabaseRole": "verify_maintenance",
              "poolSize": args.pool, "expectedTestCount": 11, "testCount": 11 if suite_passed else None,
              "httpSuitePassed": suite_passed, "verifiedTls": suite_passed,
              "productionDataUnchanged": unchanged, "hbaRestored": HBA.read_bytes() == original,
              "productionWriterEnabled": Path("/etc/verify/production-writer-enabled").exists(),
              "failureClass": failure, "cleanupErrors": cleanup_errors, "privateLog": str(log),
              "schemaSha256": hashlib.sha256(schema_bytes).hexdigest(), "sourceConnections": 0}
    output = args.directory / (database + "-runtime-role-report.json")
    write_report(output, report)
    print(json.dumps({**report, "report": str(output)}))
    return 0 if passed else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("check")
    prepare.add_argument("--expected-instance-id", required=True)
    prepare.add_argument("--directory", required=True, type=Path)
    prepare.add_argument("--pool", type=int, choices=(1, 10), default=10)
    suite = commands.add_parser("suite")
    for name in ("database", "passfile", "schema", "directory", "pool"):
        suite.add_argument("--" + name, required=True, type=Path if name in ("passfile", "schema", "directory") else (int if name == "pool" else str))
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0:
        raise Blocked("Target-only runtime verification requires root for isolated fixture administration")
    if args.command == "suite":
        return run_suite(args)
    with open("/run/verify-cutover.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return prepare_and_test(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"status": "RUNTIME_ROLE_TESTS_BLOCKED", "errorClass": type(exc).__name__,
                          "reason": str(exc) if isinstance(exc, Blocked) else "Inspect private runtime-test evidence; no source access occurred"}))
        raise SystemExit(2)
