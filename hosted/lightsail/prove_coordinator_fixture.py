#!/usr/bin/env python3
"""Exercise the real coordinator against disposable local PostgreSQL/HTTP services.

Only fixture clusters on loopback ports5433/5434 are written. Production5432,
source RDS, AWS, production units, and public routing are never called. The actual
coordinator dump/restore/schema/fingerprint/lock/fence/swap/control code runs.
Only systemd app lifecycle, S3 upload, and archive verification are adapted;
those external boundaries have separate live proofs.

Run as root with the deployed app venv. All fixture credentials are random and
private; no production database credentials or source data are read.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch
import uuid

from hosted.lightsail import cutover as migration
from hosted.lightsail.compare_data import inventory
from hosted.lightsail.migration_proxy import Gate, control, make_control, make_proxy
from hosted.server import make_server
from hosted.store import PostgresStore, chain_hash
from verify.push import _call

PG_BIN = Path("/usr/lib/postgresql/16/bin")
REPO = Path(__file__).resolve().parents[2]
REAL_RUN = subprocess.run
TARGET_PORT, SOURCE_PORT = 5433, 5434
SCENARIOS = ("success", "restore_failure", "fence_response_loss", "target_response_loss",
             "target_persist_delay", "wall_timeout")


def require(condition, reason):
    if not condition:
        raise migration.Blocked(reason)


def clean_environment():
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PG", "VERIFY_", "AWS_"))}
    environment["PYTHONPATH"] = str(REPO / "src") + ":" + str(REPO)
    return environment


def run(command, data=None, timeout=30, environment=None):
    result = REAL_RUN(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      timeout=timeout, env=environment or clean_environment())
    if result.returncode:
        # Fixtures contain synthetic data only; errors stay in a private local log.
        raise migration.Blocked("Fixture command failed: " + Path(command[0]).name
                                + " " + result.stderr.decode(errors="replace")[:1500])
    return result.stdout


def postgres(command, data=None, timeout=30):
    return run(["runuser", "-u", "postgres", "--", *command], data, timeout)


def escaped(value):
    return value.replace("\\", "\\\\").replace(":", "\\:")


class App:
    def __init__(self, dsn, port):
        self.dsn, self.port, self.store, self.server = dsn, port, None, None

    def start(self):
        require(self.server is None, "Fixture application already started")
        self.store = PostgresStore(self.dsn, pool_size=10)
        self.server = make_server(self.store, self.port, export_key="synthetic-fixture-export-key", host="127.0.0.1")
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.store is not None:
            self.store.close()
            self.store = None


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


class Fixture:
    def __init__(self, instance):
        self.instance = instance
        self.token = uuid.uuid4().hex[:12]
        self.root = Path("/var/lib/postgresql") / ("verify-fixture-" + self.token)
        self.report_dir = Path("/opt/verify-migration") / ("coordinator-fixture-" + self.token)
        self.socket_root = Path("/run") / ("verify-fixture-" + self.token)
        self.clusters = {}
        self.password = secrets.token_urlsafe(32)
        self.runtime_password = secrets.token_urlsafe(32)
        self.original_connect = None
        self.results = []
        self.started_clusters = []

    def setup(self):
        import psycopg
        from psycopg import sql
        self.original_connect = psycopg.connect
        owner = pwd.getpwnam("postgres")
        for path, mode, uid, gid in ((self.root, 0o750, 0, owner.pw_gid),
                                     (self.report_dir, 0o700, 0, 0),
                                     (self.socket_root, 0o700, 0, 0)):
            path.mkdir(mode=mode)
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        for label, port, user in (("source", SOURCE_PORT, "verify_owner"), ("target", TARGET_PORT, "postgres")):
            with socket.socket() as probe:
                require(probe.connect_ex(("127.0.0.1", port)) != 0, "Fixture PostgreSQL port is already occupied")
            require(not Path(f"/var/run/postgresql/.s.PGSQL.{port}").exists(), "Fixture PostgreSQL socket already exists")
            directory = self.root / label
            directory.mkdir(mode=0o700)
            os.chown(directory, owner.pw_uid, owner.pw_gid)
            pass_path = directory / "initial-password"
            pass_path.write_text(self.password + "\n")
            os.chown(pass_path, owner.pw_uid, owner.pw_gid)
            os.chmod(pass_path, 0o600)
            data = directory / "data"
            postgres([str(PG_BIN / "initdb"), "-D", str(data), "--encoding=UTF8", "--locale=C.UTF-8",
                      "--auth-local=trust", "--auth-host=scram-sha-256", "--username=" + user,
                      "--pwfile=" + str(pass_path)])
            pass_path.unlink()
            key, cert = directory / "tls-key.pem", directory / "tls.pem"
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=Verify coordinator fixture", "-addext", "subjectAltName=IP:127.0.0.1",
                 "-keyout", str(key), "-out", str(cert)])
            os.chown(key, owner.pw_uid, owner.pw_gid)
            os.chown(cert, owner.pw_uid, owner.pw_gid)
            os.chmod(key, 0o600)
            os.chmod(cert, 0o644)
            with (data / "postgresql.conf").open("a") as output:
                output.write(f"\nport={port}\nlisten_addresses='127.0.0.1'\nunix_socket_directories='/var/run/postgresql'\nunix_socket_permissions=0700\n"
                             f"ssl=on\nssl_cert_file='{cert}'\nssl_key_file='{key}'\nshared_buffers='32MB'\n"
                             "max_connections=35\nwork_mem='2MB'\nmaintenance_work_mem='16MB'\n"
                             "max_wal_size='256MB'\nmin_wal_size='32MB'\nlog_statement='none'\n")
            (data / "pg_hba.conf").write_text("local all all trust\nhostssl all all 127.0.0.1/32 scram-sha-256\nhost all all 0.0.0.0/0 reject\n")
            os.chown(data / "pg_hba.conf", owner.pw_uid, owner.pw_gid)
            self.clusters[label] = {"port": port, "user": user, "data": data, "cert": cert}
            # Remember attempts as well: pg_ctl may start the server before its response fails.
            self.started_clusters.append(label)
            postgres([str(PG_BIN / "pg_ctl"), "-D", str(data), "-l", str(directory / "postgres.log"), "-w", "start"])
        with self.admin("source") as connection:
            connection.execute("CREATE ROLE verify_app NOLOGIN; CREATE ROLE verify_retention NOLOGIN")
        roles = (migration.ROOT / "target_roles.sql").read_text()
        self.psql("target", "postgres", roles)
        with self.admin("target") as connection:
            connection.execute(sql.SQL("ALTER ROLE verify_runtime PASSWORD {}").format(sql.Literal(self.runtime_password)))
        self.services = self.report_dir / "source-service.conf"
        self.passfile = self.report_dir / "source.pgpass"
        self.services.write_text("[verify_source_fixture]\nhost=127.0.0.1\nport=5434\ndbname=verify\nuser=verify_owner\n"
                                 "sslmode=verify-full\nsslrootcert=" + str(self.clusters["source"]["cert"]) + "\nconnect_timeout=2\n")
        self.passfile.write_text("".join(":".join(map(escaped, ("127.0.0.1", "5434", db, "verify_owner", self.password))) + "\n"
                                         for db in ("verify", "postgres")))
        self.passfile.write_text(self.passfile.read_text() + ":".join(map(escaped, ("127.0.0.1", "5433", "verify", "verify_runtime", self.runtime_password))) + "\n")
        for path in (self.services, self.passfile):
            os.chmod(path, 0o600)

    def admin(self, label, database="postgres"):
        item = self.clusters[label]
        return self.original_connect(f"host=/var/run/postgresql port={item['port']} user={item['user']} dbname={database}",
                                     autocommit=True, connect_timeout=2)

    def psql(self, label, database, query):
        item = self.clusters[label]
        return postgres([str(PG_BIN / "psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql",
                         "-p", str(item["port"]), "-U", item["user"], "-d", database], query.encode())

    def reset(self):
        from psycopg import sql
        for label in ("source", "target"):
            with self.admin(label) as connection:
                names = connection.execute("SELECT datname FROM pg_database WHERE datname='verify' OR datname ~ '^verify_(stage|previous)_[a-f0-9]{12}$'").fetchall()
                for row in names:
                    connection.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(row[0])))
        with self.admin("source") as connection:
            connection.execute("CREATE DATABASE verify OWNER verify_owner TEMPLATE template0 ENCODING 'UTF8'")
        self.psql("source", "verify", (REPO / "hosted/schema.postgres.sql").read_text())

    def stop(self):
        errors = []
        for label in reversed(self.started_clusters):
            data = self.clusters[label]["data"]
            try:
                status = REAL_RUN(["runuser", "-u", "postgres", "--", str(PG_BIN / "pg_ctl"), "-D", str(data), "status"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_environment(), timeout=5)
                if status.returncode == 0:
                    postgres([str(PG_BIN / "pg_ctl"), "-D", str(data), "-m", "fast", "-w", "stop"], timeout=15)
                elif status.returncode != 3:
                    raise migration.Blocked("Fixture cluster stop status is uncertain")
            except Exception as error:
                errors.append(label + ":" + type(error).__name__)
        if not errors:
            if self.root.exists():
                shutil.rmtree(self.root)
            if self.socket_root.exists():
                shutil.rmtree(self.socket_root)
            if hasattr(self, "passfile"):
                self.passfile.unlink(missing_ok=True)
        return errors

    def execute(self, scenario):
        import psycopg
        require(scenario in SCENARIOS, "Unknown fixture scenario")
        self.reset()
        case = self.report_dir / scenario
        case.mkdir(mode=0o700)
        state, writer = case / "state.json", case / "writer.json"
        state.write_text(json.dumps({"version": 1, "mode": "source", "targetActivated": False}))
        os.chmod(state, 0o600)
        gate = Gate(state, queue_seconds=20)
        socket_path = self.socket_root / (scenario + ".sock")
        source_port, target_port = free_port(), free_port()
        source = App("service=verify_source_fixture application_name=verify-fixture-source-app", source_port)
        target_dsn = f"host=127.0.0.1 port=5433 dbname=verify user=verify_runtime sslmode=verify-full sslrootcert={self.clusters['target']['cert']} passfile={self.passfile} application_name=verify-fixture-target-app"
        target = App(target_dsn, target_port)
        source.start()
        proxy = make_proxy(gate, f"http://127.0.0.1:{source_port}", f"http://127.0.0.1:{target_port}", ("127.0.0.1", 0))
        admin = make_control(gate, str(socket_path))
        for server in (proxy, admin):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{proxy.server_port}"
        api_key, tenant = "fixture-key-" + secrets.token_hex(12), "fixture"
        with self.admin("source", "verify") as connection:
            connection.execute("INSERT INTO tenant VALUES (%s,%s,%s)", (tenant, hashlib.sha256(api_key.encode()).hexdigest(), datetime.now(timezone.utc).isoformat()))
        def event(number, previous):
            record = {"run_id": "fixture-run", "type": "fixture-" + str(number),
                      "at": datetime.now(timezone.utc).isoformat(), "clock_source": "system",
                      "payload_json": json.dumps({"fixture": number}, sort_keys=True),
                      "evidence_hash": None, "prev_hash": previous}
            record["hash"] = chain_hash(previous, record)
            return record
        seed = event(1, "")
        queued_event = event(2, seed["hash"])
        require(_call(base, api_key, "POST", "/v1/events", {"events": [seed]})["head"] == seed["hash"], "Synthetic source seed failed")
        config = {"instanceId": self.instance, "accountId": "842676017161", "sourceHost": "127.0.0.1",
                  "sourceService": "verify_source_fixture", "workDirectory": str(case),
                  "backupBucket": "fixture-no-aws", "backupRegion": "fixture", "backupPrefix": "fixture/",
                  "readiness": {key: True for key in ("applicationFeatureTestsPassed", "encryptedBackupRestoreTestPassed",
                       "oldAlbRequestsDrained", "allOtherSourceWritersDisabled", "httpsCertificateAndRenewalPathVerified",
                       "databaseDeadlineInterruptTestPassed")}}
        config["readiness"]["retainedSourceAutomatedBackupDays"] = 7
        owner = self
        live = {"cutover": False, "enabled": False, "fault": False, "delayedControlResolved": False,
                "queuedObserved": False, "sleepBackendPid": None, "interruptedBackendAbsent": None}
        original_change = gate.change
        def changed(mode, expected):
            if live["cutover"] and mode == "target" and scenario in ("target_response_loss", "target_persist_delay"):
                if scenario == "target_persist_delay":
                    time.sleep(1.4)
                result = original_change(mode, expected)
                if scenario == "target_response_loss":
                    time.sleep(1.4)
                live["delayedControlResolved"] = True
                return result
            return original_change(mode, expected)
        gate.change = changed

        class FixtureRunner(migration.Runner):
            def run(self, command, data=None, maximum=30):
                if command[0] == "systemctl":
                    require(command == ["systemctl", "enable", "--now", "verify.service"], "Unexpected fixture lifecycle command")
                    require(writer.exists(), "Fixture application start lacks writer authorization")
                    target.start()
                    live["enabled"] = True
                    return b""
                if command[:4] == ["/usr/bin/python3", "-m", "hosted.lightsail.cutover", "upload"]:
                    require("--dump" in command, "Unexpected fixture upload")
                    dump_path = Path(command[command.index("--dump") + 1])
                    require(dump_path.is_relative_to(case) and dump_path.exists(), "Fixture upload must be its own completed dump")
                    return json.dumps({"VersionId": "fixture-version", "ServerSideEncryption": "AES256"}).encode()
                mapped = list(command)
                if mapped[0] == "runuser":
                    mapped = ["5433" if item == "5432" else "--port=5433" if item == "--port=5432" else item for item in mapped]
                    require(all("5432" not in item for item in mapped), "Production PostgreSQL port leaked into a fixture command")
                    if "hosted.lightsail.cutover" in mapped and "inspect" in mapped:
                        mapped += ["--port", "5433"]
                        mapped[mapped.index("/opt/verify/current/.venv/bin/python")] = sys.executable
                    elif any(Path(item).name in ("psql", "pg_dump", "pg_restore") for item in mapped):
                        require("/var/run/postgresql" in mapped or "--host=/var/run/postgresql" in mapped, "Fixture target must pin the local Unix socket")
                        require("5433" in mapped or "--port=5433" in mapped, "Fixture target must pin port5433")
                else:
                    require(mapped[0] == "pg_dump" and any("service=verify_source_fixture" in item for item in mapped), "Unexpected external fixture command")
                environment = dict(self.env)
                if mapped[0] == "runuser":
                    environment = {key: value for key, value in environment.items() if not key.startswith("PG")}
                result = REAL_RUN(mapped, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=self.timeout(maximum), env=environment)
                if result.returncode:
                    migration.write_report(case / ("private-command-" + uuid.uuid4().hex[:12] + ".json"),
                                           {"command": mapped, "returncode": result.returncode, "stderr": result.stderr.decode(errors="replace")[:4000]})
                    raise migration.Blocked("Private fixture PostgreSQL command failed")
                return result.stdout

            def dump(self, output):
                if live["cutover"]:
                    until = time.monotonic() + 2
                    while gate.status()["queued"] != 3:
                        require(time.monotonic() < until, "Three authenticated fixture requests did not queue")
                        time.sleep(.01)
                    live["queuedObserved"] = True
                return super().dump(output)

            def stage(self, dump, name):
                if live["cutover"] and scenario == "restore_failure":
                    live["fault"] = True
                    # Exercise the actual failing pg_restore subprocess, not just a Python exception.
                    broken = case / "deliberately-invalid.dump"
                    broken.write_bytes(b"synthetic fixture invalid pg_restore input")
                    return super().stage(broken, name)
                return super().stage(dump, name)

            def archive_check(self):
                # Actual encrypted off-host backup/PITR has its own live proof.
                self.pg("SELECT pg_switch_wal();")

        runner = FixtureRunner(config)
        initial_dump = case / "initial.dump"
        runner.dump(initial_dump)
        runner.stage(initial_dump, "verify")
        rehearsal = migration.rehearsal(config, runner)
        rehearsal_path = Path(rehearsal["report"])

        class ConnectionFault:
            def __init__(self, connection):
                self.connection = connection
            def __getattr__(self, name):
                return getattr(self.connection, name)
            def execute(self, query, *values, **options):
                result = self.connection.execute(query, *values, **options)
                if str(query) == "ALTER DATABASE verify ALLOW_CONNECTIONS false" and not live["fault"]:
                    live["fault"] = True
                    raise ConnectionError("Synthetic lost response after the real committed admission fence")
                return result
        def connect(dsn="", *values, **options):
            connection = owner.original_connect(dsn, *values, **options)
            if scenario == "fence_response_loss" and "application_name=verify-migration-recovery" in dsn:
                return ConnectionFault(connection)
            return connection

        original_inventory = migration.source_inventory
        def delayed_inventory(connection):
            if scenario == "wall_timeout":
                live["fault"] = True
                live["sleepBackendPid"] = connection.info.backend_pid
                connection.execute("SET LOCAL statement_timeout='30s'")
                connection.execute("SELECT pg_sleep(30)")
            return original_inventory(connection)

        def systemctl(command, **options):
            require(command[0] == "systemctl", "Only fixture lifecycle calls may replace subprocess")
            if command == ["systemctl", "is-active", "--quiet", "verify.service"]:
                return SimpleNamespace(returncode=0 if target.server else 3)
            require(command == ["systemctl", "disable", "--now", "verify.service"], "Unexpected fixture cleanup lifecycle command")
            target.stop()
            live["enabled"] = False
            return SimpleNamespace(returncode=0)

        def healthy():
            if target.server is None:
                return False
            connection = http.client.HTTPConnection("127.0.0.1", target_port, timeout=1)
            try:
                connection.request("GET", "/v1/verify-chain")
                response = connection.getresponse()
                return response.status == 401 and response.read().startswith(b'{"error":')
            finally:
                connection.close()

        jobs, client_errors, monitor_errors = [], [], []
        pool = ThreadPoolExecutor(3)
        def submit_after_drain():
            until = time.monotonic() + 10
            while gate.status()["mode"] != "drain":
                if time.monotonic() > until:
                    monitor_errors.append("DRAIN not observed")
                    return
                time.sleep(.005)
            jobs.extend([pool.submit(_call, base, api_key, "POST", "/v1/events", {"events": [queued_event]}),
                         pool.submit(_call, base, api_key, "GET", "/v1/verify-chain"),
                         pool.submit(_call, base, api_key, "GET", "/v1/access-log")])
        observer = threading.Thread(target=submit_after_drain, daemon=True)
        failed, result, started, report = None, None, time.monotonic(), None
        try:
            with ExitStack() as stack:
                stack.enter_context(patch.object(migration, "SOCKET", str(socket_path)))
                stack.enter_context(patch.object(migration, "STATE", state))
                stack.enter_context(patch.object(migration, "WRITER", writer))
                stack.enter_context(patch.object(migration, "app_healthy", healthy))
                stack.enter_context(patch.object(migration, "subprocess", SimpleNamespace(run=systemctl, DEVNULL=subprocess.DEVNULL)))
                stack.enter_context(patch.object(migration, "source_inventory", delayed_inventory))
                stack.enter_context(patch.object(psycopg, "connect", connect))
                live["cutover"] = True
                observer.start()
                try:
                    result = migration.cutover(config, runner, rehearsal_path)
                except migration.Blocked as error:
                    failed = str(error)
                elapsed = time.monotonic() - started
            observer.join(timeout=1)
            require(not monitor_errors and len(jobs) == 3, "Fixture queued clients were not all submitted")
            for job in jobs:
                try:
                    job.result(timeout=22)
                except Exception as error:
                    client_errors.append(type(error).__name__)
            pool.shutdown(wait=True)
            if scenario in ("target_response_loss", "target_persist_delay"):
                until = time.monotonic() + 3
                while not live["delayedControlResolved"] and time.monotonic() < until:
                    time.sleep(.01)
            reports = sorted(case.glob("*-cutover.json"))
            require(len(reports) == 1, "Expected exactly one private coordinator result")
            report = json.loads(reports[0].read_text())
            status = gate.status()
            with self.admin("source") as connection:
                source_admission = connection.execute("SELECT datallowconn FROM pg_database WHERE datname='verify'").fetchone()[0]
                source_sessions = connection.execute("SELECT count(*) FROM pg_stat_activity WHERE datname='verify'").fetchone()[0]
                if live["sleepBackendPid"]:
                    live["interruptedBackendAbsent"] = connection.execute("SELECT count(*) FROM pg_stat_activity WHERE pid=%s", (live["sleepBackendPid"],)).fetchone()[0] == 0
            authoritative = scenario in ("success", "target_response_loss", "target_persist_delay")
            require(not client_errors and status["queueTimeouts"] == 0, "A queued authenticated fixture request failed")
            require(status["mode"] == ("target" if authoritative else "source"), "Wrong authoritative bridge after fixture")
            require(source_admission is (not authoritative), "Source admission fence/abort invariant failed")
            require(writer.exists() is authoritative and live["enabled"] is authoritative, "Writer marker and app lifecycle disagree with authority")
            require(status["forwarded"] == ({"source": 1, "target": 3} if authoritative else {"source": 4, "target": 0}),
                    "Queued requests did not forward exactly once to the authoritative database")
            require(elapsed < 19.5, "Coordinator/recovery exceeded the reviewed queue allowance")
            if scenario == "success":
                require(report["status"] == "TARGET_AUTHORITATIVE" and result is not None, "Successful fixture did not activate target")
            elif authoritative:
                require(failed is not None and not source_admission and source_sessions == 0
                        and "NO_SOURCE_UNFENCE_ATTEMPTED_TARGET_STATE_PROTECTED" in report["recovery"],
                        "Ambiguous TARGET response did not preserve the source fence")
            else:
                require(failed is not None and report["status"] == "ABORTED_TO_SOURCE" and not report["recoveryErrors"],
                        "Pre-TARGET fault did not recover source authority cleanly")
                if scenario == "wall_timeout":
                    require(live["interruptedBackendAbsent"] is True and report["errorClass"] == "DeadlineExpired",
                            "Real PostgreSQL sleep backend did not interrupt and settle")
            # Only after requests finish and the fixture SOURCE app is stopped,
            # temporarily reopen this disposable source to inspect its exact rows.
            # The production coordinator never performs this test-only inspection.
            source.stop()
            with self.admin("source") as connection:
                if not source_admission:
                    connection.execute("ALTER DATABASE verify ALLOW_CONNECTIONS true")
            with self.admin("source", "verify") as connection:
                source_data = inventory(connection)
            source_store = PostgresStore(f"host=/var/run/postgresql port=5434 user=verify_owner dbname=verify", pool_size=1)
            try:
                source_chain = source_store.verify_chain(tenant)
            finally:
                source_store.close()
            if not source_admission:
                with self.admin("source") as connection:
                    connection.execute("ALTER DATABASE verify ALLOW_CONNECTIONS false")
            with self.admin("target", "verify") as connection:
                target_data = inventory(connection)
            target_store = PostgresStore("host=/var/run/postgresql port=5433 user=postgres dbname=verify", pool_size=1)
            try:
                target_chain = target_store.verify_chain(tenant)
            finally:
                target_store.close()
            active_chain, inactive_chain = (target_chain, source_chain) if authoritative else (source_chain, target_chain)
            active_data, inactive_data = (target_data, source_data) if authoritative else (source_data, target_data)
            require(active_chain["ok"] and active_chain["events"] == 2 and active_chain["head"] == queued_event["hash"],
                    "Authoritative ledger lost or duplicated the queued event")
            require(inactive_chain["ok"] and inactive_chain["events"] == 1 and inactive_chain["head"] == seed["hash"],
                    "Inactive ledger changed or forked")
            require(active_data["access_log"]["rows"] == 4 and inactive_data["access_log"]["rows"] == 1,
                    "Authenticated GET/POST access logging was lost or duplicated")
            summary = {"scenario": scenario, "status": "PASSED", "coordinatorStatus": report["status"],
                       "observedCoordinatorSeconds": elapsed, "sourceAdmissionAtClientCompletion": source_admission,
                       "sourceSessionsAtClientCompletion": source_sessions, "queue": status,
                       "queuedClientErrors": client_errors, "source": {"data": source_data, "chain": source_chain},
                       "target": {"data": target_data, "chain": target_chain}, "faultEvidence": live,
                       "coordinatorReport": str(reports[0]), "liveSourceRehearsalSeconds": rehearsal["measuredSeconds"],
                       "sourceInspectionAfterClientsAndAppStopped": True}
            migration.write_report(case / "fixture-acceptance.json", summary)
            self.results.append(summary)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
            source.stop()
            target.stop()
            for server in (proxy, admin):
                server.shutdown()
                server.server_close()
        return self.results[-1]


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-instance-id", required=True)
    parser.add_argument("--scenario", action="append", choices=SCENARIOS)
    args = parser.parse_args()
    require(os.geteuid() == 0, "Run this target-only fixture harness as root")
    installed = json.loads(Path("/etc/verify/target-install.json").read_text())
    require(installed.get("instanceId") == args.expected_instance_id and installed.get("accountId") == "842676017161", "Target identity mismatch")
    require(migration.durable_target_state() is False and json.loads(migration.STATE.read_text()).get("mode") == "source"
            and not migration.WRITER.exists(), "Fixtures require pre-cutover SOURCE mode without writer authorization")
    require(Path(sys.prefix).resolve().is_relative_to(Path("/opt/verify/releases")), "Use the deployed app venv interpreter")
    require(PG_BIN.is_dir(), "PostgreSQL16 tools are required")
    import fcntl
    fixture, failure, cleanup = Fixture(args.expected_instance_id), None, []
    output = None
    with open("/run/verify-cutover.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        environment = {key: value for key, value in os.environ.items() if key.startswith("PG")}
        for key in environment:
            del os.environ[key]
        try:
            fixture.setup()
            os.environ.update(PGSERVICEFILE=str(fixture.services), PGPASSFILE=str(fixture.passfile))
            for scenario in args.scenario or SCENARIOS:
                fixture.execute(scenario)
        except Exception as error:
            failure = {"errorClass": type(error).__name__, "reason": str(error) if isinstance(error, migration.Blocked) else "Inspect private fixture evidence"}
        finally:
            cleanup = fixture.stop()
            for key in [key for key in os.environ if key.startswith("PG")]:
                del os.environ[key]
            os.environ.update(environment)
            report = {"status": "REAL_COORDINATOR_FIXTURE_PASSED" if failure is None and not cleanup else "COORDINATOR_FIXTURE_BLOCKED",
                      "capturedAtUtc": datetime.now(timezone.utc).isoformat(), "instanceId": args.expected_instance_id,
                      "coordinatorSha256": hashlib.sha256(Path(migration.__file__).read_bytes()).hexdigest(),
                      "scenariosPassed": [row["scenario"] for row in fixture.results], "failure": failure, "cleanupErrors": cleanup,
                      "targetFixturePort": 5433, "sourceFixturePort": 5434, "productionDatabaseConnections": 0,
                      "productionUnitCalls": 0, "sourceRdsConnections": 0, "awsCalls": 0,
                      "scope": "Real local PostgreSQL/HTTP/Unix-control handover and faults; systemd/S3/archive boundaries adapted",
                      "reports": [row["coordinatorReport"] for row in fixture.results]}
            fixture.report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            output = fixture.report_dir / "summary.json"
            migration.write_report(output, report)
    print(json.dumps({**report, "report": str(output)}))
    return 0 if failure is None and not cleanup else 2


if __name__ == "__main__":
    raise SystemExit(main())
