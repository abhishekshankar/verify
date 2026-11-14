#!/usr/bin/env python3
"""Read-only proof that the deployed psycopg/libpq wait honors the wall deadline.

Run through runuser -u postgres with the application venv on the private target.
The only deliberately slow query is pg_sleep against the local postgres DB.
Its exact backend is closed, terminated if necessary, and proved absent afterward.
"""
import json
import time

from hosted.lightsail.cutover import WallBudget, DeadlineExpired


def main():
    import psycopg
    from psycopg import pq
    name = "verify-cutover-deadline-proof"
    connection = psycopg.connect("host=/var/run/postgresql port=5432 user=postgres dbname=postgres application_name=" + name,
                                  autocommit=True, connect_timeout=1)
    pid = connection.info.backend_pid
    connection.execute("SET statement_timeout='2s'")
    budget = WallBudget(.1)
    started, interrupted = time.monotonic(), False
    try:
        budget.arm()
        connection.execute("SELECT pg_sleep(5)")
    except DeadlineExpired:
        interrupted = True
    finally:
        elapsed = time.monotonic() - started
        budget.cancel()
        connection.close()
    with psycopg.connect("host=/var/run/postgresql port=5432 user=postgres dbname=postgres", autocommit=True, connect_timeout=1) as recovery:
        recovery.execute("SET statement_timeout='1s'")
        recovery.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid=%s AND application_name=%s", (pid, name))
        deadline = time.monotonic() + 1
        while recovery.execute("SELECT count(*) FROM pg_stat_activity WHERE pid=%s AND application_name=%s", (pid, name)).fetchone()[0]:
            if time.monotonic() > deadline:
                print(json.dumps({"status": "FAILED", "reason": "Interrupted backend did not settle"}))
                return 2
            time.sleep(.01)
    passed = interrupted and elapsed < .5
    print(json.dumps({"status": "DATABASE_DEADLINE_PROVED" if passed else "FAILED",
                      "wallBudgetSeconds": .1, "observedSeconds": elapsed, "oldBackendSettled": True,
                      "psycopgVersion": psycopg.__version__, "libpqVersion": pq.version(), "pqImplementation": pq.__impl__}))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
