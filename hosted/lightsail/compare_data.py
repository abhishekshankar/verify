#!/usr/bin/env python3
"""Read-only, duplicate-aware data comparison after a proven writer fence/apply barrier.

Requires psycopg. Configure verify_source and verify_target in a private libpq
service file with sslmode=verify-full and a passfile; no credentials in arguments.
This is a data check, not a substitute for schema/role/chain/feature/restore tests.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

TABLES = ("tenant", "access_log", "event", "event_payload", "tombstone", "run", "verdict")


def fingerprint(rows):
    digest, count = hashlib.sha256(), 0
    for row in rows:
        # Sorted, length-delimited rows preserve duplicates and avoid concatenation ambiguity.
        raw = row[0].encode("utf-8")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
        count += 1
    return {"rows": count, "sha256": digest.hexdigest()}


def inventory(connection):
    from psycopg import sql
    result = {}
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        connection.execute("SET LOCAL statement_timeout = '5min'")
        connection.execute("SET LOCAL timezone = 'UTC'")
        for table in TABLES:
            with connection.cursor(name="verify_compare_" + table) as cursor:
                cursor.execute(sql.SQL('SELECT row_to_json(t)::text FROM public.{} AS t ORDER BY row_to_json(t)::text COLLATE "C"').format(sql.Identifier(table)))
                result[table] = fingerprint(cursor)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--writers-fenced-and-applied", action="store_true",
                        help="Operator attests that the documented writer fence and durable apply barrier are proved")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.writers_fenced_and_applied:
        parser.error("Source writers and destination app must be fenced; prove durable apply before comparison")
    try:
        import psycopg
        with psycopg.connect("service=verify_source", autocommit=True) as source, psycopg.connect("service=verify_target", autocommit=True) as target:
            before, after = inventory(source), inventory(target)
        report = {"capturedAtUtc": datetime.now(timezone.utc).isoformat(), "match": before == after,
                  "source": before, "target": after,
                  "scope": "Read-only table multiset check. No row values, credentials or keys are emitted."}
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"match": report["match"], "tableCount": len(TABLES)}))
        return 0 if report["match"] else 2
    except Exception as exc:
        # Database exceptions can embed connection details or row values.
        print(f"BLOCKED: comparison failed ({type(exc).__name__}); inspect privately", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
