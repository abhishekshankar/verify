#!/usr/bin/env python3
"""Restore a checked data-only export into an empty local PostgreSQL 16 target.

Never creates/drops a database, applies a schema, disables constraints/triggers,
or starts the application. The exact source schema/roles must already be restored.
The operator independently supplies the archive and schema SHA256 from the
private export record. Credentials come from a private libpq service/passfile.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile

from hosted.lightsail.export_data import TABLES, MAX_BYTES

COPY_HEADER = b"PGCOPY\n\xff\r\n\x00"
MAX_PACKED_BYTES = MAX_BYTES + 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_TAR_BYTES = MAX_BYTES + 1024 * 1024


def valid_sha(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def parse_archive(data, archive_sha256, schema_sha256, purpose):
    """Validate fully before opening a database connection; extract no paths."""
    if not valid_sha(archive_sha256) or not valid_sha(schema_sha256):
        raise ValueError("Independently verified archive and schema SHA256 are required")
    if len(data) > MAX_PACKED_BYTES or hashlib.sha256(data).hexdigest() != archive_sha256:
        raise ValueError("Archive size or checksum mismatch")
    if purpose not in ("rehearsal", "final"):
        raise ValueError("Unknown archive purpose")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as zipped:
        raw = zipped.read(MAX_TAR_BYTES + 1)
    if len(raw) > MAX_TAR_BYTES:
        raise ValueError("Uncompressed archive exceeds the bounded pilot capacity")
    expected = {name + ".copy" for name in TABLES} | {"manifest.json"}
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for item in archive:
            if item.name not in expected or item.name in files or not item.isfile():
                raise ValueError("Unexpected, duplicate or nonregular archive member")
            bound = MAX_MANIFEST_BYTES if item.name == "manifest.json" else MAX_BYTES
            if item.size < 0 or item.size > bound:
                raise ValueError("Archive member exceeds its size limit")
            if item.name != "manifest.json":
                total += item.size
                if total > MAX_BYTES:
                    raise ValueError("Copy data exceeds the bounded pilot capacity")
            with archive.extractfile(item) as member:
                files[item.name] = member.read(bound + 1)
            if len(files[item.name]) != item.size:
                raise ValueError("Truncated archive member")
    if set(files) != expected:
        raise ValueError("Archive does not contain exactly the reviewed seven tables and manifest")
    manifest = json.loads(files.pop("manifest.json"))
    if (manifest.get("format") != "verify-copy-v1" or manifest.get("purpose") != purpose
            or manifest.get("schemaSha256") != schema_sha256
            or set(manifest.get("tables", {})) != set(TABLES)):
        raise ValueError("Manifest identity, purpose, schema or table set mismatch")
    captured = datetime.fromisoformat(manifest["capturedAtUtc"].replace("Z", "+00:00"))
    if captured.tzinfo is None:
        raise ValueError("Manifest timestamp requires a timezone")
    if purpose == "final":
        age = (datetime.now(timezone.utc) - captured).total_seconds()
        if age < 0 or age > 1800:
            raise ValueError("Final export is stale or future-dated; repeat the fenced export")
    for name in TABLES:
        item, copy_data = manifest["tables"][name], files[name + ".copy"]
        if (type(item.get("rows")) is not int or item["rows"] < 0
                or type(item.get("bytes")) is not int or item["bytes"] != len(copy_data)
                or not valid_sha(item.get("sha256"))
                or item["sha256"] != hashlib.sha256(copy_data).hexdigest()
                or not copy_data.startswith(COPY_HEADER) or not copy_data.endswith(b"\xff\xff")):
            raise ValueError("Copy member metadata or checksum mismatch")
        columns = item.get("columns")
        if (not isinstance(columns, list) or not columns
                or any(not isinstance(c, list) or len(c) != 2
                       or any(not isinstance(x, str) or not x for x in c) for c in columns)
                or len({c[0] for c in columns}) != len(columns)):
            raise ValueError("Invalid reviewed column metadata")
    return files, manifest


def restore(connection, files, manifest):
    """All seven COPY operations commit together; a failure rolls back all data."""
    from psycopg import sql
    with connection.transaction():
        connection.execute("SET LOCAL lock_timeout = '10s'")
        connection.execute("SET LOCAL statement_timeout = '5min'")
        connection.execute("SET LOCAL timezone = 'UTC'")
        info = connection.execute("SELECT current_database(), current_setting('server_version_num'), current_setting('server_encoding'), inet_server_addr()::text, pg_is_in_recovery()").fetchone()
        if (info[0] != "verify" or not str(info[1]).startswith("16") or info[2] != "UTF8"
                or info[3] not in (None, "127.0.0.1", "::1") or info[4]):
            raise ValueError("Target must be a local, writable UTF8 PostgreSQL16 verify database")
        names = connection.execute("SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema'").fetchall()
        if set(names) != {("public", name) for name in TABLES}:
            raise ValueError("Target contains unreviewed tables")
        connection.execute(sql.SQL("LOCK TABLE {} IN ACCESS EXCLUSIVE MODE").format(
            sql.SQL(", ").join(sql.Identifier("public", name) for name in sorted(TABLES))))
        for name in TABLES:
            columns = connection.execute("SELECT a.attname,format_type(a.atttypid,a.atttypmod) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum", (name,)).fetchall()
            if [list(column) for column in columns] != manifest["tables"][name]["columns"]:
                raise ValueError("Target columns differ from the reviewed source")
            if connection.execute(sql.SQL("SELECT EXISTS (SELECT 1 FROM public.{})").format(sql.Identifier(name))).fetchone()[0]:
                raise ValueError("Target is not empty; no data was overwritten")
        counts = {}
        for name in TABLES:
            with connection.cursor() as cursor, cursor.copy(sql.SQL("COPY public.{} FROM STDIN WITH (FORMAT binary)").format(sql.Identifier(name))) as writer:
                writer.write(files[name + ".copy"])
            count = connection.execute(sql.SQL("SELECT count(*) FROM public.{}").format(sql.Identifier(name))).fetchone()[0]
            if count != manifest["tables"][name]["rows"]:
                raise ValueError("Imported table count mismatch; transaction rolled back")
            counts[name] = count
    return counts


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("archive", type=Path)
    p.add_argument("--archive-sha256", required=True)
    p.add_argument("--schema-sha256", required=True)
    p.add_argument("--purpose", choices=("rehearsal", "final"), required=True)
    p.add_argument("--writers-fenced", action="store_true")
    p.add_argument("--target-rehearsal-or-fenced", action="store_true")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    if not args.target_rehearsal_or_fenced or (args.purpose == "final" and not args.writers_fenced):
        p.error("Target must be private/fenced, and final import requires the proved source writer fence")
    try:
        with args.archive.open("rb") as source:
            packed = source.read(MAX_PACKED_BYTES + 1)
        files, manifest = parse_archive(packed, args.archive_sha256, args.schema_sha256, args.purpose)
        # Reserve a private, writable report path before making database changes.
        # A pre-existing path or a permission failure must not follow a committed import.
        with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            import psycopg
            output.write('{"status":"IMPORT_IN_PROGRESS"}\n')
            output.flush()
            os.fsync(output.fileno())
            with psycopg.connect("service=verify_target_admin", autocommit=True) as connection:
                counts = restore(connection, files, manifest)
            report = {"status": "DATA_IMPORTED", "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
                      "purpose": args.purpose, "archiveSha256": args.archive_sha256,
                      "schemaSha256": args.schema_sha256, "tableCounts": counts,
                      "scope": "Atomic empty-target data import only; no application, DNS, source or cutover changes"}
            output.seek(0)
            output.truncate()
            json.dump(report, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps({"status": report["status"], "purpose": args.purpose, "tableCounts": counts}))
        return 0
    except Exception as exc:
        print(f"Import failed ({type(exc).__name__}); details withheld from logs", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
