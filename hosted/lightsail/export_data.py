#!/usr/bin/env python3
"""Data-only consistent export for the existing one-off ECS task; never run on import.

Requires the existing psycopg installation. Reads a verified source schema only.
Uploads to a short-lived, private S3 presigned PUT without printing its URL or data.
The separate reviewed schema/roles and original HMAC key are mandatory companions.
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
import urllib.error
import urllib.parse
import urllib.request

TABLES = ("tenant", "event", "event_payload", "tombstone", "run", "verdict", "access_log")
MAX_BYTES = 64 * 1024 * 1024


def valid_upload_url(url):
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    return (u.scheme == "https" and u.port in (None, 443) and u.username is None and u.password is None
            and not u.fragment and bool(u.path) and "X-Amz-Signature" in urllib.parse.parse_qs(u.query)
            and (host == "s3.us-west-2.amazonaws.com" or host.endswith(".s3.us-west-2.amazonaws.com")))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_archive(connection, schema_sha256, purpose):
    from psycopg import sql
    files, manifest, total = {}, {"format": "verify-copy-v1", "purpose": purpose,
        "capturedAtUtc": datetime.now(timezone.utc).isoformat(), "schemaSha256": schema_sha256,
        "scope": "DATA ONLY. Schema, roles/ACLs, keys and runtime configuration are separate required artifacts.",
        "tables": {}}, 0
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        connection.execute("SET LOCAL statement_timeout = '5min'")
        connection.execute("SET LOCAL timezone = 'UTC'")
        info = connection.execute("SELECT current_database(), current_setting('server_version_num'), current_setting('server_encoding'), (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())").fetchone()
        if info[0] != "verify" or not str(info[1]).startswith("16") or info[2] != "UTF8" or info[3] is not True:
            raise RuntimeError("Unexpected source identity/version/encoding/TLS")
        names = connection.execute("SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema'").fetchall()
        if set(names) != {("public", name) for name in TABLES}:
            raise RuntimeError("Source contains unreviewed tables")
        for name in TABLES:
            columns = connection.execute("SELECT a.attname,format_type(a.atttypid,a.atttypmod) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum", (name,)).fetchall()
            count = connection.execute(sql.SQL("SELECT count(*) FROM public.{}").format(sql.Identifier(name))).fetchone()[0]
            data = bytearray()
            with connection.cursor() as cur, cur.copy(sql.SQL("COPY public.{} TO STDOUT WITH (FORMAT binary)").format(sql.Identifier(name))) as reader:
                for block in reader:
                    total += len(block)
                    if total > MAX_BYTES:
                        raise RuntimeError("Export exceeds the bounded pilot capacity; use a reviewed streaming tool")
                    data.extend(block)
            files[name + ".copy"] = bytes(data)
            manifest["tables"][name] = {"rows": count, "columns": columns, "bytes": len(data),
                                           "sha256": hashlib.sha256(data).hexdigest()}
    files["manifest.json"] = (json.dumps(manifest, sort_keys=True) + "\n").encode()
    packed = io.BytesIO()
    with tarfile.open(fileobj=packed, mode="w") as tar:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(data), 0o600
            tar.addfile(item, io.BytesIO(data))
    compressed = gzip.compress(packed.getvalue(), mtime=0)
    return compressed, manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--schema-sha256", required=True)
    p.add_argument("--upload-url-file", type=Path)
    p.add_argument("--purpose", choices=("rehearsal", "final"), default="rehearsal")
    p.add_argument("--writers-fenced", action="store_true")
    args = p.parse_args()
    if not re.fullmatch(r"[a-f0-9]{64}", args.schema_sha256):
        p.error("A reviewed exact-source schema SHA256 is required")
    if args.purpose == "final" and not args.writers_fenced:
        p.error("Final export requires the independently proved source-writer fence")
    try:
        upload = args.upload_url_file.read_text().strip() if args.upload_url_file else os.environ.get("VERIFY_COPY_UPLOAD_URL", "")
        if not valid_upload_url(upload):
            raise RuntimeError("A private Oregon S3 presigned PUT URL is required")
        import psycopg
        from hosted.store import dsn_from_env
        with psycopg.connect(dsn_from_env(), autocommit=True) as source:
            data, manifest = make_archive(source, args.schema_sha256, args.purpose)
        request = urllib.request.Request(upload, data=data, method="PUT", headers={
            "Content-Type": "application/gzip", "x-amz-server-side-encryption": "AES256"})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=120) as response:
            if response.status != 200 or response.headers.get("x-amz-server-side-encryption") != "AES256":
                raise RuntimeError("Upload encryption confirmation missing; do not use this artifact")
        print(json.dumps({"status": "uploaded", "purpose": args.purpose, "bytes": len(data),
                          "archiveSha256": hashlib.sha256(data).hexdigest(),
                          "tableCounts": {name: item["rows"] for name, item in manifest["tables"].items()},
                          "scope": "Data only; not cutover readiness"}))
        return 0
    except Exception as exc:
        # HTTP and database exception text can contain signed URLs, credentials or data.
        print(f"Export failed ({type(exc).__name__}); details withheld from logs", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
