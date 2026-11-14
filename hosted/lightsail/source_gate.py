#!/usr/bin/env python3
"""Evaluate read-only PostgreSQL metadata. Never connects to AWS or a database."""
import argparse
from datetime import datetime, timezone
import json
import re
from pathlib import Path
import sys

EXPECTED = {"tenant", "access_log", "event", "event_payload", "tombstone", "run", "verdict"}


def evaluate(meta, now=None, strategy="logical", account_id=None):
    now = now or datetime.now(timezone.utc)
    blocked = []
    def require(condition, reason):
        if not condition:
            blocked.append(reason)
    require(isinstance(account_id, str) and re.fullmatch(r"\d{12}", account_id) is not None,
            "Supply the independently verified AWS account ID as private operator input")
    require(meta.get("database") == "verify", "Unexpected database; source identity must be verified")
    require(str(meta.get("serverVersionNum", "")).startswith("16"), "Source must be PostgreSQL 16")
    require(meta.get("serverEncoding") == "UTF8", "UTF8 server encoding is required")
    require(meta.get("sslConnection") is True, "A verified SSL source connection is required")
    logical = str(meta.get("rdsLogicalReplication")) in {"1", "on"} and meta.get("walLevel") == "logical"
    require(strategy in {"logical", "write-drain"}, "Unknown migration strategy")
    if strategy == "logical":
        require(logical, "RDS logical replication is disabled or unknown; its static parameter requires a separately reviewed reboot")
        require(meta.get("replicationRole") is True, "The inspected login lacks the required RDS replication membership")
        require(meta.get("freeReplicationSlots", -1) >= 4, "At least four free replication slots must be reviewed")
        require(meta.get("maxWalSenders", -1) >= 4, "Insufficient WAL sender capacity")
    require(meta.get("largeObjects") == 0, "Large objects are unreviewed and are not logically replicated")
    require(meta.get("sequences") == 0, "Sequence state needs an explicit cutover plan")
    require(set(meta.get("extensions", [])) == {"plpgsql"}, "Extensions differ from the reviewed schema")
    tables = meta.get("tables", [])
    require({x.get("name") for x in tables} == EXPECTED and len(tables) == len(EXPECTED),
            "The source is not exactly the seven reviewed public tables")
    require(meta.get("otherUserRelations") == 0, "Additional user relations need a migration design")
    for table in tables:
        name = table.get("name")
        require(table.get("schema") == "public", "An unexpected table schema is present")
        require(table.get("selectPrivilege") is True, f"The inspected login cannot copy the complete table: {name}")
        require(not table.get("rls"), f"RLS policy needs explicit transfer review: {name}")
        require(not table.get("replicaOrAlwaysTriggers"), f"Replication-active triggers require review: {name}")
        if name != "access_log":
            require(table.get("primaryKey") is True, f"A primary key is required: {name}")
        else:
            require(table.get("blocksUpdateDelete") is True and table.get("blocksTruncate") is True,
                    "access_log must remain append-only; do not invent a key or change replica identity")
    try:
        captured = datetime.fromisoformat(meta["capturedAtUtc"].replace("Z", "+00:00"))
        age = (now - captured).total_seconds()
        require(0 <= age <= 1800, "Metadata is stale or future-dated; collect a fresh read-only snapshot")
    except (KeyError, TypeError, ValueError):
        require(False, "A valid UTC metadata capture time is required")
    return {
        "schemaVersion": 1,
        "accountId": account_id,
        "sourceRegion": "us-west-2",
        "sourceId": "verify-ledger",
        "evaluatedAtUtc": now.isoformat(),
        "sourceCapturedAtUtc": meta.get("capturedAtUtc"),
        "strategy": strategy,
        "sourceLogicalReplicationReady": logical and not blocked,
        "sourceRehearsalReady": not blocked,
        "status": "READY_FOR_TARGET_REHEARSAL" if not blocked else "BLOCKED",
        "blockers": blocked,
        "scope": "Metadata gate only. No publication, source modification, provisioning or cutover is performed.",
        "remainingGates": ["Verify source identity and deployed image", "Approve private database connectivity",
                           "Test resource headroom and all application features", "Verify schema, roles and all data",
                           "Restore encrypted backups and prove seven-day PITR continuity",
                           "Preissue HTTPS certificate and test renewal", "Approve writer fence, apply barrier and rollback"]
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("metadata", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--strategy", choices=("logical", "write-drain"), default="logical")
    p.add_argument("--account-id", required=True, help="Verified account ID; keep generated evidence private")
    args = p.parse_args()
    try:
        report = evaluate(json.loads(args.metadata.read_text()), strategy=args.strategy, account_id=args.account_id)
    except (OSError, ValueError, TypeError) as exc:
        print(f"BLOCKED: invalid metadata ({type(exc).__name__})", file=sys.stderr)
        return 2
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "blockers": report["blockers"]}))
    return 0 if report["sourceRehearsalReady"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
