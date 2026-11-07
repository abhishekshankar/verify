"""Hosted ledger storage. One SQL implementation, two drivers (SQLite default, Postgres if psycopg is installed).

Chain rule is identical to verify.core.Ledger: hash = sha256(prev_hash + json.dumps(row, sort_keys=True)),
chained per tenant starting from "". Payloads live in a separate table so retention can delete them
(only after a tombstone row exists) while event rows, and therefore every hash, stay forever.
"""
import hashlib, json, os, sqlite3, threading
from datetime import datetime, timedelta, timezone

ROW_KEYS = ["run_id", "type", "at", "clock_source", "payload_json", "evidence_hash"]

def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def chain_hash(prev, row): return sha(prev + json.dumps({k: row.get(k) for k in ROW_KEYS}, sort_keys=True))

class Conflict(Exception): pass      # prev_hash != head  -> 409
class Invalid(Exception): pass       # malformed or hash mismatch (tamper) -> 400

SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS tenant(id TEXT PRIMARY KEY, api_key_sha256 TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS access_log(tenant_id TEXT NOT NULL, at TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
  status INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS event(tenant_id TEXT NOT NULL, seq INTEGER NOT NULL, run_id TEXT NOT NULL, type TEXT NOT NULL,
  at TEXT NOT NULL, clock_source TEXT NOT NULL, payload_sha256 TEXT NOT NULL, evidence_hash TEXT, prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL, PRIMARY KEY(tenant_id, seq));
CREATE TABLE IF NOT EXISTS event_payload(tenant_id TEXT NOT NULL, seq INTEGER NOT NULL, payload_json TEXT NOT NULL,
  PRIMARY KEY(tenant_id, seq));
CREATE TABLE IF NOT EXISTS tombstone(tenant_id TEXT NOT NULL, seq INTEGER NOT NULL, purged_at TEXT NOT NULL, reason TEXT NOT NULL,
  PRIMARY KEY(tenant_id, seq));
CREATE TABLE IF NOT EXISTS run(tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, contract_id TEXT NOT NULL, contract_version TEXT NOT NULL,
  subject_ref TEXT NOT NULL, actor TEXT NOT NULL, started_at TEXT NOT NULL, PRIMARY KEY(tenant_id, run_id));
CREATE TABLE IF NOT EXISTS verdict(tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, verdict TEXT NOT NULL
  CHECK (verdict IN ('pass','fail','inapplicable','not_observed','blocked')), level_reached TEXT NOT NULL,
  independence TEXT NOT NULL, reasons_json TEXT NOT NULL, final_event_seq INTEGER NOT NULL, at TEXT NOT NULL,
  PRIMARY KEY(tenant_id, run_id));
""" + "".join(f"""
CREATE TRIGGER IF NOT EXISTS {t}_no_update BEFORE UPDATE ON {t} BEGIN SELECT RAISE(ABORT, 'append-only: {t}'); END;
CREATE TRIGGER IF NOT EXISTS {t}_no_delete BEFORE DELETE ON {t} BEGIN SELECT RAISE(ABORT, 'append-only: {t}'); END;
""" for t in ("event", "tombstone", "run", "verdict", "access_log")) + """
CREATE TRIGGER IF NOT EXISTS event_payload_no_update BEFORE UPDATE ON event_payload BEGIN SELECT RAISE(ABORT, 'append-only: event_payload'); END;
CREATE TRIGGER IF NOT EXISTS event_payload_delete_needs_tombstone BEFORE DELETE ON event_payload
  WHEN NOT EXISTS (SELECT 1 FROM tombstone WHERE tenant_id=OLD.tenant_id AND seq=OLD.seq)
  BEGIN SELECT RAISE(ABORT, 'payload delete requires tombstone'); END;
"""

class _Rows:
    """Buffered result so a pooled connection can go back to the pool before the caller reads rows."""
    def __init__(self, cur):
        self.rows, self.rowcount = (cur.fetchall() if cur.description else []), cur.rowcount
    def fetchone(self): return self.rows[0] if self.rows else None
    def fetchall(self): return self.rows
    def __iter__(self): return iter(self.rows)


class Store:
    """SQLite driver. Postgres subclass only changes connect/placeholder/locking."""
    ph = "?"

    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SQLITE_DDL)
        self.lock = threading.RLock()   # ponytail: whole connection serialised per process; Postgres pool for real load

    # -- plumbing --
    def q(self, sql, args=()):
        with self.lock:   # sqlite3 connections are not safe for concurrent use; reads are buffered before release
            cur = self.db.cursor(); cur.execute(sql.replace("?", self.ph), args)
            return _Rows(cur)
    def close(self): self.db.close()
    def begin(self): self.lock.acquire(); self.q("BEGIN IMMEDIATE")
    def commit(self): self.q("COMMIT"); self.lock.release()
    def rollback(self): self.q("ROLLBACK"); self.lock.release()
    def lock_tenant(self, tenant): pass

    # -- tenants --
    def add_tenant(self, tenant, api_key):
        self.begin()
        try: self.q("INSERT INTO tenant VALUES (?,?,?)", (tenant, sha(api_key), _now())); self.commit()
        except Exception: self.rollback(); raise

    def rotate_key(self, tenant, new_key):
        """Replace a tenant's key; the old key stops working at once. Returns False if no such tenant."""
        self.begin()
        try: n = self.q("UPDATE tenant SET api_key_sha256=? WHERE id=?", (sha(new_key), tenant)).rowcount; self.commit()
        except Exception: self.rollback(); raise
        return n == 1

    def log_access(self, tenant, method, path, status):
        """Trust Pack §3: every read or write of tenant data is logged (who, when, what). Append-only."""
        self.begin()
        try: self.q("INSERT INTO access_log VALUES (?,?,?,?,?)", (tenant, _now(), method, path, status)); self.commit()
        except Exception: self.rollback(); raise

    def access_log(self, tenant, limit=1000):
        return [dict(zip(("at", "method", "path", "status"), r)) for r in
                self.q("SELECT at,method,path,status FROM access_log WHERE tenant_id=? ORDER BY at DESC LIMIT ?", (tenant, limit))]

    def tenant_for_key(self, api_key):
        r = self.q("SELECT id FROM tenant WHERE api_key_sha256=?", (sha(api_key),)).fetchone()
        return r and r[0]

    # -- chain --
    def head(self, tenant):
        r = self.q("SELECT seq, hash FROM event WHERE tenant_id=? ORDER BY seq DESC LIMIT 1", (tenant,)).fetchone()
        return (r[0], r[1]) if r else (0, "")

    def append(self, tenant, events, runs=(), verdicts=()):
        """Atomic batch. Server recomputes every hash; client-sent hash must match it."""
        self.begin()
        try:
            self.lock_tenant(tenant)
            seq, head = self.head(tenant)
            by_run = {}
            for e in events:
                if not isinstance(e, dict) or not all(isinstance(e.get(k), str) for k in ROW_KEYS[:5]):
                    raise Invalid("event needs string run_id,type,at,clock_source,payload_json")
                if e.get("prev_hash", "") != head:
                    raise Conflict(f"prev_hash {e.get('prev_hash')!r} != head {head!r}")
                h = chain_hash(head, e)
                if e.get("hash") not in (None, h): raise Invalid(f"hash mismatch at event {seq + 1} (tampered?)")
                seq += 1
                self.q("INSERT INTO event VALUES (?,?,?,?,?,?,?,?,?,?)", (tenant, seq, e["run_id"], e["type"], e["at"],
                       e["clock_source"], sha(e["payload_json"]), e.get("evidence_hash"), head, h))
                self.q("INSERT INTO event_payload VALUES (?,?,?)", (tenant, seq, e["payload_json"]))
                if e["type"] == "verdict_final": by_run[e["run_id"]] = (seq, e["at"])
                head = h
            for r in runs:
                self.q("INSERT INTO run VALUES (?,?,?,?,?,?,?)", (tenant, r["run_id"], r["contract_id"], r["contract_version"],
                       r["subject_ref"], r["actor"], r["started_at"]))
            for v in verdicts:
                fin = by_run.get(v["run_id"]) or self.q("SELECT seq, at FROM event WHERE tenant_id=? AND run_id=? AND type='verdict_final'",
                                                        (tenant, v["run_id"])).fetchone()
                if not fin: raise Invalid(f"verdict for {v['run_id']} has no verdict_final event")
                self.q("INSERT INTO verdict VALUES (?,?,?,?,?,?,?,?)", (tenant, v["run_id"], v["verdict"], v["level_reached"],
                       v["independence"], v["reasons_json"], fin[0], fin[1]))
            self.commit()
            return {"head": head, "seq": seq}
        except Exception:
            self.rollback(); raise

    def events(self, tenant):
        cur = self.q("""SELECT e.seq, e.run_id, e.type, e.at, e.clock_source, p.payload_json, e.payload_sha256, e.evidence_hash,
                        e.prev_hash, e.hash, t.purged_at FROM event e
                        LEFT JOIN event_payload p ON p.tenant_id=e.tenant_id AND p.seq=e.seq
                        LEFT JOIN tombstone t ON t.tenant_id=e.tenant_id AND t.seq=e.seq
                        WHERE e.tenant_id=? ORDER BY e.seq""", (tenant,))
        keys = ["seq", "run_id", "type", "at", "clock_source", "payload_json", "payload_sha256", "evidence_hash",
                "prev_hash", "hash", "tombstoned_at"]
        return [dict(zip(keys, r)) for r in cur.fetchall()]

    def verify_chain(self, tenant):
        """Full recompute where the payload exists; for tombstoned events, linkage only (hash kept, payload gone)."""
        prev, n, tomb = "", 0, 0
        for e in self.events(tenant):
            if e["prev_hash"] != prev: return {"ok": False, "broken_at": e["seq"], "head": prev}
            if e["payload_json"] is not None:
                if sha(e["payload_json"]) != e["payload_sha256"] or chain_hash(prev, e) != e["hash"]:
                    return {"ok": False, "broken_at": e["seq"], "head": prev}
            elif not e["tombstoned_at"]:
                return {"ok": False, "broken_at": e["seq"], "head": prev, "error": "payload missing without tombstone"}
            else: tomb += 1
            prev, n = e["hash"], n + 1
        return {"ok": True, "head": prev, "events": n, "tombstoned": tomb}

    def run(self, tenant, run_id):
        r = self.q("SELECT run_id, contract_id, contract_version, subject_ref, actor, started_at FROM run WHERE tenant_id=? AND run_id=?",
                   (tenant, run_id)).fetchone()
        if not r: return None
        out = dict(zip(["run_id", "contract_id", "contract_version", "subject_ref", "actor", "started_at"], r))
        out["events"] = [e for e in self.events(tenant) if e["run_id"] == run_id]
        out["verdict"] = next(iter(self.verdicts(tenant, run_id=run_id)), None)
        return out

    def verdicts(self, tenant, since="", run_id=None):
        sql = "SELECT run_id, verdict, level_reached, independence, reasons_json, final_event_seq, at FROM verdict WHERE tenant_id=? AND at>=?"
        args = [tenant, since or ""]
        if run_id: sql += " AND run_id=?"; args.append(run_id)
        keys = ["run_id", "verdict", "level_reached", "independence", "reasons_json", "final_event_seq", "at"]
        return [dict(zip(keys, r)) for r in self.q(sql + " ORDER BY at", args).fetchall()]

    # -- retention (Trust Pack s.5: hash-chain tombstones only) --
    def purge(self, tenant, older_than_days=400, now=None, reason="retention"):
        cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=older_than_days)).isoformat()
        self.begin()
        try:
            seqs = [r[0] for r in self.q("""SELECT e.seq FROM event e JOIN event_payload p ON p.tenant_id=e.tenant_id AND p.seq=e.seq
                                            WHERE e.tenant_id=? AND e.at<?""", (tenant, cutoff)).fetchall()]
            for s in seqs:
                self.q("INSERT INTO tombstone VALUES (?,?,?,?)", (tenant, s, _now(), reason))
                self.q("DELETE FROM event_payload WHERE tenant_id=? AND seq=?", (tenant, s))
            self.commit(); return len(seqs)
        except Exception:
            self.rollback(); raise


class PostgresStore(Store):
    """Same SQL with %s placeholders. Requires psycopg (v3) and hosted/schema.postgres.sql applied by a migration role.
    With psycopg_pool installed, each transaction takes its own pooled connection and tenants serialise on a row lock
    (SELECT ... FOR UPDATE), so different tenants write in parallel. Without it: one connection behind a process lock."""
    ph = "%s"

    def __init__(self, dsn, pool_size=None):
        try: import psycopg
        except ImportError as e: raise RuntimeError("PostgresStore needs `pip install psycopg[binary]`") from e
        try: from psycopg_pool import ConnectionPool
        except ImportError: ConnectionPool = None
        size = pool_size if pool_size is not None else int(os.environ.get("VERIFY_DB_POOL", "10"))
        self.pool = ConnectionPool(dsn, min_size=1, max_size=size, kwargs={"autocommit": True}, open=True) \
            if ConnectionPool and size > 1 else None
        self.local = threading.local()
        self.lock = threading.Lock()
        self._db = None if self.pool else psycopg.connect(dsn, autocommit=True)
        enc = self.q("SHOW server_encoding").fetchone()[0]
        if enc.upper() not in ("UTF8", "UTF-8"):   # SQL_ASCII makes psycopg return bytes and breaks tenant matching
            raise RuntimeError(f"database encoding is {enc}; create it with ENCODING 'UTF8'")

    @property
    def db(self):
        """Connection for the current transaction, or a thread-held one for ad-hoc admin/test use."""
        if not self.pool: return self._db
        c = getattr(self.local, "conn", None)
        if c is None: c = self.local.conn = self.pool.getconn()
        return c

    def q(self, sql, args=()):
        sql = sql.replace("?", self.ph)
        if self.pool and getattr(self.local, "conn", None) is None:
            with self.pool.connection() as c: return _Rows(c.execute(sql, args))
        return _Rows(self.db.execute(sql, args))

    def begin(self):
        if not self.pool: self.lock.acquire()
        self.db.execute("BEGIN")
    def _end(self, sql):
        self.db.execute(sql)
        if self.pool: self.pool.putconn(self.local.conn); self.local.conn = None
        else: self.lock.release()
    def commit(self): self._end("COMMIT")
    def rollback(self): self._end("ROLLBACK")
    def lock_tenant(self, tenant): self.q("SELECT 1 FROM tenant WHERE id=? FOR UPDATE", (tenant,))
    def close(self):
        if self.pool: self.pool.close()
        elif self._db: self._db.close()


def open_store():
    url = os.environ.get("VERIFY_DATABASE_URL", "")
    return PostgresStore(url) if url.startswith("postgres") else Store(url.removeprefix("sqlite:///") or "hosted.db")

def _now(): return datetime.now(timezone.utc).isoformat()
