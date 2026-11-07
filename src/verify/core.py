"""Verify core: contracts -> independent readback -> 5 verdicts -> hash-chained ledger."""
import sqlite3, json, hashlib, time, uuid
from datetime import datetime, timezone

def now(): return datetime.now(timezone.utc).isoformat()

class Blocked(Exception):
    """Readback impossible (auth, outage, rate limit). retry_after: seconds the system asked us to wait."""
    def __init__(self, msg, retry_after=None):
        super().__init__(msg); self.retry_after = retry_after

# ---------------- evaluation ----------------
OPS = {"eq": lambda a, b: a == b, "ne": lambda a, b: a != b, "gt": lambda a, b: a is not None and a > b,
       "lt": lambda a, b: a is not None and a < b, "exists": lambda a, b: a is not None}

def resolve(v, claim):
    if isinstance(v, str) and v.startswith("{") and v.endswith("}"): return claim[v[1:-1]]
    return v

def evaluate(contract, fields, claim):
    """Returns (verdict, level, reasons). Unknown fails closed."""
    def run(checks): return [(c, fields.get(c["path"]), OPS[c["op"]](fields.get(c["path"]), resolve(c["value"], claim)))
                             for c in checks]
    pre = run(contract["preconditions"])
    if not all(ok for *_, ok in pre):
        return "inapplicable", "L0", [f"precondition {c['path']}={got!r}" for c, got, ok in pre if not ok]
    if fields.get(contract.get("subject_present", "refund.amount")) in (None, False):   # subject record absent
        return "not_observed", "L1", [f"{contract['subject_ref'].format(**claim)} not found in system of record"]
    bad = [f"forbidden {c['path']}={got!r}" for c, got, hit in run(contract["forbidden"]) if hit]
    bad += [f"{c['path']} = {got!r}, expected {c['op']} {resolve(c['value'], claim)!r}"
            for c, got, ok in run(contract["postconditions"]) if not ok]
    return ("fail", "L2", bad) if bad else ("pass", contract["required_level"], [])

# ---------------- ledger (doc 03) ----------------
LEDGER_SQL = """
CREATE TABLE IF NOT EXISTS contract(id TEXT, version TEXT, body_json TEXT NOT NULL, body_hash TEXT NOT NULL,
  registered_at TEXT NOT NULL, owner TEXT NOT NULL, PRIMARY KEY(id, version));
CREATE TABLE IF NOT EXISTS run(run_id TEXT PRIMARY KEY, contract_id TEXT NOT NULL, contract_version TEXT NOT NULL,
  subject_ref TEXT NOT NULL, actor TEXT NOT NULL, started_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS event(seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, type TEXT NOT NULL,
  at TEXT NOT NULL, clock_source TEXT NOT NULL, payload_json TEXT NOT NULL, evidence_hash TEXT, prev_hash TEXT, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS verdict(run_id TEXT PRIMARY KEY, verdict TEXT NOT NULL
  CHECK (verdict IN ('pass','fail','inapplicable','not_observed','blocked')),
  level_reached TEXT NOT NULL, independence TEXT NOT NULL, reasons_json TEXT NOT NULL, final_event_seq INTEGER NOT NULL);
"""

class Ledger:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(LEDGER_SQL)

    def event(self, run_id, type_, payload, evidence=None):
        prev = (self.db.execute("SELECT hash FROM event ORDER BY seq DESC LIMIT 1").fetchone() or [""])[0]
        row = dict(run_id=run_id, type=type_, at=now(), clock_source="system", payload_json=json.dumps(payload, sort_keys=True),
                   evidence_hash=hashlib.sha256(evidence.encode()).hexdigest() if evidence else None)
        h = hashlib.sha256((prev + json.dumps(row, sort_keys=True)).encode()).hexdigest()
        cur = self.db.execute("INSERT INTO event(run_id,type,at,clock_source,payload_json,evidence_hash,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?)",
                              (*row.values(), prev, h))
        self.db.commit(); return cur.lastrowid

    def verify_chain(self):
        prev = ""
        for *row, p, h in self.db.execute("SELECT run_id,type,at,clock_source,payload_json,evidence_hash,prev_hash,hash FROM event ORDER BY seq"):
            keys = ["run_id", "type", "at", "clock_source", "payload_json", "evidence_hash"]
            if p != prev or h != hashlib.sha256((prev + json.dumps(dict(zip(keys, row)), sort_keys=True)).encode()).hexdigest():
                return False
            prev = h
        return True

# ---------------- Verify ----------------
def verify(ledger, sor_path, claim, contract, reader, actor="support-agent", independence="full"):
    body = json.dumps(contract, sort_keys=True)
    ledger.db.execute("INSERT OR IGNORE INTO contract VALUES (?,?,?,?,?,?)", (contract["id"], contract["version"], body,
                      hashlib.sha256(body.encode()).hexdigest(), now(), contract["owner"]))
    run_id = uuid.uuid4().hex[:8]
    ledger.db.execute("INSERT INTO run VALUES (?,?,?,?,?,?)", (run_id, contract["id"], contract["version"],
                      contract["subject_ref"].format(**claim), actor, now()))
    ledger.event(run_id, "action_claimed", claim)            # claim recorded, never used as evidence
    verdict, level, reasons = "not_observed", "L1", []
    wait = contract["settle_window_s"]
    for attempt in range(1, contract["max_attempts"] + 1):
        time.sleep(wait)
        wait = contract["settle_window_s"]
        ledger.event(run_id, "readback_started", {"attempt": attempt})
        try:
            fields, raw = reader(sor_path, claim)
        except Blocked as e:
            ledger.event(run_id, "readback_blocked", {"error": str(e), "retry_after": e.retry_after})
            wait = min(e.retry_after if e.retry_after is not None else max(1, wait) * 2 ** attempt, 60)   # backoff, capped
            verdict, level, reasons = "blocked", "L0", [str(e)]
            continue
        ledger.event(run_id, "readback_observed", fields, evidence=raw)
        verdict, level, reasons = evaluate(contract, fields, claim)
        if verdict != "not_observed": break                    # retry only missing evidence
    seq = ledger.event(run_id, "verdict_final", {"verdict": verdict, "reasons": reasons})
    ledger.db.execute("INSERT INTO verdict VALUES (?,?,?,?,?,?)", (run_id, verdict, level, independence, json.dumps(reasons), seq))
    ledger.db.commit()
    return run_id, verdict, level, reasons



def check(contract, claim, reader, ledger="verify.db", actor=None, independence="full"):
    """Python API. contract: dict or path; claim: dict; reader(sor, claim) -> (fields, raw_json).
    Returns dict with verdict, level, reasons, run_id. Only verdict == "pass" means success."""
    from . import contract as _c
    c = _c.load(contract) if isinstance(contract, str) else contract
    if not isinstance(contract, str):
        errs = _c.validate(c)
        if errs: raise ValueError("invalid contract: " + "; ".join(errs))
    led = ledger if isinstance(ledger, Ledger) else Ledger(ledger)
    run_id, v, level, reasons = verify(led, None, claim, c, reader, actor=actor or claim.get("actor", "unknown"), independence=independence)
    return {"run_id": run_id, "verdict": v, "level": level, "reasons": reasons, "ok": v == "pass"}
