"""Push a local verify Ledger (SQLite file) to the hosted API, resuming from the server's chain head.

    verify push ledger.db --to https://ledger.example.com   (API key only from env VERIFY_HOSTED_KEY)
"""
import json, os, sqlite3, sys, urllib.request

def _call(base, key, method, path, body=None):
    req = urllib.request.Request(base.rstrip("/") + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r: return json.loads(r.read())

def push(ledger_path, base, key, batch=500):
    db = sqlite3.connect(f"file:{ledger_path}?mode=ro", uri=True)
    cols = ["run_id", "type", "at", "clock_source", "payload_json", "evidence_hash", "prev_hash", "hash"]
    events = [dict(zip(cols, r)) for r in db.execute(f"SELECT {','.join(cols)} FROM event ORDER BY seq")]
    head = _call(base, key, "GET", "/v1/verify-chain")["head"]
    start = 0 if head == "" else next((i + 1 for i, e in enumerate(events) if e["hash"] == head), None)
    if start is None: raise RuntimeError(f"server head {head} not found in local ledger: different chain")
    rcols = ["run_id", "contract_id", "contract_version", "subject_ref", "actor", "started_at"]
    runs = {r[0]: dict(zip(rcols, r)) for r in db.execute(f"SELECT {','.join(rcols)} FROM run")}
    vcols = ["run_id", "verdict", "level_reached", "independence", "reasons_json"]
    verdicts = {r[0]: dict(zip(vcols, r)) for r in db.execute(f"SELECT {','.join(vcols)} FROM verdict")}
    seen = {e["run_id"] for e in events[:start]}            # runs already on the server
    sent = 0
    for i in range(start, len(events), batch):
        chunk = events[i:i + batch]
        new_runs = [runs[r] for r in dict.fromkeys(e["run_id"] for e in chunk) if r not in seen and r in runs]
        seen.update(e["run_id"] for e in chunk)
        vs = [verdicts[e["run_id"]] for e in chunk if e["type"] == "verdict_final" and e["run_id"] in verdicts]
        head = _call(base, key, "POST", "/v1/events", {"events": chunk, "runs": new_runs, "verdicts": vs})["head"]
        sent += len(chunk)
    return {"pushed": sent, "head": head}
