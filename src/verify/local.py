"""Local demo: SQLite stands in for Stripe + Zendesk. No accounts, no network."""
import sqlite3, json, os, uuid, shutil, tempfile
from .core import Ledger, Blocked, verify as _verify

# ---------------- system of record (stands in for Stripe + Zendesk) ----------------
def make_sor(path):
    db = sqlite3.connect(path)
    db.executescript("""
    CREATE TABLE charge(id TEXT PRIMARY KEY, status TEXT, amount INT, amount_refunded INT DEFAULT 0);
    CREATE TABLE refund(id TEXT PRIMARY KEY, charge_id TEXT, amount INT);
    CREATE TABLE ticket(id TEXT PRIMARY KEY, charge_id TEXT, status TEXT);
    CREATE TABLE comment(ticket_id TEXT, public INT, author TEXT);
    INSERT INTO charge VALUES ('ch_1','succeeded',5000,0),('ch_2','succeeded',5000,0),('ch_3','succeeded',5000,0),('ch_4','failed',5000,0);
    INSERT INTO ticket VALUES ('t_1','ch_1','open'),('t_2','ch_2','open'),('t_3','ch_3','open'),('t_4','ch_4','open');
    """)
    db.commit(); db.close()

# ---------------- the agent (with injected faults) ----------------
def agent_handle(sor_path, ticket, fault=None):
    """Writes with the agent's own read-write connection. Always *claims* success."""
    db = sqlite3.connect(sor_path)
    charge_id = db.execute("SELECT charge_id FROM ticket WHERE id=?", (ticket,)).fetchone()[0]
    amount = db.execute("SELECT amount FROM charge WHERE id=?", (charge_id,)).fetchone()[0]
    refund_id = "re_" + ticket[2:] + "_" + uuid.uuid4().hex[:4]
    if fault != "timeout":                       # timeout: tool call died, nothing written
        amt = amount // 2 if fault == "half" else amount
        db.execute("INSERT INTO refund VALUES (?,?,?)", (refund_id, charge_id, amt))
        db.execute("UPDATE charge SET amount_refunded=amount_refunded+? WHERE id=?", (amt, charge_id))
        db.execute("UPDATE ticket SET status='solved' WHERE id=?", (ticket,))
        db.execute("INSERT INTO comment VALUES (?,1,'agent')", (ticket,))
    db.commit(); db.close()
    return {"ticket": ticket, "charge_id": charge_id, "refund_id": refund_id, "amount": amount,
            "agent_says": "Refund issued ✅"}

# ---------------- contract (doc 02, JSON form) ----------------
CONTRACT = {
    "id": "refund.full.with_reply", "version": "1.0.0", "owner": "support-ops",
    "target_system": "demo_sor", "subject_ref": "refund:{refund_id}",
    "preconditions":  [{"path": "charge.status", "op": "eq", "value": "succeeded"}],
    "postconditions": [{"path": "refund.amount", "op": "eq", "value": "{amount}"},
                       {"path": "charge.amount_refunded", "op": "eq", "value": "{amount}"},
                       {"path": "ticket.status", "op": "eq", "value": "solved"},
                       {"path": "ticket.public_agent_replies", "op": "gt", "value": 0}],
    "forbidden":      [{"path": "charge.refund_count", "op": "gt", "value": 1}],
    "required_level": "L3", "settle_window_s": 0.05, "max_attempts": 3,
    "scope": ["charge.status", "charge.amount_refunded", "charge.refund_count", "refund.amount",
              "ticket.status", "ticket.public_agent_replies"],
}

def readback(sor_path, claim):
    """Separate credential analogue: SQLite read-only URI. Returns only scoped fields."""
    if not os.path.exists(sor_path): raise Blocked("system of record unreachable")
    try:
        db = sqlite3.connect(f"file:{sor_path}?mode=ro", uri=True)
        c = db.execute("SELECT status, amount_refunded FROM charge WHERE id=?", (claim["charge_id"],)).fetchone()
        n = db.execute("SELECT count(*) FROM refund WHERE charge_id=?", (claim["charge_id"],)).fetchone()[0]
        r = db.execute("SELECT amount FROM refund WHERE id=?", (claim["refund_id"],)).fetchone()
        t = db.execute("SELECT status FROM ticket WHERE id=?", (claim["ticket"],)).fetchone()
        k = db.execute("SELECT count(*) FROM comment WHERE ticket_id=? AND public=1 AND author='agent'", (claim["ticket"],)).fetchone()[0]
        db.close()
    except sqlite3.Error as e:
        raise Blocked(str(e))
    raw = {"charge.status": c and c[0], "charge.amount_refunded": c and c[1], "charge.refund_count": n,
           "refund.amount": r and r[0], "ticket.status": t and t[0], "ticket.public_agent_replies": k}
    return {k: v for k, v in raw.items() if k in CONTRACT["scope"]}, json.dumps(raw, sort_keys=True)


def verify(led, sor, claim):
    return _verify(led, sor, claim, CONTRACT, readback)

# ---------------- demo ----------------
def demo(out="demo_out"):
    shutil.rmtree(out, ignore_errors=True); os.makedirs(out)
    sor, led = os.path.join(out, "system_of_record.db"), Ledger(os.path.join(out, "ledger.db"))
    make_sor(sor)
    plan = [("t_1", None), ("t_2", "half"), ("t_3", "timeout")]
    claims = [agent_handle(sor, t, f) for t, f in plan]
    print("\n== What the agent says ==")
    for c in claims: print(f"  {c['ticket']}: {c['agent_says']}")
    print(f"  Agent success rate: {len(claims)}/{len(claims)}\n\n== What Verify observed in the system of record ==")
    results = [verify(led, sor, c) for c in claims]
    for c, (rid, v, lvl, why) in zip(claims, results):
        print(f"  {c['ticket']}  {v.upper():13} {lvl}  run={rid}" + (f"\n      - " + "\n      - ".join(why) if why else ""))
    ok = sum(v == "pass" for _, v, *_ in results)
    print(f"\n  Verified success rate: {ok}/{len(results)}")
    print(f"  Ledger hash chain intact: {led.verify_chain()}  ({out}/ledger.db)\n")
    return results

def check():
    d = tempfile.mkdtemp(); sor = os.path.join(d, "sor.db"); make_sor(sor); led = Ledger(os.path.join(d, "l.db"))
    v = lambda c: verify(led, sor, c)[1]
    assert v(agent_handle(sor, "t_1")) == "pass"
    assert v(agent_handle(sor, "t_2", "half")) == "fail"
    assert v(agent_handle(sor, "t_3", "timeout")) == "not_observed"
    assert v(agent_handle(sor, "t_4")) == "inapplicable"           # charge failed: refund should never run
    assert verify(led, os.path.join(d, "gone.db"), {"ticket": "t_1", "charge_id": "ch_1", "refund_id": "re_1", "amount": 5000})[1] == "blocked"
    dup = agent_handle(sor, "t_1")                                 # second refund on same charge
    assert v(dup) == "fail"
    assert led.verify_chain()
    led.db.execute("UPDATE event SET payload_json='{}' WHERE seq=1"); led.db.commit()
    assert not led.verify_chain(), "tamper must be detected"
    print("all 5 verdicts + duplicate refund + tamper detection: ok")

