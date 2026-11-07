"""Verify v0 against real Stripe TEST mode. Stdlib only.

Keys come from env vars, never from code or chat:
  STRIPE_AGENT_KEY   sk_test_...  (agent: creates payments + refunds)
  STRIPE_VERIFY_KEY  rk_test_...  (Verify: restricted key, READ-only Charges + Refunds)
If STRIPE_VERIFY_KEY is missing, Verify reuses the agent key and marks independence=degraded.
Live keys are refused.

    python3 -I stripe_demo.py           # 3 test refunds, 1 honest, 1 half, 1 never sent
    python3 -I stripe_demo.py --check   # offline check with a fake Stripe
"""
import os, sys, tempfile, json, base64, urllib.request, urllib.parse, urllib.error, uuid
from .core import Ledger, verify, Blocked

CONTRACT = {
    "id": "refund.full.stripe", "version": "1.0.0", "owner": "support-ops",
    "target_system": "stripe", "subject_ref": "refund:{refund_id}",
    "preconditions":  [{"path": "charge.status", "op": "eq", "value": "succeeded"}],
    "postconditions": [{"path": "refund.status", "op": "eq", "value": "succeeded"},
                       {"path": "refund.amount", "op": "eq", "value": "{amount}"},
                       {"path": "charge.amount_refunded", "op": "eq", "value": "{amount}"}],
    "forbidden":      [{"path": "charge.refund_count", "op": "gt", "value": 1}],
    "required_level": "L2", "settle_window_s": 1.0, "max_attempts": 3,
    "scope": ["charge.status", "charge.amount_refunded", "charge.refund_count", "refund.status", "refund.amount"],
}

def test_key(name):
    k = os.environ.get(name)
    if k and not k.startswith(("sk_test_", "rk_test_")):
        sys.exit(f"{name} is not a test-mode key. Refusing.")
    return k

def stripe_http(key, method, path, data=None):
    """Returns (status, json). Network/auth errors raise Blocked."""
    req = urllib.request.Request("https://api.stripe.com/v1" + path, method=method,
                                 data=urllib.parse.urlencode(data).encode() if data else None,
                                 headers={"Authorization": "Basic " + base64.b64encode(f"{key}:".encode()).decode()})
    try:
        with urllib.request.urlopen(req, timeout=20) as r: return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404: return 404, {}
        raise Blocked(f"stripe HTTP {e.code}: {json.load(e).get('error', {}).get('message', '')}")
    except urllib.error.URLError as e:
        raise Blocked(f"stripe unreachable: {e.reason}")

# ---------------- agent (writes with its own key) ----------------
def agent_handle(http, key, fault=None, amount=5000):
    _, pi = http(key, "POST", "/payment_intents", {"amount": amount, "currency": "usd", "payment_method": "pm_card_visa",
                 "confirm": "true", "automatic_payment_methods[enabled]": "true",
                 "automatic_payment_methods[allow_redirects]": "never"})
    charge_id = pi["latest_charge"]
    refund_id = "re_never_sent_" + uuid.uuid4().hex[:6]
    if fault != "timeout":
        _, r = http(key, "POST", "/refunds", {"charge": charge_id, "amount": amount // 2 if fault == "half" else amount})
        refund_id = r["id"]
    return {"ticket": pi["id"], "charge_id": charge_id, "refund_id": refund_id, "amount": amount, "agent_says": "Refund issued ✅"}

# ---------------- Verify adapter (reads with its own key) ----------------
def make_reader(http, key):
    def reader(_unused, claim):
        sr, r = http(key, "GET", f"/refunds/{claim['refund_id']}")
        sc, c = http(key, "GET", f"/charges/{claim['charge_id']}")
        _, rl = http(key, "GET", f"/refunds?charge={claim['charge_id']}&limit=10")
        raw = {"charge.status": c.get("status") if sc == 200 else None,
               "charge.amount_refunded": c.get("amount_refunded") if sc == 200 else None,
               "charge.refund_count": len(rl.get("data", [])),
               "refund.status": r.get("status") if sr == 200 else None,
               "refund.amount": r.get("amount") if sr == 200 else None}
        return {k: v for k, v in raw.items() if k in CONTRACT["scope"]}, json.dumps(raw, sort_keys=True)
    return reader

def run(http, agent_key, verify_key, ledger_path):
    independence = "full" if verify_key and verify_key != agent_key else "degraded"
    led, reader = Ledger(ledger_path), make_reader(http, verify_key or agent_key)
    claims = [agent_handle(http, agent_key, f) for f in (None, "half", "timeout")]
    print("\n== What the agent says ==")
    for c in claims: print(f"  {c['ticket']}: {c['agent_says']}")
    print(f"  Agent success rate: 3/3\n\n== What Verify read back from Stripe (independence={independence}) ==")
    res = [verify(led, None, c, CONTRACT, reader, independence=independence) for c in claims]
    for c, (rid, v, lvl, why) in zip(claims, res):
        print(f"  {c['charge_id']}  {v.upper():13} {lvl}  run={rid}" + ("".join(f"\n      - {w}" for w in why)))
    print(f"\n  Verified success rate: {sum(v == 'pass' for _, v, *_ in res)}/3   chain intact: {led.verify_chain()}\n")
    return [v for _, v, *_ in res]

# ---------------- offline check ----------------
def fake_stripe():
    db = {"ch": {}, "re": {}}
    def http(key, method, path, data=None):
        assert key.startswith(("sk_test_", "rk_test_"))
        if method == "POST" and key.startswith("rk_"): raise Blocked("stripe HTTP 403: read-only key")
        if path == "/payment_intents":
            cid = "ch_" + uuid.uuid4().hex[:6]; db["ch"][cid] = {"status": "succeeded", "amount_refunded": 0}
            return 200, {"id": "pi_" + cid[3:], "latest_charge": cid}
        if path == "/refunds" and method == "POST":
            rid = "re_" + uuid.uuid4().hex[:6]; amt = int(data["amount"])
            db["re"][rid] = {"status": "succeeded", "amount": amt, "charge": data["charge"]}
            db["ch"][data["charge"]]["amount_refunded"] += amt
            return 200, {"id": rid}
        if path.startswith("/refunds?charge="):
            cid = path.split("=")[1].split("&")[0]
            return 200, {"data": [r for r in db["re"].values() if r["charge"] == cid]}
        kind, oid = path.strip("/").split("/")
        obj = db["ch" if kind == "charges" else "re"].get(oid)
        return (200, obj) if obj else (404, {})
    return http

def check():
    d = tempfile.mkdtemp()
    assert run(fake_stripe(), "sk_test_a", "rk_test_v", os.path.join(d, "l.db")) == ["pass", "fail", "not_observed"]
    try: fake_stripe()("rk_test_v", "POST", "/refunds", {}); assert False
    except Blocked: pass
    print("stripe adapter offline check: ok")


def main():
    agent, ver = test_key("STRIPE_AGENT_KEY"), test_key("STRIPE_VERIFY_KEY")
    if not agent: sys.exit("Set STRIPE_AGENT_KEY (sk_test_...). See docstring.")
    os.makedirs("demo_out", exist_ok=True)
    run(stripe_http, agent, ver, "demo_out/stripe_ledger.db")
