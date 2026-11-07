"""Verify v0 against a Zendesk sandbox. Stdlib only.

Env / Keychain (never in code or chat):
  ZENDESK_SUBDOMAIN     e.g. mycompany1234 (sandbox)
  ZENDESK_AGENT_OAUTH   OAuth token, scopes "read write"  (agent: updates tickets)
  ZENDESK_AGENT_AUTH    legacy "agent@x.com/token:<api_token>" (Zendesk retires these 2027-04-30)
  ZENDESK_VERIFY_TOKEN  OAuth access token with scope "read" (Verify: read-only)
If ZENDESK_VERIFY_TOKEN is missing, Verify reuses agent auth -> independence=degraded.

    python3 -I zendesk_demo.py           # 3 tickets: honest, solved-without-reply, never touched
    python3 -I zendesk_demo.py --check   # offline check with a fake Zendesk
"""
import os, sys, tempfile, json, base64, urllib.request, urllib.error
from .core import Ledger, verify, Blocked

CONTRACT = {
    "id": "ticket.solved.with_reply.zendesk", "version": "1.0.0", "owner": "support-ops",
    "target_system": "zendesk", "subject_ref": "ticket:{ticket}", "subject_present": "ticket.exists",
    "preconditions":  [],
    "postconditions": [{"path": "ticket.status", "op": "eq", "value": "solved"},
                       {"path": "ticket.public_agent_replies", "op": "gt", "value": 0}],
    "forbidden":      [{"path": "ticket.auto_closed_tag", "op": "eq", "value": True}],
    "required_level": "L2", "settle_window_s": 1.0, "max_attempts": 3,
    "scope": ["ticket.exists", "ticket.status", "ticket.public_agent_replies", "ticket.auto_closed_tag"],
}

def zd_http(sub, auth_header):
    def http(method, path, body=None):
        req = urllib.request.Request(f"https://{sub}.zendesk.com/api/v2{path}", method=method,
                                     data=json.dumps(body).encode() if body else None,
                                     headers={"Authorization": auth_header, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r: return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404: return 404, {}
            raise Blocked(f"zendesk HTTP {e.code}")
        except urllib.error.URLError as e:
            raise Blocked(f"zendesk unreachable: {e.reason}")
    return http

# ---------------- agent ----------------
def agent_handle(http, ticket_id, fault=None):
    if fault != "untouched":
        upd = {"status": "solved"}
        if fault != "no_reply": upd["comment"] = {"body": "Your refund has been issued.", "public": True}
        http("PUT", f"/tickets/{ticket_id}.json", {"ticket": upd})
    return {"ticket": ticket_id, "agent_says": "Ticket solved, customer told ✅"}

def setup_tickets(http):
    ids = []
    for i in range(3):
        _, t = http("POST", "/tickets.json", {"ticket": {"subject": f"Verify demo refund #{i+1}",
                    "comment": {"body": "Please refund my order."},
                    "requester": {"name": "Demo Customer", "email": "demo.customer@example.com"}}})
        ids.append(t["ticket"]["id"])
    return ids

# ---------------- Verify adapter ----------------
def make_reader(http):
    def reader(_unused, claim):
        st, t = http("GET", f"/tickets/{claim['ticket']}.json")
        sc, c = http("GET", f"/tickets/{claim['ticket']}/comments.json")
        t = t.get("ticket", {}) if st == 200 else {}
        submitter = t.get("requester_id")
        replies = sum(1 for x in c.get("comments", []) if x.get("public") and x.get("author_id") != submitter) if sc == 200 else 0
        raw = {"ticket.exists": st == 200, "ticket.status": t.get("status"),
               "ticket.public_agent_replies": replies, "ticket.auto_closed_tag": "auto_closed_no_reply" in t.get("tags", [])}
        return raw, json.dumps(raw, sort_keys=True)
    return reader

def run(agent_http, verify_http, independence, ledger_path):
    led, reader = Ledger(ledger_path), make_reader(verify_http)
    ids = setup_tickets(agent_http)
    claims = [agent_handle(agent_http, t, f) for t, f in zip(ids, (None, "no_reply", "untouched"))]
    print("\n== What the agent says ==")
    for c in claims: print(f"  #{c['ticket']}: {c['agent_says']}")
    print(f"  Agent success rate: 3/3\n\n== What Verify read back from Zendesk (independence={independence}) ==")
    res = [verify(led, None, c, CONTRACT, reader, independence=independence) for c in claims]
    for c, (rid, v, lvl, why) in zip(claims, res):
        print(f"  #{c['ticket']}  {v.upper():13} {lvl}  run={rid}" + "".join(f"\n      - {w}" for w in why))
    print(f"\n  Verified success rate: {sum(v == 'pass' for _, v, *_ in res)}/3   chain intact: {led.verify_chain()}\n")
    return [v for _, v, *_ in res]

# ---------------- offline check ----------------
def fake_zendesk():
    db, nxt = {}, [100]
    def agent(method, path, body=None):
        if method == "POST":
            nxt[0] += 1; db[nxt[0]] = {"id": nxt[0], "status": "open", "requester_id": 1, "tags": [],
                                       "comments": [{"public": True, "author_id": 1}]}
            return 201, {"ticket": db[nxt[0]]}
        tid = int(path.split("/")[2].split(".")[0]); t = db[tid]; u = body["ticket"]
        t["status"] = u["status"]
        if "comment" in u: t["comments"].append({"public": u["comment"]["public"], "author_id": 2})
        return 200, {"ticket": t}
    def reader(method, path, body=None):
        if method != "GET": raise Blocked("zendesk HTTP 403: read scope")
        tid = int(path.split("/")[2].split(".")[0]); t = db.get(tid)
        if not t: return 404, {}
        return (200, {"comments": t["comments"]}) if "comments" in path else (200, {"ticket": t})
    return agent, reader

def check():
    a, r = fake_zendesk()
    assert run(a, r, "full", os.path.join(tempfile.mkdtemp(), "l.db")) == ["pass", "fail", "fail"]
    try: r("PUT", "/tickets/101.json", {}); assert False
    except Blocked: pass
    print("zendesk adapter offline check: ok")


def main():
    sub, agent_auth, agent_oauth, vt = (os.environ.get(k) for k in
        ("ZENDESK_SUBDOMAIN", "ZENDESK_AGENT_AUTH", "ZENDESK_AGENT_OAUTH", "ZENDESK_VERIFY_TOKEN"))
    if not (sub and (agent_auth or agent_oauth)): sys.exit("Set ZENDESK_SUBDOMAIN and ZENDESK_AGENT_OAUTH (or _AUTH). See docstring.")
    a = zd_http(sub, f"Bearer {agent_oauth}" if agent_oauth else "Basic " + base64.b64encode(agent_auth.encode()).decode())
    v = zd_http(sub, f"Bearer {vt}") if vt else a
    os.makedirs("demo_out", exist_ok=True)
    run(a, v, "full" if vt else "degraded", "demo_out/zendesk_ledger.db")
