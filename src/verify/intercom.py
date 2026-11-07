"""Verify reader for Intercom conversations. Stdlib only.

Env (never in code or chat):
  INTERCOM_VERIFY_TOKEN  access token from an Intercom app granted only "Read conversations" (Verify: read-only)

Checks a support agent's claim "conversation closed with a reply".
Docs:
  https://developers.intercom.com/docs/references/rest-api/api.intercom.io/conversations/retrieveconversation
  https://developers.intercom.com/docs/build-an-integration/learn-more/rest-apis/api-versioning
  https://developers.intercom.com/docs/build-an-integration/learn-more/authentication
  https://developers.intercom.com/docs/references/rest-api/errors/rate-limiting
"""
import json, os, tempfile, urllib.request, urllib.error
from .core import Blocked, Ledger, verify

API_VERSION = "2.17"   # pinned; bump deliberately after reading the changelog

CONTRACT = {
    "id": "conversation.closed_with_reply.intercom", "version": "1.0.0", "owner": "support",
    "target_system": "intercom", "subject_ref": "conversation:{conversation}", "subject_present": "conversation.exists",
    "preconditions": [],
    "postconditions": [{"path": "conversation.state", "op": "eq", "value": "closed"},
                       {"path": "conversation.admin_replies", "op": "gt", "value": 0}],
    "forbidden": [{"path": "conversation.snoozed", "op": "eq", "value": True}],
    "required_level": "L2", "settle_window_s": 1.0, "max_attempts": 3,
    "scope": ["conversation.exists", "conversation.state", "conversation.admin_replies", "conversation.snoozed"],
}


def ic_http(token):
    def http(method, path):
        req = urllib.request.Request(f"https://api.intercom.io{path}", method=method, headers={
            "Authorization": f"Bearer {token}", "Accept": "application/json", "Intercom-Version": API_VERSION})
        try:
            with urllib.request.urlopen(req, timeout=20) as r: return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404: return 404, {}
            ra = e.headers.get("Retry-After")
            raise Blocked(f"intercom HTTP {e.code}", retry_after=float(ra) if ra else None)
        except urllib.error.URLError as e:
            raise Blocked(f"intercom unreachable: {e.reason}")
    return http


def make_reader(http):
    def reader(_unused, claim):
        st, d = http("GET", f"/conversations/{claim['conversation']}?display_as=plaintext")
        parts = d.get("conversation_parts", {}).get("conversation_parts", []) if st == 200 else []
        replies = sum(1 for p in parts if p.get("part_type") == "comment"
                      and (p.get("author") or {}).get("type") in ("admin", "bot"))
        raw = {"conversation.exists": st == 200, "conversation.state": d.get("state"),
               "conversation.admin_replies": replies if st == 200 else None,
               "conversation.snoozed": (d.get("state") == "snoozed" or bool(d.get("snoozed_until"))) if st == 200 else None}
        return raw, json.dumps(raw, sort_keys=True)
    return reader


def fake_intercom(convs):
    """convs: id -> (state, snoozed_until, [(part_type, author_type), ...])"""
    def http(method, path):
        if method != "GET": raise Blocked("intercom HTTP 403: read-only token")
        c = convs.get(path.split("/")[2].split("?")[0])
        if c is None: return 404, {}
        if c == "429": raise Blocked("intercom HTTP 429", retry_after=0)
        return 200, {"state": c[0], "snoozed_until": c[1], "conversation_parts": {"conversation_parts": [
            {"part_type": pt, "author": {"type": at}} for pt, at in c[2]]}}
    return http


def check():
    convs = {"1": ("closed", None, [("comment", "user"), ("comment", "admin"), ("close", "admin")]),
             "2": ("open", None, [("comment", "admin")]),
             "3": ("closed", None, [("comment", "user"), ("close", "admin"), ("note", "admin")]),
             "4": ("closed", 1900000000, [("comment", "bot")]), "5": "429"}
    c = dict(CONTRACT, settle_window_s=0, max_attempts=1)
    led, reader = Ledger(os.path.join(tempfile.mkdtemp(), "l.db")), make_reader(fake_intercom(convs))
    got = [verify(led, None, {"conversation": i}, c, reader)[1] for i in ("1", "2", "3", "4", "9", "5")]
    assert got == ["pass", "fail", "fail", "fail", "not_observed", "blocked"], got
    try: fake_intercom(convs)("POST", "/conversations/1/reply"); assert False
    except Blocked: pass
    assert led.verify_chain()
    print("intercom adapter offline check: ok")
