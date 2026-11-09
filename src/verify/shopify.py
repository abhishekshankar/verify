"""Verify reader for Shopify order refunds via the Admin GraphQL API. Stdlib only.

Env (never in code or chat):
  SHOPIFY_SHOP          shop subdomain, e.g. "acme" for acme.myshopify.com
  SHOPIFY_VERIFY_TOKEN  Admin API token of a custom app granted ONLY read_orders (Verify: read-only)

Checks a support agent's claim "refund <id> issued on order <order> for <amount>".
Docs:
  https://shopify.dev/docs/api/admin-graphql/latest/objects/Refund
  https://shopify.dev/docs/api/admin-graphql/latest/objects/OrderTransaction
  https://shopify.dev/docs/api/admin-graphql/latest/queries/order
  https://shopify.dev/docs/api/usage/authentication  (X-Shopify-Access-Token)
  https://shopify.dev/docs/api/usage/rate-limits     (THROTTLED, extensions.cost.throttleStatus)
  https://shopify.dev/docs/api/usage/versioning
"""
import json, os, tempfile, urllib.request, urllib.error
from .core import Blocked, Ledger, verify

API_VERSION = "2026-10"   # pinned; Shopify supports each stable version for at least 12 months

CONTRACT = {
    "id": "refund.issued.shopify", "version": "1.0.0", "owner": "support",
    "target_system": "shopify", "subject_ref": "order:{order}/refund:{refund_id}", "subject_present": "refund.exists",
    "preconditions": [],
    "postconditions": [{"path": "refund.amount", "op": "eq", "value": "{amount}"},
                       {"path": "refund.transactions_ok", "op": "eq", "value": True}],
    "forbidden": [{"path": "order.refund_count", "op": "gt", "value": 1}],
    "required_level": "L2", "settle_window_s": 2.0, "max_attempts": 3,
    "scope": ["refund.exists", "refund.amount", "refund.transactions_ok", "order.refund_count"],
}

QUERY = """query($id: ID!) { order(id: $id) { id refunds(first: 50) { id
  transactions(first: 50) { nodes { kind status amountSet { shopMoney { amount } } } } } } }"""


def gid(kind, v): return v if str(v).startswith("gid://") else f"gid://shopify/{kind}/{v}"


def graphql_result(d):
    """Raise Blocked on GraphQL-level errors; return data."""
    errs = d.get("errors") or []
    if errs:
        if any((e.get("extensions") or {}).get("code") == "THROTTLED" for e in errs):
            cost = (d.get("extensions") or {}).get("cost", {})
            ts = cost.get("throttleStatus", {})
            need = cost.get("requestedQueryCost", 0) - ts.get("currentlyAvailable", 0)
            rate = ts.get("restoreRate") or 0
            raise Blocked("shopify THROTTLED", retry_after=max(need, 1) / rate if rate else None)
        raise Blocked("shopify GraphQL error: " + "; ".join(str(e.get("message")) for e in errs))
    for v in (d.get("data") or {}).values():           # mutations only, but never accept them silently
        if isinstance(v, dict) and v.get("userErrors"): raise Blocked(f"shopify userErrors: {v['userErrors']}")
    return d.get("data") or {}


def sh_http(shop, token):
    url = f"https://{shop}.myshopify.com/admin/api/{API_VERSION}/graphql.json"
    def http(query, variables):
        req = urllib.request.Request(url, method="POST", data=json.dumps({"query": query, "variables": variables}).encode(),
                                     headers={"X-Shopify-Access-Token": token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r: return graphql_result(json.load(r))
        except urllib.error.HTTPError as e:
            ra = e.headers.get("Retry-After")
            raise Blocked(f"shopify HTTP {e.code}", retry_after=float(ra) if ra else None)
        except urllib.error.URLError as e:
            raise Blocked(f"shopify unreachable: {e.reason}")
    return http


def make_reader(http):
    def reader(_unused, claim):
        order = http(QUERY, {"id": gid("Order", claim["order"])}).get("order")
        refunds = (order or {}).get("refunds") or []
        r = next((x for x in refunds if x["id"] == gid("Refund", claim["refund_id"])), None)
        txns = r["transactions"]["nodes"] if r else []
        raw = {"refund.exists": r is not None,
               "refund.amount": round(sum(float(t["amountSet"]["shopMoney"]["amount"]) for t in txns), 2) if r else None,
               "refund.transactions_ok": bool(txns) and all(t["kind"] == "REFUND" and t["status"] == "SUCCESS" for t in txns) if r else None,
               "order.refund_count": len(refunds) if order else None}
        return raw, json.dumps(raw, sort_keys=True)
    return reader


def fake_shopify(orders):
    """orders: order id -> [(refund id, [(kind, status, amount), ...]), ...]; "429" -> THROTTLED."""
    def http(query, variables):
        if query.lstrip().startswith("mutation"):
            return graphql_result({"errors": [{"message": "Access denied for refundCreate field. Required access: write_orders",
                                               "extensions": {"code": "ACCESS_DENIED"}}]})
        o = orders.get(variables["id"].rsplit("/", 1)[1])
        if o == "429":
            return graphql_result({"errors": [{"message": "Throttled", "extensions": {"code": "THROTTLED"}}],
                                   "extensions": {"cost": {"requestedQueryCost": 52, "throttleStatus": {
                                       "currentlyAvailable": 2, "restoreRate": 100.0}}}})
        if o is None: return graphql_result({"data": {"order": None}})
        return graphql_result({"data": {"order": {"id": variables["id"], "refunds": [
            {"id": gid("Refund", rid), "transactions": {"nodes": [
                {"kind": k, "status": s, "amountSet": {"shopMoney": {"amount": a}}} for k, s, a in tx]}} for rid, tx in o]}}})
    return http


def check():
    orders = {"1": [("11", [("REFUND", "SUCCESS", "30.00"), ("REFUND", "SUCCESS", "20.00")])],
              "2": [("21", [("REFUND", "SUCCESS", "25.00")])],
              "3": [("31", [("REFUND", "PENDING", "50.00")])],
              "4": [("41", [("REFUND", "SUCCESS", "50.00")]), ("42", [("REFUND", "SUCCESS", "50.00")])],
              "5": [("51", [("REFUND", "SUCCESS", "50.00")])], "6": "429"}
    c = dict(CONTRACT, settle_window_s=0, max_attempts=1)
    led, reader = Ledger(os.path.join(tempfile.mkdtemp(), "l.db")), make_reader(fake_shopify(orders))
    claims = [("1", "11"), ("2", "21"), ("3", "31"), ("4", "41"), ("5", "99"), ("9", "91"), ("6", "61")]
    got = [verify(led, None, {"order": o, "refund_id": r, "amount": 50.0}, c, reader)[1] for o, r in claims]
    # money as text, as Shopify itself writes it: must still pass
    assert verify(led, None, {"order": "1", "refund_id": "11", "amount": "50.00"}, c, reader)[1] == "pass"
    assert got == ["pass", "fail", "fail", "fail", "not_observed", "not_observed", "blocked"], got
    try: fake_shopify(orders)("mutation { refundCreate(input: {}) { userErrors { message } } }", {}); assert False
    except Blocked: pass
    try: graphql_result({"data": {"x": {"userErrors": [{"message": "bad"}]}}}); assert False
    except Blocked: pass
    assert led.verify_chain()
    print("shopify adapter offline check: ok")
