"""Verify reader for HubSpot CRM deals. Stdlib only.

Env (never in code or chat):
  HUBSPOT_VERIFY_TOKEN  private-app token with ONLY crm.objects.deals.read (Verify: read-only)

Checks a RevOps agent's claim "deal moved to Closed Won for $X, linked to company Y".
"""
import json, os, tempfile, urllib.request, urllib.error
from .core import Blocked, Ledger, verify

CONTRACT = {
    "id": "deal.closed_won.hubspot", "version": "1.0.0", "owner": "revops",
    "target_system": "hubspot", "subject_ref": "deal:{deal}", "subject_present": "deal.exists",
    "preconditions": [],
    "postconditions": [{"path": "deal.dealstage", "op": "eq", "value": "closedwon"},
                       {"path": "deal.amount", "op": "eq", "value": "{amount}"},
                       {"path": "deal.company_id", "op": "eq", "value": "{company}"}],
    "forbidden": [],
    "required_level": "L2", "settle_window_s": 1.0, "max_attempts": 3,
    "scope": ["deal.exists", "deal.dealstage", "deal.amount", "deal.company_id"],
}


def hs_http(token):
    def http(method, path):
        req = urllib.request.Request(f"https://api.hubapi.com{path}", method=method,
                                     headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r: return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404: return 404, {}
            ra = e.headers.get("Retry-After")
            raise Blocked(f"hubspot HTTP {e.code}", retry_after=float(ra) if ra else None)
        except urllib.error.URLError as e:
            raise Blocked(f"hubspot unreachable: {e.reason}")
    return http


def make_reader(http):
    def reader(_unused, claim):
        st, d = http("GET", f"/crm/v3/objects/deals/{claim['deal']}?properties=dealstage,amount&associations=companies")
        p = d.get("properties", {}) if st == 200 else {}
        # HubSpot v3 lists one company twice (deal_to_company + deal_to_company_unlabeled): dedupe, keep order
        companies = list(dict.fromkeys(a["id"] for a in d.get("associations", {}).get("companies", {}).get("results", []))) if st == 200 else []
        amt = p.get("amount")
        raw = {"deal.exists": st == 200, "deal.dealstage": p.get("dealstage"),
               "deal.amount": float(amt) if amt not in (None, "") else None,     # HubSpot returns strings
               "deal.company_id": companies[0] if len(companies) == 1 else (companies or None)}
        return raw, json.dumps(raw, sort_keys=True)
    return reader


def fake_hubspot(deals):
    def http(method, path):
        if method != "GET": raise Blocked("hubspot HTTP 403: read-only scope")
        d = deals.get(path.split("/")[5].split("?")[0])
        if d is None: return 404, {}
        return 200, {"properties": {"dealstage": d[0], "amount": d[1]},
                     "associations": {"companies": {"results": [{"id": c, "type": t} for c in d[2]
                                                                for t in ("deal_to_company", "deal_to_company_unlabeled")]}}}
    return http


def check():
    deals = {"1": ("closedwon", "4200", ["77"]), "2": ("contractsent", "4200", ["77"]),
             "3": ("closedwon", "420", ["77"]), "4": ("closedwon", "4200", [])}
    c = dict(CONTRACT, settle_window_s=0)
    led, reader = Ledger(os.path.join(tempfile.mkdtemp(), "l.db")), make_reader(fake_hubspot(deals))
    got = [verify(led, None, {"deal": d, "amount": 4200.0, "company": "77"}, c, reader)[1] for d in ("1", "2", "3", "4", "9")]
    assert got == ["pass", "fail", "fail", "fail", "not_observed"], got
    try: fake_hubspot(deals)("PATCH", "/crm/v3/objects/deals/1"); assert False
    except Blocked: pass
    assert led.verify_chain()
    print("hubspot adapter offline check: ok")
