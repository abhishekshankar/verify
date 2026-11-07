"""usage:
  verify check <contract.json> <claim.json> [--ledger verify.db]   exit 0 only on pass
  verify check-batch <contract.json> <claims.jsonl> [--ledger verify.db]   one line per claim; exit 0 only if all pass
  verify push <ledger.db> --to <url>      upload to the hosted ledger (key: env VERIFY_HOSTED_KEY)
  verify validate <contract.json>...
  verify ledger <db>
  verify ledger export <db> [out.jsonl]     hash-chained JSONL + chain head
  verify ledger verify <export.jsonl>      check an export offline
  verify init {stripe,zendesk,hubspot,intercom,shopify} [dir]
  verify --version
  verify demo {local,stripe,zendesk}
  verify selfcheck
"""
import json, os, sys
from . import contract, hubspot, intercom, local, shopify, stripe, zendesk
from . import __version__
from .core import BadClaim, Ledger, verify, verify_export


def reader_for(c):
    """Pick the read-only adapter from the contract's target_system. Credentials only from env."""
    t = c["target_system"]
    if t == "stripe":
        key = stripe.test_key("STRIPE_VERIFY_KEY")
        if not key: sys.exit("Set STRIPE_VERIFY_KEY (restricted rk_test_ key, Charges+Refunds Read).")
        return stripe.make_reader(stripe.stripe_http, key)
    if t == "zendesk":
        sub, tok = os.environ.get("ZENDESK_SUBDOMAIN"), os.environ.get("ZENDESK_VERIFY_TOKEN")
        if not (sub and tok): sys.exit("Set ZENDESK_SUBDOMAIN and ZENDESK_VERIFY_TOKEN (OAuth, scope read).")
        return zendesk.make_reader(zendesk.zd_http(sub, f"Bearer {tok}"))
    if t == "hubspot":
        tok = os.environ.get("HUBSPOT_VERIFY_TOKEN")
        if not tok: sys.exit("Set HUBSPOT_VERIFY_TOKEN (private app, crm.objects.deals.read only).")
        return hubspot.make_reader(hubspot.hs_http(tok))
    if t == "intercom":
        tok = os.environ.get("INTERCOM_VERIFY_TOKEN")
        if not tok: sys.exit("Set INTERCOM_VERIFY_TOKEN (Intercom app access token, Read conversations permission only).")
        return intercom.make_reader(intercom.ic_http(tok))
    if t == "shopify":
        shop, tok = os.environ.get("SHOPIFY_SHOP"), os.environ.get("SHOPIFY_VERIFY_TOKEN")
        if not (shop and tok): sys.exit("Set SHOPIFY_SHOP (subdomain of .myshopify.com) and SHOPIFY_VERIFY_TOKEN (custom app Admin API token, read_orders scope only).")
        return shopify.make_reader(shopify.sh_http(shop, tok))
    sys.exit(f"no adapter for target_system {t!r} (have: stripe, zendesk, hubspot, intercom, shopify)")


def check(contract_path, claim_path, ledger_path="verify.db"):
    c = contract.load(contract_path)
    with open(claim_path) as f: claim = json.load(f)
    try: run_id, v, level, reasons = verify(Ledger(ledger_path), None, claim, c, reader_for(c), actor=claim.get("actor", "unknown"))
    except BadClaim as e: print(f"error: {e}", file=sys.stderr); return 2
    print(json.dumps({"run_id": run_id, "verdict": v, "level": level, "reasons": reasons, "ledger": ledger_path}, indent=1))
    return 0 if v == "pass" else 1


def check_batch(contract_path, claims_path, ledger_path="verify.db", reader=None):
    c = contract.load(contract_path)
    led, reader = Ledger(ledger_path), reader or reader_for(c)
    counts = {}
    with open(claims_path) as f:
        for n, line in enumerate(f, 1):
            if not line.strip(): continue
            claim = json.loads(line)
            try: run_id, v, level, reasons = verify(led, None, claim, c, reader, actor=claim.get("actor", "unknown"))
            except BadClaim as e: run_id, v, level, reasons = None, "bad_claim", "-", [str(e)]
            counts[v] = counts.get(v, 0) + 1
            print(json.dumps({"line": n, "run_id": run_id, "verdict": v, "level": level, "reasons": reasons}))
    total = sum(counts.values())
    print(f"# {counts.get('pass', 0)}/{total} pass  " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())), file=sys.stderr)
    return 0 if total and counts.get("pass", 0) == total else 1


CLAIMS = {"stripe": {"actor": "support-agent", "charge_id": "ch_...", "refund_id": "re_...", "amount": 5000},
          "zendesk": {"actor": "support-agent", "ticket": 123},
          "hubspot": {"actor": "revops-agent", "deal": "123", "amount": 4200.0, "company": "456"},
          "intercom": {"actor": "support-agent", "conversation": "123"},
          "shopify": {"actor": "support-agent", "order": "123", "refund_id": "456", "amount": 50.0}}


def init(system, d="."):
    mod = {"stripe": stripe, "zendesk": zendesk, "hubspot": hubspot, "intercom": intercom, "shopify": shopify}[system]
    os.makedirs(os.path.join(d, "contracts"), exist_ok=True)
    paths = [os.path.join(d, "contracts", mod.CONTRACT["id"] + ".json"), os.path.join(d, f"claim.{system}.json")]
    for p, body in zip(paths, (mod.CONTRACT, CLAIMS[system])):
        if os.path.exists(p): print(f"exists, kept: {p}"); continue
        with open(p, "w") as f: json.dump(body, f, indent=2); f.write("\n")
        print(f"wrote {p}")
    print(f"next: edit {paths[1]}, then  verify check {paths[0]} {paths[1]}")
    return 0


def main(argv=None):
    a = sys.argv[1:] if argv is None else argv
    if a[:1] in (["--version"], ["-V"]): print(f"verify {__version__}"); return 0
    if a[:1] == ["init"] and len(a) in (2, 3) and a[1] in CLAIMS: return init(*a[1:])
    if a[:2] == ["ledger", "export"] and len(a) in (3, 4):
        out = open(a[3], "w") if len(a) == 4 else sys.stdout
        head = Ledger(a[2]).export(out)
        if out is not sys.stdout: out.close(); print(f"chain head {head}")
        return 0
    if a[:2] == ["ledger", "verify"] and len(a) == 3:
        with open(a[2]) as f: ok, n, head = verify_export(f)
        print(f"{n} events, chain {'intact' if ok else 'BROKEN'}" + (f", head {head}" if ok else ""))
        return 0 if ok else 1
    if a[:1] == ["check"] and len(a) in (3, 5) and (len(a) == 3 or a[3] == "--ledger"):
        return check(a[1], a[2], *a[4:5])
    if a[:1] == ["check-batch"] and len(a) in (3, 5) and (len(a) == 3 or a[3] == "--ledger"):
        return check_batch(a[1], a[2], *a[4:5])
    if a[:1] == ["push"] and len(a) == 4 and a[2] == "--to":
        from .push import push
        key = os.environ.get("VERIFY_HOSTED_KEY")
        if not key: print("error: set VERIFY_HOSTED_KEY", file=sys.stderr); return 2
        r = push(a[1], a[3], key); print(f"pushed {r['pushed']} events, head {r['head']}"); return 0
    if a[:1] == ["validate"] and len(a) > 1:
        bad = 0
        for p in a[1:]:
            errs = contract.validate(json.load(open(p)))
            print(f"{p}: " + ("ok" if not errs else "INVALID\n  " + "\n  ".join(errs)))
            bad += bool(errs)
        return 1 if bad else 0
    if a[:1] == ["ledger"] and len(a) == 2:
        led = Ledger(a[1])
        for row in led.db.execute("SELECT run_id, verdict, level_reached, independence, reasons_json FROM verdict"):
            print(*row, sep="  ")
        ok = led.verify_chain()
        print("hash chain intact:", ok)
        return 0 if ok else 1
    if a[:2] == ["demo", "local"]: local.demo(); return 0
    if a[:2] == ["demo", "stripe"]: stripe.main(); return 0
    if a[:2] == ["demo", "zendesk"]: zendesk.main(); return 0
    if a[:1] == ["selfcheck"]: local.check(); stripe.check(); zendesk.check(); hubspot.check(); intercom.check(); shopify.check(); return 0
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main())
