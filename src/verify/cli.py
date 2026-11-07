"""usage:
  verify check <contract.json> <claim.json> [--ledger verify.db]   exit 0 only on pass
  verify validate <contract.json>...
  verify ledger <db>
  verify demo {local,stripe,zendesk}
  verify selfcheck
"""
import json, os, sys
from . import contract, hubspot, local, stripe, zendesk
from .core import Ledger, verify


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
    sys.exit(f"no adapter for target_system {t!r} (have: stripe, zendesk, hubspot)")


def check(contract_path, claim_path, ledger_path="verify.db"):
    c = contract.load(contract_path)
    with open(claim_path) as f: claim = json.load(f)
    run_id, v, level, reasons = verify(Ledger(ledger_path), None, claim, c, reader_for(c), actor=claim.get("actor", "unknown"))
    print(json.dumps({"run_id": run_id, "verdict": v, "level": level, "reasons": reasons, "ledger": ledger_path}, indent=1))
    return 0 if v == "pass" else 1


def main(argv=None):
    a = sys.argv[1:] if argv is None else argv
    if a[:1] == ["check"] and len(a) in (3, 5) and (len(a) == 3 or a[3] == "--ledger"):
        return check(a[1], a[2], *a[4:5])
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
    if a[:1] == ["selfcheck"]: local.check(); stripe.check(); zendesk.check(); hubspot.check(); return 0
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main())
