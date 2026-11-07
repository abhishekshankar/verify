import unittest
import glob, json, os
from verify import contract, hubspot, intercom, local, shopify, stripe, zendesk
from verify.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestVerify(unittest.TestCase):
    def test_local_all_verdicts_and_tamper(self): local.check()
    def test_stripe_adapter_offline(self): stripe.check()
    def test_zendesk_adapter_offline(self): zendesk.check()
    def test_hubspot_adapter_offline(self): hubspot.check()
    def test_intercom_adapter_offline(self): intercom.check()   # pass/fail/not_observed/blocked + write refused
    def test_shopify_adapter_offline(self): shopify.check()     # incl. THROTTLED, userErrors, write refused

    def test_init_intercom_shopify(self):
        import tempfile, io, contextlib
        d = tempfile.mkdtemp()
        with contextlib.redirect_stdout(io.StringIO()):
            for s, m in (("intercom", intercom), ("shopify", shopify)):
                self.assertEqual(main(["init", s, d]), 0)
                p = os.path.join(d, "contracts", m.CONTRACT["id"] + ".json")
                self.assertEqual(json.load(open(p)), m.CONTRACT)
                self.assertEqual(json.load(open(os.path.join(ROOT, "contracts", m.CONTRACT["id"] + ".json"))), m.CONTRACT)

    def test_shopify_throttle_retry_after(self):
        from verify.core import Blocked
        try: shopify.fake_shopify({"6": "429"})(shopify.QUERY, {"id": "gid://shopify/Order/6"}); self.fail()
        except Blocked as e: self.assertAlmostEqual(e.retry_after, 0.5)

    def test_shipped_contracts_valid(self):
        files = glob.glob(os.path.join(ROOT, "contracts", "*.json"))
        self.assertTrue(files)
        for f in files: self.assertEqual(contract.validate(json.load(open(f))), [], f)

    def test_invalid_contract_rejected(self):
        bad = dict(stripe.CONTRACT, required_level="L9", postconditions=[{"path": "nope", "op": "zz", "value": 1}])
        errs = contract.validate(bad)
        self.assertEqual(len(errs), 3, errs)
        self.assertIn("missing field: scope", contract.validate({k: v for k, v in stripe.CONTRACT.items() if k != "scope"}))

    def test_cli_usage_exit_code(self):
        self.assertEqual(main([]), 2)




class TestApi(unittest.TestCase):
  def test_python_api_and_blocked_backoff(self):
    import tempfile, pathlib; tmp_path = pathlib.Path(tempfile.mkdtemp())
    import verify
    from verify.core import Blocked
    c = {"id": "t", "version": "1", "owner": "o", "target_system": "x", "subject_ref": "r/{rid}",
         "subject_present": "r.amount", "preconditions": [], "forbidden": [],
         "postconditions": [{"path": "r.amount", "op": "eq", "value": "{amount}"}],
         "required_level": "L2", "settle_window_s": 0, "max_attempts": 3, "scope": ["r.amount"]}
    calls = []
    def flaky(sor, claim):
        calls.append(1)
        if len(calls) == 1: raise Blocked("429", retry_after=0)
        return {"r.amount": 5}, "{}"
    r = verify.check(c, {"rid": "1", "amount": 5}, flaky, ledger=str(tmp_path / "l.db"))
    assert r["ok"] and len(calls) == 2
    def down(sor, claim): raise Blocked("503", retry_after=0)
    assert verify.check(c, {"rid": "1", "amount": 5}, down, ledger=str(tmp_path / "l.db"))["verdict"] == "blocked"


class TestCliExtras(unittest.TestCase):
    def test_init_export_verify_tamper(self):
        import tempfile, io, contextlib
        d = tempfile.mkdtemp()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["init", "stripe", d]), 0)
            self.assertEqual(main(["validate", os.path.join(d, "contracts", "refund.full.stripe.json")]), 0)
            self.assertEqual(main(["--version"]), 0)
        from verify.core import Ledger, verify as run
        led = Ledger(os.path.join(d, "l.db"))
        c = dict(hubspot.CONTRACT, settle_window_s=0)
        r = hubspot.make_reader(hubspot.fake_hubspot({"1": ("closedwon", "1", ["2"])}))
        for _ in range(2): run(led, None, {"deal": "1", "amount": 1.0, "company": "2"}, c, r)
        exp = os.path.join(d, "e.jsonl")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["ledger", "export", os.path.join(d, "l.db"), exp]), 0)
            self.assertEqual(main(["ledger", "verify", exp]), 0)
        lines = open(exp).read().splitlines()
        lines[1] = lines[1].replace("readback", "readbacK", 1)          # flip one byte
        open(exp, "w").write("\n".join(lines) + "\n")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["ledger", "verify", exp]), 1)
        open(exp, "w").write("\n".join(lines[:-2] + lines[-1:]) + "\n")  # drop last event: head mismatch
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["ledger", "verify", exp]), 1)


class TestClaimValidation(unittest.TestCase):
    def test_missing_claim_field_rejected_before_ledger(self):
        import tempfile, io, contextlib, sqlite3
        from verify.core import BadClaim, Ledger, claim_fields, verify as run
        self.assertEqual(claim_fields(hubspot.CONTRACT), {"deal", "amount", "company"})
        d = tempfile.mkdtemp(); db = os.path.join(d, "l.db")
        with self.assertRaises(BadClaim):
            run(Ledger(db), None, {"deal": "1"}, hubspot.CONTRACT, lambda *_: self.fail("reader must not run"))
        self.assertEqual(sqlite3.connect(db).execute("SELECT count(*) FROM event").fetchone()[0], 0)
        c, cl = os.path.join(d, "c.json"), os.path.join(d, "claim.json")
        json.dump(hubspot.CONTRACT, open(c, "w")); json.dump({"deal": "1"}, open(cl, "w"))
        os.environ["HUBSPOT_VERIFY_TOKEN"] = "unused"
        try:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(main(["check", c, cl, "--ledger", db]), 2)
        finally: del os.environ["HUBSPOT_VERIFY_TOKEN"]
        self.assertIn("amount, company", err.getvalue())


if __name__ == "__main__":
    unittest.main()
