import unittest
import glob, json, os
from verify import contract, hubspot, local, stripe, zendesk
from verify.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestVerify(unittest.TestCase):
    def test_local_all_verdicts_and_tamper(self): local.check()
    def test_stripe_adapter_offline(self): stripe.check()
    def test_zendesk_adapter_offline(self): zendesk.check()
    def test_hubspot_adapter_offline(self): hubspot.check()

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


if __name__ == "__main__":
    unittest.main()
