import unittest
import glob, json, os
from verify import contract, local, stripe, zendesk
from verify.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestVerify(unittest.TestCase):
    def test_local_all_verdicts_and_tamper(self): local.check()
    def test_stripe_adapter_offline(self): stripe.check()
    def test_zendesk_adapter_offline(self): zendesk.check()

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


if __name__ == "__main__":
    unittest.main()
