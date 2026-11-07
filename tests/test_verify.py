import unittest
from verify import local, stripe, zendesk


class TestVerify(unittest.TestCase):
    def test_local_all_verdicts_and_tamper(self): local.check()
    def test_stripe_adapter_offline(self): stripe.check()
    def test_zendesk_adapter_offline(self): zendesk.check()


if __name__ == "__main__":
    unittest.main()
