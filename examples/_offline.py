"""Shared offline fixture for the examples: a fake Stripe, an agent tool that writes to it, and a read-only reader."""
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from verify import stripe

CONTRACT = dict(stripe.CONTRACT, settle_window_s=0)      # no settle wait offline
LEDGER = os.path.join(tempfile.mkdtemp(), "verify.db")
_http = stripe.fake_stripe()
READER = stripe.make_reader(_http, "rk_test_verify")      # Verify's own read-only key


def refund_tool(fault=None, amount=5000):
    """The agent's tool: creates a charge and refunds it. fault='half' refunds half, 'timeout' never sends it."""
    return stripe.agent_handle(_http, "sk_test_agent", fault, amount)
