"""OpenAI Agents SDK: verify.check runs right after the refund call, inside the function tool,
so the agent can't report "done" on an unverified write. Offline with a fake Stripe.

    pip install openai-agents   # optional; without it this runs the same flow with a stub
    python3 examples/openai_agents_sdk.py
"""
import json
import _offline
import verify


def issue_refund(fault: str = "") -> str:
    """Refund a charge and return the verified outcome."""
    claim = _offline.refund_tool(fault or None)                         # 1. the tool call
    v = verify.check(_offline.CONTRACT, claim, _offline.READER, ledger=_offline.LEDGER)   # 2. readback
    return json.dumps({"verified": v["ok"], "verdict": v["verdict"], "reasons": v["reasons"]})   # 3. agent sees it


try:
    from agents import Agent, function_tool
    agent = Agent(name="support", instructions="Only tell the customer a refund is done if verified is true.",
                  tools=[function_tool(issue_refund)])
    # Runner.run_sync(agent, "refund ch_123")  # needs OPENAI_API_KEY
    print("openai-agents installed: tool registered; calling it directly (no API key needed)")
except ImportError:
    print("note: openai-agents not installed; running the same tool flow with a stub")

if __name__ == "__main__":
    good, half = json.loads(issue_refund()), json.loads(issue_refund("half"))
    print("honest refund ->", good["verdict"]); print("half refund   ->", half["verdict"])
    assert good["verified"] and not half["verified"]
