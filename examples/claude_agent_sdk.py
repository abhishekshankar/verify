"""Claude Agent SDK: verify.check runs right after the refund tool returns, inside the tool,
so the model only ever sees a verified result. Offline: the tool is called directly with a fake Stripe.

    pip install claude-agent-sdk   # optional; without it this runs the same flow with a stub
    python3 examples/claude_agent_sdk.py
"""
import json
import _offline
import verify


def issue_refund(args):
    claim = _offline.refund_tool(args.get("fault"))                     # 1. the tool call (agent's write)
    v = verify.check(_offline.CONTRACT, claim, _offline.READER, ledger=_offline.LEDGER)   # 2. readback
    text = json.dumps({"claim": claim, "verdict": v["verdict"], "reasons": v["reasons"]})
    return {"content": [{"type": "text", "text": text}], "is_error": not v["ok"]}   # 3. model sees the verdict


# this file is named claude_agent_sdk.py; drop its dir from sys.path so the import finds the real SDK
import os, sys
sys.path[:] = [x for x in sys.path if os.path.abspath(x or ".") != os.path.dirname(os.path.abspath(__file__))]
try:
    from claude_agent_sdk import tool, create_sdk_mcp_server

    async def _handler(args): return issue_refund(args)
    server = create_sdk_mcp_server("refunds", tools=[tool("issue_refund", "Refund a charge", {"fault": str})(_handler)])
    # ClaudeAgentOptions(mcp_servers={"refunds": server}, allowed_tools=["mcp__refunds__issue_refund"])
    print("claude_agent_sdk installed: tool registered; calling it directly (no API key needed)")
except ImportError:
    print("note: claude_agent_sdk not installed; running the same tool flow with a stub")

if __name__ == "__main__":
    ok = issue_refund({})
    bad = issue_refund({"fault": "half"})
    print("honest refund ->", json.loads(ok["content"][0]["text"])["verdict"])
    print("half refund   ->", json.loads(bad["content"][0]["text"])["verdict"])
    assert not ok["is_error"] and bad["is_error"]
