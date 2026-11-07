"""LangGraph: a `verify` node sits on the edge right after the tool node; routing branches on the verdict.

    pip install langgraph   # optional; without it this runs the same two nodes in order with a stub
    python3 examples/langgraph_node.py
"""
from typing import TypedDict
import _offline
import verify


class State(TypedDict, total=False):
    fault: str
    claim: dict
    verdict: str


def refund_node(s): return {"claim": _offline.refund_tool(s.get("fault") or None)}      # tool call
def verify_node(s): return {"verdict": verify.check(_offline.CONTRACT, s["claim"], _offline.READER, ledger=_offline.LEDGER)["verdict"]}


try:
    from langgraph.graph import StateGraph, START, END
    g = StateGraph(State)
    g.add_node("refund", refund_node); g.add_node("verify", verify_node)
    g.add_edge(START, "refund"); g.add_edge("refund", "verify"); g.add_edge("verify", END)
    # real graphs: g.add_conditional_edges("verify", lambda s: "reply" if s["verdict"] == "pass" else "escalate")
    run = g.compile().invoke
    print("langgraph installed: running compiled graph")
except ImportError:
    print("note: langgraph not installed; running the same nodes in order with a stub")
    def run(s):
        for node in (refund_node, verify_node): s = {**s, **node(s)}
        return s

if __name__ == "__main__":
    good, half = run({}), run({"fault": "half"})
    print("honest refund ->", good["verdict"]); print("half refund   ->", half["verdict"])
    assert good["verdict"] == "pass" and half["verdict"] == "fail"
