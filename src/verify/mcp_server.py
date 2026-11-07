"""Minimal stdio MCP server for Verify. Stdlib only, newline-delimited JSON-RPC 2.0.

    python -m verify.mcp_server        # serve on stdin/stdout
    python -m verify.mcp_server --selftest

Tools: verify_check, verify_validate. Credentials come from the same env vars as `verify check`.
"""
import json, sys
from . import __version__, contract
from .core import check

PROTOCOL = "2025-06-18"
TOOLS = [
    {"name": "verify_check",
     "description": "Read the system of record back and return a verdict (pass/fail/inapplicable/not_observed/blocked) "
                    "for an agent's claimed action. Only verdict == 'pass' means the action really happened.",
     "inputSchema": {"type": "object", "required": ["contract_path", "claim"], "properties": {
         "contract_path": {"type": "string", "description": "Path to an outcome contract JSON file"},
         "claim": {"type": "object", "description": "The agent's claim, e.g. {charge_id, refund_id, amount}"},
         "ledger": {"type": "string", "description": "SQLite ledger path (default verify.db)"}}}},
    {"name": "verify_validate",
     "description": "Validate an outcome contract JSON file. Returns a list of problems (empty = valid).",
     "inputSchema": {"type": "object", "required": ["contract_path"],
                     "properties": {"contract_path": {"type": "string"}}}},
]


def call_tool(name, args, reader_for=None):
    """Returns (result_dict, is_error)."""
    if name == "verify_validate":
        with open(args["contract_path"]) as f: errs = contract.validate(json.load(f))
        return {"valid": not errs, "errors": errs}, False
    if name == "verify_check":
        c = contract.load(args["contract_path"])
        if reader_for is None:
            from .cli import reader_for
        try:
            reader = reader_for(c)
        except SystemExit as e:              # cli.reader_for exits on missing env; report, don't die
            return {"error": str(e.code)}, True
        return check(c, args["claim"], reader, ledger=args.get("ledger") or "verify.db"), False
    raise KeyError(name)


def handle(msg, reader_for=None):
    """One JSON-RPC message in -> response dict, or None for notifications."""
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if mid is None: return None
    def ok(result): return {"jsonrpc": "2.0", "id": mid, "result": result}
    if method == "initialize":
        return ok({"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                   "serverInfo": {"name": "verify", "version": __version__}})
    if method == "ping": return ok({})
    if method == "tools/list": return ok({"tools": TOOLS})
    if method == "tools/call":
        try:
            res, err = call_tool(params.get("name"), params.get("arguments") or {}, reader_for)
        except KeyError as e:
            if e.args == (params.get("name"),):
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool {e.args[0]!r}"}}
            res, err = {"error": f"missing argument {e}"}, True
        except Exception as e:               # tool failures are results, not protocol errors
            res, err = {"error": f"{type(e).__name__}: {e}"}, True
        return ok({"content": [{"type": "text", "text": json.dumps(res)}], "structuredContent": res, "isError": err})
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}


def serve(inp=sys.stdin, out=sys.stdout, reader_for=None):
    for line in inp:
        if not line.strip(): continue
        try:
            resp = handle(json.loads(line), reader_for)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if resp is not None:
            out.write(json.dumps(resp) + "\n"); out.flush()


def _selftest():
    import io, os, tempfile
    from . import stripe
    d = tempfile.mkdtemp()
    cpath = os.path.join(d, "c.json")
    with open(cpath, "w") as f: json.dump(dict(stripe.CONTRACT, settle_window_s=0), f)
    http = stripe.fake_stripe()
    good = stripe.agent_handle(http, "sk_test_a")
    half = stripe.agent_handle(http, "sk_test_a", "half")
    fake_reader_for = lambda c: stripe.make_reader(http, "rk_test_v")
    led = os.path.join(d, "l.db")
    reqs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTOCOL}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "verify_validate", "arguments": {"contract_path": cpath}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "verify_check", "arguments": {"contract_path": cpath, "claim": good, "ledger": led}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "verify_check", "arguments": {"contract_path": cpath, "claim": half, "ledger": led}}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "nope", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 7, "method": "bogus"}]
    out = io.StringIO()
    serve(io.StringIO("\n".join(map(json.dumps, reqs)) + "\nnot json\n"), out, fake_reader_for)
    r = [json.loads(l) for l in out.getvalue().splitlines()]
    assert [x["id"] for x in r] == [1, 2, 3, 4, 5, 6, 7, None], r
    assert r[0]["result"]["protocolVersion"] == PROTOCOL
    assert {t["name"] for t in r[1]["result"]["tools"]} == {"verify_check", "verify_validate"}
    assert r[2]["result"]["structuredContent"]["valid"] is True
    assert r[3]["result"]["structuredContent"]["verdict"] == "pass"
    v = r[4]["result"]["structuredContent"]
    assert v["verdict"] == "fail" and not v["ok"] and r[4]["result"]["isError"] is False
    assert r[5]["error"]["code"] == -32602 and r[6]["error"]["code"] == -32601 and r[7]["error"]["code"] == -32700
    # missing env -> tool error, not a crash
    def no_env(c): sys.exit("Set STRIPE_VERIFY_KEY")
    res = handle(reqs[4], no_env)["result"]
    assert res["isError"] and "STRIPE_VERIFY_KEY" in res["structuredContent"]["error"]
    print("mcp server selftest: ok")


if __name__ == "__main__":
    _selftest() if sys.argv[1:] == ["--selftest"] else serve()
