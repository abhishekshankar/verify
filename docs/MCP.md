# Verify as an MCP server

`python -m verify.mcp_server` is a stdio MCP server (JSON-RPC 2.0, newline-delimited, protocol `2025-06-18`, stdlib only).

Tools:
- `verify_check` — `{contract_path, claim, ledger?}` → `{run_id, verdict, level, reasons, ok}`. Reads back with the adapter
  for the contract's `target_system`, using the same env vars as `verify check`
  (`STRIPE_VERIFY_KEY`; `ZENDESK_SUBDOMAIN` + `ZENDESK_VERIFY_TOKEN`; `HUBSPOT_VERIFY_TOKEN`). A missing key is returned as a
  tool error. `ledger` defaults to `verify.db` in the server's working directory.
- `verify_validate` — `{contract_path}` → `{valid, errors}`.

Use absolute paths for contracts and the ledger. Give the server read-only keys only; the agent must not hold them.

Offline self-test: `PYTHONPATH=src python3 -m verify.mcp_server --selftest`

## Claude Code

```
claude mcp add verify --env PYTHONPATH=/abs/path/verify/src --env STRIPE_VERIFY_KEY=rk_test_... \
  -- python3 -m verify.mcp_server
```

Or commit a project-scoped `.mcp.json` (keep secrets out of it; `${VAR}` is expanded from your shell env):

```json
{
  "mcpServers": {
    "verify": {
      "command": "python3",
      "args": ["-m", "verify.mcp_server"],
      "env": {"PYTHONPATH": "/abs/path/verify/src", "STRIPE_VERIFY_KEY": "${STRIPE_VERIFY_KEY}"}
    }
  }
}
```

If the package is pip-installed, drop `PYTHONPATH`. Check with `/mcp` inside Claude Code.

## Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json`
(Windows), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "verify": {
      "command": "/usr/bin/python3",
      "args": ["-m", "verify.mcp_server"],
      "env": {"PYTHONPATH": "/abs/path/verify/src", "STRIPE_VERIFY_KEY": "rk_test_..."}
    }
  }
}
```

Desktop does not inherit your shell, so use an absolute interpreter path and put the env vars here.
