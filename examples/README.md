# Examples

All run offline against the fake Stripe in `verify.stripe.fake_stripe` (shared setup in `_offline.py`). No keys needed.
Framework imports are optional: if the framework isn't installed, the script prints a note and runs the same flow with a stub.

| Script | Where `verify.check` sits | Exit |
|---|---|---|
| `plain_cron.py --demo` | loop over claims in a JSONL file | **1** (one half refund fails) |
| `plain_cron.py --demo-good` | same, all honest | 0 |
| `plain_cron.py claims.jsonl contract.json` | real run; reader from env, same as `verify check` | 0 only if all pass |
| `claude_agent_sdk.py` | inside the SDK MCP tool, right after the write | 0 |
| `openai_agents_sdk.py` | inside the `function_tool`, right after the write | 0 |
| `langgraph_node.py` | its own node on the edge after the tool node | 0 |

The pattern is the same everywhere: the agent's tool writes, then Verify reads the system of record back with its
own read-only credential, and only `verdict == "pass"` is reported as done.

```
python3 examples/plain_cron.py --demo; echo $?    # 1
```
