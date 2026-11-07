# Python API and writing an adapter

```python
import verify

def read_order(sor, claim):
    """Read the system of record with a READ-ONLY credential. Return (fields, raw_json)."""
    r = my_readonly_client.get(f"/orders/{claim['order_id']}")      # your HTTP call
    if r.status_code in (401, 403, 429, 500, 502, 503):
        raise verify.Blocked(f"HTTP {r.status_code}", retry_after=r.headers.get("Retry-After") and float(r.headers["Retry-After"]))
    if r.status_code == 404:
        return {}, r.text                                              # subject absent -> not_observed
    o = r.json()
    return {"order.status": o["status"], "order.total": o["total"]}, r.text

result = verify.check("contracts/order.json", {"order_id": "o_1", "total": 4200}, read_order, ledger="verify.db")
if not result["ok"]:
    escalate(result)        # verdict is fail / inapplicable / not_observed / blocked
```

Rules for a reader:
- Use a credential the acting agent does not hold; otherwise record `independence="degraded"`.
- Return only fields listed in the contract's `scope`.
- Raise `Blocked` for anything that stops a readback. Never guess a value; a missing field fails closed.
- `retry_after` (seconds) is honoured; otherwise backoff doubles per attempt, capped at 60 s, up to `max_attempts`.

`stripe.py` and `zendesk.py` are about 40-line reference readers.
