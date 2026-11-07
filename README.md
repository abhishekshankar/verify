# Verify

Your agent says "done". Verify checks the system of record.

AI agents and automations report success from their own logs. Verify ignores the claim, reads the
system of record back with a **separate read-only credential**, and returns one of five verdicts.
Anything it can't confirm fails closed.

```
Agent says:      3/3 "Refund issued ✅"
Verify (Stripe test mode, independence=full):
  PASS          L2
  FAIL          L2   refund.amount 2500 ≠ 5000
  NOT_OBSERVED  L1   refund never reached Stripe
Verified success rate: 1/3   hash chain intact: True
```
Real output, Stripe test mode, 2026-11-07. The same run on Zendesk: 1/3.

## Verdicts
| Verdict | Meaning |
|---|---|
| `pass` | every postcondition observed in the system of record |
| `fail` | a postcondition observed false, or a forbidden side effect observed |
| `inapplicable` | preconditions not met; the action should never have run |
| `not_observed` | the subject record is absent after the observe window |
| `blocked` | readback impossible (auth, outage, rate limit) |

Only `pass` counts as success.

## Quick start
Python 3.10+, no dependencies.
```bash
pip install -e .
verify selfcheck        # all verdicts, duplicate refund, tamper detection, both adapters offline
verify demo local       # SQLite stands in for Stripe + Zendesk
verify ledger demo_out/ledger.db
```

Live adapters (test accounts only; keys come from env vars, never from code):
```bash
STRIPE_AGENT_KEY=sk_test_... STRIPE_VERIFY_KEY=rk_test_... verify demo stripe
ZENDESK_SUBDOMAIN=... ZENDESK_AGENT_OAUTH=... ZENDESK_VERIFY_TOKEN=... verify demo zendesk
```
`STRIPE_VERIFY_KEY` should be a restricted key with Charges and Refunds set to Read.
`ZENDESK_VERIFY_TOKEN` should be an OAuth token with scope `read`. Live Stripe keys are refused.

## How it works
1. **Contract**, written before the action: subject, preconditions, postconditions, forbidden effects, windows, scope.
2. **Claim**: the actor's "done" is recorded, never used as evidence.
3. **Readback**: an adapter reads only the fields in scope, with its own credential.
4. **Verdict**: evaluated, then written to an append-only SQLite ledger (`synchronous=FULL`) where each event hashes the one before it.

## Layout
`src/verify/core.py` holds contracts, evaluation, the ledger and the verify loop. The adapters are `stripe.py`, `zendesk.py` and `local.py`.

## Status
v0.1, a pre-production demo. Not yet a stable API. MIT licence.
