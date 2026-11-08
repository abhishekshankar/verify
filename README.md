# Verify

Your agent says "done". Verify checks the system of record.

AI agents and automations report success from their own logs. Verify ignores the claim, reads the
system of record back with a **separate read-only credential**, and returns one of five verdicts.
Anything it can't confirm fails closed.

![Verify demo: agent claims 3/3 refunds, Stripe confirms 1/3](docs/verify-demo.gif)

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
pip install verify-outcomes          # or: pip install git+https://github.com/abhishekshankar/verify
verify --version
verify init stripe                   # writes contracts/ and an example claim
verify selfcheck        # all verdicts, tamper detection, every adapter offline
verify demo local       # SQLite stands in for Stripe + Zendesk
verify ledger demo_out/ledger.db
verify validate contracts/*.json   # reject bad contracts before any action runs
verify ledger export demo_out/ledger.db audit.jsonl && verify ledger verify audit.jsonl
```

Live adapters (test accounts only; keys come from env vars, never from code):
```bash
STRIPE_AGENT_KEY=sk_test_... STRIPE_VERIFY_KEY=rk_test_... verify demo stripe
ZENDESK_SUBDOMAIN=... ZENDESK_AGENT_OAUTH=... ZENDESK_VERIFY_TOKEN=... verify demo zendesk
```
`STRIPE_VERIFY_KEY` should be a restricted key with Charges and Refunds set to Read.
`ZENDESK_VERIFY_TOKEN` should be an OAuth token with scope `read`. `HUBSPOT_VERIFY_TOKEN` should be a private-app token with only `crm.objects.deals.read`. `INTERCOM_VERIFY_TOKEN` should be an Intercom app access token with only the Read conversations permission. `SHOPIFY_SHOP` (the `*.myshopify.com` subdomain) and `SHOPIFY_VERIFY_TOKEN` should come from a custom app with only `read_orders`. Live Stripe keys are refused.

## Check one real action
Write a contract once, then check each claim the agent makes. The exit code is 0 only on `pass`, so it can gate a pipeline. A claim missing a field the contract needs is rejected (exit 2) before anything is read.
```bash
STRIPE_VERIFY_KEY=rk_test_... verify check contracts/refund.full.stripe.json claim.json --ledger verify.db
```
`claim.json` holds what the agent says it did, e.g. `{"actor": "support-agent", "charge_id": "ch_...", "refund_id": "re_...", "amount": 5000}` (see `examples/`).

Many claims at once (one JSON object per line; exit 0 only if every claim passes):
```bash
verify check-batch contracts/refund.full.stripe.json claims.jsonl --ledger verify.db
```

## Hosted ledger (optional)
`hosted/` is an append-only, multi-tenant ledger API (SQLite or Postgres). Push a local ledger to it with
`VERIFY_HOSTED_KEY=... verify push verify.db --to https://ledger.example.com`. Deployment to AWS us-east-2 is in `hosted/deploy/` (Terraform; not applied).

## Use from an agent
`python -m verify.mcp_server` is an MCP server with `verify_check` and `verify_validate` (see `docs/MCP.md`). Framework examples are in `examples/`.

## How it works
1. **Contract**, written before the action: subject, preconditions, postconditions, forbidden effects, windows, scope.
2. **Claim**: the actor's "done" is recorded, never used as evidence.
3. **Readback**: an adapter reads only the fields in scope, with its own credential.
4. **Verdict**: evaluated, then written to an append-only SQLite ledger (`synchronous=FULL`) where each event hashes the one before it.

## Layout
Python API: `verify.check(contract, claim, reader)`; see `docs/ADAPTERS.md`. Contracts: `docs/CONTRACTS.md`.

`src/verify/core.py` holds evaluation, the ledger and the verify loop; `contract.py` loads and validates contracts (`contracts/*.json`). The adapters are `stripe.py`, `zendesk.py`, `hubspot.py` (deals), `intercom.py` (conversations), `shopify.py` (refunds, Admin GraphQL) (the last three offline-tested, live run pending) and `local.py`.

## Status
v0.4.2 on [PyPI](https://pypi.org/project/verify-outcomes/), pre-production. Not yet a stable API. MIT licence.
