# Changelog
## 0.4.2 (2026-11-08)
- HubSpot: dedupe company associations. The v3 API lists one company twice (labelled and unlabelled), which made true claims fail. Found in the first live run on 2026-11-08; live pass, fail, not_observed and write-refused (403) now confirmed

## 0.4.1 (2026-11-07)
- CI runs the LangGraph example through a real compiled graph (`REQUIRE_LANGGRAPH=1`)

## 0.4.0 (2026-11-07)
- Claims missing a field the contract needs are rejected before any readback (`check` exits 2)
- `verify check-batch` for JSONL claim files
- `verify push`: upload a local ledger to the hosted API (`VERIFY_HOSTED_KEY`)
- Hosted: pooled Postgres connections (`VERIFY_DB_POOL`); fixed concurrent SQLite access; DSN from `VERIFY_DB_*`
- Hosted: Terraform for AWS us-east-2 (`hosted/deploy/`, validate only); Docker smoke test in CI

## 0.3.0 (2026-11-07)
- Hosted ledger: access log, key rotation, UTF8 guard; tested on Postgres in CI
- Static landing site (site/) with a manual GitHub Pages workflow
- Intercom conversation adapter and contract `conversation.closed_with_reply.intercom` (`INTERCOM_VERIFY_TOKEN`, pinned `Intercom-Version`)
- Shopify refund adapter (Admin GraphQL, pinned API version) and contract `refund.issued.shopify` (`SHOPIFY_SHOP`, `SHOPIFY_VERIFY_TOKEN`, `read_orders` only)
- `verify init intercom|shopify`; both adapters in `verify selfcheck`

## 0.2.0 (2026-11-07)
- Python API `verify.check()`
- `Blocked(retry_after=)` with capped exponential backoff
- HubSpot deal adapter and contract
- `verify init`, `verify --version`
- `verify ledger export` / `verify ledger verify` (offline tamper check)
- Docs: adapters, contracts

## 0.1.0 (2026-11-07)
- Five verdicts, hash-chained SQLite ledger, Stripe and Zendesk adapters, `check` / `validate` CLI
