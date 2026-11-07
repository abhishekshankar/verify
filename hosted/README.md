# Verify hosted ledger v0

Multi-tenant, append-only, hash-chained evidence ledger (docs 03 and 07 in `04-preproduction/`).
Stdlib-only server; Postgres driver loads only if `psycopg` is installed. **Nothing here is deployed.**

| File | What |
|---|---|
| `store.py` | Storage: `Store` (SQLite, default) and `PostgresStore`. Chain check, retention purge. |
| `server.py` | HTTP API + admin CLI (`add-tenant`, `purge`, `serve`). |
| `client.py` | Push a local `verify` ledger, resuming from the server head. |
| `schema.postgres.sql` | Postgres schema, append-only triggers, role grants. |
| `test_hosted.py` | `PYTHONPATH=src:. python3 -m unittest hosted.test_hosted -v` (from `verify/`). |

## API (all require `Authorization: Bearer <tenant key>`; keys stored only as sha256)
- `POST /v1/events` `{"events":[...], "runs":[...], "verdicts":[...]}`: atomic batch. Server recomputes
  `sha256(prev_hash + canonical_json(row))`; `prev_hash` not equal to head returns **409** (with current head); a sent `hash` that
  does not match the recomputed one returns **400**. Same rule as `verify.core.Ledger`, so pushed local chains keep their hashes.
- `GET /v1/runs/{run_id}`: run, its events and verdict.
- `GET /v1/verdicts?since=<ISO-8601>`
- `GET /v1/export`: JSONL of events, last line `{"chain_head":...}`. Header `X-Signature: hmac-sha256=<hex>` over the exact body,
  keyed by `VERIFY_EXPORT_KEY`.
- `GET /v1/verify-chain`: `{"ok", "head", "events", "tombstoned"}`.

## Retention
`python -m hosted.server purge <tenant> <days>` (default policy 400 days; contract range 30 to 2555) writes a tombstone and
deletes the payload. Event rows and hashes stay. For tombstoned events, chain verification checks linkage (`prev_hash`)
and keeps the stored hash plus `payload_sha256`; full recompute applies to events whose payload still exists. Run purge
as the `verify_retention` DB role. The app role cannot delete anything.

## Env
- `VERIFY_EXPORT_KEY`: HMAC key (required). Store in AWS Secrets Manager.
- `VERIFY_DATABASE_URL`: `postgres://...` for RDS, otherwise a SQLite path (default `hosted.db`).

## Deploying to AWS us-east-2 (instructions only)
Option A, ECS Fargate (recommended):
1. RDS Postgres 16 in us-east-2, private subnets, encryption at rest (KMS), automated backups, Multi-AZ when paid tiers start.
2. As the master user: create roles `verify_app` and `verify_retention`, then `psql -f hosted/schema.postgres.sql`.
3. Secrets Manager: `VERIFY_EXPORT_KEY` (32+ random bytes) and `VERIFY_DATABASE_URL` for `verify_app`.
4. `docker build -f hosted/Dockerfile -t verify-hosted .` from `verify/`, then push to ECR in us-east-2.
5. ECS service on Fargate (0.25 vCPU / 0.5 GB is enough for v0), secrets injected from Secrets Manager, behind an ALB
   with an ACM certificate (TLS only; the app speaks plain HTTP inside the VPC). Security group: ALB to task 8080, task to RDS 5432.
6. Retention: EventBridge scheduled ECS task, daily, `python -m hosted.server purge <tenant> <days>` per tenant, with
   `VERIFY_DATABASE_URL` for `verify_retention`.
7. Tenants: one-off ECS task `python -m hosted.server add-tenant <id>`; the key prints once. Send it to the customer out of band.

Option B, single EC2 + RDS: same RDS steps; run the container on a t4g.small with an IAM instance role reading the
secrets, Caddy or nginx in front for TLS, systemd to restart it. Cheaper, but one box with no rolling deploys.

## Known v0 limits
- The SQLite backend allows one writer per process (global lock). Postgres uses `SELECT ... FOR UPDATE` on the tenant row with a single connection; add `psycopg_pool` when you need real load.
- No access_log table yet (doc 03 lists it); add it before the first customer.
- No key rotation endpoint. The `tenant` table is insert-only, so rotation needs a migration-role operation.
- The Postgres backend is untested here (no database was available). The SQL mirrors the tested SQLite schema.
