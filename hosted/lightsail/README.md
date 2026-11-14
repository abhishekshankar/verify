# Verify minimum infrastructure migration

This directory contains the EC2 migration workflow for the hosted ledger at
`ledger.optimise.work`. The original Lightsail Terraform candidate remains
disabled by default; the execution path uses an ARM64 EC2 host in the existing
Verify VPC so that the source database stays private during rehearsal and cutover.

The source remains authoritative until a successful `TARGET_AUTHORITATIVE`
record exists. Installing a host, restoring a rehearsal copy, or obtaining a
certificate does not authorize it to accept production writes. The migration
bridge enforces one destination for both old ALB traffic and new direct HTTPS
traffic while DNS changes propagate.

## Target components

- Ubuntu 24.04 ARM64; PostgreSQL 16 and the existing hosted Python application.
- Application listens on loopback 8080. PostgreSQL listens only on loopback and
  its local socket; runtime connections require verified TLS and SCRAM passwords.
- Caddy terminates HTTPS and renews its certificate through HTTP-01.
- A temporary bridge on 8082 forwards to the observed ECS task private address
  in SOURCE mode, queues all application calls in DRAIN, then forwards to the
  local app in TARGET. Restrict 8082 to the ALB security group.
- Encrypted pgBackRest full backups and WAL archives use the existing Verify
  S3 bucket in **us-west-2**, under `live/verify-ledger/pgbackrest`. Region is
  checked with `GetBucketLocation`; this bucket is separate from the retired
  projects' archive bucket. Instance-profile credentials replace static AWS keys.
- Four Standard SecureString parameters independently preserve the runtime DB
  password, maintenance DB password, backup cipher key and exact export HMAC key.

The Linux services are `verify`, `verify-migration`, `caddy`, and
`verify-backup.timer`. Verify's writer marker is required in addition to service
configuration. The coordinator durably creates the marker and enables the app;
pre-activation recovery disables the app and durably removes the marker.

## Prepare and validate the private target

Run `install_ec2_target.sh` only on the independently verified new target. Its
arguments bind the operation to an instance, AWS account, checked application
archive and existing source private IP. It installs/configures components but
leaves the application, bridge and Caddy inactive. The installer refuses to
overwrite an initialized installation. Do not run it on an existing deployment.

`setup_target.py` checks the recorded target identity, source dump checksum and
actual backup bucket region. It preserves existing target credentials on retries,
copies the source export key without whitespace changes, verifies encrypted SSM
readback, restores an empty target with exact schema/ACLs, and tests runtime SQL
privileges. The extra `UPDATE(api_key_sha256)` grant is necessary for PostgreSQL's
`SELECT ... FOR UPDATE` tenant lock and the existing key-rotation CLI; no UPDATE
grant is added to immutable tenant IDs or ledger records.

The setup command also runs the existing hosted HTTP suite against an isolated
throwaway PostgreSQL database. The additional `runtime_role_checks.py` adapter must pass
using the real `verify_runtime` TLS login and pooled connections, with retention
performed by `verify_maintenance`. Administrator-only tests do not substitute for
that check.

Run `test_pitr_restore.py` before routing traffic. It creates an encrypted S3 full
backup, independently recovers the cipher key from SSM, archives WAL, and restores
to a separate directory on loopback/Unix port 5433. Recovery targets a timestamp
between two synthetic commits: the earlier probe must exist and the later probe
must not. All application table fingerprints and chains must also match. The
helper stops and removes the separate restore instance, saves proof to S3, and
enables the daily backup timer only on success. It never creates the production
writer marker or changes the source RDS database.

Run `prove_database_deadline.py` as the local postgres OS user with the deployed
application virtual environment. It proves that the actual psycopg/libpq build
interrupts a slow local query within the configured wall deadline, then terminates
and verifies the absence of the exact test backend. Cutover remains blocked without
this evidence.

Run `prove_coordinator_fixture.py` with the deployed application interpreter before
the live source rehearsal. It creates two disposable PostgreSQL 16 clusters on
loopback ports 5433/5434 and runs the actual coordinator through successful handover,
an actual restore failure, a lost admission-fence response, lost/delayed TARGET
responses, and an interrupted PostgreSQL query. Authenticated POST and GET calls
must queue and reach the authoritative fixture exactly once; ledger heads, access
logs, database admission, writer markers and backend termination are checked.
Production port 5432, RDS, AWS and real systemd units are outside this fixture. Systemd
lifecycle, S3 upload and WAL archive boundaries use fixture adapters because the
real encrypted backup and recovery path has a separate live proof. The harness
stops/removes its clusters and leaves a private report, including any cleanup error.

## Prepare HTTPS and the bridge

Preissue the real certificate while the original ALB still serves production.
A temporary HTTP listener can forward the ACME challenge path to Caddy port 80;
Caddy's configuration disables the TLS-ALPN challenge during this stage. Verify
the certificate hostname/chain, the actual HTTP-01 path and automatic renewal
configuration before changing DNS. Keep public 5432/5433 closed.

Start and enable the bridge in SOURCE mode. Its source must be the fresh observed
ECS task private IP, not the ALB hostname: using the ALB would create a forwarding
loop after the target group changes. Temporarily permit the new instance security
group to reach the old task on 8080. The independent `/__migration_health` route
touches neither application database.

`prepare_bridge.py source` validates the successful setup, restricted-role HTTP
and PITR reports, copies the verified RDS CA, privately fetches the source owner
credential, and creates exact libpq entries for both `verify` and `postgres`.
It reruns the installed driver's deadline proof, verifies the unauthenticated
source API response, then enables only the SOURCE bridge. It writes the private
coordinator configuration with routing-drain, external-writer and TLS gates still
false. Source databases and public routing are unchanged by this helper.

`prepare_bridge.py https` requires a fresh private observation of the existing
ALB's HTTP-01 forwarding rule. Its target group may forward to port 80 while health
checks use bridge port 8082 and `/__migration_health`, allowing readiness before
Caddy starts. The helper enables Caddy, verifies a trusted certificate for the
real hostname through loopback SNI, confirms SOURCE behavior, and records that
the HTTP listener needed for renewal is available. Only then does it mark the
TLS readiness gate true. Keep target port 80 available for renewal after DNS moves.

Attach the bridge target group to a temporary HTTP health rule and observe it
healthy before moving the HTTPS default action. An unattached target group stays
unused; creating it alone does not prove readiness to receive HTTPS traffic.

Move the ALB's HTTPS forwarding to the healthy bridge target group and wait until
old direct requests have drained. Confirm source application behavior through the
bridge. The bridge must remain SOURCE throughout rehearsal and backup testing.
Enable Caddy and the bridge so their configuration survives restart.

## Private coordinator configuration

Keep source connection files and the coordinator JSON under a private directory
with modes 0700/0600. `PGSERVICEFILE` defines `verify_source_gate` with the observed
RDS hostname, `verify_owner`, database `verify`, `sslmode=verify-full`, and the
verified RDS CA file. `PGPASSFILE` needs exact entries for both `verify` and
`postgres` on that same host/user. The latter database is the independently
recoverable management channel. Do not put source passwords in argv or environment
variables, and do not copy private connection files into the repository.

The JSON fields are:

```json
{
  "accountId": "<verified AWS account>",
  "instanceId": "<verified target instance>",
  "sourceHost": "<observed RDS endpoint>",
  "sourceService": "verify_source_gate",
  "exportKeySha256": "<verified exact source-key digest>",
  "workDirectory": "/opt/verify-migration/cutover",
  "backupBucket": "<verified existing Verify backup bucket>",
  "backupRegion": "us-west-2",
  "backupPrefix": "live/verify-ledger/cutovers/",
  "readiness": {
    "applicationFeatureTestsPassed": false,
    "encryptedBackupRestoreTestPassed": false,
    "oldAlbRequestsDrained": false,
    "allOtherSourceWritersDisabled": false,
    "httpsCertificateAndRenewalPathVerified": false,
    "databaseDeadlineInterruptTestPassed": false,
    "retainedSourceAutomatedBackupDays": 7
  }
}
```

Set readiness fields only from observed evidence. These are technical checks,
not requests for another user approval. The operator must account for tenant
administration, retention tasks and any direct source connections as well as web
requests. Authenticated GET requests also insert access-log rows, so they must
be queued together with POST requests.

Run the `cutover.py rehearse` command using the private configuration. It performs
a fresh dump/restore, checks exact schema, runtime privileges and all chains,
tests WAL archiving and the final backup upload path, and measures the work. It
also proves the database-admission fence privilege inside a rolled-back management
transaction. A successful rehearsal must be less than 30 minutes old and finish
within eight seconds before the final command is eligible to run.

Run with an explicit environment so another project's shell settings cannot
redirect database tools:

```sh
env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  LANG=C.UTF-8 \
  PYTHONPATH=/opt/verify/current/src:/opt/verify/current \
  PGSERVICEFILE=/opt/verify-migration/cutover/source-service.conf \
  PGPASSFILE=/opt/verify-migration/cutover/source.pgpass \
  /opt/verify/current/.venv/bin/python -m hosted.lightsail.cutover rehearse \
  --config /opt/verify-migration/cutover/coordinator.json
```

The final command uses the same environment, replaces `rehearse` with `cutover`,
and adds `--rehearsal` with the exact successful private report path. AWS backup
access comes from this EC2 instance's scoped profile, not an AWS key in the shell.

## Single-process cutover and rollback boundary

Run `cutover.py cutover` locally on the target with the verified configuration and
rehearsal record. Do not split its final sequence across manual browser commands.

1. Begin a 15-second wall budget before requesting DRAIN; the proxy queues every
   API call for at most 20 seconds. Wait for its in-flight requests to finish.
2. Hold SHARE locks on all seven source tables. These block DML while allowing a
   consistent `pg_dump`; an HTTP request counter alone is not a database barrier.
3. Restore into a new target database, compare duplicate-aware table fingerprints,
   schema and chains, and save the checked final dump as a versioned encrypted S3
   object. Atomically rename the target databases and verify WAL archival.
4. Durably authorize and enable the target app, then verify its private health.
5. Commit `ALTER DATABASE verify ALLOW_CONNECTIONS false` on the source through
   the separate `postgres` management connection. Terminate and verify the absence
   of all other old application sessions, then release the table locks.
6. Persist TARGET in the bridge and release queued requests to the replacement.

Before TARGET has been attempted, errors trigger a separately bounded four-second
recovery: close/quarantine interrupted connections, terminate and settle their
exact backend PIDs through a new management connection, restore source admission,
and return the bridge to SOURCE. Private target cleanup follows. A network or
storage failure can still require operator recovery; the records report that
explicitly instead of claiming a successful rollback.

**Once a TARGET command has been sent, an ambiguous response never permits an
automatic source rollback.** The control server might persist the command after
a socket timeout. Once the target has accepted writes, the source is stale; a
DNS-only rollback would lose those writes. Keep the source admission fence and
repair/complete target routing, or design a new fenced reverse-copy migration.

The bridge never automatically retries a request that may already have committed.
Its bounded queue is not a guarantee that every client has a sufficiently long
timeout. Inspect queue timeout counts and application responses after the switch.

## Finish the migration

Validate the live application, backups, service enablement, memory headroom and
certificate renewal. Then update DNS to the verified stable target IP. Keep the
old ALB forwarding to the same target while cached DNS records expire.

Retire only resources proven exclusive to the old deployment. The new instance
reuses the existing VPC/public subnet/Internet gateway, so those networking
resources must remain. Remove temporary source database/task access and expired
source-secret/SSM write permissions after recovery has been proved. Independently
recoverable export-key storage must be verified before deleting its old secret.

Retain the source's existing seven-day automated-backup recovery window when
removing the RDS instance, alongside the target's continuous WAL history. For a
pre-cutover recovery use the retained source history; for a post-cutover recovery
use the target's tested pgBackRest history. A restored source snapshot may retain
`ALLOW_CONNECTIONS false`; an administrator can enable it through the `postgres`
database after confirming it is an isolated recovery copy.

The legacy `hosted/deploy` stack is blocked by default to prevent recreation of
the former ECS, RDS, NAT and ALB deployment. Its resource addresses and arguments
remain intact for controlled state reconciliation. The CI workflow now runs on
standard GitHub-hosted runners and validates that retirement guard.
