# Complete the Verify migration

These steps follow a successful `TARGET_AUTHORITATIVE` report from the reviewed
coordinator. TARGET is now the only writer. Keep the source admission fence;
repair the target if a later check fails. A DNS rollback to the old database
would discard later target writes.

## Prove the live target and recovery material

Keep the exact cutover report and its independently recorded SHA-256 private.
Run this through SSM as root, with the deployed application interpreter:

```sh
PYTHONPATH=/opt/verify/current/src:/opt/verify/current \
  /opt/verify/current/.venv/bin/python -m hosted.lightsail.prove_live_target prove \
  --cutover-report /opt/verify-migration/cutover/REVIEWED_TOKEN-cutover.json \
  --sha256 REVIEWED_CUTOVER_REPORT_SHA256 \
  --check-source-fence
```

This helper reads one consistent snapshot of all seven target tables and checks
every ledger chain. It also checks the live runtime TLS login, target schema,
durable TARGET state, service enablement, actual memory/disk headroom, WAL archive
health, API authentication boundary and trusted certificates. New legitimate
appends, access logs, key rotations and retention are allowed; the original
fenced migration comparison remains in the cutover report. HTTP 401 probes are
not an authenticated customer API test. The earlier real restricted-role HTTP
suite and coordinator fault rehearsal provide separate functional evidence.

The helper downloads and hashes the exact final S3 dump version and independently
decrypts all four SecureString parameters, comparing their exact bytes with local
credentials. It makes no AWS writes, database changes, service restarts or gate
changes. It saves a private local JSON report for the operator to archive.

Create one normal full backup after cutover. This is a separate, explicit backup
operation; it does not stop the application:

```sh
systemctl start verify-backup.service
```

Wait for that command to finish successfully, then rerun the proof command with
both `--check-source-fence` and `--require-post-cutover-backup`. Record the exact
completed backup label, archive range and proof. Preserve the already completed
isolated encrypted PITR restore evidence. Do not rerun `test_pitr_restore.py`
against the live writer; that fixture was designed for the private pre-cutover
target and intentionally refuses TARGET state.

After recording source retirement separately, the same proof can run without
`--check-source-fence`. It then has no connection to RDS or dependency on either
old Secrets Manager secret. Omitting the check makes no claim about source
retirement; that is established by the AWS resource evidence below.

## Retire only the old deployment's dependencies

1. Verify the stable target IP over trusted HTTPS from outside the target. Change
   the domain's DNS record to that IP while retaining the old ALB's forwarding to
   the same TARGET. Save the prior DNS record, actual TTL and change time. Wait
   out the observed DNS cache interval and verify the domain through independent
   resolvers before retiring that ALB. Do not infer propagation from one resolver.
2. Preserve the versioned service/task definitions, exact old and temporary task
   ARNs/images, desired counts, network inventory, grace setting and routing
   metadata. The corrected cutover already requires the managed service at zero
   with every old managed process stopped. Confirm it remains there. After the
   target proof and backup gate pass, stop the exact temporary standalone source
   task and wait for its process and ENI to stop. Check no other task or automation
   uses the source database. Keep the ALB bridge route during DNS propagation.
   Do not restore its old source route or clear the database fence.
3. Before deleting RDS, pin its ARN, `DbiResourceId`, endpoint, account/region,
   encryption key, seven-day retention, actual earliest/latest restore times,
   parameter/option groups and deletion protection. The final logical dump is
   already versioned, downloaded and hashed, with exact schema/data validation.
   Independently record the intended final-snapshot choice. If skipping a new
   manual snapshot to avoid indefinite storage, require the logical-copy and
   tested target-recovery proofs first. Remove deletion protection only for this
   exact old instance. Explicitly send `DeleteAutomatedBackups=False` in
   `DeleteDBInstance`; the default would remove that recovery history. Verify
   retained backups afterward using the pinned `DbiResourceId`.
4. Retained source snapshots/logs age out under the existing retention window;
   this is not seven fresh days of historical coverage after deletion. Record
   the actual retained restore window and keep its KMS key usable. Target WAL
   backups cover post-cutover history. AWS's documentation describes the
   [deletion parameters](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBInstance.html)
   and [retained backup expiry and lookup](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.Retaining.html).
5. Delete the old ALB/listeners/target groups only after DNS propagation and
   target HTTPS checks pass. For each old NAT gateway, enumerate every route
   table that references it and every workload in those associated subnets.
   Delete it only if all consumers have retired or have a verified replacement
   route. Release only its recorded old EIP allocation after NAT deletion;
   preserve the target's stable EIP. Delete old security groups, execution roles
   and private subnets only after exact ENI/reference checks show no dependency.

The target reuses VPC `vpc-039a6508764a9d2b3`, public subnet
`subnet-0486ef164e8819fa9`, its public route table/association and Internet gateway.
Preserve those, target instance/volume/ENI/security group/EIP/profile, the backup
bucket, recovery parameters and encryption keys. Never destroy the entire legacy
Terraform stack: it contains this shared network, and its default guard exists
to prevent recreating the retired ECS/RDS/NAT/ALB architecture.

Keep current pgBackRest objects and WAL immediately readable. Its seven-day
retention controls the active recovery chain; cold-archive lifecycle rules must
not make active recovery depend on a delayed object restore. Preserve the exact
application release and infrastructure/configuration manifest alongside the
database backups. The image/release is needed to reconstruct the application.

## Recover without the retired source

Maintain exact-resource `ssm:GetParameter` and the required decrypt permissions for
the four `/verify-ledger/infra/` parameters: `runtime-db-password`,
`maintenance-db-password`, `export-key` and `backup-cipher-key`. Their current
temporary Get/Put grant expires; replace it with the required recovery read
permission before removing temporary writes. Keep the instance profile's scoped
S3 backup permissions. After verification, remove old RDS/export-secret reads and
temporary target-to-source security-group rules/passfiles.

A replacement host needs the saved application release, native PostgreSQL 16,
pgBackRest configuration, systemd units and the four independently recovered
values. Use the backup cipher recovered from SSM with the same bucket/prefix to
restore into a stopped, isolated PostgreSQL 16 data directory. A physical restore
includes database roles; install the matching runtime and maintenance credentials
without rotating them. Configure new local TLS and public certificate issuance,
verify restored data/chains and runtime permissions, then authorize one writer
and route traffic. Preserve the exact export HMAC key. Follow the documented
[pgBackRest restore procedure](https://pgbackrest.org/user-guide.html#restore).

Do not reuse `setup_target.py` as a disaster-recovery command: it is a migration
rehearsal helper that reads the original source export secret. Recovery must read
the independent SSM copy instead. An isolated restore of an old source RDS
backup can retain `ALLOW_CONNECTIONS false`; enable admission through its
`postgres` database only after proving that it is an isolated recovery copy.

Finish with an AWS inventory proving the old RDS instance, running ECS tasks,
ALB and exclusive NAT are gone, the target dependencies remain, backup/recovery
read access is permanent, and the domain reaches the target. Report the actual
remaining baseline and backup/traffic charges separately from temporary retained
source-backup storage.
