# Verify CI

The shared AWS Spot runner was retired on 2026-11-14. The offline test job now
uses the standard `ubuntu-latest` GitHub-hosted runner, as do the existing
PostgreSQL, Docker, Terraform and integration-example jobs. No dedicated AWS
instance or paid larger runner is requested by this workflow.

The test job checks the supported Python version, offline application tests,
hosted ledger tests, migration safety checks, shipped contracts and CLI smoke
path. It needs no third-party API secrets. Checkout does not persist credentials,
and workflow permissions remain `contents: read`.

Review runs in the repository's **Actions** tab. An account's GitHub Actions
allowances and any configured spending budget still apply; this change does not
change a billing plan or increase an account limit.

## Historical runner

The former registration was `verify-aws-i-05dbdc02343b222e6`, on EC2
`i-05dbdc02343b222e6` in `us-east-1`, with labels `self-hosted`, `Linux`, `X64`,
`aws`, `verify`. That instance is terminated and its restorable disk archive is
retained under the separate AWS retirement backup record. Do not point jobs back
to those labels or recreate the retired host just to run this workflow.
