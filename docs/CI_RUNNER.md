# Verify CI on the shared AWS runner

Verify uses its own repository registration on the existing shared AWS Spot host `i-05dbdc02343b222e6` (us-east-1), the same pattern as KnowCurrent. No new instance was provisioned. Personal-account repositories can't use the organization runner, so each one gets its own registration.

- GitHub runner: `verify-aws-i-05dbdc02343b222e6`
- Labels: `self-hosted`, `Linux`, `X64`, `aws`, `verify`
- Service: `verify-ci-runner.service`, run as the dedicated user `verify-ci` (no login shell)
- Install/workspace: `/opt/verify-ci-runner` (runner 2.338.2, copied from the KnowCurrent install without its credential files)
- Limits: 1 CPU, 1536 MB RAM, Nice 10
- Sandbox: PrivateTmp, PrivateDevices, ProtectHome, ProtectSystem=strict, NoNewPrivileges, RestrictSUIDSGID; other runner directories are inaccessible; the EC2 metadata endpoint is blocked

The workflow runs only the offline tests and a CLI smoke test. It has no Stripe or Zendesk secrets, no caches and no artifacts. Checkout doesn't persist credentials. Fork pull requests can't reach this runner.

Registration used a short-lived repository token injected through SSM. It was never printed, and the local script was deleted after dispatch. It still appears in the SSM command history for that invocation; it expired within an hour and was consumed on registration.

Status: `gh api repos/abhishekshankar/verify/actions/runners`. Diagnose the service through AWS Systems Manager. If the Spot host is down, jobs wait; don't substitute GitHub-hosted runners.
