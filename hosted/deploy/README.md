# Legacy AWS provisioning: application applies disabled

This directory describes the previous Verify deployment: ECS/Fargate, RDS,
ALB, NAT, and their network/IAM resources. It was applied on 2026-11-08 in
**us-west-2** for `ledger.optimise.work`; the original us-east-2 default is
historical. The 2026-11-14 cost migration prepares a single EC2 host in the
same region, with local PostgreSQL and encrypted PostgreSQL backups.

The presence of this guard does not mean the live source has been deleted.
Source retirement follows verified data transfer, a single-writer cutover,
HTTPS and restore checks, and the migration's explicit retirement record.

## Why an ordinary apply now fails

`retirement_guard.tf` adds a default-deny precondition. Every legacy managed
resource depends on that guard, including independent ECR, log, secret,
password, IAM, and network resources. A normal `terraform plan` or `apply`,
including a targeted resource plan, fails before it can provision the old
architecture. `terraform fmt` and `terraform validate` remain available for
read-only CI checks.

The explicit recovery authorization is reserved for a separately reviewed
disaster-recovery plan. It is not a migration or application-release option.
Normal CI, operator environments, and `.tfvars` must leave it unset. The user's
selected production architecture does not use RDS.

## Release and CI boundaries

The current repository has no workflow that applies AWS infrastructure or
deploys the ledger service. `.github/workflows/ci.yml` validates Terraform
without a backend and runs tests. `release.yml` publishes the Python package
to PyPI; `pages.yml` publishes the documentation site to GitHub Pages.

Do not add an AWS apply or ECS update step to these workflows. The replacement
host's bootstrap, database transfer, durable writer gate, service units, and
backups are in `hosted/lightsail/` (the name predates the EC2 selection). A
future automated application release must target the existing verified EC2
host and preserve its database and credentials; it must not run this legacy
module or create a second replacement host.

## Preserve state and recovery material before retiring source resources

Retain the original Terraform state and configuration in the private encrypted
migration backup. State may contain the export signing key and other secrets;
never commit it or print it into shared logs. Keep resource addresses in this
directory intact while the source and its dependencies are being retired.

Invalidate previously saved executable Terraform plans and disable any external
HCP Terraform/workspace or operator automation using this directory before
source deletion. A saved plan created before the guard already embeds the old
configuration and cannot be made safe by this commit alone. This repository
review does not establish whether such external automation exists.

Do not remove these resources from configuration and run an ordinary apply,
apply an empty configuration, or use `terraform destroy` as a migration shortcut.
Those operations can delete resources and do not enforce the migration's data,
backup, DNS, or source-retention gates. After separately verified retirement,
reconcile the archived Terraform state explicitly, preserving any still-used
VPC/subnet/security-group dependencies of the replacement host.
