# Deploy the hosted ledger (AWS us-east-2)

Applied 2026-11-08 in **us-west-2** (`-var region=us-west-2`; us-east-2 was at its 5-VPC limit) as https://ledger.optimise.work. Applying creates billable resources (ALB, NAT gateway, Fargate, RDS), about $80–90/month.

## Prerequisites
- An ACM certificate in us-east-2 for your API hostname (`certificate_arn`). HTTPS only; the API carries bearer keys.
- Your own AWS credentials with rights to create VPC, RDS, ECS, ECR, ALB, IAM roles and Secrets Manager secrets.

## Steps
1. `terraform init && terraform apply -var certificate_arn=arn:aws:acm:...`
   This also creates the ECR repo, but the service can't start until step 2.
2. Build for ARM and push:
   `docker build --platform linux/arm64 -f hosted/Dockerfile -t <ecr_repository_url>:0.4.2 . && docker push <ecr_repository_url>:0.4.2`
3. Create the roles first (`CREATE ROLE verify_app NOLOGIN; CREATE ROLE verify_retention NOLOGIN;`; the schema GRANTs to them), then apply the schema once, as the owner (credentials are in the `db_master_secret_arn` secret), from a host inside the VPC (for example an ECS exec session):
   `psql "host=<db_address> dbname=verify user=verify_owner sslmode=require" -f hosted/schema.postgres.sql`
4. Create a tenant: run `python -m hosted.server add-tenant <id>` in a one-off task with the same environment. The key is printed once.
5. Point DNS at `api_dns`.

## Known limits (v0)
- The app connects as the owner role. Move it to `verify_app` (SELECT/INSERT only; created in the schema file) before the first paying customer.
- One NAT gateway, so a single AZ.
- Retention purge isn't scheduled yet; run `python -m hosted.server purge <tenant> <days>` as a one-off task.
