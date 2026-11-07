output "api_dns" { value = aws_lb.this.dns_name }
output "ecr_repository_url" { value = aws_ecr_repository.this.repository_url }
output "db_address" { value = aws_db_instance.this.address }
output "db_master_secret_arn" { value = aws_db_instance.this.master_user_secret[0].secret_arn }
