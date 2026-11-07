# Verify hosted ledger v0 on AWS. Code only: review, then `terraform apply` yourself.
# Cost at defaults is roughly an ALB, one small Fargate task and a db.t4g.micro RDS instance.
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.70" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = { app = var.name, managed_by = "terraform" } }
}

data "aws_availability_zones" "az" { state = "available" }

locals {
  azs = slice(data.aws_availability_zones.az.names, 0, 2)
}

# ---------------- network: 2 public subnets (ALB), 2 private (tasks, RDS) ----------------
resource "aws_vpc" "this" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

resource "aws_internet_gateway" "this" { vpc_id = aws_vpc.this.id }

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(aws_vpc.this.cidr_block, 8, count.index)
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(aws_vpc.this.cidr_block, 8, count.index + 10)
  tags              = { Name = "${var.name}-private-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# One NAT gateway so private tasks can reach ECR and Secrets Manager.
# ponytail: single-AZ NAT; add one per AZ if an AZ outage must not stop pulls.
resource "aws_eip" "nat" { domain = "vpc" }

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this.id
  }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ---------------- security groups ----------------
resource "aws_security_group" "alb" {
  name   = "${var.name}-alb"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "task" {
  name   = "${var.name}-task"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name   = "${var.name}-db"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.task.id]
  }
}

# ---------------- database: Postgres 16, UTF8, encrypted, password managed by RDS ----------------
resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "this" {
  identifier                  = var.name
  engine                      = "postgres"
  engine_version              = "16"
  instance_class              = var.db_instance_class
  allocated_storage           = 20
  storage_encrypted           = true
  db_name                     = "verify"
  username                    = "verify_owner"
  manage_master_user_password = true # password lives only in Secrets Manager
  db_subnet_group_name        = aws_db_subnet_group.this.name
  vpc_security_group_ids      = [aws_security_group.db.id]
  publicly_accessible         = false
  backup_retention_period     = 7
  deletion_protection         = true
  skip_final_snapshot         = false
  final_snapshot_identifier   = "${var.name}-final"
  auto_minor_version_upgrade  = true
}

# ---------------- secrets ----------------
resource "random_password" "export_key" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "export_key" { name = "${var.name}/export-key" }

resource "aws_secretsmanager_secret_version" "export_key" {
  secret_id     = aws_secretsmanager_secret.export_key.id
  secret_string = random_password.export_key.result
}

# ---------------- container ----------------
resource "aws_ecr_repository" "this" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = 90
}

resource "aws_iam_role" "execution" {
  name = "${var.name}-execution"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ecs-tasks.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "read_secrets" {
  name = "read-secrets"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.export_key.arn, aws_db_instance.this.master_user_secret[0].secret_arn]
    }]
  })
}

resource "aws_ecs_cluster" "this" { name = var.name }

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  container_definitions = jsonencode([{
    name         = "api"
    image        = "${aws_ecr_repository.this.repository_url}:${var.image_tag}"
    essential    = true
    portMappings = [{ containerPort = 8080 }]
    environment = [
      { name = "VERIFY_DB_HOST", value = aws_db_instance.this.address },
      { name = "VERIFY_DB_NAME", value = "verify" },
      { name = "VERIFY_DB_SSLMODE", value = "require" },
    ]
    secrets = [
      { name = "VERIFY_EXPORT_KEY", valueFrom = aws_secretsmanager_secret.export_key.arn },
      { name = "VERIFY_DB_USER", valueFrom = "${aws_db_instance.this.master_user_secret[0].secret_arn}:username::" },
      { name = "VERIFY_DB_PASSWORD", valueFrom = "${aws_db_instance.this.master_user_secret[0].secret_arn}:password::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.this.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "api"
      }
    }
  }])
}

# ---------------- load balancer (HTTPS only) ----------------
resource "aws_lb" "this" {
  name            = var.name
  subnets         = aws_subnet.public[*].id
  security_groups = [aws_security_group.alb.id]
}

resource "aws_lb_target_group" "this" {
  name        = var.name
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.this.id
  target_type = "ip"
  health_check {
    path    = "/v1/verify-chain"
    matcher = "401" # unauthenticated probe: 401 proves the app and its DB lookup are up
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"
  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.task.id]
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "api"
    container_port   = 8080
  }
  depends_on = [aws_lb_listener.https]
}
