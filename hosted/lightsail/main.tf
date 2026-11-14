terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

provider "aws" {
  region              = "us-west-2"
  allowed_account_ids = [var.expected_account_id]
  default_tags { tags = { project = "verify-ledger", app = "verify-ledger", managed_by = "terraform" } }
}

# Separate state directory. Never use/import the existing hosted/deploy state here.
# No RDS, DNS, source networking, IAM credentials or application secrets are managed here.
variable "provision_target" {
  type    = bool
  default = false
}
variable "expected_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "Supply the verified AWS account ID privately."
  }
}
variable "source_gate_file" {
  type    = string
  default = "source-gate.json"
}
variable "availability_zone" {
  type = string
  validation {
    condition     = can(regex("^us-west-2[a-z]$", var.availability_zone))
    error_message = "Choose an observed available Oregon Lightsail AZ."
  }
}
variable "lightsail_key_pair_name" { type = string }
variable "admin_ipv4_cidr" {
  type = string
  validation {
    condition     = can(cidrnetmask(var.admin_ipv4_cidr)) && endswith(var.admin_ipv4_cidr, "/32")
    error_message = "SSH is restricted to one approved IPv4 /32 address."
  }
}
locals {
  gate = try(jsondecode(file(var.source_gate_file)), {})
}

resource "aws_lightsail_instance" "target" {
  count             = var.provision_target ? 1 : 0
  name              = "verify-ledger-lightsail-pilot"
  availability_zone = var.availability_zone
  blueprint_id      = "ubuntu_24_04"
  bundle_id         = "small_3_0"
  ip_address_type   = "ipv4"
  key_pair_name     = var.lightsail_key_pair_name
  # No user_data: provisioning cannot start an empty application or copy secrets.
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = try(local.gate.accountId == var.expected_account_id && local.gate.sourceId == "verify-ledger" && local.gate.sourceRegion == "us-west-2" && local.gate.sourceRehearsalReady == true && local.gate.status == "READY_FOR_TARGET_REHEARSAL", false)
      error_message = "A successful fresh source gate is required; target rehearsal is not production cutover approval."
    }
  }
}
resource "aws_lightsail_instance_public_ports" "target" {
  count         = var.provision_target ? 1 : 0
  instance_name = aws_lightsail_instance.target[0].name
  port_info {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    cidrs     = ["0.0.0.0/0"]
  }
  port_info {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidrs     = [var.admin_ipv4_cidr]
  }
  lifecycle { prevent_destroy = true }
}
resource "aws_lightsail_static_ip" "target" {
  count = var.provision_target ? 1 : 0
  name  = "verify-ledger-lightsail-pilot"
  lifecycle { prevent_destroy = true }
}
resource "aws_lightsail_static_ip_attachment" "target" {
  count          = var.provision_target ? 1 : 0
  static_ip_name = aws_lightsail_static_ip.target[0].id
  instance_name  = aws_lightsail_instance.target[0].name
  lifecycle { prevent_destroy = true }
}
output "target_ip" { value = try(aws_lightsail_static_ip.target[0].ip_address, null) }
