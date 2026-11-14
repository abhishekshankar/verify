# Legacy ECS/RDS/ALB/NAT provisioning is disabled during the EC2 migration.
# Preserve these resource addresses and the original state for audited recovery.
# Do not remove resources from configuration or apply an empty configuration:
# doing so can turn an accidental apply into a destructive retirement plan.
variable "legacy_recovery_authorization" {
  type        = string
  default     = ""
  nullable    = false
  description = "Reserved for a separately reviewed legacy disaster-recovery plan. Leave empty for normal CI, migration, and application releases."
}

resource "terraform_data" "legacy_retirement_guard" {
  input = var.legacy_recovery_authorization

  lifecycle {
    precondition {
      condition     = var.legacy_recovery_authorization == "REVIEWED-LEGACY-DISASTER-RECOVERY-ONLY"
      error_message = "Legacy Verify ECS/RDS/ALB/NAT provisioning is disabled. Do not apply hosted/deploy for an application release or migration cleanup. Follow the reviewed EC2 migration and preserve the original Terraform state."
    }
  }
}
