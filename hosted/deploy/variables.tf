variable "region" {
  type    = string
  default = "us-east-2" # decided 2026-11-07 (Trust Pack §9)
}
variable "name" {
  type    = string
  default = "verify-ledger"
}
variable "image_tag" {
  type        = string
  description = "Tag of the image pushed to the ECR repo this stack creates."
  default     = "0.4.1"
}
variable "certificate_arn" {
  type        = string
  description = "ACM certificate for the public HTTPS listener. Required: the API carries bearer keys."
}
variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}
variable "desired_count" {
  type    = number
  default = 1
}
