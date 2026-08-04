variable "name" {
  description = "Name prefix for all resources (Lambda, role, SNS, SQS)."
  type        = string
  default     = "aws-tag-enforcer"
}

variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "eu-central-1"
}
