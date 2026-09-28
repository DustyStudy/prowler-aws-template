variable "region" {
  description = "Region for the StackSet and its instances."
  type        = string
  default     = "us-east-1"
}

variable "scanner_account_id" {
  description = "Security/audit account that hosts the prowler-gha-runner role."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.scanner_account_id))
    error_message = "scanner_account_id must be a 12-digit AWS account ID."
  }
}

variable "runner_role_name" {
  description = "Name of the GitHub Actions runner role in the scanner account."
  type        = string
  default     = "prowler-gha-runner"
}

variable "scan_role_name" {
  description = "Name of the read-only role created in every account."
  type        = string
  default     = "ProwlerScan"
}

variable "target_ou_ids" {
  description = "OUs to deploy the ProwlerScan role to. Empty = the organization root (all accounts)."
  type        = list(string)
  default     = []
}
