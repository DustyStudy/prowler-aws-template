variable "region" {
  type    = string
  default = "us-east-1"
}

variable "github_owner" {
  description = "GitHub user or org that owns the repo running the scan workflow."
  type        = string
}

variable "github_repo" {
  description = "Name of the repo running the scan workflow."
  type        = string
}

# Repos that use GitHub's immutable OIDC subject format embed numeric IDs in the
# token's `sub` claim, e.g. repo:<owner>@<owner_id>/<repo>@<repo_id>:ref:refs/heads/main.
# Check which format your repo uses with:
#   gh api repos/<owner>/<repo>/actions/oidc/customization/sub
# and look up the IDs with:
#   gh api repos/<owner>/<repo> --jq '.owner.id, .id'
# Leave both null to use the classic repo:<owner>/<repo>:ref:refs/heads/main subject.
variable "github_owner_id" {
  description = "Numeric GitHub owner ID, only for the immutable OIDC subject format."
  type        = number
  default     = null
}

variable "github_repo_id" {
  description = "Numeric GitHub repo ID, only for the immutable OIDC subject format."
  type        = number
  default     = null

  validation {
    condition     = (var.github_repo_id == null) == (var.github_owner_id == null)
    error_message = "Set both github_owner_id and github_repo_id, or neither."
  }
}

variable "runner_role_name" {
  type    = string
  default = "prowler-gha-runner"
}

variable "scan_role_name" {
  description = "Name of the read-only role deployed to every account by org-roles."
  type        = string
  default     = "ProwlerScan"
}

variable "create_github_oidc_provider" {
  description = "Set false if this account already has the token.actions.githubusercontent.com OIDC provider."
  type        = bool
  default     = true
}

variable "report_retention_days" {
  description = "Days to keep scan reports in S3."
  type        = number
  default     = 365
}

variable "budget_email" {
  description = "Email for the monthly cost alarm. Null disables the budget."
  type        = string
  default     = null
}

variable "budget_limit_usd" {
  type    = number
  default = 5
}
