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

# GitHub's immutable OIDC subject (the default for new repos) embeds numeric IDs:
#   repo:<owner>@<owner_id>/<repo>@<repo_id>:ref:refs/heads/main
# so a deleted-and-recreated repo with the same name can't assume the role.
# Look up the IDs with:
#   gh api repos/<owner>/<repo> --jq '.owner.id, .id'
variable "github_owner_id" {
  description = "Numeric GitHub ID of github_owner."
  type        = number
}

variable "github_repo_id" {
  description = "Numeric GitHub ID of github_repo."
  type        = number
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

variable "report_email" {
  description = "Address that receives (and, via SES, sends) the post-scan report email. Null disables it. AWS emails a verification link on first apply."
  type        = string
  default     = null
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
