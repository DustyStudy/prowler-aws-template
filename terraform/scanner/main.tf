data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_organizations_organization" "this" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  bucket_name = "prowler-reports-${local.account_id}"

  oidc_subject = (
    var.github_owner_id == null
    ? "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/main"
    : "repo:${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}:ref:refs/heads/main"
  )

  oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
}

# ---------------------------------------------------------------------------
# GitHub OIDC
# ---------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 1 : 0

  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 0 : 1

  url = "https://token.actions.githubusercontent.com"
}

# Only workflows running on main (schedule + manual dispatch) can assume the runner role.
data "aws_iam_policy_document" "runner_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.oidc_subject]
    }
  }
}

resource "aws_iam_role" "runner" {
  name                 = var.runner_role_name
  description          = "Assumed by GitHub Actions to run Prowler across the organization"
  assume_role_policy   = data.aws_iam_policy_document.runner_trust.json
  max_session_duration = 14400
}

data "aws_iam_policy_document" "runner" {
  statement {
    sid       = "AssumeScanRoleInOrgAccounts"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:${local.partition}:iam::*:role/${var.scan_role_name}"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceOrgID"
      values   = [data.aws_organizations_organization.this.id]
    }
  }

  statement {
    sid       = "WriteReports"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.reports.arn}/reports/*"]
  }
}

resource "aws_iam_role_policy" "runner" {
  name   = "prowler-runner"
  role   = aws_iam_role.runner.id
  policy = data.aws_iam_policy_document.runner.json
}

# ---------------------------------------------------------------------------
# Reports bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "reports" {
  bucket = local.bucket_name
}

resource "aws_s3_bucket_ownership_controls" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE-S3 rather than a customer-managed KMS key: free, and avoids $1/month per key.
resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Reports are a few MB/week, so Standard storage is cheaper than paying
# transition requests and Glacier IR's 128 KB minimum object charge.
resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "expire-reports"
    status = "Enabled"

    filter {
      prefix = "reports/"
    }

    expiration {
      days = var.report_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "reports_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id
  policy = data.aws_iam_policy_document.reports_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.reports]
}

# ---------------------------------------------------------------------------
# Cost alarm (optional; the first two AWS Budgets are free)
# ---------------------------------------------------------------------------

resource "aws_budgets_budget" "monthly" {
  count = var.budget_email == null ? 0 : 1

  name         = "prowler-aws-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }
}
