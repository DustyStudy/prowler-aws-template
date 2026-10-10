data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_organizations_organization" "this" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  bucket_name = "prowler-reports-${local.account_id}"
  # Built from the name so IAM and bucket policies render in full at plan time.
  bucket_arn = "arn:${local.partition}:s3:::${local.bucket_name}"

  oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn

  report_from     = coalesce(var.report_from_email, var.report_email, "unused")
  separate_sender = var.report_email != null && var.report_from_email != null && var.report_from_email != var.report_email
  ses_identities  = compact([var.report_email, local.separate_sender ? var.report_from_email : null])
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
      values   = ["repo:${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}:ref:refs/heads/main"]
    }

    # sub alone matches every workflow file on main, including one added by
    # whoever can push there. Opt-in: a wrong path locks the scan out.
    dynamic "condition" {
      for_each = var.scan_workflow_path == null ? [] : [var.scan_workflow_path]

      content {
        test     = "StringEquals"
        variable = "token.actions.githubusercontent.com:job_workflow_ref"
        values   = ["${var.github_owner}/${var.github_repo}/${condition.value}@refs/heads/main"]
      }
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
    resources = ["${local.bucket_arn}/reports/*"]
  }

  dynamic "statement" {
    for_each = var.report_email == null ? [] : [local.report_from]

    content {
      sid       = "SendReportEmail"
      actions   = ["ses:SendEmail", "ses:SendRawEmail"]
      resources = [for email in local.ses_identities : "arn:${local.partition}:ses:${var.region}:${local.account_id}:identity/${email}"]

      condition {
        test     = "StringEquals"
        variable = "ses:FromAddress"
        values   = [statement.value]
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Report email (SES). The account stays in the SES sandbox, which only allows
# sending to verified addresses. That's fine here: sender and recipient are the
# same verified address. ~$0.10 per 1,000 emails.
# ---------------------------------------------------------------------------

resource "aws_sesv2_email_identity" "report" {
  count          = var.report_email == null ? 0 : 1
  email_identity = var.report_email
}

# Sandbox mode requires the sender to be verified too.
resource "aws_sesv2_email_identity" "report_sender" {
  count          = local.separate_sender ? 1 : 0
  email_identity = var.report_from_email
}

resource "aws_iam_role_policy" "runner" {
  name   = "prowler-runner"
  role   = aws_iam_role.runner.id
  policy = data.aws_iam_policy_document.runner.json
}

# ---------------------------------------------------------------------------
# Reports bucket
# ---------------------------------------------------------------------------

# Same trade-offs as the checkov skips below.
# trivy:ignore:AWS-0089 trivy:ignore:AWS-0090
resource "aws_s3_bucket" "reports" {
  #checkov:skip=CKV_AWS_21:Reports are regenerated every week; versioning would only add storage cost
  #checkov:skip=CKV_AWS_18:Access logging would cost more than the reports themselves; only the runner role can write here
  #checkov:skip=CKV_AWS_144:Cross-region replication doubles cost for reproducible scan output
  #checkov:skip=CKV_AWS_145:SSE-S3 instead of a CMK saves $1/month per key; see the comment on the encryption resource
  #checkov:skip=CKV2_AWS_62:Nothing consumes object events; the email job reads reports from workflow artifacts
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
# trivy:ignore:AWS-0132
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
  #checkov:skip=CKV_AWS_300:False positive; abort_incomplete_multipart_upload is set below with a prefix filter
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
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]

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
