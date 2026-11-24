data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_organizations_organization" "this" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  bucket_name = "prowler-reports-${local.account_id}"
  # Built from the name so IAM and bucket policies render in full at plan time.
  bucket_arn = "arn:${local.partition}:s3:::${local.bucket_name}"

  log_bucket_name = "prowler-reports-logs-${local.account_id}"
  log_bucket_arn  = "arn:${local.partition}:s3:::${local.log_bucket_name}"
  log_prefix      = "reports-bucket/"

  # Built from the name (the role has no path) so the key policy renders at plan time.
  runner_role_arn = "arn:${local.partition}:iam::${local.account_id}:role/${var.runner_role_name}"
  # kms:ViaService names the service as <service>.<region>.amazonaws.com, not by the partition's DNS suffix.
  s3_via_service = "s3.${var.region}.amazonaws.com"

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

    # A sub pinned to main matches every workflow file on main, including one
    # added by whoever can push there. scan_workflow_path pins the file too.
    # IAM can't read job_workflow_ref as its own condition key, so it goes in
    # sub, and the repo's OIDC subject template must include it (see README).
    # Opt-in: a wrong path or template locks the scan out.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [join(":", compact([
        "repo:${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}:ref:refs/heads/main",
        var.scan_workflow_path == null ? "" : "job_workflow_ref:${var.github_owner}/${var.github_repo}/${var.scan_workflow_path}@refs/heads/main",
      ]))]
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

      # Without this the role could mail any address once SES leaves the sandbox.
      condition {
        test     = "ForAllValues:StringEquals"
        variable = "ses:Recipients"
        values   = [var.report_email]
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

# S3 calls KMS as the runner on PutObject. GenerateDataKey covers single-part
# uploads; multipart (aws s3 cp of files over 8 MB) also needs Decrypt. Without
# s3:GetObject the runner still can't read a report back.
# jsonencode, not a policy document: a data source that references the new key
# is deferred to apply, which would hide this policy (or all of prowler-runner,
# if the statement lived there) from the plan.
resource "aws_iam_role_policy" "runner_kms" {
  count = var.create_kms_key ? 1 : 0

  name = "prowler-runner-kms"
  role = aws_iam_role.runner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EncryptReports"
      Effect    = "Allow"
      Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
      Resource  = aws_kms_key.reports[0].arn
      Condition = { StringEquals = { "kms:ViaService" = local.s3_via_service } }
    }]
  })
}

# ---------------------------------------------------------------------------
# Reports bucket
# ---------------------------------------------------------------------------

# Same trade-offs as the checkov skips below.
# trivy:ignore:AWS-0089
resource "aws_s3_bucket" "reports" {
  #checkov:skip=CKV_AWS_18:Off by default to keep cost near zero; access logging is available via enable_access_logging (count-based, so the check can't see it)
  #checkov:skip=CKV_AWS_144:Cross-region replication doubles cost for reproducible scan output
  #checkov:skip=CKV_AWS_145:SSE-S3 by default saves $1/month per key; a CMK is available via create_kms_key
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

# The runner holds s3:PutObject on reports/*; versioning keeps an overwritten
# report recoverable until the lifecycle rule below expires the old version.
resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3 by default: free, and avoids $1/month per key. A customer-managed
# KMS key is available via create_kms_key.
# trivy:ignore:AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    # The bucket key cuts KMS requests to roughly one per session instead of one per object.
    bucket_key_enabled = var.create_kms_key ? true : null

    apply_server_side_encryption_by_default {
      sse_algorithm     = var.create_kms_key ? "aws:kms" : "AES256"
      kms_master_key_id = one(aws_kms_key.reports[*].arn)
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

    noncurrent_version_expiration {
      noncurrent_days = var.report_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.reports]
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

resource "aws_s3_bucket_logging" "reports" {
  count = var.enable_access_logging ? 1 : 0

  bucket        = aws_s3_bucket.reports.id
  target_bucket = aws_s3_bucket.access_logs[0].id
  target_prefix = local.log_prefix

  # S3 rejects the logging config until the log bucket lets the logging service write.
  depends_on = [aws_s3_bucket_policy.access_logs]
}

# ---------------------------------------------------------------------------
# Reports bucket KMS key (optional, create_kms_key; about $1/month)
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "reports_key" {
  #checkov:skip=CKV_AWS_109:Key policy; resources must be "*" and root delegation to IAM is the standard admin pattern
  #checkov:skip=CKV_AWS_111:Key policy; resources must be "*" and root delegation to IAM is the standard admin pattern
  #checkov:skip=CKV_AWS_356:Key policy; resources must be "*" and always means this key
  count = var.create_kms_key ? 1 : 0

  # Hands key access control to IAM in this account, so IAM policies decide
  # who administers the key and who can decrypt reports.
  statement {
    sid       = "EnableIamPolicies"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  # Same grant as EncryptReports in the runner policy; see the comment there.
  statement {
    sid       = "RunnerEncryptsThroughS3"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.runner_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.s3_via_service]
    }
  }
}

resource "aws_kms_key" "reports" {
  count = var.create_kms_key ? 1 : 0

  description             = "Encrypts Prowler reports in ${local.bucket_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.reports_key[0].json

  # KMS rejects a key policy that names a role that doesn't exist yet.
  depends_on = [aws_iam_role.runner]
}

resource "aws_kms_alias" "reports" {
  count = var.create_kms_key ? 1 : 0

  name          = "alias/prowler-reports"
  target_key_id = aws_kms_key.reports[0].key_id
}

# ---------------------------------------------------------------------------
# Access log bucket (optional, enable_access_logging)
# ---------------------------------------------------------------------------

# Same trade-offs as the checkov skips below.
# trivy:ignore:AWS-0089
# trivy:ignore:AWS-0090
resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_18:This is the log bucket; logging it into itself would loop
  #checkov:skip=CKV_AWS_21:Only the S3 logging service writes here and it never overwrites; versioning would only add cost
  #checkov:skip=CKV_AWS_144:Cross-region replication doubles cost for low-value access logs
  #checkov:skip=CKV_AWS_145:S3 server access log delivery does not support SSE-KMS default encryption on the target bucket
  #checkov:skip=CKV2_AWS_62:Nothing consumes object events for access logs
  count = var.enable_access_logging ? 1 : 0

  bucket = local.log_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.access_logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  count = var.enable_access_logging ? 1 : 0

  bucket                  = aws_s3_bucket.access_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE-S3: log delivery fails if the target bucket defaults to SSE-KMS.
# trivy:ignore:AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.access_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.access_logs[0].id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.report_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "access_logs_bucket" {
  count = var.enable_access_logging ? 1 : 0

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.log_bucket_arn, "${local.log_bucket_arn}/*"]

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

  # The two conditions stop any other bucket or account from logging into this one.
  statement {
    sid       = "S3ServerAccessLogsDelivery"
    actions   = ["s3:PutObject"]
    resources = ["${local.log_bucket_arn}/${local.log_prefix}*"]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.bucket_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.access_logs[0].id
  policy = data.aws_iam_policy_document.access_logs_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.access_logs]
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
