# Plan-only tests. The real AWS provider renders the IAM policy JSON locally;
# dummy credentials plus overridden data sources keep it from calling AWS.
# Run with: terraform init -backend=false && terraform test

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

override_data {
  target = data.aws_caller_identity.current
  values = {
    account_id = "111111111111"
  }
}

override_data {
  target = data.aws_partition.current
  values = {
    partition  = "aws"
    dns_suffix = "amazonaws.com"
  }
}

override_data {
  target = data.aws_organizations_organization.this
  values = {
    id = "o-exampleorg1"
  }
}

override_data {
  target = data.aws_iam_openid_connect_provider.github
  values = {
    arn = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
  }
}

# terraform test also loads terraform.tfvars, so pin every input the
# assertions depend on instead of inheriting a local email setup.
variables {
  github_owner      = "example-owner"
  github_owner_id   = 1234
  github_repo       = "prowler-aws"
  github_repo_id    = 5678
  report_email      = null
  report_from_email = null

  region                = "us-east-1"
  runner_role_name      = "prowler-gha-runner"
  create_kms_key        = false
  enable_access_logging = false

  scan_workflow_path = null
}

run "runner_trust_is_pinned_to_main_of_one_repo" {
  command = plan

  variables {
    create_github_oidc_provider = false
  }

  assert {
    condition = (
      jsondecode(data.aws_iam_policy_document.runner_trust.json).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]
      == "repo:example-owner@1234/prowler-aws@5678:ref:refs/heads/main"
    )
    error_message = "Only the main branch of this exact repo (by immutable ID) may assume the runner role."
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.runner_trust.json).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "The trust policy must require the sts.amazonaws.com audience."
  }

  assert {
    condition = keys(jsondecode(data.aws_iam_policy_document.runner_trust.json).Statement[0].Condition.StringEquals) == [
      "token.actions.githubusercontent.com:aud",
      "token.actions.githubusercontent.com:sub",
    ]
    error_message = "The trust may only use aud and sub: IAM doesn't evaluate other GitHub claims, such as job_workflow_ref, as condition keys."
  }
}

run "runner_trust_can_be_pinned_to_the_scan_workflow" {
  command = plan

  variables {
    create_github_oidc_provider = false
    scan_workflow_path          = ".github/workflows/prowler-scan.yml"
  }

  assert {
    condition = (
      jsondecode(data.aws_iam_policy_document.runner_trust.json).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]
      == "repo:example-owner@1234/prowler-aws@5678:ref:refs/heads/main:job_workflow_ref:example-owner/prowler-aws/.github/workflows/prowler-scan.yml@refs/heads/main"
    )
    error_message = "With scan_workflow_path set, sub must also name the scan workflow file on main."
  }

  assert {
    condition = keys(jsondecode(data.aws_iam_policy_document.runner_trust.json).Statement[0].Condition.StringEquals) == [
      "token.actions.githubusercontent.com:aud",
      "token.actions.githubusercontent.com:sub",
    ]
    error_message = "The workflow pin must live in sub, not in a separate job_workflow_ref condition."
  }
}

run "runner_can_only_assume_scan_roles_inside_the_org" {
  command = plan

  variables {
    create_github_oidc_provider = false
  }

  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.runner.json).Statement :
      s.Condition.StringEquals["aws:ResourceOrgID"] == "o-exampleorg1" if s.Sid == "AssumeScanRoleInOrgAccounts"
    ])
    error_message = "sts:AssumeRole must be limited to roles inside this organization."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.runner.json).Statement : s.Resource if s.Sid == "WriteReports"]) == "arn:aws:s3:::prowler-reports-111111111111/reports/*"
    error_message = "The runner may write only under reports/ in the reports bucket."
  }

  assert {
    condition     = length([for s in jsondecode(data.aws_iam_policy_document.runner.json).Statement : s if s.Sid == "SendReportEmail"]) == 0
    error_message = "No SES permission should exist when report_email is null."
  }
}

run "ses_send_is_limited_to_the_configured_sender" {
  command = plan

  variables {
    create_github_oidc_provider = false
    report_email                = "security@example.com"
    report_from_email           = "security+prowler@example.com"
  }

  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.runner.json).Statement :
      s.Condition.StringEquals["ses:FromAddress"] if s.Sid == "SendReportEmail"
    ]) == "security+prowler@example.com"
    error_message = "SES sending must be restricted to the configured From address."
  }

  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.runner.json).Statement :
      s.Condition["ForAllValues:StringEquals"]["ses:Recipients"] if s.Sid == "SendReportEmail"
    ]) == "security@example.com"
    error_message = "SES sending must be restricted to report_email as the only recipient."
  }

  assert {
    condition = toset(one([
      for s in jsondecode(data.aws_iam_policy_document.runner.json).Statement : s.Resource if s.Sid == "SendReportEmail"
    ])) == toset(["arn:aws:ses:us-east-1:111111111111:identity/security@example.com", "arn:aws:ses:us-east-1:111111111111:identity/security+prowler@example.com"])
    error_message = "SES permission must cover exactly the recipient and sender identities."
  }

  assert {
    condition     = length(aws_sesv2_email_identity.report_sender) == 1
    error_message = "A separate sender address must be verified too (SES sandbox)."
  }
}

run "reports_bucket_is_private_and_expires" {
  command = plan

  variables {
    create_github_oidc_provider = false
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.reports.block_public_acls,
      aws_s3_bucket_public_access_block.reports.block_public_policy,
      aws_s3_bucket_public_access_block.reports.ignore_public_acls,
      aws_s3_bucket_public_access_block.reports.restrict_public_buckets,
    ])
    error_message = "The reports bucket must block all public access."
  }

  assert {
    condition     = one(one(aws_s3_bucket_lifecycle_configuration.reports.rule).expiration).days == 365
    error_message = "Reports must expire after report_retention_days."
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.reports.versioning_configuration).status == "Enabled"
    error_message = "The reports bucket must be versioned so an overwrite can't destroy a past report."
  }

  assert {
    condition     = one(one(aws_s3_bucket_lifecycle_configuration.reports.rule).noncurrent_version_expiration).noncurrent_days == 365
    error_message = "Overwritten report versions must expire after report_retention_days."
  }
}

run "creates_oidc_provider_by_default" {
  command = plan

  assert {
    condition     = length(aws_iam_openid_connect_provider.github) == 1
    error_message = "The GitHub OIDC provider must be created unless create_github_oidc_provider = false."
  }
}

run "hardening_is_off_by_default" {
  command = plan

  variables {
    create_github_oidc_provider = false
  }

  assert {
    condition     = length(aws_kms_key.reports) == 0 && length(aws_kms_alias.reports) == 0
    error_message = "No KMS key may exist unless create_kms_key = true."
  }

  assert {
    condition     = length(aws_s3_bucket.access_logs) == 0 && length(aws_s3_bucket_logging.reports) == 0
    error_message = "No log bucket or logging config may exist unless enable_access_logging = true."
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_server_side_encryption_configuration.reports.rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    )
    error_message = "The default encryption must stay plain SSE-S3 so existing deployments plan with no changes."
  }

  assert {
    condition     = length(aws_iam_role_policy.runner_kms) == 0
    error_message = "The runner needs no KMS permission when there is no key."
  }

  assert {
    condition     = output.kms_key_arn == null && output.access_logs_bucket == null
    error_message = "The hardening outputs must be null when the options are off."
  }
}

run "kms_key_encrypts_reports_and_runner_can_only_use_it_through_s3" {
  command = plan

  variables {
    create_github_oidc_provider = false
    create_kms_key              = true
  }

  # The key ARN is unknown until apply; pin it so the runner policy renders at plan time.
  override_resource {
    target          = aws_kms_key.reports
    override_during = plan
    values = {
      arn    = "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"
      key_id = "00000000-0000-0000-0000-000000000000"
    }
  }

  assert {
    condition     = aws_kms_key.reports[0].enable_key_rotation == true && aws_kms_key.reports[0].deletion_window_in_days == 30
    error_message = "The key must rotate and use an explicit 30-day deletion window."
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_server_side_encryption_configuration.reports.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
      && one(one(aws_s3_bucket_server_side_encryption_configuration.reports.rule).apply_server_side_encryption_by_default).kms_master_key_id == "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"
      && one(aws_s3_bucket_server_side_encryption_configuration.reports.rule).bucket_key_enabled == true
    )
    error_message = "The reports bucket must default to SSE-KMS with this key and an S3 bucket key."
  }

  assert {
    condition = [
      for s in jsondecode(aws_iam_role_policy.runner_kms[0].policy).Statement :
      [s.Effect, s.Action, s.Resource, s.Condition]
      ] == [[
        "Allow",
        ["kms:GenerateDataKey", "kms:Decrypt"],
        "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000",
        { StringEquals = { "kms:ViaService" = "s3.us-east-1.amazonaws.com" } },
    ]]
    error_message = "The runner may only GenerateDataKey/Decrypt, on this key, through S3."
  }

  assert {
    condition = [
      for s in jsondecode(data.aws_iam_policy_document.reports_key[0].json).Statement :
      [s.Effect, s.Action, s.Principal.AWS, s.Condition] if s.Sid == "RunnerEncryptsThroughS3"
      ] == [[
        "Allow",
        ["kms:GenerateDataKey", "kms:Decrypt"],
        "arn:aws:iam::111111111111:role/prowler-gha-runner",
        { StringEquals = { "kms:ViaService" = "s3.us-east-1.amazonaws.com" } },
    ]]
    error_message = "The key policy must limit the runner role to GenerateDataKey/Decrypt through S3."
  }

  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.reports_key[0].json).Statement : s.Principal.AWS if s.Sid == "EnableIamPolicies"
    ]) == "arn:aws:iam::111111111111:root"
    error_message = "The key policy must delegate key access to IAM in this account only."
  }
}

run "access_logging_writes_to_a_locked_down_log_bucket" {
  command = plan

  variables {
    create_github_oidc_provider = false
    enable_access_logging       = true
  }

  assert {
    condition     = aws_s3_bucket.access_logs[0].bucket == "prowler-reports-logs-111111111111" && aws_s3_bucket_logging.reports[0].target_prefix == "reports-bucket/"
    error_message = "The reports bucket must log to prowler-reports-logs-<account_id> under reports-bucket/."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.access_logs[0].block_public_acls,
      aws_s3_bucket_public_access_block.access_logs[0].block_public_policy,
      aws_s3_bucket_public_access_block.access_logs[0].ignore_public_acls,
      aws_s3_bucket_public_access_block.access_logs[0].restrict_public_buckets,
    ])
    error_message = "The log bucket must block all public access."
  }

  assert {
    condition = [
      for s in jsondecode(data.aws_iam_policy_document.access_logs_bucket[0].json).Statement :
      s.Condition.Bool["aws:SecureTransport"] if s.Sid == "DenyInsecureTransport" && s.Effect == "Deny"
    ] == ["false"]
    error_message = "The log bucket must deny non-TLS requests."
  }

  assert {
    condition = [
      for s in jsondecode(data.aws_iam_policy_document.access_logs_bucket[0].json).Statement :
      [s.Effect, s.Action, s.Resource, s.Principal.Service, s.Condition.StringEquals["aws:SourceAccount"], s.Condition.ArnLike["aws:SourceArn"]]
      if s.Sid == "S3ServerAccessLogsDelivery"
      ] == [[
        "Allow",
        "s3:PutObject",
        "arn:aws:s3:::prowler-reports-logs-111111111111/reports-bucket/*",
        "logging.s3.amazonaws.com",
        "111111111111",
        "arn:aws:s3:::prowler-reports-111111111111",
    ]]
    error_message = "Only the S3 logging service, acting for the reports bucket in this account, may write logs."
  }

  assert {
    condition     = one(one(aws_s3_bucket_lifecycle_configuration.access_logs[0].rule).expiration).days == 365
    error_message = "Access logs must expire after report_retention_days."
  }
}
