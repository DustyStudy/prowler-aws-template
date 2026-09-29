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
    partition = "aws"
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
}

run "creates_oidc_provider_by_default" {
  command = plan

  assert {
    condition     = length(aws_iam_openid_connect_provider.github) == 1
    error_message = "The GitHub OIDC provider must be created unless create_github_oidc_provider = false."
  }
}
