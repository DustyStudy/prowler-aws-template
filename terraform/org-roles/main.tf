terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # bucket (and profile for the security account) come from backend.hcl
  backend "s3" {
    key          = "org-roles/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

# Runs with MANAGEMENT account credentials (e.g. AWS_PROFILE=management).
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "prowler-aws"
      ManagedBy = "terraform"
    }
  }
}

data "aws_organizations_organization" "this" {}

locals {
  template = file("${path.module}/templates/prowler-scan-role.yaml")

  parameters = {
    ScannerAccountId = var.scanner_account_id
    RunnerRoleName   = var.runner_role_name
    RoleName         = var.scan_role_name
  }

  target_ou_ids = length(var.target_ou_ids) > 0 ? var.target_ou_ids : [data.aws_organizations_organization.this.roots[0].id]
}

# ProwlerScan role in every member account, including accounts created later.
resource "aws_cloudformation_stack_set" "scan_role" {
  name             = "prowler-scan-role"
  description      = "Read-only ProwlerScan role for scheduled Prowler scans"
  permission_model = "SERVICE_MANAGED"
  capabilities     = ["CAPABILITY_NAMED_IAM"]
  template_body    = local.template
  parameters       = local.parameters

  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }

  managed_execution {
    active = true
  }

  operation_preferences {
    max_concurrent_percentage    = 100
    failure_tolerance_percentage = 25
    region_concurrency_type      = "PARALLEL"
  }

  lifecycle {
    ignore_changes = [administration_role_arn]
  }
}

# IAM is global, so a single region is enough.
resource "aws_cloudformation_stack_set_instance" "scan_role" {
  stack_set_name            = aws_cloudformation_stack_set.scan_role.name
  stack_set_instance_region = var.region

  deployment_targets {
    organizational_unit_ids = local.target_ou_ids
  }

  operation_preferences {
    max_concurrent_percentage    = 100
    failure_tolerance_percentage = 25
    region_concurrency_type      = "PARALLEL"
  }
}

# Service-managed StackSets never deploy to the management account, so add the role here directly.
# The workflow also uses this role to list the organization's accounts.
resource "aws_cloudformation_stack" "management_scan_role" {
  #checkov:skip=CKV_AWS_124:One read-only role stack managed by Terraform; stack events add no signal over the Terraform plan
  name          = "prowler-scan-role"
  template_body = local.template
  parameters    = local.parameters
  capabilities  = ["CAPABILITY_NAMED_IAM"]
}
