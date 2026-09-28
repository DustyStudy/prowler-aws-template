terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # bucket (and optional profile) come from backend.hcl
  backend "s3" {
    key          = "scanner/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

# Runs with SECURITY account credentials (e.g. AWS_PROFILE=security).
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "prowler-aws"
      ManagedBy = "terraform"
    }
  }
}
