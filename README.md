# AWS Organization Prowler Scan Template

[![CI](https://github.com/DustyStudy/prowler-aws-template/actions/workflows/ci.yml/badge.svg)](https://github.com/DustyStudy/prowler-aws-template/actions/workflows/ci.yml)
[![Security Scan](https://github.com/DustyStudy/prowler-aws-template/actions/workflows/security-scan.yml/badge.svg)](https://github.com/DustyStudy/prowler-aws-template/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Low-cost, org-wide [Prowler](https://github.com/prowler-cloud/prowler) scanning for AWS.
Prowler runs **weekly in GitHub Actions** (no always-on AWS compute), assumes a read-only
role in every account of the AWS Organization, and writes HTML/CSV/OCSF reports to S3.

Expected AWS cost is **well under $1/month** under the [documented cost assumptions](docs/COST.md). The [reference deployment](docs/PROOF.md) scanned a four-account organization.

The template uses your AWS account IDs, report bucket, and GitHub deployment configuration.
You supply those at setup time, and they stay in gitignored files (`terraform.tfvars`,
`backend.hcl`) and in GitHub repository variables.

```
GitHub Actions (weekly cron / manual)
   │  OIDC (no stored AWS keys)
   ▼
Security account ── prowler-gha-runner role ── S3: prowler-reports-<acct>/reports/<date>/<account>/
   │  sts:AssumeRole
   ▼
Every org account ── ProwlerScan role (read-only; StackSet, auto-deploys to new accounts)
```

## Layout

| Path | Applied with | Purpose |
|---|---|---|
| `terraform/bootstrap/` | security account | S3 bucket for Terraform state (one-time, local state) |
| `terraform/scanner/` | security account | GitHub OIDC provider, runner role, reports bucket, optional budget |
| `terraform/org-roles/` | **management** account | StackSet → `ProwlerScan` in every member account, plus the management account itself |
| `.github/workflows/prowler-scan.yml` | – | Discovers accounts, scans each in parallel (max 5), uploads reports |
| `config/mutelist.example.yaml` | – | Copy to `config/mutelist.yaml` to mute accepted findings |

## Get your own copy

Click **Use this template** on GitHub, or:

```sh
gh repo create <your-org>/prowler-aws --private --template DustyStudy/prowler-aws-template --clone
```

Keep your copy **private**. Scan results are never committed, but anyone who can read the
repo's Actions runs sees each account's severity counts (job summary), Prowler's run log
and, with email enabled, the full reports as one-day artifacts. The repo variables also
reveal your account IDs.

## Prerequisites

- Terraform >= 1.10, AWS CLI v2, `gh`
- Two AWS CLI profiles (IAM Identity Center/SSO is fine):
  - `security`: admin in the dedicated security/audit account
  - `management`: admin in the Organization management account

## Setup

### 1. Enable StackSets trusted access (once, management account)

```sh
aws cloudformation activate-organizations-access --profile management
```

### 2. Bootstrap the state bucket (security account)

```sh
cd terraform/bootstrap
AWS_PROFILE=security terraform init
AWS_PROFILE=security terraform apply
```

This stack's state is local. It only owns the state bucket, which has `prevent_destroy` set.

### 3. Scanner stack (security account)

```sh
cd ../scanner
cp backend.hcl.example backend.hcl                 # set bucket = <state_bucket output>
cp terraform.tfvars.example terraform.tfvars      # set github_owner, github_repo
AWS_PROFILE=security terraform init -backend-config=backend.hcl
AWS_PROFILE=security terraform apply
```

`github_owner` and `github_repo` must match **your** copy of this repo. The runner role
trusts only workflows on that repo's `main` branch. GitHub's OIDC subject for new repos
includes numeric IDs, so also set `github_owner_id` and `github_repo_id`:

```sh
gh api repos/<owner>/<repo> --jq '.owner.id, .id'
```

To confirm the format, run `gh api repos/<owner>/<repo>/actions/oidc/customization/sub`.
`use_immutable_subject` should be `true`. If it is `false`, change the `sub` condition in
`scanner/main.tf` to `repo:<owner>/<repo>:ref:refs/heads/main`.

The `sub` condition matches every workflow file on `main`. To limit the role to the scan
workflow, pin the file inside `sub`. IAM evaluates only the `amr`, `aud`, `email`, `oaud`
and `sub` claims of a GitHub token as condition keys, so a separate `job_workflow_ref`
condition would never match. After your first successful scan:

1. Add `job_workflow_ref` to the repo's OIDC subject template:

   ```sh
   gh api -X PUT repos/<owner>/<repo>/actions/oidc/customization/sub \
     -F use_default=false -f 'include_claim_keys[]=repo' \
     -f 'include_claim_keys[]=context' -f 'include_claim_keys[]=job_workflow_ref'
   ```

2. Set `scan_workflow_path = ".github/workflows/prowler-scan.yml"` and apply. The `sub`
   condition becomes
   `repo:<owner>@<owner-id>/<repo>@<repo-id>:ref:refs/heads/main:job_workflow_ref:<owner>/<repo>/.github/workflows/prowler-scan.yml@refs/heads/main`.

Do both, or neither: the template changes the subject of every token the repo issues.
Names are case-sensitive, and a mismatch fails the scan with
`Not authorized to perform sts:AssumeRoleWithWebIdentity`. To go back, unset the variable,
apply, and reset the template with `-F use_default=true`.

If the account already has the GitHub OIDC provider, set `create_github_oidc_provider = false`.

### 4. Org roles (management account)

```sh
cd ../org-roles
cp backend.hcl.example backend.hcl                 # same bucket, profile = "security"
AWS_PROFILE=management terraform init -backend-config=backend.hcl
AWS_PROFILE=management terraform apply -var scanner_account_id=<SECURITY_ACCOUNT_ID>
```

State stays in the security account; resources are created with management credentials.

> **Delegated admin?** Not needed. This stack always runs from the management account,
> which works whether or not the security account is a StackSets delegated administrator.

### 5. GitHub repository variables

```sh
gh variable set SCANNER_ACCOUNT_ID    --body "<security account id>"
gh variable set MANAGEMENT_ACCOUNT_ID --body "<management account id>"
gh variable set REPORTS_BUCKET        --body "prowler-reports-<security account id>"
```

(The values come from the `scanner` and `org-roles` outputs.) Until `SCANNER_ACCOUNT_ID`
is set, the scan workflow skips instead of failing.

### 6. First scan

```sh
gh workflow run prowler-scan.yml                          # all accounts
gh workflow run prowler-scan.yml -f accounts=123456789012 # one account
gh run watch
```

Each account's job summary shows failed findings by severity.

## Email reports (optional)

After each run, the `email` job sends one message with:
- A table of failed findings per account, not counting muted ones.
- The critical and high checks.
- Each account's HTML report attached.

It uses Amazon SES in the security account (about $0.0001 per email).

To enable it:
1. Set `report_email` in `terraform/scanner/terraform.tfvars` and apply. AWS emails that address a verification link; click it.
2. `gh variable set REPORT_EMAIL --body "<same address>"`

The SES account stays in sandbox mode, which can send only to verified addresses. By default the sender and recipient are the same verified address. Use a team list address so everyone gets the report. If the first email lands in spam, mark it "Not spam". Unset the `REPORT_EMAIL` variable to turn emails off.

**Separate sender (optional).** Some mail providers, Gmail included, file mail "from" your own address as sent mail rather than showing it in the inbox. To avoid that, send from a second address, such as a `+prowler` alias:

1. Also set `report_from_email` in `terraform.tfvars` and apply. Click the verification link sent to that address too.
2. `gh variable set REPORT_FROM_EMAIL --body "$(terraform -chdir=terraform/scanner output -raw report_from_email)"`

## Viewing reports

```sh
aws s3 ls s3://prowler-reports-<id>/reports/ --profile security
aws s3 cp s3://prowler-reports-<id>/reports/<date>/<account>/prowler-<account>.html . --profile security
```

`compliance/` holds per-framework CSVs (CIS, NIST, SOC 2, and others).

## Common changes

| Want | Change |
|---|---|
| More regions | `gh variable set SCAN_REGIONS --body "us-east-1 us-west-2"` (space-separated; default `us-east-1`) |
| Different schedule | `cron` in the workflow |
| GovCloud partition | Repository variables: `AWS_PARTITION=aws-us-gov`, `AWS_REGION=us-gov-west-1`, `SCAN_REGIONS="us-gov-west-1 us-gov-east-1"`. Terraform: add `region = "us-gov-west-1"` to each `backend.hcl`, pass `-var region=us-gov-west-1` to every stack, and set `AWS_USE_FIPS_ENDPOINT=true` in the shell that runs it. Not yet tested live in GovCloud (see [docs/PROOF.md](docs/PROOF.md)) |
| Upgrade Prowler | The version in `requirements/prowler.in`, then recompile `requirements/prowler.txt` (command in that file); review the [release notes](https://github.com/prowler-cloud/prowler/releases). Also re-sync `terraform/org-roles/templates/prowler-scan-role.yaml` with upstream `permissions/prowler-additions-policy.json` |
| Keep reports longer or shorter | `report_retention_days` in `scanner` |
| Scan only some OUs | `target_ou_ids` in `org-roles` |

## Production hardening

The defaults are built for the lowest cost. For production, set these in
`terraform/scanner/terraform.tfvars` and apply:

```hcl
create_kms_key        = true # customer-managed KMS key for the reports bucket, rotated yearly
enable_access_logging = true # S3 server access logs in prowler-reports-logs-<account>
scan_workflow_path    = ".github/workflows/prowler-scan.yml" # after step 3's subject template change
```

- **KMS key:** about $1/month. The bucket uses an S3 bucket key, so KMS request
  charges stay small. The runner role can use it only through S3 uploads
  (`kms:GenerateDataKey`, plus `kms:Decrypt` for multipart uploads) and still has no
  `s3:GetObject`, so it cannot read reports back. To read
  reports, a principal needs `kms:Decrypt` on the key (`kms_key_arn` output) through
  IAM; the key policy delegates to IAM in the security account. Reports written before
  the switch stay SSE-S3 until they expire.
- **Access logging:** a few cents a month. The log bucket uses SSE-S3, because S3 access
  log delivery does not support SSE-KMS default encryption. Logs expire after
  `report_retention_days`.
- Also protect `main` (required reviews, no force pushes), keep the repo private, and
  limit who can edit repository variables.

## Security notes

- Only workflows on `main` can assume the runner role (OIDC `sub` condition). PR branches cannot.
  With `scan_workflow_path` set and the subject template customized, only that workflow file
  can (`job_workflow_ref` inside `sub`).
- The runner can only assume roles named `ProwlerScan` in accounts of *your* organization
  (`aws:ResourceOrgID`), and can only `PutObject` under `reports/`.
- `ProwlerScan` is read-only (`SecurityAudit` + `ViewOnlyAccess` + Prowler's read-only additions)
  and trusts only the runner role. Read-only still covers sensitive data: Prowler's additions
  can fetch Lambda code and environment variables, ECR image layers and CloudWatch Logs
  events, so treat the runner role as able to read those in every account.
- The scan jobs run with `harden-runner` in block mode. The allowlist names GitHub, Azure
  artifact storage (scan and email jobs), PyPI (scan job) and `*.amazonaws.com`. These are
  multi-tenant domains, so it narrows exfiltration of the job's credentials but cannot rule it out.
- The reports bucket is versioned, so a report overwritten by a workflow on `main` stays
  recoverable (`aws s3api list-object-versions`) until its old version expires. Nothing
  alerts on an overwrite, and a plain download returns the newest version.
- By default the reports bucket uses SSE-S3 and has no access logging, to keep cost near
  zero. **For production, or a NIST SP 800-53 Moderate/High baseline, turn both on** (see
  [Production hardening](#production-hardening)).
- Protect `main` with branch protection. Anyone who can push to it can change the workflow.
- Third-party actions are pinned to commit SHAs. Dependabot opens PRs to update them.

## Limits

- GitHub allows at most 256 jobs per matrix, so one run scans at most 256 accounts. Larger
  organizations can run the workflow several times with the `accounts` input.
- At most 5 accounts scan at once (`max-parallel`). The rest queue.

## Service control policies

Prowler needs to reach every region you scan, and the StackSet needs to
update `ProwlerScan` in every account. If your organization uses SCPs that
restrict regions or protect IAM roles (for example
[aws-org-guardrails](https://github.com/DustyStudy/aws-org-guardrails)):

- Exempt `arn:aws:iam::*:role/ProwlerScan` and
  `arn:aws:iam::*:role/stacksets-exec-*`, the role service-managed StackSets
  use in member accounts. `ProwlerScan` is read-only, so the exemption only
  lets it read.
- Protect the same role names, so nobody in a member account can create or
  change a role with those names and inherit the exemption.
- Otherwise a region deny shows up as access-denied errors for every region
  in `SCAN_REGIONS` outside the allowed list, and StackSet updates fail.

## Tests and CI

- `terraform/scanner/tests/` checks the security notes above against the
  rendered IAM policy JSON: the OIDC trust is pinned to `main` of one repo
  by immutable ID and, when `scan_workflow_path` is set, to that workflow file, `sts:AssumeRole` is limited to your organization,
  S3 writes are limited to `reports/`, and SES sending is limited to the
  configured sender and recipient, and the reports bucket is versioned. The tests plan with dummy credentials, so they need
  no AWS account (`terraform init -backend=false && terraform test`; the
  test file needs Terraform 1.11 or later).
- `tests/` covers the report email script: finding counts, muted
  findings, missing or truncated reports, HTML escaping, and the attachment size limit
  (`python -m pytest tests`).
- `security-scan.yml` runs Gitleaks, Checkov and Trivy on every PR and
  weekly. Accepted Checkov findings are skipped inline with the reason.

Latest results (release candidate, 2026-11-24): `terraform test` 9/9 and
pytest 9/9 pass, all stacks validate, and the hash-pinned Prowler 5.45.0 lock
installs and runs in a Linux Python 3.12 container. These use dummy AWS
credentials and a mocked SES send. The last live org-wide scan was on Prowler
5.43.0 ([docs/PROOF.md](docs/PROOF.md)); the live run for this release is still
open. Details: [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
