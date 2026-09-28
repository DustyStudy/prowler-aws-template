# prowler-aws

Low-cost, org-wide [Prowler](https://github.com/prowler-cloud/prowler) scanning for AWS.
Prowler runs **weekly in GitHub Actions** (no always-on AWS compute), assumes a read-only
role in every account of the AWS Organization, and writes HTML/CSV/OCSF reports to S3.

Expected AWS cost: **well under $1/month**. See [docs/COST.md](docs/COST.md).

This repo is a template. It contains no account IDs, bucket names, or GitHub identifiers.
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

Keep your copy **private**. Scan results never go to the repo, but the workflow file and
repo variables reveal your account IDs.

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

The SES account stays in sandbox mode, which can send only to verified addresses. That works because the sender and recipient are the same verified address. Use a team list address so everyone gets the report. If the first email lands in spam, mark it "Not spam". Unset the `REPORT_EMAIL` variable to turn emails off.

## Viewing reports

```sh
aws s3 ls s3://prowler-reports-<id>/reports/ --profile security
aws s3 cp s3://prowler-reports-<id>/reports/<date>/<account>/prowler-<account>.html . --profile security
```

`compliance/` holds per-framework CSVs (CIS, NIST, SOC 2, and others).

## Common changes

| Want | Change |
|---|---|
| More regions | `SCAN_REGIONS` in the workflow (space-separated) |
| Different schedule | `cron` in the workflow |
| Upgrade Prowler | `PROWLER_VERSION` in the workflow; review the [release notes](https://github.com/prowler-cloud/prowler/releases). Also re-sync `org-roles/templates/prowler-scan-role.yaml` with upstream `permissions/prowler-additions-policy.json` |
| Keep reports longer or shorter | `report_retention_days` in `scanner` |
| Scan only some OUs | `target_ou_ids` in `org-roles` |

## Security notes

- Only workflows on `main` can assume the runner role (OIDC `sub` condition). PR branches cannot.
- The runner can only assume roles named `ProwlerScan` in accounts of *your* organization
  (`aws:ResourceOrgID`), and can only `PutObject` under `reports/`.
- `ProwlerScan` is read-only (`SecurityAudit` + `ViewOnlyAccess` + Prowler's read-only additions)
  and trusts only the runner role.
- Protect `main` with branch protection. Anyone who can push to it can change the workflow.
- Third-party actions are pinned to commit SHAs. Dependabot opens PRs to update them.
