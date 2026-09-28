# Cost breakdown

These assumptions are illustrative: 10 accounts, us-east-1 only, weekly scans, and about 2 MB of reports per account per scan.

| Item | Cost | Notes |
|---|---|---|
| Compute | **$0** | GitHub-hosted runners. No EC2/ECS/Lambda/NAT |
| GitHub Actions minutes | $0 within 2,000 min/month (private repo) | ~10 min/account/scan → 10 accounts × 4.3 runs ≈ 430 min/month. Each matrix job is billed separately, rounded up to the minute |
| S3 reports | ~$0.02/month | ~1 GB after a year × $0.023/GB. Expired after 365 days |
| S3 requests | < $0.01/month | A few hundred PUTs per week |
| Terraform state bucket | < $0.01/month | |
| IAM, OIDC, StackSets, Organizations | $0 | |
| AWS Budgets | $0 | The first 2 budgets are free |
| SNS email summaries (optional) | $0 | The first 1,000 email deliveries a month are free. The AWS-managed `aws/sns` key has no monthly fee |
| API calls made by Prowler | $0 | Read-only Describe/List/Get calls are free. CloudTrail management events are free for the first trail |

## Choices made to keep cost down

- **No Prowler App**: its UI, API, Postgres, and Valkey run all the time and would cost roughly $50–150/month.
- **No NAT gateway, VPC, or containers in AWS**: the scan runs entirely in GitHub.
- **SSE-S3 instead of a KMS key**: this saves $1/month per key plus request charges.
- **No Glacier transitions**: the reports are small. Glacier IR charges each object as at least 128 KB, and transitions carry per-request fees, so moving the reports would cost more than keeping them in S3 Standard.
- **Security Hub integration off**: Security Hub charges for each finding it ingests. Enable it with `-S` only if you already pay for Security Hub.
- **One region**: scan time, and therefore Actions minutes, grows with each region scanned.

## Watch for

- **Actions minutes on large orgs**: past about 40 accounts, you may exceed 2,000 min/month.
  - Scan less often, split accounts across days, or make the repo public (public repos get unlimited minutes; reports never go to the repo).
  - Check usage with `gh api /users/<user>/settings/billing/usage` (or `/orgs/<org>/settings/billing/usage`), or under Settings → Billing.
- **Scheduled workflows**: GitHub disables them after 60 days without repo activity (public repos only). Private repos are not affected.
