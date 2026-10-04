# Live proof

The scan workflow in this template was run against a real AWS Organization
on 2026-10-04. This page records the setup, what the run produced, and what
it did not cover. Account IDs, bucket names and finding details are left
out: the deployment is a private copy of this template, as the README
recommends.

## Setup

- **Organization:** four active accounts (management, a dedicated security
  account, and two workload accounts), with service control policies
  attached at the root.
- **Deployed from this template:** `terraform/bootstrap` and
  `terraform/scanner` in the security account, and `terraform/org-roles`
  from the management account, which puts the read-only `ProwlerScan` role
  in every account through a StackSet.
- **Workflow:** `.github/workflows/prowler-scan.yml` as of commit `1eeaa61`,
  started by hand with `gh workflow run prowler-scan.yml`. The private copy
  differs from the template in two settings only: it scans three regions
  instead of one, and it passes a Prowler config file.
- **Repository settings:** Actions limited to GitHub-owned actions,
  `aws-actions/configure-aws-credentials` and `step-security/harden-runner`,
  with SHA pinning required.

## Results

| Step | Result |
|---|---|
| Discover accounts | 4 active accounts listed from AWS Organizations, 21 s |
| Scan (4 parallel jobs) | 4 of 4 succeeded, 4 min 39 s to 5 min 18 s each |
| Reports in S3 | HTML, CSV, OCSF JSON and per-framework compliance CSVs under `reports/2026-10-04/<account>/` for all 4 accounts |
| Email reports | One message sent through SES with 4 HTML attachments (3,850 KB) |
| Whole run | 6 min 9 s, start to finish |

What the run shows about each control in the workflow:

| Control | Evidence |
|---|---|
| No stored AWS keys | Every job reached AWS through GitHub OIDC. The repository holds no AWS secrets. |
| Role chaining | Each scan job assumed the runner role in the security account, and Prowler assumed `ProwlerScan` in the target account from there. |
| Blocked egress | harden-runner ran with `egress-policy: block` in all six jobs. Checkout, the hash-checked install from PyPI, every AWS call, the S3 upload and the SES send all completed inside the allowlist, so the list in the workflow is complete for Prowler 5.43.0. |
| Hash-pinned install | `pip install --require-hashes -r requirements/prowler.txt` succeeded on the runner in all four scan jobs. The OCSF output reports Prowler 5.43.0. |
| Mutelist | 132 findings across the four accounts were written as `Suppressed` and left out of the job summaries and the email. |
| Service control policies | The scans completed with the organization's SCPs in place, including a region restriction. The scan role is exempt, as described in the README. |

The OCSF files hold 1,474 check results (pass and fail) across the four
accounts. The email subject line matched the severity counts in those files.

## Cost

The run used about 21 runner-minutes. AWS charges were S3 storage for
278 MB of reports (236 objects for the day) and one SES message. See [COST.md](COST.md).

## Not covered

- **GovCloud.** The workflow takes the ARN partition from
  `vars.AWS_PARTITION`, and the Terraform uses the current partition, but
  this run was in the commercial partition only.
- **The scheduled trigger on this exact commit.** The run was started by
  hand. The weekly schedule has fired on earlier versions of the workflow.
- **A fresh setup from the README.** The three Terraform stacks were
  applied when the private copy was created, not as part of this run.
- **Large organizations.** Four accounts ran in parallel under the
  `max-parallel: 5` limit. Queueing beyond five accounts was not exercised.
