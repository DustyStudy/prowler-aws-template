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

## v1.1.0 release candidate (2026-11-24)

The same four-account organization ran the release candidate, with
`create_kms_key` and `enable_access_logging` turned on.

| Check | Result |
|---|---|
| Terraform on the existing deployment | `plan`: 11 to add, 3 to change, 0 to destroy; applied |
| Scan on the old workflow, new Terraform | 4 of 4 accounts succeeded; reports uploaded to the KMS-encrypted bucket |
| Scan on the synced workflow | 4 of 4 accounts succeeded in 4 min 7 s to 5 min 30 s each; whole run 6 min 27 s |
| KMS encryption | `head-object` on a new report: `aws:kms` with the new key, bucket key enabled |
| Versioning | Enabled on the reports bucket |
| Region variables | `SCAN_REGIONS` resolved to the copy's three regions through the workflow default |
| `discover` without Azure blob storage | Succeeded |
| Email with the recipient-limited SES policy | Sent: 4 accounts, 4 HTML attachments, 3,639 KB |
| harden-runner | Started with `egress-policy: block` and the allowlist in every job on the private repo |

A third run on the same day covered the two remaining items:

| Check | Result |
|---|---|
| Prowler 5.45.0 | The private copy moved to the template's hash-pinned 5.45.0 lock (`--no-deps`, overrides, patched floors); the OCSF output reports 5.45.0. All jobs completed inside the harden-runner allowlist |
| `scan_workflow_path` | Subject template set to `repo`, `context`, `job_workflow_ref` with immutable IDs kept; `plan` changed only the runner role's `sub` to `repo:<owner>@<id>/<repo>@<id>:ref:refs/heads/main:job_workflow_ref:<owner>/<repo>/.github/workflows/prowler-scan.yml@refs/heads/main`; applied |
| Scan with both | 4 of 4 accounts, triage and email succeeded in 6 min 6 s |
| Versioning | The account's HTML report held 3 versions after the day's 3 runs |

Not covered by these runs:

- **Access-log delivery.** S3 delivers server access logs with a delay of
  up to a few hours; none had arrived when this was written.
- **GovCloud**: not exercised.
