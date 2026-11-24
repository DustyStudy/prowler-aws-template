# Changelog

All notable changes to this template are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

If you made your own copy from this template, compare your copy against
the release you started from to see what changed.

## [Unreleased]

## [1.1.0] - 2026-11-24

### Security

- New optional `scan_workflow_path` variable: when set, the runner role's
  trust policy requires the OIDC `sub` to name that workflow file on
  `main` (`...:ref:refs/heads/main:job_workflow_ref:<file>@refs/heads/main`),
  which needs `job_workflow_ref` added to the repo's OIDC subject template.
  Without it, `sub` matches any workflow file on `main`; the October 2026
  GhostAction campaign committed credential-stealing workflows to default
  branches with stolen maintainer tokens
  ([Socket](https://socket.dev/blog/ghostaction-cloud-credentials)).
  Off by default, because a wrong path or template locks the scan out of
  the role. (An earlier unreleased version used a separate
  `job_workflow_ref` condition, which IAM doesn't evaluate for GitHub
  tokens, so it would have blocked the role.)

- The scan workflow's jobs run with blocked egress (`harden-runner`): only
  GitHub, Azure artifact storage (scan and email jobs), PyPI (scan job) and
  `*.amazonaws.com` are reachable while the jobs hold AWS credentials. These
  are multi-tenant domains, so this narrows exfiltration but cannot rule it out.

- The reports bucket is versioned, with noncurrent versions expiring on the
  same schedule as reports, so a report overwritten by a workflow on `main`
  stays recoverable until then. Nothing alerts on an overwrite.

- The runner role can send SES email only to the configured `report_email`
  (`ses:Recipients`), not just only from the configured sender. This matters
  once the account leaves the SES sandbox.

- The scan job installs Prowler from `requirements/prowler.txt` with
  `--require-hashes`, so every package in its dependency tree is
  hash-checked before the job assumes a role in each account.

- New opt-in `create_kms_key` (customer-managed KMS key for the reports
  bucket, with rotation, a 30-day deletion window and an S3 bucket key) and
  `enable_access_logging` (S3 server access logs to a separate private,
  TLS-only bucket). Both default to off, so existing deployments plan with
  no changes. The README's new Production hardening section recommends both.

### Changed

- Role ARNs in the scan workflow take their partition from the optional
  `AWS_PARTITION` repository variable (default `aws`) instead of a
  hardcoded `arn:aws:`.
- The Prowler version now lives in `requirements/prowler.in`, not
  `PROWLER_VERSION` in the workflow.
- `AWS_REGION` and `SCAN_REGIONS` come from optional repository variables
  (default `us-east-1`), so changing regions or moving to GovCloud needs no
  workflow edit. The README lists the Terraform settings GovCloud also needs.

### Fixed

- The report email is still sent when one account's OCSF file is truncated
  or unreadable; that account is listed as failed.
- The report email measures the whole encoded message, body included, and
  drops the largest attachments until it fits the 40 MB SES limit. The old
  30 MiB attachment-only cap could exceed it.
- A finding without `metadata.event_code` no longer aborts the email; it is
  listed as `unknown`.
- The README no longer says scan results never reach the repo: job
  summaries, run logs and (with email on) one-day artifacts carry them. It
  now also documents the 256-account-per-run matrix limit.
- `docs/COST.md` no longer suggests making the repo public to save Actions
  minutes, which would expose findings through summaries, logs and artifacts.

## [1.0.0] - 2026-09-29

First tagged release, under the MIT license. Commits before this release
were published under Apache 2.0.

### Added
- Weekly, organization-wide Prowler scans in GitHub Actions. There is no
  always-on AWS compute, and it costs well under $1/month.
- GitHub OIDC trust pinned to `main` of one repository by immutable
  repository and owner IDs. No stored AWS keys.
- Read-only `ProwlerScan` role in every account through a service-managed
  StackSet that auto-deploys to new accounts. `sts:AssumeRole` is limited
  to the organization.
- HTML, CSV and OCSF reports in S3 under `reports/<date>/<account>/`.
- Optional SES report email with finding counts and attachments, sent
  from an optional separate verified address.
- Bootstrap stack for the Terraform state bucket.
- Tests: `terraform test` for the scanner stack, run against the rendered
  IAM policy JSON, and pytest for the report email script.
- CI: Gitleaks, Checkov and Trivy on every PR and weekly, plus CodeQL.
  Actions are pinned to commit SHAs.

### Fixed
- The state bucket denies non-HTTPS access.
- The report email finds reports when a single artifact is downloaded.

[Unreleased]: https://github.com/DustyStudy/prowler-aws-template/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/DustyStudy/prowler-aws-template/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/DustyStudy/prowler-aws-template/releases/tag/v1.0.0
