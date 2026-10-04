# Changelog

All notable changes to this template are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

If you made your own copy from this template, compare your copy against
the release you started from to see what changed.

## [Unreleased]

### Security

- The scan job installs Prowler from `requirements/prowler.txt` with
  `--require-hashes`, so every package in its dependency tree is
  hash-checked before the job assumes a role in each account.

### Changed

- Role ARNs in the scan workflow take their partition from the optional
  `AWS_PARTITION` repository variable (default `aws`) instead of a
  hardcoded `arn:aws:`.
- The Prowler version now lives in `requirements/prowler.in`, not
  `PROWLER_VERSION` in the workflow.

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

[Unreleased]: https://github.com/DustyStudy/prowler-aws-template/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/DustyStudy/prowler-aws-template/releases/tag/v1.0.0
