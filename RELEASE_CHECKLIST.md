# Release checklist: v1.1.0

Release branch: `release/v1-rc` (from `main` at `ecf84bf`). Scope: the
`[Unreleased]` section of `CHANGELOG.md` plus fixes from the release review.
Baseline: the README's documented setup, workflows and security notes, and the
commercial AWS partition (GovCloud is documented but marked untested).

Status: PASS, FAIL, OPEN (needs a run that can't happen locally), BLOCKED (needs the owner).

## Criteria

| # | Criterion | Status | Evidence / blocker |
|---|---|---|---|
| 1 | All three Terraform stacks pass `fmt -check` and `validate` | PASS | Local, Terraform 1.16.6, 2026-11-24. CI pins 1.15.9: see #8 |
| 2 | `terraform test` passes for the scanner stack (trust, org limit, S3, SES, versioning) | PASS | 9 passed, 0 failed, incl. defaults-unchanged, KMS-on and access-logging-on runs (plan-only, dummy credentials: **mocked AWS**) |
| 3 | Report email tests pass | PASS | pytest 9 passed in a fresh venv from `requirements/dev.txt --require-hashes`; SES is mocked by `DRY_RUN` |
| 4 | Hash-pinned Prowler lock installs on Linux / Python 3.12 and runs | PASS | `python:3.12-slim` container: `pip install --no-deps --require-hashes -r requirements/prowler.txt` OK; `prowler --version` = 5.45.0; `prowler aws --list-checks` = 662 checks. `pip check` notes h2/pymongo above upstream exact pins: intended, see `requirements/prowler-overrides.txt` |
| 5 | No hardcoded `arn:aws:` in Terraform, CloudFormation or workflows | PASS | grep: only README SCP guidance and a test fixture |
| 6 | No open Dependabot, code-scanning or secret-scanning alerts | PASS | GitHub API, 2026-11-24: 0 / 0 / 0 |
| 7 | Independent security review: no unresolved high/critical findings | PASS | Fable reviewer: 0 critical/high. Codex (gpt-6-astra) review: 2 medium email-script bugs (body not counted in SES size, KeyError on missing metadata) and 1 overstated versioning claim, all fixed with tests. Remaining items fixed or documented (see Decisions). Codex confirm pass on the KMS/logging change: 1 medium (kms:ViaService used the partition DNS suffix; KMS docs require `.amazonaws.com` in all partitions), fixed |
| 8 | CI (Terraform 1.15.9, pytest) and Security Scan (Gitleaks, Checkov, Trivy) pass on the release PR | PASS (re-check on head) | 12/12 checks passed on `4e90bb1` (PR #34): Terraform ×3, pytest, CodeQL, Checkov, Trivy, Gitleaks, zizmor. Later commits only touch the email script, its tests and docs; confirm green on the PR head before merge |
| 9 | Live org-wide scan passes on the release candidate (new workflow, region variables, email script) | PASS | Run 2 (2026-11-24, private copy after merging the synced workflow, `3f46956`): discover without blob egress, 4/4 scans, triage and email succeeded in 6 min 27 s; `SCAN_REGIONS` resolved via default; email sent under the `ses:Recipients` policy. Private copy runs Prowler 5.43.0, so 5.45.0 is covered by #4 (container) only |
| 10 | `scan_workflow_path` (OIDC `sub` pinned to the workflow file) works live | OPEN (optional) | Plan-tested only. Needs a live apply + scan in the owner's copy (README step 3) |
| 11 | Versioning, SES recipient condition, KMS key and access logging apply cleanly to an existing deployment, and a scan uploads to the KMS-encrypted bucket | PASS (logs pending) | Private copy, 2026-11-24: plan 11 add / 3 change / 0 destroy, applied. Run 1 uploaded 236 objects; head-object shows `aws:kms` with the new key and bucket key enabled; versioning Enabled. Access-log delivery not yet observed (S3 delivers with hours of delay) |
| 12 | README and CHANGELOG match the code | PASS | Fixed claims: scan results visibility, egress allowlist, GovCloud steps, 256-account limit, ProwlerScan read scope |
| 13 | Release cut: CHANGELOG `[1.1.0]` dated, tag `v1.1.0`, GitHub release | PASS | PR #34 squash-merged as `667bf33` after 12/12 checks; tag `v1.1.0` and release published 2026-11-24 (owner approved after the live scan) |
| 14 | GovCloud partition | OPEN (not a release commitment) | Documented as untested in README; no GovCloud org available |

## Decisions

- **Release as 1.1.0** (minor): new optional variables, no breaking interface changes.
- **Reports bucket versioning on**, noncurrent versions expire after `report_retention_days`. Overwritten or expired reports can be retained up to 2× the retention window; at ~300 MB/week this is cents per month.
- **SES `ses:Recipients` restricted to `report_email`.** Upgrade note: the `REPORT_EMAIL` repo variable must equal `report_email` in tfvars, as the README already requires, or the email send is denied.
- **Production hardening is opt-in** (owner delegated the call, 2026-11-24): `create_kms_key` (CMK, rotation, 30-day deletion window, bucket key) and `enable_access_logging` (separate SSE-S3, TLS-only log bucket; S3 log delivery doesn't support SSE-KMS targets). Defaults stay off so the documented cost (<$1/month) and existing deployments are unchanged; the README's Production hardening section tells production users to turn both on.
- **Runner KMS grant is `kms:GenerateDataKey` + `kms:Decrypt`** with `kms:ViaService = s3.<region>`: Decrypt is required for multipart uploads (reports over 8 MB). The runner has no `s3:GetObject`, so it still can't read reports back.
- **`docs/COST.md` no longer suggests making the repo public** to save Actions minutes (would expose findings).
- **Test file needs Terraform >= 1.11** (`override_during`); stacks still accept >= 1.10. CI pins 1.15.9.
- **Egress allowlist kept multi-tenant** (`*.amazonaws.com`, `*.blob.core.windows.net`): narrowing to per-service hosts risks breaking Prowler across regions; documented instead. Removed the unused blob entry from `discover`.
- **Not done:** Dependabot pip version updates (only security updates touch the lock), Prowler upgrade to 5.52.0 (would invalidate the 5.43 allowlist evidence further), chunking >256 accounts (documented limit).
- **Template repo `main` is protected** by the active "Protect main" ruleset (PR required, squash only, required CI and security checks, CodeQL gate, no force push or deletion, no bypass) and release tags by "Protect release tags". An earlier note here said it was unprotected: the classic branch-protection API doesn't report rulesets.

## Blockers needing the owner

None for v1.1.0. Follow-ups after release:

1. Access-log delivery to `prowler-reports-logs-<account>`: configuration verified 2026-11-24; first delivery not yet observed.
2. Live run on Prowler 5.45.0 (private copy upgrade in progress), and `scan_workflow_path` pinning.
3. GovCloud: no GovCloud organization available to test.

## AWS resources

Created in the owner's private deployment by the owner's apply (not disposable, part of the release): KMS key + alias `alias/prowler-reports`, log bucket `prowler-reports-logs-<account>` and its settings, versioning on the reports bucket. Nothing created by this session.

## Notes

- The private copy's #19 says harden-runner disables itself on private repos without a StepSecurity plan. Run 1's log shows the agent starting with `EgressPolicy:block`, `Private:true` and the allowlist loaded in every job, and no disable message. Enforcement of a blocked call was not tested; template docs unchanged.

## Resume point

Released 2026-11-24 as v1.1.0. The release branch and worktree were removed after merge.
