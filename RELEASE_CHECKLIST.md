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
| 2 | `terraform test` passes for the scanner stack (trust, org limit, S3, SES, versioning) | PASS | 6 passed, 0 failed (plan-only, dummy credentials: **mocked AWS**) |
| 3 | Report email tests pass | PASS | pytest 9 passed in a fresh venv from `requirements/dev.txt --require-hashes`; SES is mocked by `DRY_RUN` |
| 4 | Hash-pinned Prowler lock installs on Linux / Python 3.12 and runs | PASS | `python:3.12-slim` container: `pip install --no-deps --require-hashes -r requirements/prowler.txt` OK; `prowler --version` = 5.45.0; `prowler aws --list-checks` = 662 checks. `pip check` notes h2/pymongo above upstream exact pins: intended, see `requirements/prowler-overrides.txt` |
| 5 | No hardcoded `arn:aws:` in Terraform, CloudFormation or workflows | PASS | grep: only README SCP guidance and a test fixture |
| 6 | No open Dependabot, code-scanning or secret-scanning alerts | PASS | GitHub API, 2026-11-24: 0 / 0 / 0 |
| 7 | Independent security review: no unresolved high/critical findings | PASS | Fable reviewer: 0 critical/high. Codex (gpt-6-astra) review: 2 medium email-script bugs (body not counted in SES size, KeyError on missing metadata) and 1 overstated versioning claim, all fixed with tests. Remaining items fixed or documented (see Decisions) |
| 8 | CI (Terraform 1.15.9, pytest) and Security Scan (Gitleaks, Checkov, Trivy) pass on the release PR | OPEN | Runs on the draft PR |
| 9 | Live org-wide scan passes on the release candidate (Prowler 5.45.0, new allowlist, region variables) | BLOCKED | Last live proof: 2026-10-04, Prowler 5.43.0, commit `1eeaa61` ([docs/PROOF.md](docs/PROOF.md)). Needs the owner to run `gh workflow run prowler-scan.yml` in their private deployed copy after syncing this branch |
| 10 | `scan_workflow_path` (OIDC `sub` pinned to the workflow file) works live | BLOCKED | Plan-tested only. Needs a live apply + scan in the owner's copy (README step 3) |
| 11 | Reports-bucket versioning and SES recipient condition apply cleanly to an existing deployment | BLOCKED | Plan-tested only. Needs `terraform plan`/`apply` in the owner's security account |
| 12 | README and CHANGELOG match the code | PASS | Fixed claims: scan results visibility, egress allowlist, GovCloud steps, 256-account limit, ProwlerScan read scope |
| 13 | Release cut: CHANGELOG `[1.1.0]` dated, tag `v1.1.0`, GitHub release | BLOCKED | Needs owner approval to merge to `main` and publish |
| 14 | GovCloud partition | OPEN (not a release commitment) | Documented as untested in README; no GovCloud org available |

## Decisions

- **Release as 1.1.0** (minor): new optional variables, no breaking interface changes.
- **Reports bucket versioning on**, noncurrent versions expire after `report_retention_days`. Overwritten or expired reports can be retained up to 2× the retention window; at ~300 MB/week this is cents per month.
- **SES `ses:Recipients` restricted to `report_email`.** Upgrade note: the `REPORT_EMAIL` repo variable must equal `report_email` in tfvars, as the README already requires, or the email send is denied.
- **SSE-S3, no access logging, no KMS CMK kept** for the cost target; the README now states this does not meet an 800-53 Moderate/High baseline as shipped. Accepting this as a documented residual risk needs owner sign-off (see Blockers).
- **Egress allowlist kept multi-tenant** (`*.amazonaws.com`, `*.blob.core.windows.net`): narrowing to per-service hosts risks breaking Prowler across regions; documented instead. Removed the unused blob entry from `discover`.
- **Not done:** Dependabot pip version updates (only security updates touch the lock), Prowler upgrade to 5.52.0 (would invalidate the 5.43 allowlist evidence further), chunking >256 accounts (documented limit).
- **Template repo `main` has no branch protection.** Changing repo settings needs owner approval.

## Blockers needing the owner

1. Approve accepting SSE-S3 / no access logging / no CMK as residual risk, or ask for opt-in CMK + logging variables.
2. Run the live checks (#9–#11) in the private deployed copy.
3. Approve merge of the release PR, then the `v1.1.0` tag and release (#13).
4. Optional: enable branch protection on the template repo's `main`.

## AWS resources

None created by this release run.

## Resume point

If a session ends: branch `release/v1-rc` in worktree `C:\repos\_wt\prowler-rc`. Next step: check criterion #8 on the draft PR, then the owner blockers above.
