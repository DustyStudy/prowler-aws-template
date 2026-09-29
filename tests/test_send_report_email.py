"""Tests for scripts/send_report_email.py. DRY_RUN writes the email to a file
instead of calling SES, so nothing here touches AWS."""

import email
import importlib.util
import json
import pathlib
import sys

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "send_report_email.py"
spec = importlib.util.spec_from_file_location("send_report_email", SCRIPT)
sre = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sre)


def _finding(status_code, severity="High", code="s3_bucket_public", status="New"):
    return {"status_code": status_code, "severity": severity, "status": status, "metadata": {"event_code": code}}


def _write_account(reports_dir, account, findings, html="<html>report</html>", flat=False):
    # flat=True mimics download-artifact v5+, which unpacks a lone artifact
    # straight into the download path with no per-account folder.
    acct_dir = reports_dir if flat else reports_dir / f"prowler-{account}"
    acct_dir.mkdir(parents=True, exist_ok=True)
    (acct_dir / f"prowler-{account}.ocsf.json").write_text(json.dumps(findings), encoding="utf-8")
    if html is not None:
        (acct_dir / f"prowler-{account}.html").write_text(html, encoding="utf-8")


def test_summarize_counts_failed_findings_and_excludes_muted(tmp_path):
    path = tmp_path / "f.json"
    path.write_text(
        json.dumps(
            [
                _finding("FAIL", "Critical", "iam_root_mfa"),
                _finding("FAIL", "High", "s3_bucket_public"),
                _finding("FAIL", "High", "s3_bucket_public"),
                _finding("FAIL", "High", "ec2_open_ssh", status="Suppressed"),
                _finding("FAIL", "Low", "tags_missing"),
                _finding("PASS", "High"),
            ]
        ),
        encoding="utf-8",
    )

    s = sre.summarize(path)

    assert s["checks"] == 6
    assert s["passed"] == 1
    assert s["muted"] == 1
    assert s["by_sev"] == {"Critical": 1, "High": 2, "Low": 1}
    assert s["top"] == {("Critical", "iam_root_mfa"): 1, ("High", "s3_bucket_public"): 2}


@pytest.fixture
def run_script(tmp_path, monkeypatch):
    def _run(accounts, names=None, scan_result="success"):
        out = tmp_path / "email.eml"
        monkeypatch.setenv("REPORT_EMAIL", "security@example.com")
        monkeypatch.setenv("ACCOUNTS", json.dumps(accounts))
        monkeypatch.setenv("ACCOUNT_NAMES", json.dumps(names or {}))
        monkeypatch.setenv("SCAN_RESULT", scan_result)
        monkeypatch.setenv("RUN_DATE", "2026-09-27")
        monkeypatch.setenv("RUN_URL", "https://github.com/example/prowler-aws/actions/runs/1")
        monkeypatch.setenv("REPORTS_BUCKET", "prowler-reports-111111111111")
        monkeypatch.setenv("DRY_RUN", str(out))
        monkeypatch.setattr(sys, "argv", ["send_report_email.py", str(tmp_path / "reports")])
        sre.main()
        return email.message_from_bytes(out.read_bytes())

    return _run


def _html_body(msg):
    return next(p for p in msg.walk() if p.get_content_type() == "text/html" and not p.get_filename()).get_payload(decode=True).decode()


def test_email_totals_subject_and_attachments(tmp_path, run_script):
    reports = tmp_path / "reports"
    _write_account(reports, "111111111111", [_finding("FAIL", "Critical"), _finding("FAIL", "High")])
    _write_account(reports, "222222222222", [_finding("FAIL", "High"), _finding("PASS")])

    msg = run_script(["111111111111", "222222222222"], names={"111111111111": "prod", "222222222222": "dev"})

    assert msg["Subject"] == "Prowler 2026-09-27: 1 critical, 2 high across 2 accounts"
    attachments = sorted(p.get_filename() for p in msg.walk() if p.get_filename())
    assert attachments == ["prowler-dev-222222222222-2026-09-27.html", "prowler-prod-111111111111-2026-09-27.html"]


def test_single_account_run_finds_flat_reports(tmp_path, run_script):
    reports = tmp_path / "reports"
    _write_account(reports, "111111111111", [_finding("FAIL", "High")], flat=True)

    msg = run_script(["111111111111"], {"111111111111": "dev"})

    assert "Scan failed" not in _html_body(msg)
    assert [p.get_filename() for p in msg.walk() if p.get_filename()] == ["prowler-dev-111111111111-2026-09-27.html"]


def test_missing_report_is_called_out(tmp_path, run_script):
    (tmp_path / "reports").mkdir()

    msg = run_script(["333333333333"], scan_result="failure")

    assert msg["Subject"].endswith("(failure)")
    assert "Scan failed: no report" in _html_body(msg)


def test_account_names_are_html_escaped(tmp_path, run_script):
    reports = tmp_path / "reports"
    _write_account(reports, "111111111111", [_finding("FAIL", "High")])

    msg = run_script(["111111111111"], names={"111111111111": "<script>alert(1)</script>"})

    body = _html_body(msg)
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


def test_oversized_reports_are_dropped_and_mentioned(tmp_path, run_script, monkeypatch):
    monkeypatch.setattr(sre, "MAX_ATTACHMENT_BYTES", 100)
    reports = tmp_path / "reports"
    _write_account(reports, "111111111111", [_finding("PASS")], html="x" * 50)
    _write_account(reports, "222222222222", [_finding("PASS")], html="x" * 500)

    msg = run_script(["111111111111", "222222222222"])

    assert [p.get_filename() for p in msg.walk() if p.get_filename()] == ["prowler-account-111111111111-2026-09-27.html"]
    assert "1 report(s) were too large to attach" in _html_body(msg)
