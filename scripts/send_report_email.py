"""Email a Prowler run summary with each account's HTML report attached, via Amazon SES.

Usage: send_report_email.py <reports_dir>
  <reports_dir> holds one sub-directory per account (downloaded artifacts), each with
  prowler-<account>.ocsf.json and prowler-<account>.html.

Env: REPORT_EMAIL, REPORT_FROM_EMAIL (optional, defaults to REPORT_EMAIL), ACCOUNTS (JSON list), ACCOUNT_NAMES (JSON object id -> name),
     SCAN_RESULT, RUN_DATE, RUN_URL, REPORTS_BUCKET
"""

import base64
import html
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from email.message import EmailMessage
from pathlib import Path

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEV_COLORS = {"Critical": "#7a1c1c", "High": "#c0392b", "Medium": "#d68910", "Low": "#5d6d7e"}
MAX_ATTACHMENT_BYTES = 30 * 1024 * 1024  # SES v2 raw limit is 40 MB incl. base64 overhead


def summarize(ocsf_path: Path) -> dict:
    findings = json.loads(ocsf_path.read_text(encoding="utf-8"))
    failed = [f for f in findings if f.get("status_code") == "FAIL"]
    active = [f for f in failed if f.get("status") != "Suppressed"]
    by_sev = Counter(f.get("severity") for f in active)
    top = Counter(
        (f.get("severity"), f["metadata"]["event_code"])
        for f in active
        if f.get("severity") in ("Critical", "High")
    )
    return {
        "checks": len(findings),
        "passed": sum(1 for f in findings if f.get("status_code") == "PASS"),
        "muted": len(failed) - len(active),
        "by_sev": by_sev,
        "top": top,
    }


def main() -> None:
    reports_dir = Path(sys.argv[1])
    to_addr = os.environ["REPORT_EMAIL"]
    from_addr = os.environ.get("REPORT_FROM_EMAIL") or to_addr
    accounts = json.loads(os.environ["ACCOUNTS"])
    names = json.loads(os.environ.get("ACCOUNT_NAMES") or "{}")
    run_date = os.environ["RUN_DATE"]
    run_url = os.environ["RUN_URL"]
    bucket = os.environ["REPORTS_BUCKET"]

    rows, details, attachments, totals = [], [], [], Counter()
    for acct in accounts:
        label = f"{names.get(acct, '')} ({acct})".strip()
        # download-artifact (v5+) unpacks a lone matching artifact straight
        # into reports/ instead of reports/prowler-<acct>/, so a
        # single-account run has no per-account folder.
        acct_dir = reports_dir / f"prowler-{acct}"
        if not acct_dir.is_dir():
            acct_dir = reports_dir
        ocsf = acct_dir / f"prowler-{acct}.ocsf.json"
        report = acct_dir / f"prowler-{acct}.html"

        if not ocsf.exists():
            rows.append(
                f"<tr><td>{html.escape(label)}</td>"
                f"<td colspan='6' style='color:#c0392b'>Scan failed: no report. See the run log.</td></tr>"
            )
            continue

        s = summarize(ocsf)
        totals.update(s["by_sev"])
        cells = "".join(
            f"<td style='text-align:right;{'font-weight:bold;color:' + SEV_COLORS[sev] if s['by_sev'][sev] else 'color:#999'}'>"
            f"{s['by_sev'][sev]}</td>"
            for sev in SEVERITIES
        )
        rows.append(
            f"<tr><td>{html.escape(label)}</td>{cells}"
            f"<td style='text-align:right;color:#999'>{s['muted']}</td>"
            f"<td style='text-align:right;color:#999'>{s['passed']}/{s['checks']}</td></tr>"
        )
        if s["top"]:
            items = "".join(
                f"<li><b style='color:{SEV_COLORS[sev]}'>{sev}</b> {html.escape(code)} &times;{n}</li>"
                for (sev, code), n in sorted(s["top"].items(), key=lambda kv: (SEVERITIES.index(kv[0][0]), -kv[1]))
            )
            details.append(f"<h4 style='margin:16px 0 4px'>{html.escape(label)}</h4><ul style='margin:0'>{items}</ul>")
        if report.exists():
            safe_name = "".join(c if c.isalnum() or c in "-_" else "-" for c in names.get(acct, "account"))
            attachments.append((f"prowler-{safe_name}-{acct}-{run_date}.html", report.read_bytes()))

    header = "".join(f"<th style='text-align:right'>{s}</th>" for s in SEVERITIES)
    body = f"""<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222">
<p>Prowler scan for <b>{run_date}</b> ({html.escape(os.environ.get('SCAN_RESULT', ''))}).
Counts are failed findings, excluding muted ones.</p>
<table cellpadding="6" style="border-collapse:collapse;border:1px solid #ddd">
<tr style="background:#f4f4f4"><th style="text-align:left">Account</th>{header}
<th style="text-align:right">Muted</th><th style="text-align:right">Passed</th></tr>
{''.join(rows)}
</table>
{'<h3 style="margin-top:24px">Critical and high findings</h3>' + ''.join(details) if details else '<p>No critical or high findings.</p>'}
<p style="margin-top:24px">The full HTML report for each account is attached. The CSV, OCSF and compliance files are in
<code>s3://{bucket}/reports/{run_date}/</code>.<br>
Run log: <a href="{run_url}">{run_url}</a></p>
</body></html>"""

    # Drop attachments (largest first) if the total would exceed the SES size limit.
    attachments.sort(key=lambda a: len(a[1]))
    kept, size = [], 0
    for name, data in attachments:
        if size + len(data) <= MAX_ATTACHMENT_BYTES:
            kept.append((name, data))
            size += len(data)
    if len(kept) < len(attachments):
        body = body.replace("</body>", f"<p><i>{len(attachments) - len(kept)} report(s) were too large to attach; get them from S3.</i></p></body>")

    crit_high = totals["Critical"] + totals["High"]
    msg = EmailMessage()
    msg["Subject"] = f"Prowler {run_date}: {totals['Critical']} critical, {totals['High']} high across {len(accounts)} accounts"
    if os.environ.get("SCAN_RESULT") not in ("success", ""):
        msg.replace_header("Subject", msg["Subject"] + f" ({os.environ['SCAN_RESULT']})")
    msg["From"] = f"Prowler <{from_addr}>"
    msg["To"] = to_addr
    msg.set_content(f"Prowler scan {run_date}: {crit_high} critical/high findings. View this email as HTML, or see {run_url}")
    msg.add_alternative(body, subtype="html")
    for name, data in kept:
        msg.add_attachment(data, maintype="text", subtype="html", filename=name)

    if os.environ.get("DRY_RUN"):
        Path(os.environ["DRY_RUN"]).write_bytes(msg.as_bytes())
        print(f"DRY_RUN: wrote {os.environ['DRY_RUN']}: {msg['Subject']} ({len(kept)} attachments, {size // 1024} KB)")
        return

    content = {"Raw": {"Data": base64.b64encode(msg.as_bytes()).decode()}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(content, f)
    subprocess.run(
        ["aws", "sesv2", "send-email", "--from-email-address", from_addr,
         "--destination", json.dumps({"ToAddresses": [to_addr]}),
         "--content", f"file://{f.name}"],
        check=True,
    )
    print(f"Sent to {to_addr}: {msg['Subject']} ({len(kept)} attachments, {size // 1024} KB)")


if __name__ == "__main__":
    main()
