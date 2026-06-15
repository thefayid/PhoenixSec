from __future__ import annotations

import json
import smtplib
import urllib.request
from email.mime.text import MIMEText

from phoenixsec.core.config import PhoenixSecConfig
from phoenixsec.core.logger import get_logger
from phoenixsec.models.report import Report
from phoenixsec.models.vulnerability import Severity

log = get_logger(__name__)


def send_slack_notification(webhook_url: str, report: Report) -> None:
    """Send a structured scan summary to a Slack channel."""
    summary = report.generate_summary()
    findings_count = report.total_findings

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🛡️ PhoenixSec Security Scan Report",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Target:* `{report.scan_target}`\n*Scanner:* `{report.scanner_name}`\n*Risk Level:* *{summary.risk_level}* (Score: {summary.risk_score})",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Critical:* {summary.critical}"},
                {"type": "mrkdwn", "text": f"*High:* {summary.high}"},
                {"type": "mrkdwn", "text": f"*Medium:* {summary.medium}"},
                {"type": "mrkdwn", "text": f"*Low:* {summary.low}"},
            ],
        },
    ]

    if findings_count > 0:
        blocks.append({"type": "divider"})
        # Add details of the top 5 findings
        findings_text = "*Top Findings:*\n"
        for idx, f in enumerate(report.findings[:5], start=1):
            findings_text += (
                f"{idx}. *[{f.severity.name}]* {f.vulnerability_type} at `{f.location}`\n"
            )
        if findings_count > 5:
            findings_text += f"...and {findings_count - 5} more."
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": findings_text}})

    payload = {"blocks": blocks}
    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as res:
            if res.status in (200, 204):
                log.info("Slack notification sent successfully.")
            else:
                log.warning(f"Slack webhook returned status code: {res.status}")
    except Exception as exc:
        log.warning(f"Failed to send Slack notification: {exc}")


def send_jira_issue(
    url: str, project_key: str, username: str, api_token: str, report: Report
) -> None:
    """Automatically create Jira tickets for High or Critical vulnerabilities."""
    import base64

    high_critical_findings = [f for f in report.findings if f.severity >= Severity.HIGH]
    if not high_critical_findings:
        return

    # Prepare authorization header
    auth_str = f"{username}:{api_token}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
    headers = {
        "Authorization": f"Basic {auth_b64}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    create_url = f"{url.rstrip('/')}/rest/api/2/issue"

    for idx, f in enumerate(high_critical_findings):
        summary = f"[{f.severity.name}] PhoenixSec Security Finding: {f.vulnerability_type} in {f.file_path}"
        description = (
            f"PhoenixSec detected a {f.severity.name} vulnerability.\n\n"
            f"*Type:* {f.vulnerability_type}\n"
            f"*Rule ID:* {f.rule_id}\n"
            f"*CWE:* {f.cwe_id or 'N/A'}\n"
            f"*File:* {f.file_path}\n"
            f"*Line:* {f.line_number or 'N/A'}\n\n"
            f"*Recommendation:*\n{f.recommendation}\n\n"
            f"*References:*\n" + "\n".join(f.references)
        )

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": "Bug"},
            }
        }

        try:
            req = urllib.request.Request(
                create_url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
            )
            with urllib.request.urlopen(req) as res:
                if res.status == 201:
                    res_data = json.loads(res.read().decode("utf-8"))
                    log.info(f"Jira issue created successfully: {res_data.get('key')}")
                else:
                    log.warning(f"Jira REST API returned status code: {res.status}")
        except Exception as exc:
            log.warning(f"Failed to create Jira issue for finding #{idx}: {exc}")


def send_email_notification(
    smtp_server: str,
    smtp_port: int,
    sender: str,
    recipient: str,
    username: str | None,
    password: str | None,
    report: Report,
) -> None:
    """Send an email digest summarizing the scan findings."""
    summary = report.generate_summary()
    findings_count = report.total_findings

    subject = f"🛡️ PhoenixSec Scan Alert: {summary.risk_level} Risk for {report.scan_target}"

    body = (
        f"PhoenixSec Security Scan Summary\n"
        f"================================\n"
        f"Target: {report.scan_target}\n"
        f"Scanner: {report.scanner_name}\n"
        f"Overall Risk Level: {summary.risk_level} (Score: {summary.risk_score})\n\n"
        f"Breakdown:\n"
        f"- Critical: {summary.critical}\n"
        f"- High: {summary.high}\n"
        f"- Medium: {summary.medium}\n"
        f"- Low: {summary.low}\n"
        f"- Info: {summary.info}\n\n"
    )

    if findings_count > 0:
        body += "Vulnerabilities Found:\n"
        body += "----------------------\n"
        for idx, f in enumerate(report.findings, start=1):
            body += f"{idx}. [{f.severity.name}] {f.vulnerability_type} at {f.location}\n"
            body += f"   Remediation: {f.recommendation}\n\n"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            if smtp_port == 587:
                server.starttls()
                server.ehlo()
            if username and password:
                server.login(username, password)
            server.sendmail(sender, [recipient], msg.as_string())
            log.info("Email notification sent successfully.")
    except Exception as exc:
        log.warning(f"Failed to send email notification: {exc}")


def dispatch_notifications(report: Report, config: PhoenixSecConfig) -> None:
    """Dispatch notifications to all configured & enabled backends."""
    notif = config.notifiers

    if notif.slack.enabled and notif.slack.webhook_url:
        log.debug("Dispatching Slack notification")
        send_slack_notification(notif.slack.webhook_url, report)

    if notif.jira.enabled and notif.jira.url and notif.jira.project_key:
        if notif.jira.username and notif.jira.api_token:
            log.debug("Dispatching Jira tickets creation")
            send_jira_issue(
                notif.jira.url,
                notif.jira.project_key,
                notif.jira.username,
                notif.jira.api_token,
                report,
            )

    if (
        notif.email.enabled
        and notif.email.smtp_server
        and notif.email.sender
        and notif.email.recipient
    ):
        log.debug("Dispatching Email notification")
        send_email_notification(
            notif.email.smtp_server,
            notif.email.smtp_port,
            notif.email.sender,
            notif.email.recipient,
            notif.email.username,
            notif.email.password,
            report,
        )
