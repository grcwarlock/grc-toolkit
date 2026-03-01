"""
notify.py
Assessment notification handlers for Slack and email.

Wire these into your pipeline after the assessment step
to get real-time alerts when controls drift out of compliance.
"""

import json
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests

logger = logging.getLogger(__name__)


def send_slack_alert(webhook_url: str, summary: dict, failures: list[dict]):
    """
    Post assessment results to a Slack channel via incoming webhook.

    Color-codes the message based on pass rate:
    green (>=90%), yellow (>=70%), red (<70%).
    """
    pass_rate = float(summary.get("pass_rate", "0%").replace("%", ""))
    color = "#36a64f" if pass_rate >= 90 else "#ff9900" if pass_rate >= 70 else "#ff0000"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "GRC Assessment Results"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Pass Rate:* {summary.get('pass_rate', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Total Checks:* {summary['total_checks']}"},
                {"type": "mrkdwn", "text": f"*Passed:* {summary['passed']}"},
                {"type": "mrkdwn", "text": f"*Failed:* {summary['failed']}"},
            ]
        },
    ]

    if failures:
        failure_text = "\n".join(
            f"• *{f['control_id']}* ({f['check_id']}): "
            f"{f.get('findings', [''])[0][:100]}"
            for f in failures[:5]
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top Findings:*\n{failure_text}"}
        })

    payload = {"attachments": [{"color": color, "blocks": blocks}]}

    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        logger.info("Slack notification sent successfully")
    except requests.RequestException as e:
        logger.error("Failed to send Slack notification: %s", e)


def send_email_digest(smtp_config: dict, summary: dict,
                      recipients: list[str], failures: list[dict] = None):
    """
    Send a formatted assessment digest email.

    smtp_config expects: server, port, sender, password
    """
    pass_rate = summary.get("pass_rate", "N/A")
    subject = f"GRC Assessment: {pass_rate} Pass Rate - {summary['failed']} Findings"

    body = f"""GRC Compliance Assessment Results
==================================

Pass Rate:      {pass_rate}
Total Checks:   {summary['total_checks']}
Passed:         {summary['passed']}
Failed:         {summary['failed']}
Errors:         {summary['errors']}

Control Family Breakdown:
"""
    for family, counts in summary.get("by_control", {}).items():
        body += f"  {family}: {counts['pass']} pass / {counts['fail']} fail / {counts['error']} error\n"

    if failures:
        body += "\nTop Findings:\n"
        for f in failures[:10]:
            finding = f.get("findings", ["No detail"])[0][:120]
            body += f"  [{f.get('control_id')}] {finding}\n"

    body += "\nFull report available in the reports/ directory."

    msg = MIMEMultipart()
    msg["From"] = smtp_config["sender"]
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_config["server"], smtp_config["port"]) as server:
            server.starttls()
            server.login(smtp_config["sender"], smtp_config["password"])
            server.sendmail(smtp_config["sender"], recipients, msg.as_string())
        logger.info("Email digest sent to %s", ", ".join(recipients))
    except Exception as e:
        logger.error("Failed to send email digest: %s", e)
