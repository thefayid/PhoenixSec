from __future__ import annotations

from unittest.mock import MagicMock, patch

from phoenixsec.core.config import (
    EmailConfig,
    JiraConfig,
    NotifiersConfig,
    PhoenixSecConfig,
    SlackConfig,
)
from phoenixsec.core.notifiers import dispatch_notifications
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.report import Report
from phoenixsec.models.vulnerability import Severity


def test_dispatch_notifications_all() -> None:
    report = Report(scan_target="test_target")
    report.add_finding(
        Finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence_score=0.9,
            recommendation="Fix",
            file_path="app.py",
            line_number=10,
            rule_id="PY-SQLI-001",
        )
    )

    config = PhoenixSecConfig(
        notifiers=NotifiersConfig(
            slack=SlackConfig(enabled=True, webhook_url="https://hooks.slack.com/dummy"),
            jira=JiraConfig(
                enabled=True,
                url="https://jira.dummy.com",
                project_key="SEC",
                username="user",
                api_token="token",
            ),
            email=EmailConfig(
                enabled=True,
                smtp_server="smtp.dummy.com",
                smtp_port=587,
                sender="sender@dummy.com",
                recipient="recipient@dummy.com",
                username="user",
                password="pass",
            ),
        )
    )

    with patch("urllib.request.urlopen") as mock_urlopen, patch("smtplib.SMTP") as mock_smtp_class:
        mock_smtp = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_smtp

        mock_response = MagicMock()
        # Jira response requires 201 status for creation success
        mock_response.status = 201
        mock_response.read.return_value = b'{"key": "SEC-123"}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        dispatch_notifications(report, config)

        assert mock_urlopen.call_count >= 2
        slack_call = mock_urlopen.call_args_list[0]
        slack_req = slack_call[0][0]
        assert slack_req.full_url == "https://hooks.slack.com/dummy"
        assert slack_req.method == "POST"

        jira_call = mock_urlopen.call_args_list[1]
        jira_req = jira_call[0][0]
        assert jira_req.full_url == "https://jira.dummy.com/rest/api/2/issue"
        assert jira_req.method == "POST"

        mock_smtp_class.assert_called_once_with("smtp.dummy.com", 587)
        mock_smtp.login.assert_called_once_with("user", "pass")
        mock_smtp.sendmail.assert_called_once()
