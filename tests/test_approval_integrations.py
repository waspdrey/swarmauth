import swarmauth


def test_slack_webhook_channel_posts_rendered_payload() -> None:
    sent = []
    channel = swarmauth.SlackWebhookChannel(
        "https://hooks.slack.test",
        post=lambda url, payload, timeout: sent.append((url, payload, timeout)),
    )
    request = swarmauth.ApprovalRequest("req", "deploy", "prod:deploy", "agent", "release", "Deploy", 999)
    payload = channel.message(request, "https://review.test/a", "https://review.test/r")
    assert sent[0][0] == "https://hooks.slack.test"
    assert payload["blocks"] == sent[0][1]["blocks"]


class FakeSMTP:
    messages = []

    def __init__(self, host, port, timeout):
        self.connection = (host, port, timeout)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def starttls(self, *, context):
        assert context.check_hostname is True
        pass

    def login(self, username, password):
        assert username == "user"
        assert password == "pass"

    def send_message(self, message):
        self.messages.append(message)


def test_smtp_channel_sends_html_and_plaintext_without_token_secrets() -> None:
    channel = swarmauth.SMTPEmailChannel(
        "smtp.test",
        sender="security@example.com",
        recipients=("reviewer@example.com",),
        username="user",
        password="pass",
        smtp_factory=FakeSMTP,
    )
    request = swarmauth.ApprovalRequest("req", "refund", "tool:refund", "agent", "billing", "Refund", 999)
    channel.message(request, "https://review.test/a", "https://review.test/r")
    assert FakeSMTP.messages[-1]["To"] == "reviewer@example.com"
    assert "bearer" not in FakeSMTP.messages[-1].as_string().lower()
