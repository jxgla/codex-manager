import imaplib
from email.message import EmailMessage as MimeEmailMessage

from src.services.outlook.account import OutlookAccount
from src.services.outlook.providers.graph_api import GraphAPIProvider
from src.services.outlook.providers.imap_old import IMAPOldProvider


def _build_raw_email(code: str, *, date_value: str) -> bytes:
    msg = MimeEmailMessage()
    msg["From"] = "OpenAI <noreply@openai.com>"
    msg["To"] = "tester@example.com"
    msg["Subject"] = "Your verification code"
    msg["Date"] = date_value
    msg["Message-ID"] = f"<{code}@example.com>"
    msg.set_content(f"Your OpenAI verification code is {code}")
    return msg.as_bytes()


class FakeIMAPConnection:
    def __init__(self, mailboxes):
        self.mailboxes = mailboxes
        self.selected = None

    def select(self, mailbox, readonly=False):
        if mailbox not in self.mailboxes:
            raise imaplib.IMAP4.error(f"missing mailbox: {mailbox}")
        self.selected = mailbox
        return "OK", [b"1"]

    def search(self, charset, flag):
        ids = list(self.mailboxes[self.selected].keys())
        return "OK", [b" ".join(ids)]

    def fetch(self, msg_id, query):
        return "OK", [(b"RFC822", self.mailboxes[self.selected][msg_id])]


class FakeGraphResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class FakeTokenManager:
    def get_access_token(self):
        return "token-123"

    def clear_cache(self):
        return None


def test_imap_old_provider_merges_inbox_and_junk_by_received_time():
    provider = IMAPOldProvider(OutlookAccount(email="tester@example.com", password="secret"))
    provider._connected = True
    provider._conn = FakeIMAPConnection(
        {
            "INBOX": {
                b"1": _build_raw_email("111111", date_value="Fri, 10 Apr 2026 10:00:00 +0000"),
            },
            "Junk": {
                b"2": _build_raw_email("654321", date_value="Fri, 10 Apr 2026 10:00:05 +0000"),
            },
        }
    )

    emails = provider.get_recent_emails(count=5, only_unseen=True)

    assert [mail.subject for mail in emails] == ["Your verification code", "Your verification code"]
    assert [mail.body for mail in emails] == [
        "Your OpenAI verification code is 654321",
        "Your OpenAI verification code is 111111",
    ]


def test_graph_api_provider_merges_inbox_and_junk_messages(monkeypatch):
    provider = GraphAPIProvider(
        OutlookAccount(
            email="tester@example.com",
            client_id="client-id",
            refresh_token="refresh-token",
        )
    )
    provider._connected = True
    provider._token_manager = FakeTokenManager()

    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if url.endswith("/mailFolders/inbox/messages"):
            return FakeGraphResponse(
                payload={
                    "value": [
                        {
                            "id": "msg-inbox",
                            "subject": "Your verification code",
                            "from": {"emailAddress": {"address": "noreply@openai.com"}},
                            "toRecipients": [{"emailAddress": {"address": "tester@example.com"}}],
                            "receivedDateTime": "2026-04-10T10:00:00Z",
                            "isRead": False,
                            "hasAttachments": False,
                            "bodyPreview": "111111",
                            "body": {"content": "Your OpenAI verification code is 111111"},
                        }
                    ]
                }
            )
        if url.endswith("/mailFolders/junkemail/messages"):
            return FakeGraphResponse(
                payload={
                    "value": [
                        {
                            "id": "msg-junk",
                            "subject": "Your verification code",
                            "from": {"emailAddress": {"address": "noreply@openai.com"}},
                            "toRecipients": [{"emailAddress": {"address": "tester@example.com"}}],
                            "receivedDateTime": "2026-04-10T10:00:05Z",
                            "isRead": False,
                            "hasAttachments": False,
                            "bodyPreview": "654321",
                            "body": {"content": "Your OpenAI verification code is 654321"},
                        }
                    ]
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr("src.services.outlook.providers.graph_api._requests.get", fake_get)

    emails = provider.get_recent_emails(count=5, only_unseen=True)

    assert calls == [
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages",
        "https://graph.microsoft.com/v1.0/me/mailFolders/junkemail/messages",
    ]
    assert [mail.body for mail in emails] == [
        "Your OpenAI verification code is 654321",
        "Your OpenAI verification code is 111111",
    ]
