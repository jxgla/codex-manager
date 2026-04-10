import imaplib
from email.message import EmailMessage

from src.services.imap_mail import ImapMailService


def _build_raw_email(code: str, *, date_value: str, sender: str = "OpenAI <noreply@openai.com>") -> bytes:
    msg = EmailMessage()
    msg["From"] = sender
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
        self.store_calls = []

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

    def store(self, msg_id, action, flag):
        self.store_calls.append((self.selected, msg_id, action, flag))
        return "OK", []

    def logout(self):
        return "BYE", [b"logout"]


def test_imap_mail_service_prefers_newer_junk_message(monkeypatch):
    service = ImapMailService(
        {
            "host": "imap.example.com",
            "email": "tester@example.com",
            "password": "secret",
        }
    )
    connection = FakeIMAPConnection(
        {
            "INBOX": {
                b"1": _build_raw_email("111111", date_value="Fri, 10 Apr 2026 10:00:00 +0000"),
            },
            "Junk": {
                b"7": _build_raw_email("654321", date_value="Fri, 10 Apr 2026 10:00:05 +0000"),
            },
        }
    )

    monkeypatch.setattr(service, "_connect", lambda: connection)

    code = service.get_verification_code(
        email="tester@example.com",
        timeout=1,
    )

    assert code == "654321"
    assert connection.store_calls == [("Junk", b"7", "+FLAGS", "\\Seen")]


def test_imap_mail_service_falls_back_when_junk_mailbox_is_missing(monkeypatch):
    service = ImapMailService(
        {
            "host": "imap.example.com",
            "email": "tester@example.com",
            "password": "secret",
        }
    )
    connection = FakeIMAPConnection(
        {
            "INBOX": {
                b"1": _build_raw_email("111111", date_value="Fri, 10 Apr 2026 10:00:00 +0000"),
            },
        }
    )

    monkeypatch.setattr(service, "_connect", lambda: connection)

    code = service.get_verification_code(
        email="tester@example.com",
        timeout=1,
    )

    assert code == "111111"
    assert connection.store_calls == [("INBOX", b"1", "+FLAGS", "\\Seen")]
