"""
Legacy Outlook IMAP provider.
Uses outlook.office365.com and supports password auth or XOAUTH2.
"""

import email
import imaplib
import logging
from email.header import decode_header
from email.utils import parsedate_to_datetime
from typing import List, Optional

from ..account import OutlookAccount
from ..base import EmailMessage, ProviderType
from ..token_manager import TokenManager
from .base import OutlookProvider, ProviderConfig


logger = logging.getLogger(__name__)


class IMAPOldProvider(OutlookProvider):
    """
    Legacy IMAP provider for Outlook.
    Uses outlook.office365.com:993 with login.live.com tokens.
    """

    IMAP_HOST = "outlook.office365.com"
    IMAP_PORT = 993
    MAILBOX_CANDIDATES = ("INBOX", "Junk", "Junk E-mail", "Spam")

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.IMAP_OLD

    def __init__(
        self,
        account: OutlookAccount,
        config: Optional[ProviderConfig] = None,
    ):
        super().__init__(account, config)
        self._conn: Optional[imaplib.IMAP4_SSL] = None
        self._token_manager: Optional[TokenManager] = None

    def connect(self) -> bool:
        """Connect to the IMAP server."""
        if self._connected and self._conn:
            try:
                self._conn.noop()
                return True
            except Exception:
                self.disconnect()

        try:
            logger.debug(f"[{self.account.email}] connecting IMAP ({self.IMAP_HOST})")
            self._conn = imaplib.IMAP4_SSL(
                self.IMAP_HOST,
                self.IMAP_PORT,
                timeout=self.config.timeout,
            )

            if self.account.has_oauth():
                if self._authenticate_xoauth2():
                    self._connected = True
                    self.record_success()
                    logger.info(f"[{self.account.email}] IMAP connected with XOAUTH2")
                    return True
                logger.warning(f"[{self.account.email}] XOAUTH2 failed, trying password auth")

            if self.account.password:
                self._conn.login(self.account.email, self.account.password)
                self._connected = True
                self.record_success()
                logger.info(f"[{self.account.email}] IMAP connected with password auth")
                return True

            raise ValueError("no available authentication method")

        except Exception as e:
            self.disconnect()
            self.record_failure(str(e))
            logger.error(f"[{self.account.email}] IMAP connection failed: {e}")
            return False

    def _authenticate_xoauth2(self) -> bool:
        """Authenticate via XOAUTH2."""
        if not self._token_manager:
            self._token_manager = TokenManager(
                self.account,
                ProviderType.IMAP_OLD,
                self.config.proxy_url,
                self.config.timeout,
            )

        token = self._token_manager.get_access_token()
        if not token:
            return False

        try:
            auth_string = f"user={self.account.email}\x01auth=Bearer {token}\x01\x01"
            self._conn.authenticate("XOAUTH2", lambda _: auth_string.encode("utf-8"))
            return True
        except Exception as e:
            logger.debug(f"[{self.account.email}] XOAUTH2 auth failed: {e}")
            self._token_manager.clear_cache()
            return False

    def disconnect(self):
        """Disconnect from the IMAP server."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            try:
                self._conn.logout()
            except Exception:
                pass
            self._conn = None

        self._connected = False

    def _select_mailbox(self, mailbox: str, readonly: bool = True) -> bool:
        try:
            status, _ = self._conn.select(mailbox, readonly=readonly)
        except imaplib.IMAP4.error as e:
            logger.debug(f"[{self.account.email}] mailbox unavailable: {mailbox}: {e}")
            return False
        return status == "OK"

    def _fetch_recent_emails_from_mailbox(
        self,
        mailbox: str,
        count: int,
        only_unseen: bool,
    ) -> List[EmailMessage]:
        if not self._select_mailbox(mailbox, readonly=True):
            return []

        flag = "UNSEEN" if only_unseen else "ALL"
        status, data = self._conn.search(None, flag)
        if status != "OK" or not data or not data[0]:
            return []

        ids = data[0].split()
        recent_ids = ids[-count:][::-1]

        emails = []
        for msg_id in recent_ids:
            try:
                email_msg = self._fetch_email(msg_id)
                if email_msg:
                    emails.append(email_msg)
            except Exception as e:
                logger.warning(
                    f"[{self.account.email}] failed to parse email ({mailbox}, ID: {msg_id}): {e}"
                )

        return emails

    def get_recent_emails(
        self,
        count: int = 20,
        only_unseen: bool = True,
    ) -> List[EmailMessage]:
        """Fetch recent emails from inbox and junk folders, merged by timestamp."""
        if not self._connected:
            if not self.connect():
                return []

        try:
            merged_emails: List[EmailMessage] = []
            for mailbox in self.MAILBOX_CANDIDATES:
                merged_emails.extend(
                    self._fetch_recent_emails_from_mailbox(mailbox, count, only_unseen)
                )

            merged_emails.sort(key=lambda item: item.received_timestamp or 0, reverse=True)
            return merged_emails[:count]

        except Exception as e:
            self.record_failure(str(e))
            logger.error(f"[{self.account.email}] failed to fetch emails: {e}")
            return []

    def _fetch_email(self, msg_id: bytes) -> Optional[EmailMessage]:
        """Fetch and parse a single email."""
        status, data = self._conn.fetch(msg_id, "(RFC822)")
        if status != "OK" or not data or not data[0]:
            return None

        raw = b""
        for part in data:
            if isinstance(part, tuple) and len(part) > 1:
                raw = part[1]
                break

        if not raw:
            return None

        return self._parse_email(raw)

    @staticmethod
    def _parse_email(raw: bytes) -> EmailMessage:
        """Parse the raw RFC822 payload into EmailMessage."""
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]

        msg = email.message_from_bytes(raw)

        subject = IMAPOldProvider._decode_header(msg.get("Subject", ""))
        sender = IMAPOldProvider._decode_header(msg.get("From", ""))
        to = IMAPOldProvider._decode_header(msg.get("To", ""))
        delivered_to = IMAPOldProvider._decode_header(msg.get("Delivered-To", ""))
        x_original_to = IMAPOldProvider._decode_header(msg.get("X-Original-To", ""))
        date_str = IMAPOldProvider._decode_header(msg.get("Date", ""))
        body = IMAPOldProvider._extract_body(msg)

        received_timestamp = 0
        received_at = None
        try:
            if date_str:
                received_at = parsedate_to_datetime(date_str)
                received_timestamp = int(received_at.timestamp())
        except Exception:
            pass

        recipients = [value for value in [to, delivered_to, x_original_to] if value]

        return EmailMessage(
            id=msg.get("Message-ID", ""),
            subject=subject,
            sender=sender,
            recipients=recipients,
            body=body,
            received_at=received_at,
            received_timestamp=received_timestamp,
            is_read=False,
            raw_data=raw[:500] if len(raw) > 500 else raw,
        )

    @staticmethod
    def _decode_header(header: str) -> str:
        """Decode MIME headers."""
        if not header:
            return ""

        parts = []
        for chunk, encoding in decode_header(header):
            if isinstance(chunk, bytes):
                try:
                    decoded = chunk.decode(encoding or "utf-8", errors="replace")
                    parts.append(decoded)
                except Exception:
                    parts.append(chunk.decode("utf-8", errors="replace"))
            else:
                parts.append(str(chunk))

        return "".join(parts).strip()

    @staticmethod
    def _extract_body(msg) -> str:
        """Extract email body text from plain-text or HTML parts."""
        import html as html_module
        import re

        texts = []
        parts = msg.walk() if msg.is_multipart() else [msg]

        for part in parts:
            content_type = part.get_content_type()
            if content_type not in ("text/plain", "text/html"):
                continue

            payload = part.get_payload(decode=True)
            if not payload:
                continue

            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = payload.decode("utf-8", errors="replace")

            if "<html" in text.lower():
                text = re.sub(r"<[^>]+>", " ", text)

            texts.append(text)

        combined = " ".join(texts)
        combined = html_module.unescape(combined)
        combined = re.sub(r"\s+", " ", combined).strip()
        return combined

    def test_connection(self) -> bool:
        """Test the IMAP connection."""
        try:
            with self:
                if self._select_mailbox("INBOX", readonly=True):
                    self._conn.search(None, "ALL")
                    return True
            return False
        except Exception as e:
            logger.warning(f"[{self.account.email}] IMAP connection test failed: {e}")
            return False
