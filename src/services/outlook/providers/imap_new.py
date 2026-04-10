"""
Modern Outlook IMAP provider.
Uses outlook.live.com and requires XOAUTH2.
"""

import imaplib
import logging
from typing import Optional

from ..account import OutlookAccount
from ..base import ProviderType
from ..token_manager import TokenManager
from .base import ProviderConfig
from .imap_old import IMAPOldProvider


logger = logging.getLogger(__name__)


class IMAPNewProvider(IMAPOldProvider):
    """
    Modern IMAP provider for Outlook.
    Uses outlook.live.com:993 and consumer OAuth tokens.
    """

    IMAP_HOST = "outlook.live.com"
    IMAP_PORT = 993

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.IMAP_NEW

    def __init__(
        self,
        account: OutlookAccount,
        config: Optional[ProviderConfig] = None,
    ):
        super().__init__(account, config)

        if not account.has_oauth():
            logger.warning(
                f"[{self.account.email}] modern IMAP provider requires OAuth2 "
                f"(client_id + refresh_token)"
            )

    def connect(self) -> bool:
        """Connect to the IMAP server with XOAUTH2 only."""
        if self._connected and self._conn:
            try:
                self._conn.noop()
                return True
            except Exception:
                self.disconnect()

        if not self.account.has_oauth():
            logger.debug(f"[{self.account.email}] skipping IMAP_NEW because OAuth is missing")
            return False

        try:
            logger.debug(f"[{self.account.email}] connecting IMAP ({self.IMAP_HOST})")
            self._conn = imaplib.IMAP4_SSL(
                self.IMAP_HOST,
                self.IMAP_PORT,
                timeout=self.config.timeout,
            )

            if self._authenticate_xoauth2():
                self._connected = True
                self.record_success()
                logger.info(f"[{self.account.email}] modern IMAP connected with XOAUTH2")
                return True

            return False

        except Exception as e:
            self.disconnect()
            self.record_failure(str(e))
            logger.error(f"[{self.account.email}] modern IMAP connection failed: {e}")
            return False

    def _authenticate_xoauth2(self) -> bool:
        """Authenticate via XOAUTH2."""
        if not self._token_manager:
            self._token_manager = TokenManager(
                self.account,
                ProviderType.IMAP_NEW,
                self.config.proxy_url,
                self.config.timeout,
            )

        token = self._token_manager.get_access_token()
        if not token:
            logger.error(f"[{self.account.email}] failed to obtain IMAP token")
            return False

        try:
            auth_string = f"user={self.account.email}\x01auth=Bearer {token}\x01\x01"
            self._conn.authenticate("XOAUTH2", lambda _: auth_string.encode("utf-8"))
            return True
        except Exception as e:
            logger.error(f"[{self.account.email}] XOAUTH2 auth failed: {e}")
            self._token_manager.clear_cache()
            return False
