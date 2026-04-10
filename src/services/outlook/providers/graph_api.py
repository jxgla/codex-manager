"""
Microsoft Graph provider for Outlook mail retrieval.
"""

import logging
from datetime import datetime
from typing import List, Optional

from curl_cffi import requests as _requests

from ..account import OutlookAccount
from ..base import EmailMessage, ProviderType
from ..token_manager import TokenManager
from .base import OutlookProvider, ProviderConfig


logger = logging.getLogger(__name__)


class GraphAPIProvider(OutlookProvider):
    """
    Microsoft Graph mail provider.
    Reads both inbox and junk mail folders and merges them by receive time.
    """

    GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
    MAIL_FOLDER_IDS = ("inbox", "junkemail")

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GRAPH_API

    def __init__(
        self,
        account: OutlookAccount,
        config: Optional[ProviderConfig] = None,
    ):
        super().__init__(account, config)
        self._token_manager: Optional[TokenManager] = None

        if not account.has_oauth():
            logger.warning(
                f"[{self.account.email}] Graph API provider requires OAuth2 "
                f"(client_id + refresh_token)"
            )

    def connect(self) -> bool:
        """Validate OAuth connectivity by obtaining an access token."""
        if not self.account.has_oauth():
            error = "Graph API requires OAuth2 configuration"
            self.record_failure(error)
            logger.error(f"[{self.account.email}] {error}")
            return False

        if not self._token_manager:
            self._token_manager = TokenManager(
                self.account,
                ProviderType.GRAPH_API,
                self.config.proxy_url,
                self.config.timeout,
            )

        token = self._token_manager.get_access_token()
        if token:
            self._connected = True
            self.record_success()
            logger.info(f"[{self.account.email}] Graph API connected")
            return True

        return False

    def disconnect(self):
        """Reset connection state."""
        self._connected = False

    def _build_request_options(self, token: str, count: int, only_unseen: bool):
        params = {
            "$top": count,
            "$select": "id,subject,from,toRecipients,receivedDateTime,isRead,hasAttachments,bodyPreview,body",
            "$orderby": "receivedDateTime desc",
        }
        if only_unseen:
            params["$filter"] = "isRead eq false"

        proxies = None
        if self.config.proxy_url:
            proxies = {"http": self.config.proxy_url, "https": self.config.proxy_url}

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Prefer": "outlook.body-content-type='text'",
        }

        return params, headers, proxies

    def _fetch_folder_messages(
        self,
        token: str,
        folder_id: str,
        count: int,
        only_unseen: bool,
    ) -> Optional[List[dict]]:
        url = f"{self.GRAPH_API_BASE}/me/mailFolders/{folder_id}/messages"
        params, headers, proxies = self._build_request_options(token, count, only_unseen)

        resp = _requests.get(
            url,
            params=params,
            headers=headers,
            proxies=proxies,
            timeout=self.config.timeout,
            impersonate="chrome110",
        )

        if resp.status_code == 401:
            if self._token_manager:
                self._token_manager.clear_cache()
            self._connected = False
            logger.warning(f"[{self.account.email}] Graph API returned 401 for folder {folder_id}")
            return None

        if resp.status_code == 404:
            logger.debug(f"[{self.account.email}] Graph mail folder missing: {folder_id}")
            return []

        if resp.status_code != 200:
            error_body = resp.text[:200]
            raise RuntimeError(f"HTTP {resp.status_code}: {error_body}")

        data = resp.json()
        return data.get("value", [])

    def get_recent_emails(
        self,
        count: int = 20,
        only_unseen: bool = True,
    ) -> List[EmailMessage]:
        """Fetch recent emails from inbox and junk, merged by receivedDateTime."""
        if not self._connected:
            if not self.connect():
                return []

        try:
            token = self._token_manager.get_access_token()
            if not token:
                self.record_failure("unable to obtain Access Token")
                return []

            merged_messages: List[dict] = []
            seen_ids = set()
            successful_folders = 0

            for folder_id in self.MAIL_FOLDER_IDS:
                messages = self._fetch_folder_messages(token, folder_id, count, only_unseen)
                if messages is None:
                    return []

                successful_folders += 1
                for msg in messages:
                    message_id = msg.get("id")
                    if message_id and message_id in seen_ids:
                        continue
                    if message_id:
                        seen_ids.add(message_id)
                    merged_messages.append(msg)

            if successful_folders == 0:
                self.record_failure("no accessible mail folders")
                return []

            merged_messages.sort(
                key=lambda item: item.get("receivedDateTime", ""),
                reverse=True,
            )

            emails = []
            for msg in merged_messages[:count]:
                try:
                    email_msg = self._parse_graph_message(msg)
                    if email_msg:
                        emails.append(email_msg)
                except Exception as e:
                    logger.warning(f"[{self.account.email}] failed to parse Graph email: {e}")

            self.record_success()
            return emails

        except Exception as e:
            self.record_failure(str(e))
            logger.error(f"[{self.account.email}] Graph API failed to fetch emails: {e}")
            return []

    def _parse_graph_message(self, msg: dict) -> Optional[EmailMessage]:
        """Parse a Graph message object."""
        from_info = msg.get("from", {})
        sender_info = from_info.get("emailAddress", {})
        sender = sender_info.get("address", "")

        recipients = []
        for recipient in msg.get("toRecipients", []):
            addr_info = recipient.get("emailAddress", {})
            addr = addr_info.get("address", "")
            if addr:
                recipients.append(addr)

        received_at = None
        received_timestamp = 0
        try:
            date_str = msg.get("receivedDateTime", "")
            if date_str:
                received_at = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                received_timestamp = int(received_at.timestamp())
        except Exception:
            pass

        body_info = msg.get("body", {})
        body = body_info.get("content", "")
        body_preview = msg.get("bodyPreview", "")

        return EmailMessage(
            id=msg.get("id", ""),
            subject=msg.get("subject", ""),
            sender=sender,
            recipients=recipients,
            body=body,
            body_preview=body_preview,
            received_at=received_at,
            received_timestamp=received_timestamp,
            is_read=msg.get("isRead", False),
            has_attachments=msg.get("hasAttachments", False),
        )

    def test_connection(self) -> bool:
        """Test the Graph API connection."""
        try:
            self.get_recent_emails(count=1, only_unseen=False)
            return True
        except Exception as e:
            logger.warning(f"[{self.account.email}] Graph API connection test failed: {e}")
            return False
