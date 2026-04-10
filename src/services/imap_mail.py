"""
IMAP 邮箱服务
支持 Gmail / QQ / 163 / Yahoo / Outlook 等标准 IMAP 协议邮箱服务商。
仅用于接收验证码，强制直连（imaplib 不支持代理）。
"""

import email as py_email
import imaplib
import logging
import re
import time
from email.header import decode_header
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional

from .base import BaseEmailService, OTPNoOpenAISenderEmailServiceError, get_email_code_settings
from ..config.constants import (
    EmailServiceType,
    OTP_CODE_PATTERN,
    OTP_CODE_SEMANTIC_PATTERN,
)

logger = logging.getLogger(__name__)


class ImapMailService(BaseEmailService):
    """标准 IMAP 邮箱服务，仅接收验证码。"""

    DEFAULT_MAILBOXES = ("INBOX", "Junk", "Junk E-mail", "Spam")

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        super().__init__(EmailServiceType.IMAP_MAIL, name)

        cfg = config or {}
        required_keys = ["host", "email", "password"]
        missing_keys = [k for k in required_keys if not cfg.get(k)]
        if missing_keys:
            raise ValueError(f"缺少必需配置: {missing_keys}")

        self.host: str = str(cfg["host"]).strip()
        self.port: int = int(cfg.get("port", 993))
        self.use_ssl: bool = bool(cfg.get("use_ssl", True))
        self.email_addr: str = str(cfg["email"]).strip()
        self.password: str = str(cfg["password"])
        self.timeout: int = int(cfg.get("timeout", 30))
        self.max_retries: int = int(cfg.get("max_retries", 3))
        self.mailboxes: List[str] = self._normalize_mailboxes(cfg.get("mailboxes"))

    def _normalize_mailboxes(self, mailboxes: Any) -> List[str]:
        normalized: List[str] = []
        seen = set()

        candidates = mailboxes
        if isinstance(candidates, str):
            candidates = [item.strip() for item in candidates.split(",")]
        if not candidates:
            candidates = self.DEFAULT_MAILBOXES

        for mailbox in ["INBOX", *candidates]:
            value = str(mailbox or "").strip()
            if not value:
                continue
            lowered = value.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            normalized.append(value)

        return normalized or ["INBOX"]

    def _connect(self) -> imaplib.IMAP4:
        """建立 IMAP 连接并登录，返回 mail 对象。"""
        if self.use_ssl:
            mail = imaplib.IMAP4_SSL(self.host, self.port)
        else:
            mail = imaplib.IMAP4(self.host, self.port)
            mail.starttls()
        mail.login(self.email_addr, self.password)
        return mail

    def _decode_str(self, value) -> str:
        """解码邮件头部字段。"""
        if value is None:
            return ""
        parts = decode_header(value)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return " ".join(decoded)

    def _get_text_body(self, msg) -> str:
        """提取邮件纯文本正文。"""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    charset = part.get_content_charset() or "utf-8"
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode(charset, errors="replace")
        else:
            charset = msg.get_content_charset() or "utf-8"
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(charset, errors="replace")
        return body

    def _is_openai_sender(self, from_addr: str) -> bool:
        """判断发件人是否为 OpenAI。"""
        return self._is_openai_sender_value(from_addr)

    def _extract_otp(self, text: str) -> Optional[str]:
        """从文本中提取 6 位验证码，优先语义匹配，回退简单匹配。"""
        match = re.search(OTP_CODE_SEMANTIC_PATTERN, text, re.IGNORECASE)
        if match:
            return match.group(1)
        match = re.search(OTP_CODE_PATTERN, text)
        if match:
            return match.group(1)
        return None

    def _select_mailbox(self, mail: imaplib.IMAP4, mailbox: str) -> bool:
        try:
            status, _ = mail.select(mailbox)
        except imaplib.IMAP4.error as e:
            logger.debug(f"IMAP 无法选择收件箱 {mailbox}: {e}")
            return False
        return status == "OK"

    def _get_message_timestamp(self, msg) -> float:
        date_value = msg.get("Date")
        if not date_value:
            return float("-inf")

        try:
            return parsedate_to_datetime(date_value).timestamp()
        except Exception:
            return float("-inf")

    def _collect_mailbox_candidates(
        self,
        mail: imaplib.IMAP4,
        mailbox: str,
        seen_ids: set,
    ) -> List[Dict[str, Any]]:
        if not self._select_mailbox(mail, mailbox):
            return []

        status, data = mail.search(None, "UNSEEN")
        if status != "OK" or not data or not data[0]:
            return []

        candidates: List[Dict[str, Any]] = []
        for msg_id in reversed(data[0].split()):
            id_str = msg_id.decode(errors="ignore")
            seen_key = f"{mailbox}:{id_str}"
            if seen_key in seen_ids:
                continue
            seen_ids.add(seen_key)

            status, msg_data = mail.fetch(msg_id, "(RFC822)")
            if status != "OK" or not msg_data:
                continue

            first_part = msg_data[0]
            if not isinstance(first_part, tuple) or len(first_part) < 2 or first_part[1] is None:
                continue

            msg = py_email.message_from_bytes(first_part[1])
            candidates.append(
                {
                    "mailbox": mailbox,
                    "msg_id": msg_id,
                    "from_addr": self._decode_str(msg.get("From", "")),
                    "body": self._get_text_body(msg),
                    "timestamp": self._get_message_timestamp(msg),
                }
            )

        return candidates

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """IMAP 模式不创建新邮箱，直接返回配置中的固定地址。"""
        self.update_status(True)
        return {
            "email": self.email_addr,
            "service_id": self.email_addr,
            "id": self.email_addr,
        }

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 60,
        pattern: str = None,
        otp_sent_at: Optional[float] = None,
    ) -> Optional[str]:
        """轮询 IMAP 邮箱，获取 OpenAI 验证码。"""
        poll_interval = get_email_code_settings()["poll_interval"]
        start_time = time.time()
        seen_ids: set = set()
        mail: Optional[imaplib.IMAP4] = None

        try:
            mail = self._connect()

            while time.time() - start_time < timeout:
                self._raise_if_cancelled("等待 IMAP 验证码时任务已取消")
                try:
                    candidates: List[Dict[str, Any]] = []
                    seen_any_message = False
                    found_openai_sender = False

                    for mailbox in self.mailboxes:
                        mailbox_candidates = self._collect_mailbox_candidates(mail, mailbox, seen_ids)
                        if mailbox_candidates:
                            seen_any_message = True
                            candidates.extend(mailbox_candidates)

                    if not candidates:
                        self._sleep_with_cancel(poll_interval)
                        continue

                    candidates.sort(key=lambda item: item["timestamp"], reverse=True)

                    for candidate in candidates:
                        if not self._is_openai_sender(candidate["from_addr"]):
                            continue
                        found_openai_sender = True

                        code = self._extract_otp(candidate["body"])
                        if code:
                            if self._select_mailbox(mail, candidate["mailbox"]):
                                mail.store(candidate["msg_id"], "+FLAGS", "\\Seen")
                            self.update_status(True)
                            logger.info(f"IMAP 获取验证码成功: {code}")
                            return code

                    if seen_any_message and not found_openai_sender:
                        raise OTPNoOpenAISenderEmailServiceError()

                except imaplib.IMAP4.error as e:
                    logger.debug(f"IMAP 搜索邮件失败: {e}")

                self._sleep_with_cancel(poll_interval)

        except Exception as e:
            if isinstance(e, OTPNoOpenAISenderEmailServiceError):
                raise
            logger.warning(f"IMAP 连接/轮询失败: {e}")
            self.update_status(False, e)
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

        return None

    def check_health(self) -> bool:
        """尝试 IMAP 登录并选择收件箱。"""
        mail = None
        try:
            mail = self._connect()
            status, _ = mail.select("INBOX")
            return status == "OK"
        except Exception as e:
            logger.warning(f"IMAP 健康检查失败: {e}")
            return False
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

    def list_emails(self, **kwargs) -> list:
        """IMAP 单账号模式，返回固定地址。"""
        return [{"email": self.email_addr, "id": self.email_addr}]

    def delete_email(self, email_id: str) -> bool:
        """IMAP 模式无需删除逻辑。"""
        return True
