"""
Playwright V3 registration engine.

V3 follows the two-stage daily-bing style flow:
1. finish account creation first
2. run the daily-playwright style OAuth flow afterwards
"""

from __future__ import annotations

import time
from urllib.parse import urlparse

from .register import RegistrationResult, TaskCancelledError
from .register_playwright import (
    EmailAlreadyUsedError,
    PlaywrightRegistrationEngine,
    _payload_error_summary,
)


class PlaywrightRegistrationEngineV3(PlaywrightRegistrationEngine):
    def _resolved_execution_mode(self) -> str:
        return "playwright_v3"

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)

        try:
            self._raise_if_cancelled()
            self._log("=" * 60)
            self._log("Start Playwright V3 registration flow")
            self._log("=" * 60)

            self._emit_status("ip_check", "Check IP location", step_index=1)
            ip_ok, location = self._check_ip_location()
            if not ip_ok:
                self._log(f"IP region check blocked current exit node: {location}", "error")
                result.error_message = f"IP region unsupported: {location}"
                return result
            if location:
                self._log(f"IP region check passed: {location}")
            else:
                self._log("IP region check unavailable, continuing without geo restriction", "warning")

            self._emit_status("email_prepare", "Create email address", step_index=2)
            if not self._phase_email_prepare():
                phase = self._get_phase_result("email_prepare")
                result.error_message = phase.error_message if phase else "Email creation failed"
                result.error_code = phase.error_code if phase else ""
                return result
            result.email = self.email

            self._emit_status("session_init", "Initialize browser session", step_index=3)
            if not self._init_session():
                result.error_message = "Session initialization failed"
                return result

            self._emit_status("register_entry", "Enter register flow", step_index=4)
            entry_url = self._restart_register_entry(self.email or "")
            if "log-in/password" in urlparse(str(entry_url or "")).path.lower():
                raise EmailAlreadyUsedError(self.email or "")

            self._emit_status("signup_submit", "Submit register payload", step_index=5)
            status, register_data = self.register(self.email or "")
            if self._is_invalid_state(status, register_data):
                self._log("Register state expired, refreshing entry and retrying", "warning")
                entry_url = self._restart_register_entry(self.email or "")
                if "log-in/password" in urlparse(str(entry_url or "")).path.lower():
                    raise EmailAlreadyUsedError(self.email or "")
                status, register_data = self.register(self.email or "")

            if int(status or 0) not in (200, 201):
                current_path, _ = self._browser_path()
                if "log-in/password" in current_path:
                    raise EmailAlreadyUsedError(self.email or "")
                error_summary = _payload_error_summary(register_data)
                self._log(f"提交注册失败详情: {error_summary}", "error")
                result.error_message = f"注册失败: {error_summary}"
                return result

            self._emit_status("otp_send", "Send OTP email", step_index=6)
            if not self._send_verification_code():
                result.error_message = "Send OTP failed"
                return result

            self._emit_status("otp_secondary", "Wait for OTP", step_index=7)
            code, otp_phase = self._await_verification_code_with_resends(
                self._send_verification_code,
                timeout_retry_log_template="OTP timeout, resend attempt {attempt}",
                non_openai_retry_log_template="Non-OpenAI mail detected, resend attempt {attempt}",
                timeout_retry_status_template="Resend OTP attempt {attempt}",
                non_openai_retry_status_template="Resend OTP after noisy mail attempt {attempt}",
                step_index=7,
            )
            if not code:
                result.error_message = otp_phase.error_message if otp_phase else "Fetch OTP failed"
                result.error_code = otp_phase.error_code if otp_phase else ""
                return result

            self._emit_status("otp_validate", "Validate OTP", step_index=8)
            if not self._validate_otp_with_retry(code):
                result.error_message = "OTP validation failed"
                return result

            self._emit_status("account_create", "Create account profile", step_index=9)
            create_status, created = self.create_account(self.email or "")
            if int(create_status or 0) not in (200, 201):
                result.error_message = f"Create account failed: {_payload_error_code(created) or created}"
                return result
            self._append_account_checkpoint(
                "account_created",
                oauth=False,
                metadata={"status": "created"},
            )

            self._emit_status("session_fetch", "Fetch chat session", step_index=10)
            session_data = self.callback_and_get_session(created)
            result.workspace_id = (
                self._extract_workspace_id_from_auth_json(session_data)
                or result.workspace_id
            )

            self._emit_status("oauth_start", "Bootstrap OAuth after account creation", step_index=11)
            if not self._start_oauth():
                result.error_message = "Initialize OAuth failed"
                return result

            self._emit_status("oauth_callback", "Extract OAuth code and exchange token", step_index=12)
            callback_url = self.perform_oauth()
            # Extract code from callback_url and exchange via Playwright session
            # (mirrors daily-bing's _oauth_exchange_code for reliable token exchange)
            from .register_playwright import _extract_code_from_url
            auth_code = _extract_code_from_url(callback_url)
            token_info = None
            if auth_code:
                token_info = self._oauth_exchange_code_via_playwright(auth_code)
                if token_info:
                    self._log("OAuth token acquired via Playwright exchange")
            if not token_info:
                # Fallback to original oauth_manager.handle_callback
                self._log("Playwright exchange unavailable, falling back to oauth_manager", "warning")
                token_info = self._handle_oauth_callback(callback_url)
            if not token_info:
                result.error_message = "OAuth callback handling failed"
                return result

            if not result.workspace_id:
                # Try from token exchange result first (Playwright exchange extracts from JWT)
                result.workspace_id = str(token_info.get("workspace_id") or "").strip()
            if not result.workspace_id:
                auth_session = self._decode_auth_session_cookie() or {}
                workspaces = auth_session.get("workspaces") or []
                if workspaces and isinstance(workspaces[0], dict):
                    result.workspace_id = str(workspaces[0].get("id") or "").strip()

            result.success = True
            result.account_id = str(token_info.get("account_id") or "")
            result.access_token = str(token_info.get("access_token") or "")
            result.refresh_token = str(token_info.get("refresh_token") or "")
            result.id_token = str(token_info.get("id_token") or "")
            result.password = self.password
            result.source = "register"
            result.cookies = self._compose_cookie_string()

            session_cookie = self.session.cookies.get("__Secure-next-auth.session-token")
            if session_cookie:
                result.session_token = session_cookie

            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "proxy_used": self.proxy_url,
                "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "registration_mode": self._resolved_execution_mode(),
            }
            self._append_account_checkpoint(
                "oauth_success",
                oauth=True,
                metadata={
                    "source": result.source,
                    "account_id": result.account_id,
                    "workspace_id": result.workspace_id,
                    "status": "oauth_success",
                },
            )
            return result

        except EmailAlreadyUsedError:
            result.error_message = "Email entered the existing-account flow"
            result.error_code = "EMAIL_ALREADY_USED"
            return result
        except TaskCancelledError as exc:
            result.error_message = str(exc)
            result.error_code = getattr(exc, "error_code", "TASK_CANCELLED")
            return result
        except Exception as exc:
            self._log(f"Playwright V3 registration flow failed: {exc}", "error")
            result.error_message = str(exc)
            return result
