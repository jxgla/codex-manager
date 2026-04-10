"""
Playwright-assisted registration engine.

This engine adapts the validated browser-assisted flow while preserving the
existing email service abstraction, task logging, and database persistence.
"""

import base64
import json
import logging
import random
import re
import secrets
import time
import uuid
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from ..config.constants import generate_random_user_info
from ..config.settings import get_settings
from .register import RegistrationEngine, RegistrationResult, TaskCancelledError


logger = logging.getLogger(__name__)

CHATGPT_SIGNIN_URL = "https://chatgpt.com/signin"
CHATGPT_AUTH_CSRF_URL = "https://chatgpt.com/api/auth/csrf"
CHATGPT_AUTH_SIGNIN_OPENAI_URL = "https://chatgpt.com/api/auth/signin/openai"
CHATGPT_AUTH_SESSION_URL = "https://chatgpt.com/api/auth/session"
SENTINEL_REQ_PATH = "/backend-api/sentinel/req"
SENTINEL_FRAME_PATH = "/backend-api/sentinel/frame.html"
SENTINEL_SDK_PATH = "/sentinel/20260124ceb8/sdk.js"
ERROR_EMAIL_ALREADY_USED = "EMAIL_ALREADY_USED"

_BROWSER_PROFILES = (
    {"width": 1512, "height": 982, "platform": "Win32"},
    {"width": 1470, "height": 956, "platform": "MacIntel"},
    {"width": 1365, "height": 940, "platform": "Linux x86_64"},
)

_UA_POOL = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
)


class EmailAlreadyUsedError(RuntimeError):
    """Raised when the browser flow clearly lands in an existing-account path."""


class _PlaywrightResponseShim:
    def __init__(
        self,
        status_code: int = 0,
        headers: Optional[Dict[str, str]] = None,
        text: str = "",
        url: str = "",
        json_data: Optional[Any] = None,
    ):
        self.status_code = int(status_code or 0)
        self.headers = {
            str(key).lower(): str(value)
            for key, value in (headers or {}).items()
        }
        self.text = str(text or "")
        self.url = str(url or "")
        self._json_data = json_data

    def json(self):
        if self._json_data is not None:
            return self._json_data
        self._json_data = json.loads(self.text or "{}")
        return self._json_data


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _extract_code_from_url(url: str) -> Optional[str]:
    if not url:
        return None
    values = parse_qs(urlparse(str(url)).query).get("code") or []
    return values[0] if values else None


def _payload_error_code(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    error_obj = data.get("error")
    if isinstance(error_obj, dict):
        value = str(error_obj.get("code") or "").strip()
        if value:
            return value
    for key in ("code", "error_code", "type"):
        value = str(data.get(key) or "").strip()
        if value:
            return value
    return ""


def _random_browser_profile(rng: random.Random) -> Dict[str, Any]:
    profile = dict(rng.choice(_BROWSER_PROFILES))
    profile.update(
        {
            "user_agent": rng.choice(_UA_POOL),
            "language": "en-US,en;q=0.9",
            "timezone": "UTC",
            "hardware_concurrency": rng.choice((4, 8, 12, 16)),
            "device_memory": rng.choice((4, 8, 16)),
        }
    )
    return profile


def _auth_base_from_settings() -> str:
    parsed = urlparse(get_settings().openai_auth_url)
    return f"{parsed.scheme or 'https'}://{parsed.netloc}"


def _sentinel_base() -> str:
    return "https://sentinel.openai.com"


def _cookie_items(jar: Any) -> list[Tuple[str, str]]:
    items: list[Tuple[str, str]] = []
    seen = set()
    try:
        iterable = list(jar)
    except Exception:
        iterable = []
    for cookie in iterable:
        name = str(getattr(cookie, "name", "") or "").strip()
        value = str(getattr(cookie, "value", "") or "")
        if not name or name in seen:
            continue
        seen.add(name)
        items.append((name, value))
    if items:
        return items
    try:
        for name, value in dict(jar.items()).items():
            key = str(name).strip()
            if not key or key in seen:
                continue
            seen.add(key)
            items.append((key, str(value)))
    except Exception:
        return []
    return items


class _SentinelTokenBuilder:
    def __init__(self, rng: random.Random, browser_profile: Dict[str, Any]):
        self.rng = rng
        self.browser_profile = dict(browser_profile)

    def _config(self) -> Dict[str, Any]:
        stamp = int(time.time() * 1000)
        return {
            "resolution": (
                f"{self.browser_profile['width']}x{self.browser_profile['height']}"
            ),
            "language": self.browser_profile["language"],
            "platform": self.browser_profile["platform"],
            "user_agent": self.browser_profile["user_agent"],
            "sdk_url": f"{_sentinel_base()}{SENTINEL_SDK_PATH}",
            "frame_url": f"{_sentinel_base()}{SENTINEL_FRAME_PATH}",
            "timestamp_ms": stamp,
            "time_origin": stamp - self.rng.randint(5000, 80000),
            "hardware_concurrency": self.browser_profile["hardware_concurrency"],
            "device_memory": self.browser_profile["device_memory"],
            "cookie_enabled": True,
            "pdf_viewer_enabled": True,
            "do_not_track": None,
            "random": _b64url_no_pad(secrets.token_bytes(9)),
        }

    def _encode(self, payload: Dict[str, Any]) -> str:
        raw = json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return _b64url_no_pad(raw)

    @staticmethod
    def _fnv1a32(data: bytes) -> int:
        value = 0x811C9DC5
        for byte in data:
            value ^= byte
            value = (value * 0x01000193) & 0xFFFFFFFF
        return value

    def generate_requirements_token(self) -> str:
        return self._encode({"type": "requirements", "config": self._config()})

    def generate_pow_token(self, seed: str, difficulty: int) -> str:
        config = self._config()
        difficulty = max(0, min(int(difficulty or 0), 31))
        start = self.rng.randint(0, 4096)
        limit = start + max(5000, 1 << min(difficulty, 12))
        blob = json.dumps(
            config,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        seed_bytes = str(seed or "").encode("utf-8")
        for nonce in range(start, limit):
            digest = self._fnv1a32(
                seed_bytes + b":" + str(nonce).encode("ascii") + b":" + blob
            )
            if difficulty <= 0 or (digest & ((1 << difficulty) - 1)) == 0:
                return self._encode(
                    {
                        "type": "pow",
                        "seed": str(seed or ""),
                        "difficulty": difficulty,
                        "nonce": nonce,
                        "config": config,
                    }
                )
        raise RuntimeError("sentinel pow unsatisfied")


class PlaywrightRegistrationEngine(RegistrationEngine):
    """Browser-assisted registration flow with cookie sync and Sentinel support."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rng = random.Random()
        self.browser_profile = _random_browser_profile(self.rng)
        self.sentinel = _SentinelTokenBuilder(self.rng, self.browser_profile)
        self.auth_base = _auth_base_from_settings()
        self.chat_base = "https://chatgpt.com"
        self.sentinel_base = _sentinel_base()
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._pw_timeout_ms = 45000
        self._cf_primed_hosts: set[str] = set()
        self._last_browser_url = ""
        self.last_session: Dict[str, Any] = {}
        user_info = generate_random_user_info()
        self.name = user_info.get("name") or "Neo"
        self.birthdate = user_info.get("birthdate") or "2000-02-20"
        self.password = self._generate_password()
        self.device_id = str(uuid.uuid4())

    def _resolved_execution_mode(self) -> str:
        return "playwright_v2"

    def _init_session(self) -> bool:
        try:
            self.session = self.http_client.session
            self.session.headers.update(
                {
                    "accept": "*/*",
                    "accept-language": self.browser_profile["language"],
                    "cache-control": "no-cache",
                    "pragma": "no-cache",
                    "user-agent": self.browser_profile["user_agent"],
                    "origin": self.chat_base,
                    "referer": CHATGPT_SIGNIN_URL,
                }
            )
            return True
        except Exception as exc:
            self._log(f"初始化浏览器会话失败: {exc}", "error")
            return False

    def close(self):
        for attr in ("_page", "_context", "_browser"):
            obj = getattr(self, attr, None)
            if not obj:
                continue
            try:
                obj.close()
            except Exception:
                pass
            setattr(self, attr, None)
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
        super().close()

    def _ensure_playwright_runtime(self):
        if self._context is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            raise RuntimeError(f"playwright import failed: {exc}") from exc

        launch_args = {"headless": True}
        if self.proxy_url:
            launch_args["proxy"] = {"server": self.proxy_url}

        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(**launch_args)
        self._context = self._browser.new_context(
            user_agent=str(self.browser_profile.get("user_agent") or ""),
            locale="en-US",
            viewport={"width": 1366, "height": 860},
            ignore_https_errors=True,
        )
        self._context.set_default_timeout(self._pw_timeout_ms)
        self._page = self._context.new_page()
        self._sync_http_cookies_to_browser(CHATGPT_SIGNIN_URL)

    def _sync_http_cookies_to_browser(self, seed_url: str):
        if self._context is None or self.session is None:
            return
        parsed = urlparse(str(seed_url or ""))
        origin = f"{parsed.scheme or 'https'}://{parsed.hostname or 'chatgpt.com'}"
        cookies = []
        for name, value in _cookie_items(getattr(self.session, "cookies", None) or {}):
            cookies.append({"name": name, "value": value, "url": origin, "path": "/"})
        if not cookies:
            return
        try:
            self._context.add_cookies(cookies)
        except Exception:
            pass

    def _sync_browser_cookies_to_http(self):
        if self._context is None or self.session is None:
            return
        try:
            cookies = self._context.cookies()
        except Exception:
            return
        for cookie in cookies:
            name = str((cookie or {}).get("name") or "").strip()
            value = str((cookie or {}).get("value") or "")
            domain = str((cookie or {}).get("domain") or ".chatgpt.com").strip()
            if not name:
                continue
            try:
                self.session.cookies.set(name, value, domain=domain or None)
            except Exception:
                pass

    def _prime_cf_for_url(self, url: str, force: bool = False):
        self._ensure_playwright_runtime()
        host = str(urlparse(str(url or "")).hostname or "").strip().lower()
        if not host:
            return
        if not force and host in self._cf_primed_hosts:
            return
        self._page.goto(
            str(url),
            wait_until="domcontentloaded",
            timeout=self._pw_timeout_ms,
        )
        self._page.wait_for_timeout(1400)
        self._cf_primed_hosts.add(host)
        self._sync_browser_cookies_to_http()

    def _browser_goto(self, url: str, referer: Optional[str] = None, wait_ms: int = 1200):
        self._ensure_playwright_runtime()
        try:
            self._page.goto(
                str(url),
                referer=referer,
                wait_until="domcontentloaded",
                timeout=self._pw_timeout_ms,
            )
            if int(wait_ms or 0) > 0:
                self._page.wait_for_timeout(int(wait_ms))
        finally:
            self._sync_browser_cookies_to_http()
        host = str(urlparse(str(url)).hostname or "").strip().lower()
        if host:
            self._cf_primed_hosts.add(host)
        current = str(getattr(self._page, "url", "") or url)
        if current:
            self._last_browser_url = current
        return current

    def _browser_path(self) -> Tuple[str, str]:
        raw = str(getattr(self._page, "url", "") or "").strip()
        sentinel_host = str(urlparse(self.sentinel_base).hostname or "").strip().lower()
        current_host = str(urlparse(raw).hostname or "").strip().lower()
        if raw and current_host != sentinel_host:
            self._last_browser_url = raw
        if (not raw or current_host == sentinel_host) and self._last_browser_url:
            raw = self._last_browser_url
        return urlparse(raw).path.lower(), raw

    @staticmethod
    def _is_cf_challenge_response(status: int, headers: Dict[str, str], body_text: str) -> bool:
        if int(status or 0) != 403:
            return False
        lowered_headers = {
            str(key).lower(): str(value).lower()
            for key, value in (headers or {}).items()
        }
        if lowered_headers.get("cf-mitigated"):
            return True
        text = str(body_text or "").lower()
        needles = ("cloudflare", "just a moment", "attention required", "cf-chl")
        return any(needle in text for needle in needles)

    def _playwright_request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        form: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = False,
    ) -> _PlaywrightResponseShim:
        self._ensure_playwright_runtime()
        parsed = urlparse(str(url))
        host = str(parsed.hostname or "").strip().lower()
        if host and host != str(urlparse(self.sentinel_base).hostname or "").lower():
            self._prime_cf_for_url(str(url), force=False)

        request_headers = {
            "accept": "*/*",
            "accept-language": str(self.browser_profile.get("language") or "en-US,en;q=0.9"),
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "user-agent": str(self.browser_profile.get("user_agent") or ""),
        }
        if parsed.scheme and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"
            request_headers.setdefault("origin", origin)
            request_headers.setdefault("referer", origin + "/")
        if headers:
            request_headers.update({str(key): str(value) for key, value in headers.items()})

        request_args: Dict[str, Any] = {
            "method": str(method or "GET").upper(),
            "headers": request_headers,
            "timeout": self._pw_timeout_ms,
            "fail_on_status_code": False,
            "ignore_https_errors": True,
            "max_redirects": 20 if allow_redirects else 0,
        }
        if params:
            request_args["params"] = {
                str(key): value
                for key, value in params.items()
                if value is not None
            }
        if json_body is not None:
            request_headers.setdefault("content-type", "application/json")
            request_args["data"] = json.dumps(
                json_body,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        elif form is not None:
            request_args["form"] = {
                str(key): "" if value is None else str(value)
                for key, value in dict(form).items()
            }

        response = self._context.request.fetch(str(url), **request_args)
        status = int(getattr(response, "status", 0) or 0)
        text = str(response.text() or "")
        response_headers = dict(response.headers or {})

        if self._is_cf_challenge_response(status, response_headers, text):
            self._prime_cf_for_url(str(url), force=True)
            response = self._context.request.fetch(str(url), **request_args)
            status = int(getattr(response, "status", 0) or 0)
            text = str(response.text() or "")
            response_headers = dict(response.headers or {})

        try:
            parsed_json = response.json()
        except Exception:
            parsed_json = None

        self._sync_browser_cookies_to_http()
        return _PlaywrightResponseShim(
            status_code=status,
            headers=response_headers,
            text=text,
            url=str(getattr(response, "url", url) or url),
            json_data=parsed_json,
        )

    def _api(
        self,
        method: str,
        url: str,
        step: str,
        *,
        expected: Tuple[int, ...] = (200, 201),
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        form: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = False,
    ) -> Tuple[int, Any, _PlaywrightResponseShim]:
        response = self._playwright_request(
            method,
            url,
            headers=headers,
            json_body=json_body,
            form=form,
            params=params,
            allow_redirects=allow_redirects,
        )
        status = int(getattr(response, "status_code", 0) or 0)
        try:
            data = response.json()
        except Exception:
            data = {"text": str(getattr(response, "text", "") or "")[:300]}

        if status in expected:
            self._log(f"{step} 成功 (HTTP {status})")
        else:
            compact = json.dumps(
                data if isinstance(data, dict) else {"text": str(data)},
                ensure_ascii=False,
            )
            self._log(f"{step} 失败: HTTP {status} {compact[:260]}", "warning")
        return status, data, response

    def _build_sentinel_token(self, label: str) -> str:
        payload = {
            "pathname": label,
            "sdk_url": f"{self.sentinel_base}{SENTINEL_SDK_PATH}",
            "user_agent": self.browser_profile.get("user_agent") or "",
        }
        try:
            status, data, _ = self._api(
                "POST",
                f"{self.sentinel_base}{SENTINEL_REQ_PATH}",
                f"Sentinel {label}",
                expected=(200, 201),
                json_body=payload,
            )
            if status in (200, 201) and isinstance(data, dict):
                seed = str(data.get("seed") or data.get("token") or "").strip()
                difficulty = int(data.get("difficulty") or 0)
                if seed:
                    return self.sentinel.generate_pow_token(seed, difficulty)
        except Exception as exc:
            self._log(f"Sentinel 回退 requirements token: {exc}", "warning")
        return self.sentinel.generate_requirements_token()

    def _signin_query_params(self, email: str) -> Dict[str, Any]:
        return {
            "prompt": "login",
            "ext-oai-did": self.device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "ext-passkey-client-capabilities": "1111",
            "screen_hint": "login_or_signup",
            "login_hint": str(email or "").strip(),
        }

    def _restart_register_entry(self, email: str) -> str:
        self._api(
            "GET",
            CHATGPT_SIGNIN_URL,
            "访问 signin",
            expected=(200, 302),
            allow_redirects=True,
        )
        status, csrf_data, _ = self._api(
            "GET",
            CHATGPT_AUTH_CSRF_URL,
            "获取 CSRF",
            expected=(200,),
            headers={"content-type": "application/json"},
        )
        csrf_token = str(
            (csrf_data if isinstance(csrf_data, dict) else {}).get("csrfToken") or ""
        ).strip()
        if status != 200 or not csrf_token:
            raise RuntimeError(f"csrfToken missing (status={status})")

        signin_status, signin_data, _ = self._api(
            "POST",
            CHATGPT_AUTH_SIGNIN_OPENAI_URL,
            "提交 signin/openai",
            expected=(200, 302),
            params=self._signin_query_params(email),
            form={
                "csrfToken": csrf_token,
                "callbackUrl": CHATGPT_SIGNIN_URL,
                "json": "true",
            },
            allow_redirects=False,
        )
        if signin_status not in (200, 302):
            raise RuntimeError(
                f"signin failed status={signin_status} code={_payload_error_code(signin_data)}"
            )
        auth_url = str((signin_data if isinstance(signin_data, dict) else {}).get("url") or "").strip()
        if not auth_url:
            return ""
        final_url = self._browser_goto(auth_url, referer=CHATGPT_SIGNIN_URL, wait_ms=1800)
        return str(final_url or auth_url)

    def _is_invalid_state(self, status: int, data: Any) -> bool:
        if int(status or 0) == 409 and _payload_error_code(data) == "invalid_state":
            return True
        body = json.dumps(
            data if isinstance(data, dict) else {"text": str(data)},
            ensure_ascii=False,
        ).lower()
        return "invalid_state" in body or "invalid session" in body

    def register(self, email: str) -> Tuple[int, Any]:
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "origin": self.auth_base,
            "referer": f"{self.auth_base}/create-account/password",
            "openai-sentinel-token": self._build_sentinel_token("username_password_create"),
        }
        params = {
            "ext-passkey-client-capabilities": json.dumps(
                {
                    "is_passkey_supported": False,
                    "is_platform_authenticator_available": False,
                    "is_conditional_mediation_available": False,
                },
                separators=(",", ":"),
            )
        }
        status, data, _ = self._api(
            "POST",
            f"{self.auth_base}/api/accounts/user/register",
            "提交注册",
            expected=(200, 201, 400, 409),
            headers=headers,
            params=params,
            json_body={"username": email, "password": self.password},
        )
        return status, data

    def _send_verification_code(self, referer: Optional[str] = None) -> bool:
        self._otp_sent_at = time.time()
        _, current_url = self._browser_path()
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "origin": self.auth_base,
            "referer": str(referer or current_url or f"{self.auth_base}/create-account/password"),
            "openai-sentinel-token": self._build_sentinel_token("email_otp_verification"),
        }
        status, data, _ = self._api(
            "POST",
            f"{self.auth_base}/api/accounts/email-otp/send",
            "发送 OTP",
            expected=(200, 201, 400, 409),
            headers=headers,
            json_body={},
        )
        return int(status or 0) in (200, 201) or _payload_error_code(data) in {
            "invalid_auth_step",
            "invalid_state",
        }

    def validate_otp(self, otp: str) -> Tuple[int, Any]:
        _, current_url = self._browser_path()
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "origin": self.auth_base,
            "referer": str(current_url or f"{self.auth_base}/email-verification"),
            "openai-sentinel-token": self._build_sentinel_token("email_otp_verification"),
        }
        return self._api(
            "POST",
            f"{self.auth_base}/api/accounts/email-otp/validate",
            "校验 OTP",
            expected=(200, 201, 400, 401, 409),
            headers=headers,
            json_body={"code": str(otp or "").strip()},
        )[:2]

    def create_account(self, email: str) -> Tuple[int, Any]:
        _, current_url = self._browser_path()
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "origin": self.auth_base,
            "referer": str(current_url or f"{self.auth_base}/about-you"),
            "openai-sentinel-token": self._build_sentinel_token("oauth_create_account"),
        }
        status, data, _ = self._api(
            "POST",
            f"{self.auth_base}/api/accounts/create_account",
            "创建账号资料",
            expected=(200, 201, 400, 409),
            headers=headers,
            json_body={"name": self.name, "birthdate": self.birthdate},
        )
        if int(status or 0) not in (200, 201) and _payload_error_code(data) == "user_already_exists":
            raise EmailAlreadyUsedError(email)
        return status, data

    def callback_and_get_session(self, created: Any) -> Dict[str, Any]:
        continue_url = ""
        if isinstance(created, dict):
            continue_url = str(
                created.get("continue_url")
                or created.get("redirect_url")
                or created.get("url")
                or ""
            ).strip()
        if continue_url:
            self._api(
                "GET",
                continue_url,
                "处理 callback",
                expected=(200, 302),
                allow_redirects=True,
            )
        status, data, _ = self._api(
            "GET",
            CHATGPT_AUTH_SESSION_URL,
            "获取 auth session",
            expected=(200,),
        )
        access_token = str(
            (data if isinstance(data, dict) else {}).get("accessToken")
            or (data if isinstance(data, dict) else {}).get("access_token")
            or ""
        ).strip()
        if status != 200 or not access_token:
            raise RuntimeError("session accessToken missing")
        self.last_session = data if isinstance(data, dict) else {}
        return self.last_session

    @staticmethod
    def _is_callback_url(url: str) -> bool:
        raw = str(url or "").strip()
        return bool(raw and "code=" in raw and "localhost" in raw)

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "accept": "application/json",
            "content-type": "application/json",
            "origin": self.auth_base,
            "referer": self.auth_base,
        }

    def _abs_auth_url(self, url: str) -> str:
        raw = str(url or "").strip()
        if not raw:
            return ""
        if raw.startswith("/"):
            return f"{self.auth_base}{raw}"
        return raw

    def _decode_auth_session_cookie(self) -> Optional[Dict[str, Any]]:
        values = []
        if self._context is not None:
            try:
                for item in self._context.cookies():
                    name = str((item or {}).get("name") or "").strip().lower()
                    value = str((item or {}).get("value") or "").strip()
                    if "oai-client-auth-session" in name and value:
                        values.append(value)
            except Exception:
                pass
        if self.session is not None:
            for name, value in _cookie_items(getattr(self.session, "cookies", None) or {}):
                if "oai-client-auth-session" in str(name).lower() and value:
                    values.append(value)
        for raw in values:
            for candidate in (raw, raw.replace("%22", '"')):
                try:
                    current = candidate[1:-1] if candidate[:1] in ("'", '"') and candidate[:1] == candidate[-1:] else candidate
                    chunk = current.split(".", 1)[0] if "." in current else current
                    chunk += "=" * ((4 - len(chunk) % 4) % 4)
                    data = json.loads(base64.urlsafe_b64decode(chunk).decode())
                    if isinstance(data, dict):
                        return data
                except Exception:
                    continue
        return None

    def _oauth_follow_chain_for_callback(
        self,
        start_url: str,
        referer: Optional[str] = None,
        max_hops: int = 12,
    ) -> Optional[str]:
        current = self._abs_auth_url(start_url)
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "upgrade-insecure-requests": "1",
        }
        if referer:
            headers["referer"] = self._abs_auth_url(referer)
        for hop in range(max(int(max_hops or 12), 1)):
            status, _, response = self._api(
                "GET",
                current,
                f"OAuth follow[{hop + 1}]",
                expected=(200, 301, 302, 303, 307, 308),
                headers=headers,
                allow_redirects=False,
            )
            last_url = str(getattr(response, "url", "") or current)
            if self._is_callback_url(last_url):
                return last_url
            location = self._abs_auth_url(
                str((getattr(response, "headers", {}) or {}).get("location") or "").strip()
            )
            if self._is_callback_url(location):
                return location
            if int(status or 0) not in (301, 302, 303, 307, 308) or not location:
                break
            headers["referer"] = last_url
            current = location
        return None

    def _oauth_browser_allow_redirect_callback(
        self,
        url: str,
        referer: Optional[str] = None,
    ) -> Optional[str]:
        target = self._abs_auth_url(url)
        if not target:
            return None
        try:
            final = self._browser_goto(target, referer=referer, wait_ms=1200)
        except Exception as exc:
            match = re.search(r"(https?://localhost[^\s'\"<>]+)", str(exc))
            final = match.group(1) if match else str(getattr(self._page, "url", "") or "")
        return final if self._is_callback_url(final) else None

    def _oauth_submit_workspace_org(self, consent_url: str) -> Optional[str]:
        session = self._decode_auth_session_cookie() or {}
        workspaces = session.get("workspaces") or []
        workspace_id = str(((workspaces[0] or {}).get("id")) or "").strip() if workspaces else ""
        if not workspace_id:
            return None

        headers = self._auth_headers()
        if consent_url:
            headers["referer"] = self._abs_auth_url(consent_url)

        status, data, response = self._api(
            "POST",
            f"{self.auth_base}/api/accounts/workspace/select",
            "OAuth workspace/select",
            expected=(200, 201, 301, 302, 303, 307, 308, 400),
            headers=headers,
            json_body={"workspace_id": workspace_id},
            allow_redirects=False,
        )
        location = self._abs_auth_url(
            str((getattr(response, "headers", {}) or {}).get("location") or "").strip()
        )
        if self._is_callback_url(location):
            return location
        if location:
            return (
                self._oauth_follow_chain_for_callback(location, referer=headers.get("referer"))
                or self._oauth_browser_allow_redirect_callback(location, referer=headers.get("referer"))
            )
        if int(status or 0) not in (200, 201) or not isinstance(data, dict):
            return None
        next_url = self._abs_auth_url(str(data.get("continue_url") or "").strip())
        orgs = ((data.get("data") or {}).get("orgs")) or []
        if orgs and isinstance(orgs[0], dict) and str(orgs[0].get("id") or "").strip():
            org_payload = {"org_id": str(orgs[0].get("id") or "").strip()}
            projects = (orgs[0] or {}).get("projects") or []
            if projects and isinstance(projects[0], dict) and str(projects[0].get("id") or "").strip():
                org_payload["project_id"] = str(projects[0].get("id") or "").strip()
            org_headers = dict(headers)
            if next_url:
                org_headers["referer"] = next_url
            status2, data2, response2 = self._api(
                "POST",
                f"{self.auth_base}/api/accounts/organization/select",
                "OAuth organization/select",
                expected=(200, 201, 301, 302, 303, 307, 308, 400),
                headers=org_headers,
                json_body=org_payload,
                allow_redirects=False,
            )
            location2 = self._abs_auth_url(
                str((getattr(response2, "headers", {}) or {}).get("location") or "").strip()
            )
            if self._is_callback_url(location2):
                return location2
            if location2:
                return (
                    self._oauth_follow_chain_for_callback(location2, referer=org_headers.get("referer"))
                    or self._oauth_browser_allow_redirect_callback(location2, referer=org_headers.get("referer"))
                )
            if int(status2 or 0) in (200, 201) and isinstance(data2, dict):
                next_url = self._abs_auth_url(str(data2.get("continue_url") or next_url or "").strip())
        if self._is_callback_url(next_url):
            return next_url
        return (
            self._oauth_follow_chain_for_callback(next_url, referer=headers.get("referer"))
            or self._oauth_browser_allow_redirect_callback(next_url, referer=headers.get("referer"))
        )

    def perform_oauth(self) -> str:
        if not self.oauth_start:
            raise RuntimeError("oauth not initialized")

        _, _, response = self._api(
            "GET",
            self.oauth_start.auth_url,
            "OAuth bootstrap",
            expected=(200, 302, 303, 307, 308),
            allow_redirects=False,
        )
        location = self._abs_auth_url(
            str((getattr(response, "headers", {}) or {}).get("location") or "").strip()
        )
        if self._is_callback_url(location):
            return location
        callback_url = (
            self._oauth_follow_chain_for_callback(location or self.oauth_start.auth_url, referer=self.oauth_start.auth_url)
            or self._oauth_browser_allow_redirect_callback(location or self.oauth_start.auth_url, referer=self.oauth_start.auth_url)
            or self._oauth_submit_workspace_org(location or self.oauth_start.auth_url)
        )
        if not callback_url:
            raise RuntimeError("oauth callback url not captured")
        if "state=" not in callback_url:
            sep = "&" if "?" in callback_url else "?"
            callback_url = f"{callback_url}{sep}state={self.oauth_start.state}"
        return callback_url

    def _validate_otp_with_retry(self, code: str) -> bool:
        status, data = self.validate_otp(code)
        if int(status or 0) in (200, 201):
            return True
        if self._is_invalid_state(status, data) or _payload_error_code(data) == "invalid_auth_step":
            self._log("OTP 状态失效，重发一次并重试验证码", "warning")
            self._send_verification_code()
            retry_status, _ = self.validate_otp(code)
            return int(retry_status or 0) in (200, 201)
        return False

    def _compose_cookie_string(self) -> str:
        if self.session is None:
            return ""
        return "; ".join(
            f"{name}={value}"
            for name, value in _cookie_items(getattr(self.session, "cookies", None) or {})
        )

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)

        try:
            self._raise_if_cancelled()
            self._log("=" * 60)
            self._log("开始 Playwright 注册流程")
            self._log("=" * 60)

            self._emit_status("ip_check", "检查 IP 地理位置", step_index=1)
            ip_ok, location = self._check_ip_location()
            if not ip_ok:
                result.error_message = f"IP 地理位置不支持: {location}"
                return result

            self._emit_status("email_prepare", "创建邮箱地址", step_index=2)
            if not self._phase_email_prepare():
                phase = self._get_phase_result("email_prepare")
                result.error_message = phase.error_message if phase else "创建邮箱失败"
                result.error_code = phase.error_code if phase else ""
                return result
            result.email = self.email

            self._emit_status("session_init", "初始化浏览器会话", step_index=3)
            if not self._init_session():
                result.error_message = "初始化会话失败"
                return result

            self._emit_status("oauth_start", "初始化 OAuth 参数", step_index=4)
            if not self._start_oauth():
                result.error_message = "初始化 OAuth 失败"
                return result

            self._emit_status("register_entry", "进入注册入口", step_index=5)
            entry_url = self._restart_register_entry(self.email or "")
            if "log-in/password" in urlparse(str(entry_url or "")).path.lower():
                raise EmailAlreadyUsedError(self.email or "")

            self._emit_status("signup_submit", "提交注册信息", step_index=6)
            status, register_data = self.register(self.email or "")
            if self._is_invalid_state(status, register_data):
                self._log("注册状态失效，刷新入口后重试", "warning")
                entry_url = self._restart_register_entry(self.email or "")
                if "log-in/password" in urlparse(str(entry_url or "")).path.lower():
                    raise EmailAlreadyUsedError(self.email or "")
                status, register_data = self.register(self.email or "")

            if int(status or 0) not in (200, 201):
                current_path, _ = self._browser_path()
                if "log-in/password" in current_path:
                    raise EmailAlreadyUsedError(self.email or "")
                result.error_message = f"注册失败: {_payload_error_code(register_data) or register_data}"
                return result

            self._emit_status("otp_send", "发送邮箱验证码", step_index=7)
            if not self._send_verification_code():
                result.error_message = "发送验证码失败"
                return result

            self._emit_status("otp_secondary", "等待邮箱验证码", step_index=8)
            code, otp_phase = self._await_verification_code_with_resends(
                self._send_verification_code,
                timeout_retry_log_template="验证码超时，第 {attempt} 次重发",
                non_openai_retry_log_template="检测到非 OpenAI 发件干扰，第 {attempt} 次重发",
                timeout_retry_status_template="验证码重发（第 {attempt} 次）",
                non_openai_retry_status_template="验证码重发（非 OpenAI 发件，第 {attempt} 次）",
                step_index=8,
            )
            if not code:
                result.error_message = otp_phase.error_message if otp_phase else "获取验证码失败"
                result.error_code = otp_phase.error_code if otp_phase else ""
                return result

            self._emit_status("otp_validate", "校验验证码", step_index=9)
            if not self._validate_otp_with_retry(code):
                result.error_message = "验证码校验失败"
                return result

            self._emit_status("account_create", "创建账号资料", step_index=10)
            create_status, created = self.create_account(self.email or "")
            if int(create_status or 0) not in (200, 201):
                result.error_message = f"创建账号失败: {_payload_error_code(created) or created}"
                return result

            self._emit_status("session_fetch", "同步 chat 会话", step_index=11)
            session_data = self.callback_and_get_session(created)
            result.workspace_id = (
                self._extract_workspace_id_from_auth_json(session_data)
                or result.workspace_id
            )

            self._emit_status("oauth_callback", "完成 OAuth 授权", step_index=12)
            callback_url = self.perform_oauth()
            token_info = self._handle_oauth_callback(callback_url)
            if not token_info:
                result.error_message = "OAuth 回调处理失败"
                return result

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
            return result

        except EmailAlreadyUsedError:
            result.error_message = "邮箱已进入既有账号流程"
            result.error_code = ERROR_EMAIL_ALREADY_USED
            return result
        except TaskCancelledError as exc:
            result.error_message = str(exc)
            result.error_code = getattr(exc, "error_code", "TASK_CANCELLED")
            return result
        except Exception as exc:
            self._log(f"Playwright 注册流程异常: {exc}", "error")
            result.error_message = str(exc)
            return result
