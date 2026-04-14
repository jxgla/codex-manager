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
from urllib.parse import parse_qs, urlencode, urlparse

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
SENTINEL_FRAME_VERSION = "20260219f9f6"
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
    raw = str(url or "").strip()
    if not raw:
        return None
    candidate = raw
    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"
    parsed = urlparse(candidate)
    for chunk in (parsed.query, parsed.fragment):
        values = parse_qs(chunk, keep_blank_values=True).get("code") or []
        if values and str(values[0] or "").strip():
            return str(values[0]).strip()
    values = parse_qs(raw.lstrip("?"), keep_blank_values=True).get("code") or []
    if values and str(values[0] or "").strip():
        return str(values[0]).strip()
    return None


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


def _payload_error_summary(data: Any) -> str:
    if isinstance(data, dict):
        error_obj = data.get("error")
        if isinstance(error_obj, dict):
            code = str(error_obj.get("code") or "").strip()
            message = str(error_obj.get("message") or "").strip()
            if code and message:
                return f"{code}: {message}"
            if message:
                return message
            if code:
                return code
        for key in ("message", "detail", "text", "error_description"):
            value = str(data.get(key) or "").strip()
            if value:
                return value
        return json.dumps(data, ensure_ascii=False)[:500]
    return str(data or "").strip()[:500]


def _extract_direct_token(raw: Any) -> Optional[str]:
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    if isinstance(raw, dict):
        for key in ("token", "sentinel", "sentinel_token", "sentinelToken", "value", "result"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _extract_triplet(raw: Any) -> Optional[Dict[str, str]]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            return None
    if not isinstance(raw, dict):
        return None
    proof = str(raw.get("p") or raw.get("pow") or raw.get("proof") or "").strip()
    turnstile = str(raw.get("t") or raw.get("turnstile") or raw.get("turnstile_token") or "").strip()
    challenge = str(raw.get("c") or raw.get("challenge") or raw.get("challenge_token") or raw.get("token") or "").strip()
    return {"p": proof, "t": turnstile, "c": challenge} if proof and challenge else None


def _trace_headers() -> Dict[str, str]:
    trace_id = random.randint(10**17, 10**18 - 1)
    parent_id = random.randint(10**17, 10**18 - 1)
    return {
        "traceparent": f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": str(trace_id),
        "x-datadog-parent-id": str(parent_id),
    }


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
        self._sentinel_page = None
        self._pw_timeout_ms = 45000
        self._cf_primed_hosts: set[str] = set()
        self._last_browser_url = ""
        self.last_session: Dict[str, Any] = {}
        self.oauth_fail_reason = ""
        self._oauth_passwordless_active = False
        self._sentinel_bundle_loaded = False
        self._sentinel_flow_tokens: Dict[str, str] = {}
        self._sentinel_flow_so_tokens: Dict[str, str] = {}
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
        for attr in ("_sentinel_page", "_page", "_context", "_browser"):
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
        self._initialize_sentinel_page()

    def _initialize_sentinel_page(self):
        if self._context is None or self._sentinel_page is not None:
            return
        try:
            self._sentinel_page = self._context.new_page()
            frame_url = f"{self.sentinel_base}{SENTINEL_FRAME_PATH}?sv={SENTINEL_FRAME_VERSION}"
            self._sentinel_page.goto(
                frame_url,
                wait_until="domcontentloaded",
                timeout=self._pw_timeout_ms,
            )
            self._sentinel_page.wait_for_timeout(3000)
            self._sentinel_bundle_loaded = False
            self._log(f"Sentinel frame ready: {frame_url}")
        except Exception as exc:
            self._log(f"Sentinel frame init failed: {exc}", "warning")

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

    def _open_fresh_browser_page(self, seed_url: str = CHATGPT_SIGNIN_URL):
        self._ensure_playwright_runtime()
        self._sync_http_cookies_to_browser(seed_url)
        previous_page = self._page
        self._page = self._context.new_page()
        self._page.set_default_timeout(self._pw_timeout_ms)
        if previous_page is not None:
            try:
                previous_page.close()
            except Exception:
                pass
        return self._page

    @staticmethod
    def _extract_next_url(data: Any, default: str = "") -> str:
        if not isinstance(data, dict):
            return str(default or "").strip()
        return str(
            data.get("continue_url")
            or data.get("url")
            or data.get("redirect_url")
            or default
            or ""
        ).strip()

    @staticmethod
    def _extract_page_type(data: Any) -> str:
        if not isinstance(data, dict):
            return ""
        return str(((data.get("page") or {}).get("type")) or "").strip()

    @staticmethod
    def _looks_like_about_you(page_type: str = "", next_url: str = "") -> bool:
        lowered = f"{page_type} {next_url}".lower()
        return "about-you" in lowered or "about_you" in lowered

    @staticmethod
    def _looks_like_callback(page_type: str = "", next_url: str = "") -> bool:
        lowered_page = str(page_type or "").lower()
        lowered_url = str(next_url or "").lower()
        combined = f"{lowered_page} {lowered_url}"
        return (
            "callback" in lowered_page
            or "localhost:1455/auth/callback" in combined
            or "/auth/callback" in combined
            or ("callback" in combined and any(marker in combined for marker in ("code=", "state=", "error=")))
        )

    @staticmethod
    def _looks_like_password_step(page_type: str = "", next_url: str = "") -> bool:
        lowered = f"{page_type} {next_url}".lower()
        return "password" in lowered or "/log-in/password" in lowered or "login_password" in lowered

    @staticmethod
    def _looks_like_otp_step(page_type: str = "", next_url: str = "") -> bool:
        lowered = f"{page_type} {next_url}".lower()
        return "email_otp_verification" in lowered or "email-verification" in lowered or "email-otp" in lowered

    @staticmethod
    def _looks_like_consent_step(page_type: str = "", next_url: str = "") -> bool:
        lowered = f"{page_type} {next_url}".lower()
        return (
            "consent" in lowered
            or "workspace" in lowered
            or "organization" in lowered
            or "sign-in-with-chatgpt" in lowered
        )

    @staticmethod
    def _looks_like_challenge(page_type: str = "", next_url: str = "") -> bool:
        lowered = f"{page_type} {next_url}".lower()
        markers = (
            "__cf_chl",
            "cdn-cgi/challenge-platform",
            "cf-mitigated",
            "challenges.cloudflare.com",
            "/api/auth/error",
        )
        return any(marker in lowered for marker in markers)

    @staticmethod
    def _looks_like_add_phone(page_type: str = "", next_url: str = "") -> bool:
        lowered = f"{page_type} {next_url}".lower()
        return "add-phone" in lowered or "add_phone" in lowered or "/add-phone" in lowered

    @staticmethod
    def _text_looks_like_add_phone(text: str = "", page_type: str = "", next_url: str = "") -> bool:
        lowered = f"{page_type} {next_url} {text}".lower()
        markers = (
            "add-phone",
            "add_phone",
            "/add-phone",
            "add phone number",
            "add a phone number",
            "enter your phone number",
            "verify your phone number",
            "phone number to continue",
        )
        return any(marker in lowered for marker in markers)

    def _report_add_phone(
        self,
        stage: str,
        page_type: str = "",
        next_url: str = "",
        payload: Optional[Any] = None,
    ) -> None:
        self.oauth_fail_reason = "add-phone gate"
        self._log(
            f"OAuth add-phone gate stage={stage} page={page_type or '-'} url={(next_url or '-')[:220]}",
            "warning",
        )
        if payload is not None:
            compact = json.dumps(payload if isinstance(payload, dict) else {"text": str(payload)}, ensure_ascii=False)
            self._log(f"OAuth add-phone payload: {compact[:320]}", "warning")

    def _detect_browser_add_phone(
        self,
        stage: str,
        candidate_url: str = "",
        payload: Optional[Any] = None,
    ) -> bool:
        current_url = self._abs_auth_url(getattr(self._page, "url", "")) or self._abs_auth_url(candidate_url)
        if self._looks_like_add_phone(next_url=current_url):
            self._report_add_phone(stage, next_url=current_url, payload=payload)
            return True
        try:
            html = self._page.content() or ""
        except Exception:
            html = ""
        if html and self._text_looks_like_add_phone(html, next_url=current_url):
            report_payload = payload if payload is not None else {"url": current_url, "html": html[:260]}
            self._report_add_phone(stage, next_url=current_url, payload=report_payload)
            return True
        return False

    @staticmethod
    def _locator_is_editable(locator) -> bool:
        try:
            return bool(locator.is_editable(timeout=200))
        except Exception:
            pass
        try:
            return bool(
                locator.evaluate(
                    """(el) => {
                        if (!el) return false;
                        const disabled = !!el.disabled || el.getAttribute('aria-disabled') === 'true';
                        const readOnly = !!el.readOnly || el.getAttribute('readonly') !== null;
                        return !disabled && !readOnly;
                    }"""
                )
            )
        except Exception:
            return False

    def _find_first_visible(self, selectors, timeout_ms: int = 4000, editable_only: bool = False):
        deadline = time.time() + max(int(timeout_ms or 0), 250) / 1000.0
        while time.time() < deadline:
            for selector in selectors:
                try:
                    group = self._page.locator(selector)
                    count = min(group.count(), 6)
                    for index in range(count):
                        try:
                            locator = group.nth(index)
                            if not locator.is_visible():
                                continue
                            if editable_only and not self._locator_is_editable(locator):
                                continue
                            return locator
                        except Exception:
                            continue
                except Exception:
                    continue
            try:
                self._page.wait_for_timeout(200)
            except Exception:
                time.sleep(0.2)
        return None

    @staticmethod
    def _locator_value(locator) -> str:
        try:
            return str(locator.input_value(timeout=1200))
        except Exception:
            pass
        try:
            return str(locator.evaluate("(el) => ('value' in el ? el.value : '')"))
        except Exception:
            return ""

    def _fill_first_visible(self, selectors, value: str, timeout_ms: int = 4000) -> bool:
        locator = self._find_first_visible(selectors, timeout_ms=timeout_ms)
        if not locator:
            return False
        target = str(value or "")
        try:
            locator.click(timeout=2000)
        except Exception:
            pass
        for attempt in range(3):
            try:
                locator.fill("")
            except Exception:
                try:
                    locator.press("Control+A")
                    locator.press("Backspace")
                except Exception:
                    pass
            try:
                locator.fill(target)
            except Exception:
                try:
                    if attempt > 0:
                        locator.press("Control+A")
                        locator.press("Backspace")
                    locator.type(target, delay=20)
                except Exception:
                    if attempt >= 2:
                        return False
                    continue
            if self._locator_value(locator).strip() == target:
                return True
            try:
                self._page.wait_for_timeout(200)
            except Exception:
                time.sleep(0.2)
        return False

    def _click_first_visible(self, selectors, timeout_ms: int = 4000) -> bool:
        locator = self._find_first_visible(selectors, timeout_ms=timeout_ms)
        if not locator:
            return False
        try:
            locator.click(timeout=2000)
            return True
        except Exception:
            try:
                locator.press("Enter")
                return True
            except Exception:
                return False

    @staticmethod
    def _auth_email_selectors():
        return [
            "input[type='email']",
            "input[inputmode='email']",
            "input[autocomplete*='email' i]",
            "input[autocomplete*='username' i]",
            "input[name='email']",
            "input[name='username']",
            "input[name*='email' i]",
            "input[id*='email' i]",
            "input[placeholder*='mail' i]",
            "input[aria-label*='mail' i]",
            "input[data-testid*='email' i]",
        ]

    @staticmethod
    def _auth_password_selectors():
        return [
            "input[type='password']",
            "input[name='password']",
            "input[name*='password' i]",
            "input[id*='password' i]",
            "input[autocomplete*='current-password' i]",
            "input[autocomplete*='new-password' i]",
            "input[placeholder*='password' i]",
            "input[aria-label*='password' i]",
            "input[data-testid*='password' i]",
        ]

    @staticmethod
    def _auth_submit_selectors():
        return [
            "button[type='submit']",
            "button:has-text('Continue')",
            "button:has-text('Next')",
            "button:has-text('Log in')",
            "button:has-text('Login')",
            "button:has-text('Sign in')",
            "button:has-text('Sign up')",
            "button:has-text('Create account')",
            "button:has-text('Create Account')",
            "button:has-text('Verify email')",
            "[role='button']:has-text('Continue')",
            "[role='button']:has-text('Next')",
            "[role='button']:has-text('Sign in')",
            "[role='button']:has-text('Sign up')",
            "[role='button']:has-text('Create account')",
        ]

    def _detect_browser_auth_state(self) -> Tuple[str, str]:
        current = str(getattr(self._page, "url", "") or "")
        email_selectors = self._auth_email_selectors()
        password_selectors = self._auth_password_selectors()
        if _extract_code_from_url(current):
            return current, "callback"
        if self._looks_like_challenge("", current):
            return current, "challenge"
        if self._looks_like_callback("", current):
            return current, "callback"
        if self._looks_like_about_you("", current):
            return current, "about_you"
        if self._looks_like_consent_step("", current):
            return current, "consent"
        if self._looks_like_otp_step("", current):
            return current, "email_otp_verification"
        email_visible = bool(self._find_first_visible(email_selectors, timeout_ms=300))
        password_visible = bool(self._find_first_visible(password_selectors, timeout_ms=300))
        email_editable = bool(self._find_first_visible(email_selectors, timeout_ms=300, editable_only=True))
        password_editable = bool(self._find_first_visible(password_selectors, timeout_ms=300, editable_only=True))
        if self._looks_like_password_step("", current) and (password_editable or password_visible):
            return current, "login_password"
        if email_editable and password_editable:
            return current, "login_email_password"
        if "create-account" in urlparse(current).path.lower() and (password_editable or password_visible):
            return current, "login_email_password" if email_editable else "login_password"
        if password_editable or password_visible:
            return current, "login_password"
        if email_editable or email_visible:
            return current, "login_email"
        return current, ""

    def _oauth_browser_authenticate(self, email: str, password: str, start_url: str = "") -> Tuple[str, str]:
        target = self._abs_auth_url(start_url or getattr(self._page, "url", "") or f"{self.auth_base}/log-in")
        current = self._abs_auth_url(getattr(self._page, "url", "") or "")
        if target and target != current:
            self._browser_goto(target, referer=f"{self.auth_base}/log-in", wait_ms=1800)

        submit_selectors = self._auth_submit_selectors()
        email_selectors = self._auth_email_selectors()
        password_selectors = self._auth_password_selectors()
        email_submitted = False
        password_submitted = False
        challenge_hits = 0

        for _ in range(8):
            current_url, state = self._detect_browser_auth_state()
            email_visible = bool(self._find_first_visible(email_selectors, timeout_ms=300))
            password_visible = bool(self._find_first_visible(password_selectors, timeout_ms=300))
            password_stage = self._looks_like_password_step("", current_url)
            if state == "challenge":
                challenge_hits += 1
                self._sync_browser_cookies_to_http()
                if challenge_hits >= 2:
                    return current_url, state
                if target:
                    try:
                        self._browser_goto(target, referer=current_url or f"{self.auth_base}/log-in", wait_ms=1500)
                    except Exception:
                        pass
                continue
            if state in ("callback", "about_you", "consent", "email_otp_verification"):
                self._sync_browser_cookies_to_http()
                return current_url, state
            if state == "login_email_password":
                require_email_fill = not password_stage and not email_submitted
                if require_email_fill and self._fill_first_visible(email_selectors, email, timeout_ms=2500):
                    email_submitted = True
                if not password_submitted and self._fill_first_visible(password_selectors, password, timeout_ms=2500):
                    password_submitted = True
                ready_to_submit = password_submitted if password_stage else (email_submitted and password_submitted)
                if ready_to_submit:
                    if not self._click_first_visible(submit_selectors, timeout_ms=2500):
                        try:
                            self._page.keyboard.press("Enter")
                        except Exception:
                            pass
                    if password_submitted:
                        self._otp_sent_at = time.time()
                    self._page.wait_for_timeout(1800)
                    self._sync_browser_cookies_to_http()
                    continue
                self._page.wait_for_timeout(500)
                self._sync_browser_cookies_to_http()
                continue
            if state == "login_email" and not email_submitted:
                if self._fill_first_visible(email_selectors, email, timeout_ms=2500):
                    email_submitted = True
                    if not self._click_first_visible(submit_selectors, timeout_ms=2500):
                        try:
                            self._page.keyboard.press("Enter")
                        except Exception:
                            pass
                    self._page.wait_for_timeout(1200)
                    self._sync_browser_cookies_to_http()
                    continue
            if email_visible and not email_submitted:
                if self._fill_first_visible(email_selectors, email, timeout_ms=2500):
                    email_submitted = True
                    self._sync_browser_cookies_to_http()
                    continue
            if (state == "login_password" or password_visible) and not password_submitted:
                if self._fill_first_visible(password_selectors, password, timeout_ms=2500):
                    password_submitted = True
                    self._otp_sent_at = time.time()
                    if not self._click_first_visible(submit_selectors, timeout_ms=2500):
                        try:
                            self._page.keyboard.press("Enter")
                        except Exception:
                            pass
                    self._page.wait_for_timeout(1800)
                    self._sync_browser_cookies_to_http()
                    continue
            self._page.wait_for_timeout(1200)
            self._sync_browser_cookies_to_http()
        return self._detect_browser_auth_state()

    @staticmethod
    def _consent_action_selectors():
        return [
            "button:has-text('Continue')",
            "button:has-text('Continue to')",
            "button:has-text('Allow')",
            "button:has-text('Authorize')",
            "button:has-text('Accept')",
            "button:has-text('Approve')",
            "button:has-text('Confirm')",
            "button:has-text('Agree')",
            "button:has-text('OK')",
            "[role='button']:has-text('Continue')",
            "[role='button']:has-text('Allow')",
            "text=/continue/i",
            "text=/allow/i",
            "text=/authorize/i",
            "text=/accept/i",
            "text=/confirm/i",
            "a:has-text('Continue')",
            "a:has-text('Allow')",
            "[role='link']:has-text('Continue')",
            "button[type='submit']",
        ]

    def _click_consent_action_fallback(self, timeout_ms: int = 2500) -> bool:
        deadline = time.time() + max(int(timeout_ms or 0), 250) / 1000.0
        pattern = r"(continue|continue to|allow|authorize|accept|approve|confirm|agree|ok)"
        while time.time() < deadline:
            try:
                clicked = self._page.evaluate(
                    """(pattern) => {
                        const re = new RegExp(pattern, 'i');
                        const selectors = ['button', '[role="button"]', 'a', '[role="link"]', 'input[type="submit"]', 'input[type="button"]'];
                        const visible = (el) => {
                            if (!el) return false;
                            const style = window.getComputedStyle(el);
                            if (style.display === 'none' || style.visibility === 'hidden') return false;
                            const rect = el.getBoundingClientRect();
                            return rect.width > 0 && rect.height > 0;
                        };
                        const textOf = (el) => (
                            el.innerText || el.textContent || el.value || el.getAttribute('aria-label') || el.getAttribute('title') || ''
                        ).trim();
                        for (const selector of selectors) {
                            for (const el of document.querySelectorAll(selector)) {
                                const text = textOf(el);
                                if (!text || !re.test(text) || !visible(el)) continue;
                                if (el.disabled || el.getAttribute('aria-disabled') === 'true') continue;
                                el.click();
                                return text;
                            }
                        }
                        return '';
                    }""",
                    pattern,
                )
            except Exception:
                clicked = ""
            if clicked:
                return True
            try:
                self._page.wait_for_timeout(200)
            except Exception:
                time.sleep(0.2)
        return False

    def _report_workspace_issue(
        self,
        reason: str,
        consent_url: str = "",
        session: Optional[Dict[str, Any]] = None,
    ) -> None:
        current = self._abs_auth_url(getattr(self._page, "url", "")) or self._abs_auth_url(consent_url)
        button_visible = bool(self._find_first_visible(self._consent_action_selectors(), timeout_ms=400))
        workspace_count = len((session or {}).get("workspaces") or []) if isinstance(session, dict) else 0
        if self._detect_browser_add_phone(f"workspace_{reason}", candidate_url=current):
            return
        self.oauth_fail_reason = (
            f"{reason} (workspaces={workspace_count}, "
            f"consent={'yes' if self._looks_like_consent_step('', current) else 'no'}, "
            f"button={'yes' if button_visible else 'no'})"
        )
        self._log(
            f"OAuth workspace issue reason={reason} workspaces={workspace_count} "
            f"consent={'yes' if self._looks_like_consent_step('', current) else 'no'} "
            f"button={'yes' if button_visible else 'no'} "
            f"url={(current or '-')[:220]}",
            "warning",
        )

    def _advance_browser_consent(
        self,
        consent_url: str = "",
        referer: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        target = self._abs_auth_url(consent_url or getattr(self._page, "url", ""))
        if target:
            try:
                self._browser_goto(target, referer=referer, wait_ms=1600)
            except Exception:
                pass
        if self._detect_browser_add_phone("consent_open", candidate_url=target):
            return False, None
        if not self._click_first_visible(self._consent_action_selectors(), timeout_ms=2500):
            if not self._click_consent_action_fallback(timeout_ms=1800):
                return False, None
        try:
            self._page.wait_for_timeout(1800)
        except Exception:
            time.sleep(1.8)
        self._sync_browser_cookies_to_http()
        final = self._abs_auth_url(getattr(self._page, "url", "")) or target
        if self._detect_browser_add_phone("consent_click", candidate_url=final):
            return True, None
        return True, (_extract_code_from_url(final) or self._oauth_follow_chain_for_code(final, referer=target)[0])

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

        compact = json.dumps(
            data if isinstance(data, dict) else {"text": str(data)},
            ensure_ascii=False,
        )

        if status in expected and 200 <= status < 300:
            self._log(f"{step} 成功 (HTTP {status})")
        elif status in expected:
            self._log(f"{step} 返回 HTTP {status}: {compact[:500]}", "warning")
        else:
            self._log(f"{step} 失败: HTTP {status} {compact[:500]}", "warning")
        return status, data, response

    def _ensure_sentinel_bundle(self) -> bool:
        self._ensure_playwright_runtime()
        if self._sentinel_page is None:
            self._initialize_sentinel_page()
        if self._sentinel_page is None:
            return False
        if self._sentinel_bundle_loaded:
            return True
        try:
            result = self._sentinel_page.evaluate(
                """async (flows) => {
                    const out = {};
                    const sdk = window.SentinelSDK || window.sentinelSDK || window.__SentinelSDK || (window.openai && window.openai.SentinelSDK);
                    if (!sdk) return out;
                    for (const flow of flows) {
                        let tokenRaw = null;
                        let soRaw = null;
                        let error = null;
                        try {
                            if (typeof sdk.init === "function") await sdk.init(flow);
                            tokenRaw = await sdk.token(flow);
                        } catch (e) {
                            error = String((e && e.message) || e || "token failed");
                        }
                        try {
                            if (typeof sdk.sessionObserverToken === "function") {
                                soRaw = await sdk.sessionObserverToken(flow);
                            }
                        } catch (e) {
                            if (!error) error = String((e && e.message) || e || "so failed");
                        }
                        out[flow] = { tokenRaw, soRaw, error };
                    }
                    return out;
                }""",
                [
                    "authorize_continue",
                    "username_password_create",
                    "password_verify",
                    "oauth_create_account",
                    "email_otp_verification",
                ],
            )
        except Exception as exc:
            self._log(f"Sentinel SDK preload failed: {exc}", "warning")
            return False

        self._sentinel_bundle_loaded = True
        if not isinstance(result, dict):
            return True

        for flow, data in result.items():
            if not isinstance(data, dict):
                continue
            token = _extract_direct_token(data.get("tokenRaw"))
            if not token:
                triplet = _extract_triplet(data.get("tokenRaw"))
                if triplet and triplet.get("p") and triplet.get("c"):
                    triplet["id"] = self.device_id
                    triplet["flow"] = str(flow)
                    token = json.dumps(triplet, separators=(",", ":"))
            so_token = _extract_direct_token(data.get("soRaw")) or ""
            if token:
                self._sentinel_flow_tokens[str(flow)] = token
            if so_token:
                self._sentinel_flow_so_tokens[str(flow)] = so_token
        return True

    def _resolve_sentinel_token(
        self,
        flow: str,
        fallback_flow: str = "",
    ) -> Optional[str]:
        self._ensure_sentinel_bundle()
        flow = str(flow or "").strip()
        fallback_flow = str(fallback_flow or "").strip()
        token = self._sentinel_flow_tokens.get(flow) or (
            self._sentinel_flow_tokens.get(fallback_flow) if fallback_flow else None
        )
        if token:
            return token
        if self._sentinel_page is None:
            return None
        try:
            result = self._sentinel_page.evaluate(
                """async ({flow,deviceId}) => {
                    const sdk = window.SentinelSDK || window.sentinelSDK || window.__SentinelSDK || (window.openai && window.openai.SentinelSDK);
                    if (!sdk || typeof sdk.token !== 'function') return null;
                    const lang = navigator.language || 'en-US';
                    const caps = JSON.stringify({
                        is_passkey_supported: false,
                        is_platform_authenticator_available: false,
                        is_conditional_mediation_available: false,
                    });
                    const tries = [
                        () => sdk.token({flow, id: deviceId}),
                        () => sdk.token({flow, id: deviceId, 'data-build': lang}),
                        () => sdk.token({flow, id: deviceId, dataBuild: lang}),
                        () => sdk.token({flow, id: deviceId, 'data-build': lang, 'ext-passkey-client-capabilities': caps}),
                        () => sdk.token(flow),
                        () => sdk.token({flow}),
                        () => sdk.token(),
                    ];
                    for (const fn of tries) {
                        try { return await fn(); } catch (e) {}
                    }
                    return null;
                }""",
                {"flow": flow, "deviceId": self.device_id},
            )
        except Exception as exc:
            self._log(f"Sentinel SDK token({flow}) failed: {exc}", "warning")
            return None

        direct = _extract_direct_token(result)
        if direct:
            self._sentinel_flow_tokens[flow] = direct
            return direct
        triplet = _extract_triplet(result)
        if triplet and triplet.get("p") and triplet.get("c"):
            triplet["id"] = self.device_id
            triplet["flow"] = flow
            token = json.dumps(triplet, separators=(",", ":"))
            self._sentinel_flow_tokens[flow] = token
            return token
        return None

    def _resolve_sentinel_so_token(self, flow: str) -> str:
        self._ensure_sentinel_bundle()
        flow = str(flow or "").strip()
        token = self._sentinel_flow_so_tokens.get(flow)
        if token:
            return token
        if self._sentinel_page is None:
            return ""
        try:
            token = self._sentinel_page.evaluate(
                """async (flow) => {
                    const sdk = window.SentinelSDK || window.sentinelSDK || window.__SentinelSDK || (window.openai && window.openai.SentinelSDK);
                    if (!sdk || typeof sdk.sessionObserverToken !== 'function') return '';
                    try { return await sdk.sessionObserverToken(flow); } catch(e) { return ''; }
                }""",
                flow,
            ) or ""
        except Exception as exc:
            self._log(f"Sentinel sessionObserverToken({flow}) failed: {exc}", "warning")
            return ""
        token = str(token or "").strip()
        if token:
            self._sentinel_flow_so_tokens[flow] = token
        return token

    def _build_sentinel_pow_token(self, label: str) -> str:
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

    def _build_sentinel_token(self, label: str, fallback_flow: str = "") -> str:
        token = self._resolve_sentinel_token(label, fallback_flow=fallback_flow)
        if token:
            self._log(f"Sentinel SDK token ready: {label}")
            return token
        self._log(
            f"Sentinel SDK token unavailable for {label}, falling back to local PoW token",
            "warning",
        )
        return self._build_sentinel_pow_token(label)

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
        headers = self._auth_headers()
        headers["referer"] = f"{self.auth_base}/create-account/password"
        headers["openai-sentinel-token"] = self._build_sentinel_token("username_password_create")
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
        headers = self._auth_headers()
        headers["referer"] = str(referer or current_url or f"{self.auth_base}/create-account/password")
        headers["openai-sentinel-token"] = self._build_sentinel_token("email_otp_verification")
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
        headers = self._auth_headers()
        headers["referer"] = str(current_url or f"{self.auth_base}/email-verification")
        headers["openai-sentinel-token"] = self._build_sentinel_token("email_otp_verification")
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
        headers = self._auth_headers()
        headers["referer"] = str(current_url or f"{self.auth_base}/about-you")
        headers["openai-sentinel-token"] = self._build_sentinel_token(
            "oauth_create_account",
            fallback_flow="create_account",
        )
        sentinel_so_token = self._resolve_sentinel_so_token("oauth_create_account")
        if sentinel_so_token:
            headers["openai-sentinel-so-token"] = sentinel_so_token
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
            "oai-device-id": self.device_id,
            **_trace_headers(),
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

    def _oauth_auth_cookie_names(self) -> list[str]:
        names: list[str] = []
        seen = set()
        if self._context is not None:
            try:
                for item in self._context.cookies():
                    name = str((item or {}).get("name") or "").strip()
                    domain = str((item or {}).get("domain") or "").strip().lower()
                    if (
                        name
                        and name not in seen
                        and (
                            "auth.openai.com" in domain
                            or domain.endswith(".openai.com")
                            or domain == "openai.com"
                        )
                    ):
                        seen.add(name)
                        names.append(name)
            except Exception:
                pass
        if self.session is not None:
            for name, _value in _cookie_items(getattr(self.session, "cookies", None) or {}):
                key = str(name or "").strip()
                if key and key not in seen:
                    seen.add(key)
                    names.append(key)
        return names

    def _oauth_bootstrap_authorize_session(self) -> Tuple[bool, str]:
        if not self.oauth_start:
            return False, ""

        auth_url = str(self.oauth_start.auth_url or "").strip()
        parsed = urlparse(auth_url)
        auth_params = {
            key: values[-1]
            for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
            if values
        }

        def has_login_cookie() -> bool:
            cookies = self._oauth_auth_cookie_names()
            return ("login_session" in cookies) or any(
                str(name).startswith("oai-client-auth-session") for name in cookies
            )

        status, data, response = self._api(
            "GET",
            auth_url,
            "OAuth authorize page",
            expected=(200, 301, 302, 303, 307, 308),
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "referer": f"{self.chat_base}/",
                "upgrade-insecure-requests": "1",
            },
            allow_redirects=True,
        )
        final_url = self._abs_auth_url(
            str(getattr(response, "url", "") or self._extract_next_url(data, auth_url) or auth_url)
        )
        has_login = has_login_cookie()
        self._log(f"OAuth bootstrap final={(final_url or '-')[:180]} login_session={'yes' if has_login else 'no'}")

        if has_login or not auth_params:
            return has_login, final_url

        status2, data2, response2 = self._api(
            "GET",
            f"{self.auth_base}/api/oauth/oauth2/auth",
            "OAuth oauth2/auth",
            expected=(200, 301, 302, 303, 307, 308),
            params=auth_params,
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "referer": auth_url,
                "upgrade-insecure-requests": "1",
            },
            allow_redirects=True,
        )
        final2 = self._abs_auth_url(
            str(getattr(response2, "url", "") or self._extract_next_url(data2, final_url) or final_url)
        )
        has_login = has_login_cookie()
        self._log(f"OAuth bootstrap retry final={(final2 or '-')[:180]} login_session={'yes' if has_login else 'no'}")
        return has_login, final2

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

    def _oauth_follow_chain_for_code(
        self,
        start_url: str,
        referer: Optional[str] = None,
        max_hops: int = 12,
    ) -> Tuple[Optional[str], str]:
        current = self._abs_auth_url(start_url)
        last = current
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
            last = str(getattr(response, "url", "") or current)
            code = _extract_code_from_url(last)
            if code:
                self._log(f"OAuth code captured from follow url: {last[:180]}")
                return code, last
            location = self._abs_auth_url(
                str((getattr(response, "headers", {}) or {}).get("location") or "").strip()
            )
            if location:
                code = _extract_code_from_url(location)
                if code:
                    self._log(f"OAuth code captured from redirect location: {location[:180]}")
                    return code, location
            if int(status or 0) not in (301, 302, 303, 307, 308) or not location:
                break
            headers["referer"] = last
            current = location
        return None, last

    def _oauth_browser_allow_redirect_code(
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
        code = _extract_code_from_url(final)
        if code:
            self._log(f"OAuth code captured from browser redirect: {str(final)[:180]}")
        return code

    def _oauth_submit_workspace_org_for_code(self, consent_url: str) -> Optional[str]:
        session = self._decode_auth_session_cookie() or {}
        workspaces = session.get("workspaces") or []
        workspace_id = str(((workspaces[0] or {}).get("id")) or "").strip() if workspaces else ""
        if not workspace_id:
            clicked, code = self._advance_browser_consent(consent_url, referer=consent_url)
            if code:
                return code
            if self.oauth_fail_reason == "add-phone gate":
                return None
            if clicked:
                session = self._decode_auth_session_cookie() or session
                workspaces = session.get("workspaces") or []
                workspace_id = str(((workspaces[0] or {}).get("id")) or "").strip() if workspaces else ""
            if not workspace_id:
                self._report_workspace_issue("no_workspace_id", consent_url=consent_url, session=session)
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
        if location:
            return (
                _extract_code_from_url(location)
                or self._oauth_follow_chain_for_code(location, referer=headers.get("referer"))[0]
                or self._oauth_browser_allow_redirect_code(location, referer=headers.get("referer"))
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
            if location2:
                return (
                    _extract_code_from_url(location2)
                    or self._oauth_follow_chain_for_code(location2, referer=org_headers.get("referer"))[0]
                    or self._oauth_browser_allow_redirect_code(location2, referer=org_headers.get("referer"))
                )
            if int(status2 or 0) in (200, 201) and isinstance(data2, dict):
                next_url = self._abs_auth_url(str(data2.get("continue_url") or next_url or "").strip())
        if next_url:
            return (
                _extract_code_from_url(next_url)
                or self._oauth_follow_chain_for_code(next_url, referer=headers.get("referer"))[0]
                or self._oauth_browser_allow_redirect_code(next_url, referer=headers.get("referer"))
            )
        return None

    def _oauth_resolve_code(
        self,
        consent_url: str = "",
        referer: Optional[str] = None,
    ) -> Optional[str]:
        candidates = []
        seen = set()
        for raw in (
            consent_url,
            getattr(self._page, "url", ""),
            self._last_browser_url,
            self.last_otp_url,
            f"{self.auth_base}/sign-in-with-chatgpt/codex/consent",
        ):
            candidate = self._abs_auth_url(raw)
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)

        for candidate in candidates:
            self._log(f"OAuth resolve candidate: {candidate[:180]}")
            code = _extract_code_from_url(candidate)
            if code:
                return code
            code, _ = self._oauth_follow_chain_for_code(candidate, referer=referer)
            if code:
                return code
            code = self._oauth_browser_allow_redirect_code(candidate, referer=referer)
            if code:
                return code
            _, code = self._advance_browser_consent(candidate, referer=referer or candidate)
            if code:
                return code
            if self.oauth_fail_reason == "add-phone gate":
                return None
            code = self._oauth_submit_workspace_org_for_code(candidate)
            if code:
                return code
            if self.oauth_fail_reason == "add-phone gate":
                return None
        return None

    def _oauth_send_passwordless_otp(
        self,
        referer: Optional[str] = None,
        step: str = "OAuth passwordless/send-otp",
    ) -> Tuple[int, Any, str, str]:
        resolved_referer = self._abs_auth_url(referer) or f"{self.auth_base}/log-in/password"
        headers = self._auth_headers()
        headers["referer"] = resolved_referer
        headers["openai-sentinel-token"] = self._build_sentinel_token("email_otp_verification")
        self._otp_sent_at = time.time()
        status, data, _ = self._api(
            "POST",
            f"{self.auth_base}/api/accounts/passwordless/send-otp",
            step,
            expected=(200, 201, 400, 401, 409),
            headers=headers,
            json_body={},
            allow_redirects=False,
        )
        next_url = self._extract_next_url(data, "")
        page_type = self._extract_page_type(data)
        return int(status or 0), data, self._abs_auth_url(next_url), page_type

    def _oauth_resend_verification_code(self) -> bool:
        _, current_url = self._browser_path()
        status, data, next_url, page_type = self._oauth_send_passwordless_otp(
            referer=current_url or f"{self.auth_base}/log-in/password",
            step="OAuth passwordless/resend-otp",
        )
        if int(status or 0) in (200, 201):
            self._oauth_passwordless_active = True
            target = next_url or current_url
            if target:
                try:
                    self._browser_goto(target, referer=current_url or f"{self.auth_base}/log-in/password", wait_ms=1200)
                except Exception:
                    pass
            if self._looks_like_add_phone(page_type, next_url):
                self._report_add_phone("oauth_resend", page_type, next_url, data)
                return False
            return True
        return self._send_verification_code(referer=current_url or f"{self.auth_base}/log-in/password")

    def _oauth_validate_secondary_otp(self, code: str) -> Tuple[int, Any]:
        _, current_url = self._browser_path()
        headers = self._auth_headers()
        headers["referer"] = self._abs_auth_url(current_url) or f"{self.auth_base}/email-verification"
        headers["openai-sentinel-token"] = self._build_sentinel_token("email_otp_verification")
        status, data, _ = self._api(
            "POST",
            f"{self.auth_base}/api/accounts/email-otp/validate",
            "OAuth validate OTP",
            expected=(200, 201, 400, 401, 409),
            headers=headers,
            json_body={"code": str(code or "").strip()},
            allow_redirects=False,
        )
        if int(status or 0) in (200, 201):
            return int(status or 0), data
        if self._is_invalid_state(status, data) or _payload_error_code(data) == "invalid_auth_step":
            self._log("OAuth OTP state expired, resend once and retry same code", "warning")
            if self._oauth_resend_verification_code():
                retry_status, retry_data, _ = self._api(
                    "POST",
                    f"{self.auth_base}/api/accounts/email-otp/validate",
                    "OAuth validate OTP retry",
                    expected=(200, 201, 400, 401, 409),
                    headers=headers,
                    json_body={"code": str(code or "").strip()},
                    allow_redirects=False,
                )
                return int(retry_status or 0), retry_data
        return int(status or 0), data

    def _oauth_authorize_continue(
        self,
        email: str,
        referer_url: str,
    ) -> Tuple[int, Any, str, str]:
        headers = self._auth_headers()
        headers["referer"] = self._abs_auth_url(referer_url) or f"{self.auth_base}/log-in"
        headers["openai-sentinel-token"] = self._build_sentinel_token("authorize_continue")
        status, data, _ = self._api(
            "POST",
            f"{self.auth_base}/api/accounts/authorize/continue",
            "OAuth authorize/continue",
            expected=(200, 201, 400, 401, 409),
            headers=headers,
            json_body={"username": {"kind": "email", "value": str(email or "").strip()}},
            allow_redirects=False,
        )
        next_url = self._abs_auth_url(self._extract_next_url(data, ""))
        page_type = self._extract_page_type(data)
        return int(status or 0), data, next_url, page_type

    def _oauth_password_verify(
        self,
        password: str,
        referer_url: str = "",
    ) -> Tuple[int, Any, str, str]:
        headers = self._auth_headers()
        headers["referer"] = self._abs_auth_url(referer_url) or f"{self.auth_base}/log-in/password"
        headers["openai-sentinel-token"] = self._build_sentinel_token("password_verify")
        status, data, _ = self._api(
            "POST",
            f"{self.auth_base}/api/accounts/password/verify",
            "OAuth password/verify",
            expected=(200, 201, 400, 401, 409),
            headers=headers,
            json_body={"password": str(password or "").strip()},
            allow_redirects=False,
        )
        next_url = self._abs_auth_url(self._extract_next_url(data, ""))
        page_type = self._extract_page_type(data)
        return int(status or 0), data, next_url, page_type

    def _oauth_sync_step_from_browser(
        self,
        start_url: str = "",
        referer: Optional[str] = None,
    ) -> Tuple[str, str]:
        target = self._abs_auth_url(start_url or getattr(self._page, "url", "") or "")
        if target:
            try:
                self._browser_goto(target, referer=referer or f"{self.auth_base}/log-in", wait_ms=1200)
            except Exception:
                pass
        current_url, current_state = self._detect_browser_auth_state()
        current_url = self._abs_auth_url(current_url or getattr(self._page, "url", "") or target)
        return current_url, str(current_state or "").strip()

    def _oauth_browser_submit_email(
        self,
        email: str,
        start_url: str = "",
    ) -> Tuple[str, str]:
        target = self._abs_auth_url(start_url or getattr(self._page, "url", "") or f"{self.auth_base}/log-in")
        current = self._abs_auth_url(getattr(self._page, "url", "") or "")
        if target and target != current:
            self._browser_goto(target, referer=f"{self.auth_base}/log-in", wait_ms=1500)

        email_selectors = self._auth_email_selectors()
        submit_selectors = self._auth_submit_selectors()
        email_submitted = False

        for _ in range(6):
            current_url, state = self._detect_browser_auth_state()
            if state in (
                "challenge",
                "callback",
                "about_you",
                "consent",
                "email_otp_verification",
                "login_password",
                "login_email_password",
            ):
                self._sync_browser_cookies_to_http()
                return current_url, state
            if self._fill_first_visible(email_selectors, email, timeout_ms=2500):
                email_submitted = True
                if not self._click_first_visible(submit_selectors, timeout_ms=2500):
                    try:
                        self._page.keyboard.press("Enter")
                    except Exception:
                        pass
                self._otp_sent_at = time.time()
                self._page.wait_for_timeout(1500)
                self._sync_browser_cookies_to_http()
                continue
            if email_submitted:
                self._page.wait_for_timeout(1000)
                self._sync_browser_cookies_to_http()
                continue
            self._page.wait_for_timeout(800)
        return self._detect_browser_auth_state()

    def _perform_oauth_passwordless_flow(self) -> Optional[str]:
        if not self.oauth_start or not self.email:
            return None

        self.oauth_fail_reason = ""
        self._oauth_passwordless_active = False
        self._open_fresh_browser_page(self.oauth_start.auth_url)
        current_url = self._browser_goto(
            self.oauth_start.auth_url,
            referer=f"{self.chat_base}/",
            wait_ms=1800,
        )
        current_url = self._abs_auth_url(current_url or self.oauth_start.auth_url)
        current_url, page_state = self._detect_browser_auth_state()
        current_url = self._abs_auth_url(current_url or self.oauth_start.auth_url)
        self._log(f"OAuth V2 bootstrap state={page_state or '-'} url={current_url[:180]}")

        if self._looks_like_add_phone(page_state, current_url):
            self._report_add_phone("oauth_v2_bootstrap", page_state, current_url)
            return None
        if self._looks_like_challenge(page_state, current_url):
            self.oauth_fail_reason = "cloudflare challenge loop at oauth bootstrap"
            return None

        status, data, next_url, next_state = self._oauth_authorize_continue(
            self.email or "",
            current_url or self.oauth_start.auth_url,
        )
        if int(status or 0) in (200, 201):
            page_state = str(next_state or page_state or "").strip()
            current_url = self._abs_auth_url(next_url or current_url)
            if current_url:
                current_url, browser_state = self._oauth_sync_step_from_browser(
                    current_url,
                    referer=current_url or self.oauth_start.auth_url,
                )
                page_state = str(browser_state or page_state or "").strip()
        else:
            self._log(f"OAuth authorize/continue returned {_payload_error_summary(data)}", "warning")
            current_url, page_state = self._oauth_browser_submit_email(
                self.email or "",
                start_url=current_url or self.oauth_start.auth_url,
            )
            current_url = self._abs_auth_url(current_url or self.oauth_start.auth_url)
        self._log(f"OAuth V2 post-email state={page_state or '-'} url={(current_url or '-')[:180]}")

        if page_state in ("login_password", "login_email_password"):
            raise EmailAlreadyUsedError(self.email or "")
        if self._looks_like_add_phone(page_state, current_url):
            self._report_add_phone("oauth_v2_post_email", page_state, current_url, data)
            return None
        if self._looks_like_challenge(page_state, current_url):
            self.oauth_fail_reason = "cloudflare challenge loop at oauth email step"
            return None

        if not self._looks_like_otp_step(page_state, current_url):
            otp_status, otp_data, otp_next, otp_state = self._oauth_send_passwordless_otp(
                referer=current_url or f"{self.auth_base}/log-in",
                step="OAuth passwordless/send-otp (v2)",
            )
            if int(otp_status or 0) in (200, 201):
                self._oauth_passwordless_active = True
                current_url = self._abs_auth_url(otp_next or current_url)
                page_state = str(otp_state or page_state or "").strip()
                if current_url:
                    current_url, browser_state = self._oauth_sync_step_from_browser(
                        current_url,
                        referer=current_url or f"{self.auth_base}/log-in/password",
                    )
                    page_state = str(browser_state or page_state or "").strip()
            else:
                otp_summary = _payload_error_summary(otp_data)
                self._log(f"OAuth V2 passwordless send-otp returned {otp_summary}", "warning")
        self._log(f"OAuth V2 otp state={page_state or '-'} url={(current_url or '-')[:180]}")

        if self._looks_like_otp_step(page_state, current_url):
            self._otp_sent_at = time.time()
            self._oauth_passwordless_active = True
            self._log("[OTP][oauth-v2] waiting for OAuth verification code")
            code, otp_phase = self._await_verification_code_with_resends(
                self._oauth_resend_verification_code,
                timeout_retry_log_template="OAuth V2 OTP timeout, resend attempt {attempt}",
                non_openai_retry_log_template="OAuth V2 OTP noisy mailbox, resend attempt {attempt}",
                timeout_retry_status_template="OAuth V2 resend attempt {attempt}",
                non_openai_retry_status_template="OAuth V2 resend after noisy mailbox {attempt}",
            )
            if not code:
                self.oauth_fail_reason = (
                    otp_phase.error_message if otp_phase and otp_phase.error_message else "oauth otp fetch failed"
                )
                return None
            validate_status, validate_data = self._oauth_validate_secondary_otp(code)
            if int(validate_status or 0) not in (200, 201):
                self.oauth_fail_reason = f"oauth otp validate failed: {_payload_error_summary(validate_data)}"
                self._log(f"OAuth V2 OTP validate failed: {_payload_error_summary(validate_data)}", "warning")
                return None
            next_url = self._extract_next_url(validate_data, current_url)
            next_state = self._extract_page_type(validate_data) or page_state
            if self._looks_like_add_phone(next_state, next_url):
                self._report_add_phone("oauth_v2_post_otp", next_state, next_url, validate_data)
                return None
            current_url = self._abs_auth_url(next_url or current_url)
            if current_url:
                current_url, browser_state = self._oauth_sync_step_from_browser(
                    current_url,
                    referer=current_url or f"{self.auth_base}/email-verification",
                )
                page_state = str(browser_state or next_state or "").strip()
            else:
                page_state = str(next_state or page_state or "").strip()
        self._log(f"OAuth V2 post-otp state={page_state or '-'} url={(current_url or '-')[:180]}")

        if self._looks_like_about_you(page_state, current_url):
            create_status, created = self.create_account(self.email or "")
            if int(create_status or 0) not in (200, 201):
                self.oauth_fail_reason = f"oauth about-you create_account failed: {_payload_error_summary(created)}"
                self._log(f"OAuth V2 about-you failed: {_payload_error_summary(created)}", "warning")
                return None
            self._append_account_checkpoint(
                "account_created",
                oauth=False,
                metadata={"status": "created_passwordless"},
            )
            next_url = self._extract_next_url(created, current_url)
            next_state = self._extract_page_type(created) or page_state
            if self._looks_like_add_phone(next_state, next_url):
                self._report_add_phone("oauth_v2_about_you", next_state, next_url, created)
                return None
            current_url = self._abs_auth_url(next_url or current_url)
            if current_url:
                current_url, browser_state = self._oauth_sync_step_from_browser(
                    current_url,
                    referer=current_url or f"{self.auth_base}/about-you",
                )
                page_state = str(browser_state or next_state or "").strip()
        self._log(f"OAuth V2 consent state={page_state or '-'} url={(current_url or '-')[:180]}")

        if self._looks_like_add_phone(page_state, current_url):
            self._report_add_phone("oauth_v2_final", page_state, current_url)
            return None

        code = _extract_code_from_url(current_url)
        if not code and current_url:
            code = self._oauth_follow_chain_for_code(current_url, referer=current_url)[0]
        if not code and self._looks_like_consent_step(page_state, current_url):
            code = self._oauth_resolve_code(current_url, referer=current_url or self.oauth_start.auth_url)
        if not code:
            code = self._oauth_resolve_code("", referer=current_url or self.oauth_start.auth_url)
        if not code:
            self.oauth_fail_reason = self.oauth_fail_reason or "no authorization code after consent"
            return None
        self._log("OAuth V2 captured authorization code")
        return self._build_callback_url_from_code(code)

    def _perform_oauth_browser_flow(self) -> Optional[str]:
        if not self.oauth_start or not self.email or not self.password:
            return None

        self.oauth_fail_reason = ""
        self._oauth_passwordless_active = False
        self._open_fresh_browser_page(self.oauth_start.auth_url)
        has_login, current_url = self._oauth_bootstrap_authorize_session()
        current_url = self._abs_auth_url(current_url or self.oauth_start.auth_url)
        page_state = ""
        self._log(f"OAuth V3 bootstrap state={page_state or '-'} url={current_url[:180]}")

        if self._looks_like_add_phone("", current_url):
            self._report_add_phone("oauth_bootstrap", "", current_url)
            return None
        if self._looks_like_challenge("", current_url):
            self.oauth_fail_reason = "cloudflare challenge loop at oauth bootstrap"
            return None

        status, data, next_url, next_state = self._oauth_authorize_continue(
            self.email or "",
            current_url if str(current_url).startswith(self.auth_base) else f"{self.auth_base}/log-in",
        )
        if int(status or 0) == 400 and "invalid_auth_step" in json.dumps(data, ensure_ascii=False).lower():
            self._log("OAuth V3 invalid_auth_step, retry bootstrap once", "warning")
            has_login, current_url = self._oauth_bootstrap_authorize_session()
            current_url = self._abs_auth_url(current_url or self.oauth_start.auth_url)
            status, data, next_url, next_state = self._oauth_authorize_continue(
                self.email or "",
                current_url if str(current_url).startswith(self.auth_base) else f"{self.auth_base}/log-in",
            )
        if int(status or 0) not in (200, 201):
            self.oauth_fail_reason = f"oauth authorize_continue failed: {_payload_error_summary(data)}"
            self._log(f"OAuth V3 authorize/continue failed: {_payload_error_summary(data)}", "warning")
            return None

        current_url = self._abs_auth_url(next_url or current_url)
        page_state = str(next_state or "").strip()
        self._log(f"OAuth V3 post-email state={page_state or '-'} url={(current_url or '-')[:180]}")
        if self._looks_like_add_phone(page_state, current_url):
            self._report_add_phone("oauth_authorize_continue", page_state, current_url, data)
            return None

        status, data, next_url, next_state = self._oauth_password_verify(
            self.password or "",
            referer_url=f"{self.auth_base}/log-in/password",
        )
        if int(status or 0) not in (200, 201):
            self.oauth_fail_reason = f"oauth password_verify failed: {_payload_error_summary(data)}"
            self._log(f"OAuth V3 password/verify failed: {_payload_error_summary(data)}", "warning")
            return None

        current_url = self._abs_auth_url(next_url or current_url)
        page_state = str(next_state or page_state or "").strip()
        self._log(f"OAuth V3 post-password state={page_state or '-'} url={(current_url or '-')[:180]}")
        if self._looks_like_add_phone(page_state, current_url):
            self._report_add_phone("oauth_password_verify", page_state, current_url, data)
            return None

        if current_url:
            current_url, browser_state = self._oauth_sync_step_from_browser(
                current_url,
                referer=f"{self.auth_base}/log-in/password",
            )
            current_url = self._abs_auth_url(current_url or next_url or self.oauth_start.auth_url)
            page_state = str(browser_state or page_state or "").strip()
            self._log(f"OAuth V3 browser sync state={page_state or '-'} url={(current_url or '-')[:180]}")
            if self._looks_like_add_phone(page_state, current_url):
                self._report_add_phone("oauth_browser_sync", page_state, current_url)
                return None
            if self._looks_like_challenge(page_state, current_url):
                self.oauth_fail_reason = "cloudflare challenge loop after oauth password verify"
                return None

        need_otp = self._looks_like_otp_step(page_state, current_url)
        if not need_otp:
            need_otp = self._looks_like_otp_step(next_state, next_url)

        if need_otp:
            self._otp_sent_at = time.time()
            self._oauth_passwordless_active = True
            self.last_otp_url = self._abs_auth_url(current_url or next_url or f"{self.auth_base}/email-verification")
            self._log("[OTP][oauth] waiting for OAuth verification code")
            code, otp_phase = self._await_verification_code_with_resends(
                self._oauth_resend_verification_code,
                timeout_retry_log_template="OAuth OTP timeout, resend attempt {attempt}",
                non_openai_retry_log_template="OAuth OTP noisy mailbox, resend attempt {attempt}",
                timeout_retry_status_template="OAuth resend attempt {attempt}",
                non_openai_retry_status_template="OAuth resend after noisy mailbox {attempt}",
            )
            if not code:
                self.oauth_fail_reason = (
                    otp_phase.error_message if otp_phase and otp_phase.error_message else "oauth otp fetch failed"
                )
                return None
            status, data = self._oauth_validate_secondary_otp(code)
            if int(status or 0) not in (200, 201):
                self.oauth_fail_reason = f"oauth otp validate failed: {_payload_error_summary(data)}"
                self._log(f"OAuth V3 OTP validate failed: {_payload_error_summary(data)}", "warning")
                return None
            next_url = self._extract_next_url(data, current_url)
            next_state = self._extract_page_type(data) or page_state
            if self._looks_like_add_phone(next_state, next_url):
                self._report_add_phone("oauth_post_otp", next_state, next_url, data)
                return None
            current_url = self._abs_auth_url(next_url or current_url)
            if current_url:
                current_url, browser_state = self._oauth_sync_step_from_browser(
                    current_url,
                    referer=current_url or f"{self.auth_base}/email-verification",
                )
                current_url = self._abs_auth_url(current_url or next_url)
                page_state = str(browser_state or next_state or "").strip()
            else:
                page_state = str(next_state or page_state or "").strip()
            self._log(f"OAuth V3 post-otp state={page_state or '-'} url={(current_url or '-')[:180]}")

        if self._looks_like_about_you(page_state, current_url):
            self._log("OAuth landed on about-you, replaying profile create once", "warning")
            create_status, created = self.create_account(self.email or "")
            if int(create_status or 0) not in (200, 201) and _payload_error_code(created) != "user_already_exists":
                self.oauth_fail_reason = f"oauth about-you create_account failed: {_payload_error_summary(created)}"
                return None
            next_url = self._extract_next_url(created, current_url)
            if next_url:
                current_url = self._browser_goto(next_url, referer=current_url or f"{self.auth_base}/about-you", wait_ms=1500)
                current_url, browser_state = self._detect_browser_auth_state()
                current_url = self._abs_auth_url(current_url or next_url)
                page_state = str(browser_state or page_state or "").strip()

        if self._looks_like_add_phone(page_state, current_url):
            self._report_add_phone("oauth_final", page_state, current_url)
            return None

        code = _extract_code_from_url(current_url)
        if not code and current_url:
            code = self._oauth_follow_chain_for_code(
                current_url,
                referer=f"{self.auth_base}/log-in/password",
            )[0]
        if not code and self._looks_like_consent_step(page_state, current_url):
            code = self._oauth_resolve_code(
                current_url,
                referer=f"{self.auth_base}/log-in/password",
            )
        if not code:
            code = self._oauth_resolve_code(
                "",
                referer=f"{self.auth_base}/log-in/password",
            )
        if not code:
            self.oauth_fail_reason = self.oauth_fail_reason or "no authorization code after consent"
            return None
        self._log("OAuth V3 API-first flow captured authorization code")
        return self._build_callback_url_from_code(code)

    def _build_callback_url_from_code(self, code: str) -> str:
        if not self.oauth_start:
            raise RuntimeError("oauth not initialized")
        redirect_uri = str(self.oauth_start.redirect_uri or "").strip() or "http://localhost/callback"
        query = urlencode(
            {
                "code": str(code or "").strip(),
                "state": str(self.oauth_start.state or "").strip(),
            }
        )
        sep = "&" if "?" in redirect_uri else "?"
        return f"{redirect_uri}{sep}{query}"

    def _oauth_exchange_code_via_playwright(self, code: str) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for tokens using Playwright request context.

        Mirrors daily-bing's _oauth_exchange_code: uses the browser session (with
        all cookies) to POST to /oauth/token, then does workspace/select and
        organization/select with the resulting access_token.
        """
        if not self.oauth_start or not str(code or "").strip():
            return None

        from ..config.constants import OAUTH_CLIENT_ID, OAUTH_REDIRECT_URI

        redirect_uri = str(self.oauth_start.redirect_uri or OAUTH_REDIRECT_URI).strip()
        client_id = OAUTH_CLIENT_ID
        code_verifier = str(self.oauth_start.code_verifier or "").strip()
        token_url = f"{self.auth_base}/oauth/token"

        token_payload = {
            "grant_type": "authorization_code",
            "code": str(code).strip(),
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
        }

        # Try form-encoded first (matches daily-bing _oauth_exchange_code)
        status, data, _ = self._api(
            "POST",
            token_url,
            "OAuth token(form)",
            expected=(200, 201, 400),
            headers={"content-type": "application/x-www-form-urlencoded"},
            form=token_payload,
            allow_redirects=False,
        )
        access_token = str((data if isinstance(data, dict) else {}).get("access_token") or "").strip()
        if int(status or 0) in (200, 201) and access_token:
            self._log("OAuth token exchange succeeded (form)")
        else:
            # Fallback: try JSON body
            status, data, _ = self._api(
                "POST",
                token_url,
                "OAuth token(json)",
                expected=(200, 201, 400),
                headers=self._auth_headers(),
                json_body=token_payload,
                allow_redirects=False,
            )
            access_token = str((data if isinstance(data, dict) else {}).get("access_token") or "").strip()
            if int(status or 0) not in (200, 201) or not access_token:
                self._log(f"OAuth token exchange failed: status={status}", "error")
                return None
            self._log("OAuth token exchange succeeded (json)")

        # Post-exchange: workspace/select + organization/select (mirrors daily-bing)
        tokens = data if isinstance(data, dict) else {}
        id_token_raw = str(tokens.get("id_token") or "").strip()
        if id_token_raw:
            try:
                from .openai.oauth import _jwt_claims_no_verify
                claims = _jwt_claims_no_verify(id_token_raw)
            except Exception:
                claims = {}
        else:
            claims = {}

        workspace_id = str(
            tokens.get("workspace_id") or claims.get("workspace_id") or ""
        ).strip()
        organization = str(
            tokens.get("organization")
            or claims.get("organization")
            or claims.get("org_id")
            or ""
        ).strip()

        if workspace_id:
            try:
                self._api(
                    "POST",
                    f"{self.auth_base}/api/accounts/workspace/select",
                    "OAuth post-exchange workspace/select",
                    expected=(200, 201, 400),
                    headers={"authorization": f"Bearer {access_token}", **self._auth_headers()},
                    json_body={"workspace_id": workspace_id},
                )
            except Exception as exc:
                self._log(f"Post-exchange workspace/select warning: {exc}", "warning")

        if organization:
            try:
                self._api(
                    "POST",
                    f"{self.auth_base}/api/accounts/organization/select",
                    "OAuth post-exchange organization/select",
                    expected=(200, 201, 400),
                    headers={"authorization": f"Bearer {access_token}", **self._auth_headers()},
                    json_body={"organization": organization},
                )
            except Exception as exc:
                self._log(f"Post-exchange organization/select warning: {exc}", "warning")

        # Build token_info dict compatible with _handle_oauth_callback return
        auth_claims = claims.get("https://api.openai.com/auth") or {}
        account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()
        email_from_claims = str(claims.get("email") or "").strip()

        import time as _time
        now = int(_time.time())
        expires_in = int(tokens.get("expires_in") or 0)

        return {
            "id_token": id_token_raw,
            "access_token": access_token,
            "refresh_token": str(tokens.get("refresh_token") or "").strip(),
            "account_id": account_id,
            "last_refresh": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime(now)),
            "email": email_from_claims,
            "type": "codex",
            "expired": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime(now + max(expires_in, 0))),
            "workspace_id": workspace_id,
        }

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

        mode = self._resolved_execution_mode()
        if mode == "playwright_v3":
            callback_url = self._perform_oauth_browser_flow()
            if callback_url:
                return callback_url
            raise RuntimeError(self.oauth_fail_reason or "oauth authorization code not captured")
        elif mode == "playwright_v2":
            callback_url = self._perform_oauth_passwordless_flow()
            if callback_url:
                return callback_url
            raise RuntimeError(self.oauth_fail_reason or "oauth authorization code not captured")

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
        if not location:
            location = self._abs_auth_url(str(getattr(response, "url", "") or "").strip())
        if location:
            self._log(f"OAuth bootstrap location: {location[:180]}")
        if self._is_callback_url(location):
            return location
        callback_url = (
            self._oauth_follow_chain_for_callback(location or self.oauth_start.auth_url, referer=self.oauth_start.auth_url)
            or self._oauth_browser_allow_redirect_callback(location or self.oauth_start.auth_url, referer=self.oauth_start.auth_url)
            or self._oauth_submit_workspace_org(location or self.oauth_start.auth_url)
        )
        if callback_url:
            if "state=" not in callback_url:
                sep = "&" if "?" in callback_url else "?"
                callback_url = f"{callback_url}{sep}state={self.oauth_start.state}"
            return callback_url

        code = _extract_code_from_url(location) if location else None
        if not code:
            code = self._oauth_resolve_code(location or self.oauth_start.auth_url, referer=self.oauth_start.auth_url)
        if not code:
            raise RuntimeError("oauth authorization code not captured")
        self._log("OAuth authorization code captured, synthesizing callback URL")
        callback_url = self._build_callback_url_from_code(code)
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
            self._log("Start Playwright V2 OAuth-first flow")
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
            self.password = ""

            self._emit_status("session_init", "Initialize browser session", step_index=3)
            if not self._init_session():
                result.error_message = "Session initialization failed"
                return result

            self._emit_status("oauth_start", "Initialize OAuth parameters", step_index=4)
            if not self._start_oauth():
                result.error_message = "Initialize OAuth failed"
                return result

            self._emit_status("oauth_flow", "Run direct OAuth passwordless flow", step_index=5)
            callback_url = self.perform_oauth()

            self._emit_status("oauth_callback", "Handle OAuth callback", step_index=6)
            token_info = self._handle_oauth_callback(callback_url)
            if not token_info:
                result.error_message = "OAuth callback handling failed"
                return result

            auth_session = self._decode_auth_session_cookie() or {}
            result.workspace_id = (
                self._extract_workspace_id_from_auth_json(auth_session)
                or result.workspace_id
            )

            result.success = True
            result.account_id = str(token_info.get("account_id") or "")
            result.access_token = str(token_info.get("access_token") or "")
            result.refresh_token = str(token_info.get("refresh_token") or "")
            result.id_token = str(token_info.get("id_token") or "")
            result.password = ""
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
                "oauth_flow": "passwordless",
            }
            self._append_account_checkpoint(
                "oauth_success",
                oauth=True,
                metadata={
                    "source": result.source,
                    "account_id": result.account_id,
                    "workspace_id": result.workspace_id,
                    "status": "oauth_success",
                    "oauth_flow": "passwordless",
                },
            )
            return result

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
                error_summary = _payload_error_summary(register_data)
                self._log(f"提交注册失败详情: {error_summary}", "error")
                result.error_message = f"注册失败: {error_summary}"
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
            self._append_account_checkpoint(
                "account_created",
                oauth=False,
                metadata={"status": "created"},
            )
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
