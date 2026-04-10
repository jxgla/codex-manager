from types import SimpleNamespace

import pytest

from src.core.register_playwright import (
    PlaywrightRegistrationEngine,
    _PlaywrightResponseShim,
    _extract_code_from_url,
)


def _dummy_email_service():
    return SimpleNamespace(service_type=SimpleNamespace(value="tempmail"))


def test_extract_code_from_url_accepts_fragment_and_raw_query():
    assert _extract_code_from_url("https://example.com/cb#code=frag-code") == "frag-code"
    assert _extract_code_from_url("?code=query-code&state=abc") == "query-code"


def test_perform_oauth_builds_callback_from_authorization_code(monkeypatch):
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )
    engine.oauth_start = SimpleNamespace(
        auth_url="https://auth.openai.com/oauth/authorize?client_id=test",
        state="state-123",
        redirect_uri="http://localhost:1455/callback",
    )
    engine._resolved_execution_mode = lambda: "legacy"

    def fake_api(method, url, step, **kwargs):
        return (
            302,
            {},
            _PlaywrightResponseShim(
                status_code=302,
                headers={"location": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"},
                url=str(url),
            ),
        )

    monkeypatch.setattr(engine, "_api", fake_api)
    monkeypatch.setattr(engine, "_oauth_follow_chain_for_callback", lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, "_oauth_browser_allow_redirect_callback", lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, "_oauth_submit_workspace_org", lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, "_oauth_resolve_code", lambda *args, **kwargs: "oauth-code-xyz")

    callback_url = engine.perform_oauth()

    assert callback_url == "http://localhost:1455/callback?code=oauth-code-xyz&state=state-123"


def test_build_sentinel_token_prefers_sdk_over_local_pow(monkeypatch):
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )
    pow_calls = []

    monkeypatch.setattr(
        engine,
        "_resolve_sentinel_token",
        lambda flow, fallback_flow="": f"sdk::{flow}::{fallback_flow}",
    )
    monkeypatch.setattr(
        engine,
        "_build_sentinel_pow_token",
        lambda label: pow_calls.append(label) or "pow-token",
    )

    token = engine._build_sentinel_token("authorize_continue")

    assert token == "sdk::authorize_continue::"
    assert pow_calls == []


def test_oauth_bootstrap_authorize_session_retries_oauth2_auth(monkeypatch):
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )
    engine.oauth_start = SimpleNamespace(
        auth_url=(
            "https://auth.openai.com/oauth/authorize?"
            "client_id=test-client&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fcallback&state=state-123"
        ),
        state="state-123",
        redirect_uri="http://localhost:1455/callback",
    )

    calls = []
    responses = [
        (
            200,
            {},
            _PlaywrightResponseShim(status_code=200, url="https://auth.openai.com/log-in"),
        ),
        (
            200,
            {},
            _PlaywrightResponseShim(status_code=200, url="https://auth.openai.com/log-in/password"),
        ),
    ]
    cookie_snapshots = [[], ["login_session"]]

    def fake_api(method, url, step, **kwargs):
        calls.append((url, kwargs.get("params")))
        return responses.pop(0)

    monkeypatch.setattr(engine, "_api", fake_api)
    monkeypatch.setattr(
        engine,
        "_oauth_auth_cookie_names",
        lambda: cookie_snapshots.pop(0) if cookie_snapshots else ["login_session"],
    )

    has_login, final_url = engine._oauth_bootstrap_authorize_session()

    assert has_login is True
    assert final_url == "https://auth.openai.com/log-in/password"
    assert calls[1][0] == "https://auth.openai.com/api/oauth/oauth2/auth"
    assert calls[1][1]["client_id"] == "test-client"


def test_oauth_authorize_continue_uses_sdk_sentinel_token(monkeypatch):
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )
    resolved = []
    pow_calls = []
    captured = {}

    monkeypatch.setattr(
        engine,
        "_resolve_sentinel_token",
        lambda flow, fallback_flow="": resolved.append((flow, fallback_flow)) or "sdk-authorize-token",
    )
    monkeypatch.setattr(
        engine,
        "_build_sentinel_pow_token",
        lambda label: pow_calls.append(label) or "pow-token",
    )

    def fake_api(method, url, step, **kwargs):
        captured.update(kwargs)
        return 200, {"continue_url": "/log-in/password", "page": {"type": "login_password"}}, _PlaywrightResponseShim(status_code=200)

    monkeypatch.setattr(engine, "_api", fake_api)

    status, data, next_url, page_type = engine._oauth_authorize_continue(
        "sdk@example.com",
        "https://auth.openai.com/log-in",
    )

    assert status == 200
    assert data["continue_url"] == "/log-in/password"
    assert next_url == "https://auth.openai.com/log-in/password"
    assert page_type == "login_password"
    assert captured["headers"]["openai-sentinel-token"] == "sdk-authorize-token"
    assert captured["headers"]["oai-device-id"] == engine.device_id
    assert resolved == [("authorize_continue", "")]
    assert pow_calls == []


def test_oauth_password_verify_uses_sdk_sentinel_token(monkeypatch):
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )
    resolved = []
    pow_calls = []
    captured = {}

    monkeypatch.setattr(
        engine,
        "_resolve_sentinel_token",
        lambda flow, fallback_flow="": resolved.append((flow, fallback_flow)) or "sdk-password-token",
    )
    monkeypatch.setattr(
        engine,
        "_build_sentinel_pow_token",
        lambda label: pow_calls.append(label) or "pow-token",
    )

    def fake_api(method, url, step, **kwargs):
        captured.update(kwargs)
        return 200, {"continue_url": "/email-verification", "page": {"type": "email_otp_verification"}}, _PlaywrightResponseShim(status_code=200)

    monkeypatch.setattr(engine, "_api", fake_api)

    status, data, next_url, page_type = engine._oauth_password_verify(
        "pw-123",
        "https://auth.openai.com/log-in/password",
    )

    assert status == 200
    assert data["continue_url"] == "/email-verification"
    assert next_url == "https://auth.openai.com/email-verification"
    assert page_type == "email_otp_verification"
    assert captured["headers"]["openai-sentinel-token"] == "sdk-password-token"
    assert captured["headers"]["oai-device-id"] == engine.device_id
    assert resolved == [("password_verify", "")]
    assert pow_calls == []


def test_create_account_uses_sdk_token_and_session_observer(monkeypatch):
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )
    token_calls = []
    captured = {}

    monkeypatch.setattr(engine, "_browser_path", lambda: ("", "https://auth.openai.com/about-you"))
    monkeypatch.setattr(
        engine,
        "_resolve_sentinel_token",
        lambda flow, fallback_flow="": token_calls.append((flow, fallback_flow)) or "sdk-create-account-token",
    )
    monkeypatch.setattr(engine, "_resolve_sentinel_so_token", lambda flow: "sdk-session-observer-token")

    def fake_api(method, url, step, **kwargs):
        captured.update(kwargs)
        return 200, {"continue_url": "https://chatgpt.com/"}, _PlaywrightResponseShim(status_code=200)

    monkeypatch.setattr(engine, "_api", fake_api)

    status, data = engine.create_account("sdk@example.com")

    assert status == 200
    assert data["continue_url"] == "https://chatgpt.com/"
    assert captured["headers"]["openai-sentinel-token"] == "sdk-create-account-token"
    assert captured["headers"]["openai-sentinel-so-token"] == "sdk-session-observer-token"
    assert captured["headers"]["oai-device-id"] == engine.device_id
    assert token_calls == [("oauth_create_account", "create_account")]


def test_perform_oauth_v3_uses_api_first_sequence(monkeypatch):
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )
    engine.email = "v3@example.com"
    engine.password = "pw-123"
    engine.oauth_start = SimpleNamespace(
        auth_url="https://auth.openai.com/oauth/authorize?client_id=test",
        state="state-123",
        redirect_uri="http://localhost:1455/callback",
    )

    sync_steps = [
        ("https://auth.openai.com/email-verification", "email_otp_verification"),
        ("https://auth.openai.com/sign-in-with-chatgpt/codex/consent", "consent"),
    ]
    password_verify_calls = []

    monkeypatch.setattr(engine, "_open_fresh_browser_page", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(engine, "_oauth_bootstrap_authorize_session", lambda: (True, "https://auth.openai.com/log-in"))
    monkeypatch.setattr(
        engine,
        "_oauth_authorize_continue",
        lambda *_args, **_kwargs: (
            200,
            {"continue_url": "/log-in/password", "page": {"type": "login_password"}},
            "https://auth.openai.com/log-in/password",
            "login_password",
        ),
    )

    def fake_password_verify(password, referer_url=""):
        password_verify_calls.append((password, referer_url))
        return (
            200,
            {"continue_url": "/email-verification", "page": {"type": "email_otp_verification"}},
            "https://auth.openai.com/email-verification",
            "email_otp_verification",
        )

    monkeypatch.setattr(engine, "_oauth_password_verify", fake_password_verify)
    monkeypatch.setattr(engine, "_oauth_sync_step_from_browser", lambda *_args, **_kwargs: sync_steps.pop(0))
    monkeypatch.setattr(engine, "_await_verification_code_with_resends", lambda *_args, **_kwargs: ("123456", None))
    monkeypatch.setattr(
        engine,
        "_oauth_validate_secondary_otp",
        lambda _code: (
            200,
            {"continue_url": "/sign-in-with-chatgpt/codex/consent", "page": {"type": "consent"}},
        ),
    )
    monkeypatch.setattr(engine, "_oauth_resolve_code", lambda *_args, **_kwargs: "oauth-code-v3")
    monkeypatch.setattr(engine, "_oauth_follow_chain_for_code", lambda *_args, **_kwargs: (None, ""))
    monkeypatch.setattr(
        engine,
        "_oauth_browser_authenticate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("legacy browser login path should not run for V3")),
    )

    callback_url = engine._perform_oauth_browser_flow()

    assert callback_url == "http://localhost:1455/callback?code=oauth-code-v3&state=state-123"
    assert password_verify_calls == [("pw-123", "https://auth.openai.com/log-in/password")]


def test_perform_oauth_v3_raises_flow_reason(monkeypatch):
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )
    engine.oauth_start = SimpleNamespace(
        auth_url="https://auth.openai.com/oauth/authorize?client_id=test",
        state="state-123",
        redirect_uri="http://localhost:1455/callback",
    )
    engine._resolved_execution_mode = lambda: "playwright_v3"
    engine.oauth_fail_reason = "add-phone gate"
    monkeypatch.setattr(engine, "_perform_oauth_browser_flow", lambda: None)

    with pytest.raises(RuntimeError, match="add-phone gate"):
        engine.perform_oauth()


def test_perform_oauth_v2_uses_passwordless_flow():
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )
    engine.oauth_start = SimpleNamespace(
        auth_url="https://auth.openai.com/oauth/authorize?client_id=test",
        state="state-123",
        redirect_uri="http://localhost:1455/callback",
    )
    engine._resolved_execution_mode = lambda: "playwright_v2"
    engine._perform_oauth_passwordless_flow = lambda: "http://localhost:1455/callback?code=v2-code&state=state-123"

    callback_url = engine.perform_oauth()

    assert callback_url == "http://localhost:1455/callback?code=v2-code&state=state-123"


def test_oauth_submit_workspace_org_for_code_uses_browser_consent_when_workspace_missing(monkeypatch):
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )

    monkeypatch.setattr(engine, "_decode_auth_session_cookie", lambda: {"workspaces": []})
    monkeypatch.setattr(engine, "_advance_browser_consent", lambda *args, **kwargs: (True, "oauth-code-from-consent"))

    code = engine._oauth_submit_workspace_org_for_code("https://auth.openai.com/sign-in-with-chatgpt/codex/consent")

    assert code == "oauth-code-from-consent"


def test_v2_run_returns_passwordless_success(monkeypatch):
    engine = PlaywrightRegistrationEngine(
        email_service=_dummy_email_service(),
        callback_logger=lambda *_args, **_kwargs: None,
    )
    engine.session = SimpleNamespace(cookies=SimpleNamespace(get=lambda _name: ""))
    monkeypatch.setattr(engine, "_check_ip_location", lambda: (True, "US"))
    monkeypatch.setattr(engine, "_emit_status", lambda *args, **kwargs: None)

    def fake_email_prepare():
        engine.email = "v2@example.com"
        return True

    monkeypatch.setattr(engine, "_phase_email_prepare", fake_email_prepare)
    monkeypatch.setattr(engine, "_init_session", lambda: True)
    monkeypatch.setattr(engine, "_start_oauth", lambda: True)
    monkeypatch.setattr(engine, "perform_oauth", lambda: "http://localhost:1455/callback?code=v2-code&state=state-123")
    monkeypatch.setattr(
        engine,
        "_handle_oauth_callback",
        lambda _callback: {
            "account_id": "acct-v2",
            "access_token": "access-v2",
            "refresh_token": "refresh-v2",
            "id_token": "id-v2",
        },
    )
    monkeypatch.setattr(engine, "_decode_auth_session_cookie", lambda: {"workspaces": [{"id": "ws-v2"}]})
    monkeypatch.setattr(engine, "_compose_cookie_string", lambda: "cookie=v2")
    monkeypatch.setattr(engine, "_append_account_checkpoint", lambda *args, **kwargs: None)

    result = engine.run()

    assert result.success is True
    assert result.password == ""
    assert result.workspace_id == "ws-v2"
    assert result.metadata["oauth_flow"] == "passwordless"
