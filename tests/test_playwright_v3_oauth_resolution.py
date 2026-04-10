from types import SimpleNamespace

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
