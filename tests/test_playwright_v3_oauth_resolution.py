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
