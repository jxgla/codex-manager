from types import SimpleNamespace

from src.core import registration_factory


def test_normalize_engine_mode_maps_aliases():
    assert registration_factory.normalize_engine_mode(None) == "playwright_v3"
    assert registration_factory.normalize_engine_mode("playwright") == "playwright_v3"
    assert registration_factory.normalize_engine_mode("v3") == "playwright_v3"
    assert registration_factory.normalize_engine_mode("playwright_v2") == "playwright_v2"
    assert registration_factory.normalize_engine_mode("curl_cffi") == "legacy"


def test_create_registration_engine_selects_expected_class(monkeypatch):
    calls = []

    class DummyLegacy:
        def __init__(self, **kwargs):
            calls.append(("legacy", kwargs))

    class DummyPlaywright:
        def __init__(self, **kwargs):
            calls.append(("playwright_v2", kwargs))

    class DummyPlaywrightV3:
        def __init__(self, **kwargs):
            calls.append(("playwright_v3", kwargs))

    monkeypatch.setattr(registration_factory, "RegistrationEngine", DummyLegacy)
    monkeypatch.setattr(
        registration_factory,
        "PlaywrightRegistrationEngine",
        DummyPlaywright,
    )
    monkeypatch.setattr(
        registration_factory,
        "PlaywrightRegistrationEngineV3",
        DummyPlaywrightV3,
    )

    email_service = SimpleNamespace(service_type=SimpleNamespace(value="tempmail"))

    registration_factory.create_registration_engine(
        mode="legacy",
        email_service=email_service,
        proxy_url="http://127.0.0.1:8080",
        task_uuid="task-1",
    )
    registration_factory.create_registration_engine(
        mode="playwright",
        email_service=email_service,
        proxy_url=None,
        task_uuid="task-2",
    )
    registration_factory.create_registration_engine(
        mode="playwright_v2",
        email_service=email_service,
        proxy_url=None,
        task_uuid="task-3",
    )
    registration_factory.create_registration_engine(
        mode="playwright_v3",
        email_service=email_service,
        proxy_url=None,
        task_uuid="task-4",
    )

    assert calls[0][0] == "legacy"
    assert calls[0][1]["task_uuid"] == "task-1"
    assert calls[1][0] == "playwright_v3"
    assert calls[1][1]["task_uuid"] == "task-2"
    assert calls[2][0] == "playwright_v2"
    assert calls[2][1]["task_uuid"] == "task-3"
    assert calls[3][0] == "playwright_v3"
    assert calls[3][1]["task_uuid"] == "task-4"
