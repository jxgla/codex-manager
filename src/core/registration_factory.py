"""
Registration engine factory.

Keeps route orchestration independent from the concrete registration engine.
"""

from typing import Optional

from ..services.base import BaseEmailService
from .register import RegistrationEngine
from .register_playwright import PlaywrightRegistrationEngine

DEFAULT_ENGINE_MODE = "playwright_v2"
SUPPORTED_ENGINE_MODES = {"legacy", "playwright_v2"}


def normalize_engine_mode(mode: Optional[str]) -> str:
    normalized = str(mode or "").strip().lower() or DEFAULT_ENGINE_MODE
    aliases = {
        "curl": "legacy",
        "curl_cffi": "legacy",
        "legacy_v1": "legacy",
        "playwright": "playwright_v2",
        "playwrightv2": "playwright_v2",
        "browser": "playwright_v2",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in SUPPORTED_ENGINE_MODES:
        raise ValueError(f"unsupported engine mode: {mode}")
    return normalized


def create_registration_engine(
    *,
    mode: Optional[str],
    email_service: BaseEmailService,
    proxy_url: Optional[str] = None,
    callback_logger=None,
    status_callback=None,
    task_uuid: Optional[str] = None,
):
    normalized_mode = normalize_engine_mode(mode)
    engine_cls = (
        PlaywrightRegistrationEngine
        if normalized_mode == "playwright_v2"
        else RegistrationEngine
    )
    return engine_cls(
        email_service=email_service,
        proxy_url=proxy_url,
        callback_logger=callback_logger,
        status_callback=status_callback,
        task_uuid=task_uuid,
    )
