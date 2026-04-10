"""
Incremental checkpoint writer for account creation and OAuth success.
"""

from __future__ import annotations

import os
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


_WRITE_LOCK = threading.Lock()
_PREFERRED_METADATA_KEYS = (
    "source",
    "email_service",
    "email_service_id",
    "registration_mode",
    "task_uuid",
    "account_id",
    "workspace_id",
    "proxy_used",
    "status",
)


def _project_root() -> Path:
    app_data_dir = os.environ.get("APP_DATA_DIR")
    if app_data_dir:
        return Path(app_data_dir).resolve().parent
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def resolve_accounts_checkpoint_path() -> Path:
    return _project_root() / "accounts.txt"


def _clean_field(value: Any) -> str:
    text = str(value or "").strip()
    return text.replace("\r", " ").replace("\n", " ").replace("\t", " ")


def _iter_metadata_items(metadata: Optional[Dict[str, Any]]) -> list[tuple[str, str]]:
    raw = dict(metadata or {})
    items: list[tuple[str, str]] = []

    for key in _PREFERRED_METADATA_KEYS:
        value = _clean_field(raw.pop(key, ""))
        if value:
            items.append((key, value))

    for key in sorted(raw):
        value = _clean_field(raw[key])
        if value:
            items.append((key, value))

    return items


def format_account_checkpoint_line(
    email: str,
    password: str,
    *,
    stage: str,
    oauth: Optional[bool] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    fields = [
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        _clean_field(email),
        _clean_field(password),
        f"stage={_clean_field(stage)}",
        "register_success=1",
    ]

    if oauth is not None:
        fields.append(f"oauth={1 if oauth else 0}")

    for key, value in _iter_metadata_items(metadata):
        fields.append(f"{key}={value}")

    return "\t".join(fields) + "\n"


def append_account_checkpoint(
    email: str,
    password: str,
    *,
    stage: str,
    oauth: Optional[bool] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Path:
    path = resolve_accounts_checkpoint_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = format_account_checkpoint_line(
        email,
        password,
        stage=stage,
        oauth=oauth,
        metadata=metadata,
    )

    with _WRITE_LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)

    return path
