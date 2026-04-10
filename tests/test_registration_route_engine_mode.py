from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks

from src.web.routes import registration as registration_routes


@contextmanager
def _fake_db():
    yield object()


def _fake_task(task_uuid: str):
    return SimpleNamespace(
        id=1,
        task_uuid=task_uuid,
        status="pending",
        email_service_id=None,
        proxy=None,
        logs="",
        result=None,
        error_message=None,
        created_at=None,
        started_at=None,
        completed_at=None,
    )


@pytest.mark.asyncio
async def test_start_registration_threads_engine_mode(monkeypatch):
    created = []

    monkeypatch.setattr(registration_routes, "get_db", _fake_db)
    monkeypatch.setattr(
        registration_routes.crud,
        "create_registration_task",
        lambda db, task_uuid, proxy=None: created.append((task_uuid, proxy)) or _fake_task(task_uuid),
    )

    background_tasks = BackgroundTasks()
    request = registration_routes.RegistrationTaskCreate(
        email_service_type="tempmail",
        engine_mode="legacy",
    )

    await registration_routes.start_registration(request, background_tasks)

    task = background_tasks.tasks[0]
    assert task.func is registration_routes.run_registration_task
    assert task.args[5] == "legacy"


@pytest.mark.asyncio
async def test_start_batch_registration_threads_engine_mode(monkeypatch):
    tasks = {}

    monkeypatch.setattr(registration_routes, "get_db", _fake_db)
    monkeypatch.setattr(
        registration_routes.crud,
        "create_registration_task",
        lambda db, task_uuid, proxy=None: tasks.setdefault(task_uuid, _fake_task(task_uuid)),
    )
    monkeypatch.setattr(
        registration_routes.crud,
        "get_registration_task",
        lambda db, task_uuid: tasks[task_uuid],
    )

    background_tasks = BackgroundTasks()
    request = registration_routes.BatchRegistrationRequest(
        count=2,
        email_service_type="tempmail",
        engine_mode="playwright_v2",
    )

    await registration_routes.start_batch_registration(request, background_tasks)

    task = background_tasks.tasks[0]
    assert task.func is registration_routes.run_batch_registration
    assert task.args[10] == "playwright_v2"


@pytest.mark.asyncio
async def test_start_outlook_batch_registration_threads_engine_mode():
    background_tasks = BackgroundTasks()
    request = registration_routes.OutlookBatchRegistrationRequest(
        service_ids=[101, 202],
        skip_registered=False,
        engine_mode="legacy",
    )

    await registration_routes.start_outlook_batch_registration(request, background_tasks)

    task = background_tasks.tasks[0]
    assert task.func is registration_routes.run_outlook_batch_registration
    assert task.args[8] == "legacy"
