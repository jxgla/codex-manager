import asyncio
from contextlib import contextmanager
from types import SimpleNamespace

from src.web.routes import registration as registration_routes
from src.web.task_manager import task_manager


def test_init_batch_state_persists_state_in_task_manager():
    batch_id = "batch-sync-init"
    task_uuids = ["task-1", "task-2", "task-3"]

    registration_routes._init_batch_state(batch_id, task_uuids)

    manager_snapshot = task_manager.get_batch_status(batch_id)

    assert manager_snapshot is not None
    assert manager_snapshot["task_uuids"] == task_uuids
    assert manager_snapshot["total"] == 3
    assert manager_snapshot["completed"] == 0
    assert manager_snapshot["success"] == 0
    assert manager_snapshot["failed"] == 0
    assert manager_snapshot["finished"] is False
    assert manager_snapshot["status"] == "running"
    assert task_manager.get_batch_logs(batch_id) == []


def test_run_batch_parallel_keeps_counter_updates_in_sync(monkeypatch):
    batch_id = "batch-sync-parallel"
    task_uuids = ["task-ok-1", "task-fail-1", "task-ok-2"]
    task_statuses = {
        "task-ok-1": "completed",
        "task-fail-1": "failed",
        "task-ok-2": "completed",
    }

    async def fake_run_registration_task(
        task_uuid,
        email_service_type,
        proxy,
        email_service_config,
        email_service_id,
        engine_mode="playwright_v2",
        log_prefix="",
        batch_id="",
        auto_upload_cpa=False,
        cpa_service_ids=None,
        auto_upload_sub2api=False,
        sub2api_service_ids=None,
        auto_upload_tm=False,
        tm_service_ids=None,
        auto_upload_newapi=False,
        newapi_service_ids=None,
    ):
        assert task_uuid in task_statuses

    @contextmanager
    def fake_get_db():
        yield object()

    def fake_get_registration_task(db, task_uuid):
        status = task_statuses[task_uuid]
        error_message = None if status == "completed" else f"{task_uuid}-error"
        return SimpleNamespace(status=status, error_message=error_message)

    monkeypatch.setattr(registration_routes, "run_registration_task", fake_run_registration_task)
    monkeypatch.setattr(registration_routes, "get_db", fake_get_db)
    monkeypatch.setattr(registration_routes.crud, "get_registration_task", fake_get_registration_task)

    asyncio.run(
        registration_routes.run_batch_parallel(
            batch_id=batch_id,
            task_uuids=task_uuids,
            email_service_type="tempmail",
            proxy=None,
            email_service_config=None,
            email_service_id=None,
            concurrency=2,
        )
    )

    manager_snapshot = task_manager.get_batch_status(batch_id)

    assert manager_snapshot is not None
    assert manager_snapshot["completed"] == 3
    assert manager_snapshot["success"] == 2
    assert manager_snapshot["failed"] == 1
    assert manager_snapshot["finished"] is True
    assert manager_snapshot["status"] == "completed"
