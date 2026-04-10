from src.core.account_checkpoint import (
    append_account_checkpoint,
    format_account_checkpoint_line,
    resolve_accounts_checkpoint_path,
)


def test_format_account_checkpoint_line_contains_stage_and_oauth():
    line = format_account_checkpoint_line(
        "user@example.com",
        "pass123",
        stage="oauth_success",
        oauth=True,
        metadata={
            "source": "register",
            "account_id": "acct_123",
            "workspace_id": "ws_123",
        },
    )

    assert "\tuser@example.com\tpass123\t" in line
    assert "stage=oauth_success" in line
    assert "oauth=1" in line
    assert "account_id=acct_123" in line
    assert "workspace_id=ws_123" in line


def test_append_account_checkpoint_uses_project_root_from_app_data_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path / "data"))

    output = append_account_checkpoint(
        "user@example.com",
        "pass123",
        stage="account_created",
        oauth=False,
        metadata={"task_uuid": "task-1"},
    )

    assert output == tmp_path / "accounts.txt"
    assert resolve_accounts_checkpoint_path() == tmp_path / "accounts.txt"
    assert output.read_text(encoding="utf-8").count("stage=account_created") == 1
