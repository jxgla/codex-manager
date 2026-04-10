from src.database.session import _build_sqlalchemy_url


def test_build_sqlalchemy_url_supports_relative_sqlite_path(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path / "data"))

    actual = _build_sqlalchemy_url("data/database.db")

    expected = (tmp_path / "data").resolve().parent / "data" / "database.db"
    assert actual == f"sqlite:///{expected.resolve().as_posix()}"


def test_build_sqlalchemy_url_supports_relative_sqlite_url(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path / "data"))

    actual = _build_sqlalchemy_url("sqlite:///data/database.db")

    expected = (tmp_path / "data").resolve().parent / "data" / "database.db"
    assert actual == f"sqlite:///{expected.resolve().as_posix()}"


def test_build_sqlalchemy_url_normalizes_postgresql_driver():
    actual = _build_sqlalchemy_url("postgresql://user:pass@localhost:5432/testdb")

    assert actual == "postgresql+psycopg://user:pass@localhost:5432/testdb"


def test_build_sqlalchemy_url_preserves_sqlite_memory():
    assert _build_sqlalchemy_url(":memory:") == "sqlite:///:memory:"
    assert _build_sqlalchemy_url("sqlite:///:memory:") == "sqlite:///:memory:"
