"""tenant_env: the environment always wins over a credentials file."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tenant_env import KEYS, tenant_credentials  # noqa: E402

FILE_VALUES = {"DEMISTO_BASE_URL": "https://api-file.example", "DEMISTO_API_KEY": "file-key",
               "XSIAM_AUTH_ID": "9"}


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)
    path = tmp_path / "creds"
    path.write_text("".join('{}="{}"\n'.format(k, v) for k, v in FILE_VALUES.items()) + "# comment\n")
    return str(path)


def test_the_environment_wins_over_the_file(env_file, monkeypatch):
    monkeypatch.setenv("DEMISTO_BASE_URL", "https://api-lab.example")
    monkeypatch.setenv("DEMISTO_API_KEY", "env-key")
    monkeypatch.setenv("XSIAM_AUTH_ID", "1")
    assert tenant_credentials(env_file) == {"DEMISTO_BASE_URL": "https://api-lab.example",
                                            "DEMISTO_API_KEY": "env-key", "XSIAM_AUTH_ID": "1"}


def test_the_file_fills_only_what_the_environment_lacks(env_file, monkeypatch):
    monkeypatch.setenv("DEMISTO_BASE_URL", "https://api-lab.example")
    creds = tenant_credentials(env_file)
    assert creds["DEMISTO_BASE_URL"] == "https://api-lab.example"
    assert creds["DEMISTO_API_KEY"] == "file-key"


def test_missing_credentials_name_what_is_missing_and_how_to_run(tmp_path, monkeypatch):
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(SystemExit) as e:
        tenant_credentials(str(tmp_path / "absent"))
    assert "DEMISTO_API_KEY" in str(e.value) and "povkit exec" in str(e.value)


def test_not_required_returns_the_gap(tmp_path, monkeypatch):
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)
    assert tenant_credentials(str(tmp_path / "absent"), required=False) == {}
