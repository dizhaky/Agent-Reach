"""Contract test verifying test suite isolation and import-time sandboxing in Agent-Reach."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

_PROBE_ENV = "AGENT_REACH_IMPORT_GUARD_PROBE"
_SENTINEL_NAME = "AGENT-REACH-REAL-HOME-SENTINEL"


def test_conftest_sandboxes_state_before_module_imports() -> None:
    """Verify that conftest.py redirects HOME and state directories at import time."""
    from tests.conftest import (
        APPDATA_AT_CONFTEST_IMPORT,
        HOME_AT_CONFTEST_IMPORT,
        LOCALAPPDATA_AT_CONFTEST_IMPORT,
        USERPROFILE_AT_CONFTEST_IMPORT,
        XDG_CONFIG_HOME_AT_CONFTEST_IMPORT,
    )

    assert HOME_AT_CONFTEST_IMPORT, "conftest must set HOME at import time"
    assert "agent-reach-test-sandbox-" in HOME_AT_CONFTEST_IMPORT
    assert USERPROFILE_AT_CONFTEST_IMPORT == HOME_AT_CONFTEST_IMPORT
    assert XDG_CONFIG_HOME_AT_CONFTEST_IMPORT == str(Path(HOME_AT_CONFTEST_IMPORT) / ".config")
    assert APPDATA_AT_CONFTEST_IMPORT == str(Path(HOME_AT_CONFTEST_IMPORT) / "AppData" / "Roaming")
    assert LOCALAPPDATA_AT_CONFTEST_IMPORT == str(Path(HOME_AT_CONFTEST_IMPORT) / "AppData" / "Local")


def test_subprocess_credential_scrubbing_contract() -> None:
    """Spawn a clean Python subprocess with fake exported keys and verify scrubbing."""
    probe_code = f"""
import os
import sys

sys.path.insert(0, {repr(str(TESTS_DIR))})
from tests import conftest

# Verify credential detection
assert conftest._is_credential_var("EXA_API_KEY") is True
assert conftest._is_credential_var("OPENAI_API_KEY") is True
assert conftest._is_credential_var("TWITTER_AUTH_TOKEN") is True
assert conftest._is_credential_var("GITHUB_TOKEN") is True
assert conftest._is_credential_var("CUSTOM_TEST_API_KEY") is True
assert conftest._is_credential_var("SAFE_CONFIG_PATH") is False
print("GUARD_PROBE_PASSED")
"""
    env = dict(os.environ)
    env["EXA_API_KEY"] = "sentinel-exa-key-12345"
    env["GITHUB_TOKEN"] = "sentinel-gh-token"

    result = subprocess.run(
        [sys.executable, "-c", probe_code],
        cwd=str(Path(__file__).resolve().parents[1]),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, f"Probe failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    assert "GUARD_PROBE_PASSED" in result.stdout


def test_probe_child_binds_guarded_paths() -> None:
    """Child-only probe. Skipped in the parent run; driven by test_import_guard_beats_exported_env."""
    if not os.environ.get(_PROBE_ENV):
        pytest.skip("child-only probe, driven by test_import_guard_beats_exported_env")

    # The parent exported HOME=<...>/AGENT-REACH-REAL-HOME-SENTINEL before
    # spawning us. conftest must have overridden it at import.
    assert _SENTINEL_NAME not in os.environ["HOME"]
    assert _SENTINEL_NAME not in os.environ["USERPROFILE"]
    assert _SENTINEL_NAME not in os.environ["XDG_CONFIG_HOME"]

    # Credential env vars must be stripped by conftest at import time.
    assert "EXA_API_KEY" not in os.environ
    assert "OPENAI_API_KEY" not in os.environ
    assert "GROQ_API_KEY" not in os.environ
    assert "GITHUB_TOKEN" not in os.environ
    assert "TWITTER_AUTH_TOKEN" not in os.environ
    assert "TWITTER_CT0" not in os.environ
    assert "LINEAR_API_KEY" not in os.environ
    assert "ANTHROPIC_API_KEY" not in os.environ
    assert "GEMINI_API_KEY" not in os.environ
    assert "SLACK_BOT_TOKEN" not in os.environ
    assert "CUSTOM_TEST_API_KEY" not in os.environ
    assert "SOME_SERVICE_TOKEN" not in os.environ
    assert "DATABASE_PASSWORD" not in os.environ
    assert "APP_WEBHOOK_SECRET" not in os.environ

    # Deterministic environment variables must be set.
    assert os.environ.get("TZ") == "UTC"
    assert os.environ.get("LANG") == "C.UTF-8"
    assert os.environ.get("LC_ALL") == "C.UTF-8"
    assert os.environ.get("PYTHONHASHSEED") == "0"
    assert os.environ.get("AWS_EC2_METADATA_DISABLED") == "true"


def test_import_guard_beats_exported_env(tmp_path: Path) -> None:
    """Export a sentinel home root and credentials, then assert child ignored/stripped them."""
    sentinel = tmp_path / _SENTINEL_NAME
    sentinel.mkdir(parents=True)

    env = {
        **os.environ,
        "HOME": str(sentinel / "home"),
        "USERPROFILE": str(sentinel / "userprofile"),
        "XDG_CONFIG_HOME": str(sentinel / "config"),
        "EXA_API_KEY": "sentinel-exa-key",
        "OPENAI_API_KEY": "sentinel-openai-key",
        "GROQ_API_KEY": "sentinel-groq-key",
        "GITHUB_TOKEN": "sentinel-gh-token",
        "TWITTER_AUTH_TOKEN": "sentinel-tw-token",
        "TWITTER_CT0": "sentinel-tw-ct0",
        "LINEAR_API_KEY": "sentinel-linear-key",
        "ANTHROPIC_API_KEY": "sentinel-anthropic-key",
        "GEMINI_API_KEY": "sentinel-gemini-key",
        "SLACK_BOT_TOKEN": "sentinel-slack-token",
        "CUSTOM_TEST_API_KEY": "sentinel-custom-key",
        "SOME_SERVICE_TOKEN": "sentinel-token",
        "DATABASE_PASSWORD": "sentinel-password",
        "APP_WEBHOOK_SECRET": "sentinel-webhook-secret",
        "TZ": "America/New_York",
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "PYTHONHASHSEED": "12345",
        "AWS_EC2_METADATA_DISABLED": "false",
        _PROBE_ENV: "1",
    }
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            f"{__file__}::test_probe_child_binds_guarded_paths",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "conftest import guard did not override an exported HOME or scrub credentials.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
